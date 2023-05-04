#
# MIT License
#
# (C) Copyright 2020, 2022 Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
import json

import base64
import fixtures
from kubernetes.client import rest
import mock
import requests
import responses
import testtools

from keycloak_setup import keycloak_setup


class TestKeycloakSetup(testtools.TestCase):
    def test_run(self):
        skc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, '_setup_keycloak')).mock

        kcs = keycloak_setup.KeycloakSetup()

        kcs.run()

        skc_mock.assert_called_once_with()

    def test_run_post_clients(self):
        ccs_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, '_cleanup_clients')).mock
        css_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, '_cleanup_secrets')).mock
        cfs_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, '_check_features')).mock

        kcs = keycloak_setup.KeycloakSetup()
        kcs.run_post_clients()

        ccs_mock.assert_called_once_with()
        css_mock.assert_called_once_with()
        cfs_mock.assert_called_once_with()

    def test_kc_master_admin_client(self):
        kcs = keycloak_setup.KeycloakSetup()

        lac_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.oauthlib.oauth2, 'LegacyApplicationClient')).mock
        osess_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.requests_oauthlib, 'OAuth2Session')).mock

        client = kcs.kc_master_admin_client

        self.assertIs(client, osess_mock.return_value)

        lac_mock.assert_called_once_with(client_id='admin-cli')

        kc_master_token_endpoint = (
            'http://keycloak.services:8080/keycloak/realms/'
            'master/protocol/openid-connect/token')
        osess_mock.assert_called_once_with(
            client=lac_mock.return_value,
            auto_refresh_url=kc_master_token_endpoint,
            auto_refresh_kwargs={
                'client_id': 'admin-cli',
            },
            token_updater=mock.ANY)

        oauth2session = osess_mock.return_value

        oauth2session.fetch_token.assert_called_once_with(
            token_url=kc_master_token_endpoint,
            client_id='admin-cli',
            username='admin',
            password='adminpwd')

        self.assertIs(kcs._kc_master_admin_client_cache, client)

    def test_setup_keycloak(self):
        wkr_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, '_wait_keycloak_ready'
        )).mock

        csr_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, 'create_realm'
        )).mock

        kcs = keycloak_setup.KeycloakSetup()

        kcs._setup_keycloak()

        wkr_mock.assert_called_once_with()
        csr_mock.assert_called_once_with(kcs.SHASTA_REALM_NAME)

    def test_wait_keycloak_ready_up_2_30(self):
        gu_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, '_get_uptime_ms'
        )).mock
        gu_mock.return_value = 150001
        rt_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, 'reset_keycloak_master_admin_session'
        )).mock

        kcs = keycloak_setup.KeycloakSetup()
        kcs._wait_keycloak_ready()

        gu_mock.assert_called_with()
        self.assertEqual(6, gu_mock.call_count)
        rt_mock.assert_called_once_with()

    def test_wait_keycloak_ready_up_short(self):
        gu_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, '_get_uptime_ms'
        )).mock
        # First time through loop one of the responses is <2:30, next time
        # all are >2:30
        gu_mock.side_effect = [
            1000, 150001, 150001, 150001, 150001, 150001,
            150001, 150001, 150001, 150001, 150001, 150001,
        ]
        sleep_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.time, 'sleep'
        )).mock
        rt_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, 'reset_keycloak_master_admin_session'
        )).mock

        kcs = keycloak_setup.KeycloakSetup()
        kcs._wait_keycloak_ready()

        gu_mock.assert_called_with()
        self.assertEqual(12, gu_mock.call_count)
        sleep_mock.assert_called_once_with((150000 - 1000) / 1000.0)
        rt_mock.assert_called_with()
        self.assertEqual(2, rt_mock.call_count)

    @responses.activate
    def test_get_uptime_ms(self):
        si_url = 'http://keycloak.services:8080/keycloak/admin/serverinfo'
        si_example_response = {
            'systemInfo': {
                'version': '9.0.0',
                'serverTime': 'Fri May 15 19:12:50 GMT 2020',
                'uptime': '1 day, 1 hour, 45 minutes, 48 seconds',
                'uptimeMillis': 92748706,
            },
            # Other stuff we don't care about.
        }
        responses.add(responses.GET, si_url, json=si_example_response)

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()

        result = kcs._get_uptime_ms()
        self.assertEqual(92748706, result)

    @responses.activate
    def test_create_realm(self):
        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()

        kc_realms_url = 'http://keycloak.services:8080/keycloak/admin/realms'
        responses.add(responses.POST, kc_realms_url, status=201, json={})

        kcs.create_realm(kcs.SHASTA_REALM_NAME)

        self.assertEqual(1, len(responses.calls))
        self.assertEqual(kc_realms_url, responses.calls[0].request.url)

        exp_req_body = {
            'realm': 'shasta',
            'enabled': True,
            'ssoSessionIdleTimeout': 31536000,
            'ssoSessionMaxLifespan': 31536000,
            'accessTokenLifespan': 31536000,
            'accessTokenLifespanForImplicitFlow': 31536000,
            'roles': {'realm': [{'name': 'tenant-admin'}]},
        }
        self.assertEqual(
            exp_req_body, json.loads(responses.calls[0].request.body))

    @responses.activate
    def test_create_realm_fail(self):
        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()

        kc_realms_url = 'http://keycloak.services:8080/keycloak/admin/realms'
        responses.add(responses.POST, kc_realms_url, status=401, json={})

        self.assertRaises(Exception, kcs.create_realm, kcs.SHASTA_REALM_NAME)

    @responses.activate
    def test_calc_client_url_found(self):
        realm_url = 'http://keycloak.services:8080/keycloak/admin/realms/shasta'
        clients_url = f'{realm_url}/clients'
        fake_id = str(mock.sentinel.id)
        responses.add(responses.GET, clients_url, json=[{'id': fake_id}])

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()
        fake_client_id = str(mock.sentinel.client_id)
        res = kcs.calc_client_url(fake_client_id)
        exp_client_url = f'{clients_url}/{fake_id}'
        self.assertEqual(exp_client_url, res)

        exp_query_url = f'{clients_url}?clientId={fake_client_id}'
        self.assertEqual(exp_query_url, responses.calls[0].request.url)

    @responses.activate
    def test_calc_client_url_not_found(self):
        realm_url = 'http://keycloak.services:8080/keycloak/admin/realms/shasta'
        clients_url = f'{realm_url}/clients'
        responses.add(responses.GET, clients_url, json=[])

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()
        fake_client_id = str(mock.sentinel.client_id)
        res = kcs.calc_client_url(fake_client_id)
        self.assertIsNone(res)

    @responses.activate
    def test_calc_client_url_error(self):
        realm_url = 'http://keycloak.services:8080/keycloak/admin/realms/shasta'
        clients_url = f'{realm_url}/clients'
        responses.add(responses.GET, clients_url, status=500, json=[])

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()
        fake_client_id = str(mock.sentinel.client_id)
        self.assertRaises(
            requests.exceptions.HTTPError, kcs.calc_client_url, fake_client_id)

    def test_cleanup_clients(self):
        cc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, '_cleanup_client')).mock
        clients_to_cleanup = [str(mock.sentinel.client1)]
        kcs = keycloak_setup.KeycloakSetup(clients_to_cleanup=clients_to_cleanup)
        kcs._cleanup_clients()
        cc_mock.assert_called_once_with(str(mock.sentinel.client1))

    @responses.activate
    def test_cleanup_client_exists(self):
        ccu_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, 'calc_client_url')).mock
        fake_url = 'http://keycloak.services:8080/whatever'
        ccu_mock.return_value = fake_url

        responses.add(responses.DELETE, fake_url, status=204)

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()
        fake_client_id = str(mock.sentinel.client_id)
        kcs._cleanup_client(fake_client_id)

        ccu_mock.assert_called_once_with(fake_client_id)
        self.assertEqual(1, len(responses.calls))

    def test_cleanup_client_not_found(self):
        ccu_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, 'calc_client_url')).mock
        ccu_mock.return_value = None
        kcs = keycloak_setup.KeycloakSetup()
        fake_client_id = str(mock.sentinel.client_id)
        kcs._cleanup_client(fake_client_id)
        ccu_mock.assert_called_once_with(fake_client_id)

    @responses.activate
    def test_cleanup_client_error(self):
        # When _cleanup_client is called and the delete operation fails
        # the error is ignored.
        ccu_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, 'calc_client_url')).mock
        fake_url = 'http://keycloak.services:8080/whatever'
        ccu_mock.return_value = fake_url

        responses.add(responses.DELETE, fake_url, status=500)

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()
        fake_client_id = str(mock.sentinel.client_id)
        kcs._cleanup_client(fake_client_id)

        ccu_mock.assert_called_once_with(fake_client_id)
        self.assertEqual(1, len(responses.calls))

    def test_cleanup_secrets(self):
        cs_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, '_cleanup_secret')).mock
        fake_secret_name = str(mock.sentinel.secret_1)
        fake_secret_namespaces = [str(mock.sentinel.namespace1_1)]
        secrets_to_cleanup = [
            {
                'name': fake_secret_name,
                'namespaces': fake_secret_namespaces,
            },
        ]
        kcs = keycloak_setup.KeycloakSetup(secrets_to_cleanup=secrets_to_cleanup)
        kcs._cleanup_secrets()
        cs_mock.assert_called_once_with(fake_secret_name, fake_secret_namespaces)

    def test_cleanup_secret(self):
        ds_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.KeycloakSetup, '_delete_secret')).mock
        kcs = keycloak_setup.KeycloakSetup()
        fake_secret_name = str(mock.sentinel.secret_1)
        fake_secret_namespace = str(mock.sentinel.namespace1_1)
        fake_secret_namespaces = [fake_secret_namespace]
        kcs._cleanup_secret(fake_secret_name, fake_secret_namespaces)
        ds_mock.assert_called_once_with(fake_secret_name, fake_secret_namespace)

    def test_delete_secret_deleted(self):
        kcs = keycloak_setup.KeycloakSetup()
        k8s_corev1_mock = mock.Mock()
        kcs._k8s_corev1_cache = k8s_corev1_mock
        fake_secret_name = str(mock.sentinel.secret_1)
        fake_namespace = str(mock.sentinel.namespace1_1)
        kcs._delete_secret(fake_secret_name, fake_namespace)
        k8s_corev1_mock.delete_namespaced_secret.assert_called_once_with(
            fake_secret_name, fake_namespace)

    def test_delete_secret_doesnt_exist(self):
        # If the secret already doesn't exist, that's ignored.
        kcs = keycloak_setup.KeycloakSetup()
        k8s_corev1_mock = mock.Mock()
        k8s_corev1_mock.delete_namespaced_secret.side_effect = rest.ApiException(404)
        kcs._k8s_corev1_cache = k8s_corev1_mock
        fake_secret_name = str(mock.sentinel.secret_1)
        fake_namespace = str(mock.sentinel.namespace1_1)
        kcs._delete_secret(fake_secret_name, fake_namespace)

    def test_delete_secret_fails(self):
        # If there's another error deleting the secret it's re-raised.
        kcs = keycloak_setup.KeycloakSetup()
        k8s_corev1_mock = mock.Mock()
        k8s_corev1_mock.delete_namespaced_secret.side_effect = rest.ApiException(403)
        kcs._k8s_corev1_cache = k8s_corev1_mock
        fake_secret_name = str(mock.sentinel.secret_1)
        fake_namespace = str(mock.sentinel.namespace1_1)
        self.assertRaises(
            rest.ApiException, kcs._delete_secret, fake_secret_name, fake_namespace)

    def test_client_input_validation(self):

        """Test input validation for the KeycloakClient class"""

        kcs = keycloak_setup.KeycloakSetup()

        # -----------------------------------------------------------
        # Type checking
        # -----------------------------------------------------------

        # bad keycloak setup type
        self.assertRaises(TypeError,
                          keycloak_setup.KeycloakClient,
                          None,
                          kcs.SHASTA_REALM_NAME,
                          'test')
        # bad realm type
        self.assertRaises(TypeError,
                          keycloak_setup.KeycloakClient,
                          kcs,
                          None,
                          'test')
        # bad client type
        self.assertRaises(TypeError,
                          keycloak_setup.KeycloakClient,
                          kcs,
                          kcs.SHASTA_REALM_NAME,
                          None)
        # bad k8s secret name type
        self.assertRaises(TypeError,
                          keycloak_setup.KeycloakClient,
                          kcs,
                          kcs.SHASTA_REALM_NAME,
                          'test',
                          0)
        # bad k8s secret namespace type
        self.assertRaises(TypeError,
                          keycloak_setup.KeycloakClient,
                          kcs,
                          kcs.SHASTA_REALM_NAME,
                          'test',
                          'test-secret-name',
                          0)

        # bad k8s secret namespace element
        self.assertRaises(TypeError,
                          keycloak_setup.KeycloakClient,
                          kcs,
                          kcs.SHASTA_REALM_NAME,
                          'test',
                          'test-secret-name',
                          [0])

        # bad k8s secret namespace element
        self.assertRaises(TypeError,
                          keycloak_setup.KeycloakClient,
                          kcs,
                          kcs.SHASTA_REALM_NAME,
                          'test',
                          'test-secret-name',
                          [0])

        # -----------------------------------------------------------
        # Value checking
        # -----------------------------------------------------------

        # bad realm
        self.assertRaises(ValueError,
                          keycloak_setup.KeycloakClient,
                          kcs,
                          '\t',
                          'test')

        # bad user
        self.assertRaises(ValueError,
                          keycloak_setup.KeycloakClient,
                          kcs,
                          'test',
                          '\t')

        # bad k8s secret name
        self.assertRaises(ValueError,
                          keycloak_setup.KeycloakClient,
                          kcs,
                          kcs.SHASTA_REALM_NAME,
                          'test',
                          'bad_secret_name',
                          ['test'])
        # bad k8s secret namespace
        self.assertRaises(ValueError,
                          keycloak_setup.KeycloakClient,
                          kcs,
                          kcs.SHASTA_REALM_NAME,
                          'test',
                          'test',
                          ['bad_namespace'])
        # k8s secret name set to None, namespaces not
        self.assertRaises(ValueError,
                          keycloak_setup.KeycloakClient,
                          kcs,
                          kcs.SHASTA_REALM_NAME,
                          'test',
                          None,
                          ['test'])
        # k8s secret namespaces set to None, name not
        self.assertRaises(ValueError,
                          keycloak_setup.KeycloakClient,
                          kcs,
                          kcs.SHASTA_REALM_NAME,
                          'test',
                          'test',
                          None)

        # test attempt to create secret with no name set (should be no op)

        c = keycloak_setup.KeycloakClient(kcs, 'test', 'test')
        c.create_k8s_secrets()

        # test attempt to create secret without first creating client
        c = keycloak_setup.KeycloakClient(kcs, 'test', 'test', 'secret-name', ['test'])
        self.assertRaises(ValueError, c.create_k8s_secrets)

        # validate defaults
        c = keycloak_setup.KeycloakClient(kcs, 'test', 'test', 'secret-name', ['test'])
        self.assertFalse(c.standard_flow_enabled)
        self.assertFalse(c.implicit_flow_enabled)
        self.assertFalse(c.direct_access_grants_enabled)
        self.assertFalse(c.service_accounts_enabled)
        self.assertFalse(c.public_client)

        # validate unable to set properties to bad type
        # then good bool value
        for p in ('public_client',
                  'service_accounts_enabled',
                  'direct_access_grants_enabled',
                  'implicit_flow_enabled',
                  'standard_flow_enabled'):

            self.assertRaises(TypeError,
                              setattr,
                              c,
                              p,
                              None)

            setattr(c, p, True)

        self.assertTrue(c.standard_flow_enabled)
        self.assertTrue(c.implicit_flow_enabled)
        self.assertTrue(c.direct_access_grants_enabled)
        self.assertTrue(c.service_accounts_enabled)
        self.assertTrue(c.public_client)

        # test role assignment type and value errors
        self.assertRaises(TypeError,
                          c.create_role,
                          None)

        self.assertRaises(ValueError,
                          c.create_role,
                          '\t')

        # client URL is not set before create
        self.assertRaises(ValueError,
                          c.create_role,
                          'test')

        # create collision for core attributes (keycloak)
        c.set_req_attr('implicitFlowEnabled', False)
        self.assertRaises(ValueError, c.create)

        # create collision for core K8S secret attributes
        c.set_k8s_secret_attr('client-id', 'foo')
        self.assertRaises(ValueError, c.create_k8s_secrets)

        # validate type checking when setting client_roles
        self.assertRaises(TypeError, setattr, c, 'client_roles', None)
        self.assertRaises(TypeError, setattr, c, 'client_roles', [None])
        c.client_roles = ['role1']
        self.assertEquals(['role1'], c.client_roles)

        # validate type checking when setting authorization_services_enabled
        self.assertRaises(TypeError, setattr, c, 'authorization_services_enabled', None)
        c.authorization_services_enabled = True
        self.assertTrue(c.authorization_services_enabled)

    @responses.activate
    def test_create_client(self):

        """Test non-public client creation"""

        kc_base = 'http://keycloak.services:8080/keycloak'

        # initial client create call
        kc_clients_url = '{}/admin/realms/shasta/clients'.format(kc_base)
        responses.add(
            responses.POST, kc_clients_url, status=201, json={},
            headers={'location': str(mock.sentinel.location)})

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()

        # mock k8s_apply_secret, tested elsewhere

        k8s_secret_create_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_setup, 'k8s_apply_secret'
        )).mock

        # create client and request properties
        client = keycloak_setup.KeycloakClient(kcs,
                                               kcs.SHASTA_REALM_NAME,
                                               'test_client',
                                               'test-k8s-secret-name',
                                               ['test-k8s-secret-namespace']
                                               )

        client.direct_access_grants_enabled = True
        client.service_accounts_enabled = True

        # use dummy values for client.id for audience mapping
        client_pm = \
            [
                {
                    'name': 'admin-role',
                    'protocol': 'openid-connect',
                    'protocolMapper': 'oidc-hardcoded-role-mapper',
                    'consentRequired': False,
                    'config': {
                        'role': 'shasta.admin',
                    },
                },
                {
                    'name': '{}-aud-mapper'.format(client.id),
                    'protocolMapper': 'oidc-audience-mapper',
                    'protocol': 'openid-connect',
                    'config': {
                        'included.client.audience': client.id,
                        'id.token.claim': False,
                        'access.token.claim': True,
                    },
                },
            ]

        client.set_req_attr('protocolMappers', client_pm)

        # call to get keycloak ID
        kc_clients_uuid_url = f'{kc_clients_url}?clientId={client.id}'
        responses.add(
            responses.GET, kc_clients_uuid_url, status=200, json=[{'id': "12345"}])

        # call to get keycloak client secret, usign 12345 as keycloak id
        kc_clients_secret_url = f'{kc_base}/admin/realms/shasta/clients/12345/client-secret'
        responses.add(
            responses.GET, kc_clients_secret_url, status=200, json={'value': "secret"})

        # Get the service account user for the client
        kc_clients_user_url = f'{kc_base}/admin/realms/shasta/users?username=service-account-test_client'
        responses.add(
            responses.GET, kc_clients_user_url, status=200, json=[{'id': "dummy-client-uuid", 'username': "service-account-test_client"}])

        # Get the client ID
        kc_clients_realm_mgmt_url = f'{kc_base}/admin/realms/shasta/clients?clientId=realm-management'
        responses.add(
            responses.GET, kc_clients_realm_mgmt_url, status=200, json=[{'id': "dummy-client-realm-mgmt-uuid"}])

        # Get the client role ID
        kc_realm_mgmt_roles_url = f'{kc_base}/admin/realms/shasta/clients/dummy-client-realm-mgmt-uuid/roles/view-clients'
        responses.add(
            responses.GET, kc_realm_mgmt_roles_url, status=200, json={'id': 'id', 'name': 'view-clients', 'clientRole': True})

        # Post the client role list to the users endpoint
        kc_user_role_map_url = f'{kc_base}/admin/realms/shasta/users/dummy-client-uuid/role-mappings/clients/dummy-client-realm-mgmt-uuid'
        responses.add(
            responses.POST, kc_user_role_map_url, status=204, json={})

        # Request adding a service account role
        client._service_account_client_roles = {"realm-management": ["view-clients"]}

        # Test create and create_k8s_secrets
        client.create()
        client.create_k8s_secrets()

        k8s_secret_create_mock.assert_called_with(client.k8s_secret_namespaces[0],
                                                  client.k8s_secret_name,
                                                  {'client-id': client.id, 'client-secret': 'secret'})

        # verify calls, there should be:
        # - one to create client
        # - one to get the keycloak ID for client
        # - one to get the keycloak secret for the client
        # Additional calls are for the purpose of adding a client role as noted above.

        self.assertEqual(7, len(responses.calls))
        self.assertEqual(kc_clients_url, responses.calls[0].request.url)

        exp_req_body = {
            'authorizationServicesEnabled': False,
            'clientId': client.id,
            'standardFlowEnabled': False,
            'implicitFlowEnabled': False,
            'directAccessGrantsEnabled': True,
            'serviceAccountsEnabled': True,
            'publicClient': False,
            'protocolMappers': client_pm
        }
        self.assertEqual(
            exp_req_body, json.loads(responses.calls[0].request.body))

        self.assertEqual(kc_clients_uuid_url, responses.calls[1].request.url)
        self.assertEqual(kc_clients_user_url, responses.calls[2].request.url)
        self.assertEqual(kc_clients_realm_mgmt_url, responses.calls[3].request.url)
        self.assertEqual(kc_realm_mgmt_roles_url, responses.calls[4].request.url)
        self.assertEqual(kc_user_role_map_url, responses.calls[5].request.url)
        self.assertEqual(kc_clients_secret_url, responses.calls[6].request.url)

    @responses.activate
    def test_create_client_fail(self):

        """Test non-public client creation failure"""

        kc_base = 'http://keycloak.services:8080/keycloak'

        # initial client create call, forced to 401 status
        kc_clients_url = '{}/admin/realms/shasta/clients'.format(kc_base)
        responses.add(
            responses.POST, kc_clients_url, status=401, json={},
            headers={'location': str(mock.sentinel.location)})

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()

        client = keycloak_setup.KeycloakClient(kcs,
                                               kcs.SHASTA_REALM_NAME,
                                               'test_client')

        client.direct_access_grants_enabled = True
        client.service_accounts_enabled = True

        # Test create and create_k8s_secrets
        self.assertRaises(Exception, client.create)

    @responses.activate
    def test_create_client_service_acct_role_fail(self):

        """Test non-public client creation"""

        kc_base = 'http://keycloak.services:8080/keycloak'

        # initial client create call
        kc_clients_url = '{}/admin/realms/shasta/clients'.format(kc_base)
        responses.add(
            responses.POST, kc_clients_url, status=201, json={},
            headers={'location': str(mock.sentinel.location)})

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()

        # create client and request properties
        client = keycloak_setup.KeycloakClient(kcs,
                                               kcs.SHASTA_REALM_NAME,
                                               'test_client',
                                               'test-k8s-secret-name',
                                               ['test-k8s-secret-namespace']
                                               )
        # Mock call to get keycloak ID
        kc_clients_uuid_url = kc_clients_url + "?clientId=" + client.id
        responses.add(
            responses.GET, kc_clients_uuid_url, status=200, json=[{'id': "12345"}])

        # Mock the case where a service account user for the client was not found.
        # This will return a 200 response and an empty list.
        kc_clients_user_url = f'{kc_base}/admin/realms/shasta/users?username=service-account-test_client'
        responses.add(
            responses.GET, kc_clients_user_url, status=200, json=[])

        # Request adding a service account role
        client._service_account_client_roles = {"realm-management": ["view-clients"]}
        client.create()

        # Verify the expected number of API calls.
        self.assertEqual(3, len(responses.calls))

        # Test the handling when the client is not found.
        # Update the previous mock so that it will return the expected result.
        responses.replace(
            responses.GET, kc_clients_user_url, status=200,
            json=[{'id': "test_client-uuid", 'username': "service-account-test_client"}])

        # Mock the case where the client ID can not be found from the client name.
        kc_clients_realm_mgmt_url = f'{kc_base}/admin/realms/shasta/clients?clientId=realm-management'
        responses.add(
            responses.GET, kc_clients_realm_mgmt_url, status=200,
            json=[])

        client.create()
        self.assertEqual(3 + 4, len(responses.calls))  # Expecting 4 new calls for this test

    @responses.activate
    def test_create_public_client(self):

        """Test public client create with role assignment"""

        kc_base = 'http://keycloak.services:8080/keycloak'

        # initial client create call
        kc_clients_url = '{}/admin/realms/shasta/clients'.format(kc_base)

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()

        client = keycloak_setup.KeycloakClient(kcs,
                                               kcs.SHASTA_REALM_NAME,
                                               'test_client')

        client.public_client = True
        client.direct_access_grants_enabled = True

        # use dummy values for client.id for audience mapping
        client_pm = \
            [
                {
                    'name': 'uid-user-attribute-mapper',
                    'protocolMapper': 'oidc-usermodel-attribute-mapper',
                    'protocol': 'openid-connect',
                    'config': {
                        'user.attribute': 'uidNumber',
                        'claim.name': 'uidNumber',
                        'id.token.claim': True,
                        'access.token.claim': False,
                        'userinfo.token.claim': True,
                    },
                },
                {
                    'name': 'gid-user-attribute-mapper',
                    'protocolMapper': 'oidc-usermodel-attribute-mapper',
                    'protocol': 'openid-connect',
                    'config': {
                        'user.attribute': 'gidNumber',
                        'claim.name': 'gidNumber',
                        'id.token.claim': True,
                        'access.token.claim': False,
                        'userinfo.token.claim': True,
                    },
                },
                {
                    'name': 'loginshell-user-attribute-mapper',
                    'protocolMapper': 'oidc-usermodel-attribute-mapper',
                    'protocol': 'openid-connect',
                    'config': {
                        'user.attribute': 'loginShell',
                        'claim.name': 'loginShell',
                        'id.token.claim': True,
                        'access.token.claim': False,
                        'userinfo.token.claim': True,
                    },
                },
                {
                    'name': 'homedirectory-user-attribute-mapper',
                    'protocolMapper': 'oidc-usermodel-attribute-mapper',
                    'protocol': 'openid-connect',
                    'config': {
                        'user.attribute': 'homeDirectory',
                        'claim.name': 'homeDirectory',
                        'id.token.claim': True,
                        'access.token.claim': False,
                        'userinfo.token.claim': True,
                    },
                },
                {
                    'name': '{}-aud-mapper'.format(client.id),
                    'protocolMapper': 'oidc-audience-mapper',
                    'protocol': 'openid-connect',
                    'config': {
                        'included.client.audience': client.id,
                        'id.token.claim': True,
                        'access.token.claim': True,
                    },
                },
                {
                    'name': '{}-aud-mapper'.format(client.id),
                    'protocolMapper': 'oidc-audience-mapper',
                    'protocol': 'openid-connect',
                    'config': {
                        'included.client.audience': client.id,
                        'id.token.claim': False,
                        'access.token.claim': True,
                    },
                },
            ]

        client.set_req_attr('protocolMappers', client_pm)

        # call for initial client create
        responses.add(
            responses.POST, kc_clients_url, status=201, json={},
            headers={'location': '{}/admin/realms/shasta/clients/{}'.format(kc_base, client.id)})

        # call to get keycloak id
        kc_clients_uuid_url = kc_clients_url + "?clientId=" + client.id
        responses.add(
            responses.GET, kc_clients_uuid_url, status=200, json=[{'id': "12345"}],
            headers={'location': str(mock.sentinel.location)})

        # call to set roles
        kc_roles_url = '{}/admin/realms/shasta/clients/{}/roles'.format(kc_base, "12345")
        responses.add(responses.POST, kc_roles_url, status=201, json={})

        # Test create
        client.create()

        # verify first call to create client
        exp_req_body = {
            'authorizationServicesEnabled': False,
            'clientId': client.id,
            'standardFlowEnabled': False,
            'implicitFlowEnabled': False,
            'directAccessGrantsEnabled': True,
            'serviceAccountsEnabled': False,
            'publicClient': True,
            'protocolMappers': client_pm
        }
        self.assertEqual(
            exp_req_body, json.loads(responses.calls[0].request.body))
        self.assertEqual(kc_clients_url, responses.calls[0].request.url)
        self.assertEqual(kc_clients_uuid_url, responses.calls[1].request.url)

        # Test role creation
        client.create_role('user')
        client.create_role('admin')
        client.create_role('monitor-ro')

        # verify overall call count
        self.assertEqual(5, len(responses.calls))

        # Verify calls to create roles
        exp_req_body = {'name': 'user'}
        self.assertEqual(exp_req_body, json.loads(responses.calls[2].request.body))
        exp_req_body = {'name': 'admin'}
        self.assertEqual(exp_req_body, json.loads(responses.calls[3].request.body))
        exp_req_body = {'name': 'monitor-ro'}
        self.assertEqual(exp_req_body, json.loads(responses.calls[4].request.body))

    @responses.activate
    def test_create_role_already_exists(self):
        """Test client create with role assignment, where role exists"""

        kc_base = 'http://keycloak.services:8080/keycloak'

        # initial client create call
        kc_clients_url = '{}/admin/realms/shasta/clients'.format(kc_base)

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()

        client = keycloak_setup.KeycloakClient(kcs,
                                               kcs.SHASTA_REALM_NAME,
                                               'test_client')

        responses.add(
            responses.POST, kc_clients_url, status=201, json={},
            headers={'location': '{}/admin/realms/shasta/clients/{}'.format(kc_base, client.id)})

        # call to get keycloak id
        kc_clients_uuid_url = kc_clients_url + "?clientId=" + client.id
        responses.add(
            responses.GET, kc_clients_uuid_url, status=200, json=[{'id': "12345"}],
            headers={'location': str(mock.sentinel.location)})

        # call to create role(s)
        kc_roles_url = '{}/admin/realms/shasta/clients/{}/roles'.format(kc_base, "12345")
        responses.add(responses.POST, kc_roles_url, status=409, json={})

        client.create()
        self.assertEqual(kc_clients_url, responses.calls[0].request.url)
        self.assertEqual(kc_clients_uuid_url, responses.calls[1].request.url)

        client.create_role("user")
        self.assertEqual(3, len(responses.calls))
        self.assertEqual(kc_roles_url, responses.calls[2].request.url)

    @responses.activate
    def test_create_role_fails(self):
        """Test client create with role assignment, where the role assignment fails"""

        kc_base = 'http://keycloak.services:8080/keycloak'

        # initial client create call
        kc_clients_url = '{}/admin/realms/shasta/clients'.format(kc_base)

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()

        client = keycloak_setup.KeycloakClient(kcs,
                                               kcs.SHASTA_REALM_NAME,
                                               'test_client')

        responses.add(
            responses.POST, kc_clients_url, status=201, json={},
            headers={'location': '{}/admin/realms/shasta/clients/{}'.format(kc_base, client.id)})

        # call to get keycloak id
        kc_clients_uuid_url = kc_clients_url + "?clientId=" + client.id
        responses.add(
            responses.GET, kc_clients_uuid_url, status=200, json=[{'id': "12345"}],
            headers={'location': str(mock.sentinel.location)})

        # call to create roles
        kc_roles_url = '{}/admin/realms/shasta/clients/{}/roles'.format(kc_base, "12345")

        responses.add(responses.POST, kc_roles_url, status=404, json={})

        client.create()

        self.assertRaises(
            Exception, client.create_role, "user")

    @responses.activate
    def test_create_client_exists(self):

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()

        kc_base = 'http://keycloak.services:8080/keycloak'
        kc_clients_url = '{}/admin/realms/{}/clients'.format(kc_base, kcs.SHASTA_REALM_NAME)
        responses.add(
            responses.POST, kc_clients_url, status=409, json={})

        client = keycloak_setup.KeycloakClient(kcs,
                                               kcs.SHASTA_REALM_NAME,
                                               'test')

        # call to get keycloak id
        kc_clients_uuid_url = kc_clients_url + "?clientId=" + client.id
        responses.add(
            responses.GET, kc_clients_uuid_url, status=200, json=[{'id': "12345"}],
            headers={'location': str(mock.sentinel.location)})

        client.create()

        self.assertEqual(2, len(responses.calls))
        self.assertEqual(kc_clients_url, responses.calls[0].request.url)
        self.assertEqual(kc_clients_uuid_url, responses.calls[1].request.url)

    @responses.activate
    def test_create_client_fails(self):
        kc_base = 'http://keycloak.services:8080/keycloak'
        kc_clients_url = '{}/admin/realms/shasta/clients'.format(kc_base)
        responses.add(
            responses.POST, kc_clients_url, status=401, json={})

        kcs = keycloak_setup.KeycloakSetup()
        kcs._kc_master_admin_client_cache = requests.Session()

        client = keycloak_setup.KeycloakClient(kcs,
                                               'test',
                                               'test')

        self.assertRaises(Exception, client.create)

    def test_create_keycloak_client_from_spec_minimal(self):
        client_id = str(mock.sentinel.client_id)
        min_spec = {}  # All of the keys are optional.
        kcs = keycloak_setup.KeycloakSetup()
        customer_access_url = str(mock.sentinel.customer_access_url)
        res = keycloak_setup.create_keycloak_client_from_spec(
            client_id, min_spec, kcs, customer_access_url)
        self.assertEqual(kcs, res.kas)
        self.assertEqual(kcs.SHASTA_REALM_NAME, res.realm)
        self.assertEqual(client_id, res.id)
        self.assertIsNone(res.k8s_secret_name)
        self.assertIsNone(res.k8s_secret_namespaces)
        self.assertEqual({}, res._k8s_secret_ext_attr)
        self.assertIs(res.standard_flow_enabled, False)
        self.assertIs(res.implicit_flow_enabled, False)
        self.assertIs(res.direct_access_grants_enabled, False)
        self.assertIs(res.service_accounts_enabled, False)
        self.assertIs(res.authorization_services_enabled, False)
        self.assertIs(res.public_client, False)
        self.assertEqual({}, res._kc_ext_attr)

    def test_create_keycloak_client_from_spec_all(self):
        client_id = str(mock.sentinel.client_id)
        spec = {  # Sets all the possible keys
            'type': 'public',
            'standardFlowEnabled': True,
            'implicitFlowEnabled': True,
            'directAccessGrantsEnabled': True,
            'serviceAccountsEnabled': True,
            'authorizationServicesEnabled': True,
            'proxiedHosts': [
                'test1',
                'test2',
            ],
            'secret': {
                'name': 'secret1',
                'namespaces': ['namespace1', 'namespace2'],
            }
        }
        kcs = keycloak_setup.KeycloakSetup()
        customer_access_url = str(mock.sentinel.customer_access_url)
        res = keycloak_setup.create_keycloak_client_from_spec(
            client_id, spec, kcs, customer_access_url)
        self.assertEqual(kcs, res.kas)
        self.assertEqual(kcs.SHASTA_REALM_NAME, res.realm)
        self.assertEqual(client_id, res.id)
        self.assertEqual('secret1', res.k8s_secret_name)
        self.assertEqual(['namespace1', 'namespace2'], res.k8s_secret_namespaces)

        exp_secret_ext_attr = {
            'discovery-url': f'{customer_access_url}/realms/shasta'
        }

        self.assertEqual(exp_secret_ext_attr, res._k8s_secret_ext_attr)
        self.assertIs(res.standard_flow_enabled, True)
        self.assertIs(res.implicit_flow_enabled, True)
        self.assertIs(res.direct_access_grants_enabled, True)
        self.assertIs(res.service_accounts_enabled, True)
        self.assertIs(res.authorization_services_enabled, True)
        self.assertIs(res.public_client, True)

        exp_ext_attr = {
            'redirectUris': [
                'https://test1/oauth/callback',
                'https://test2/oauth/callback',
            ]
        }
        self.assertEqual(exp_ext_attr, res._kc_ext_attr)

    def test_k8s_get_secret(self):
        # Mocks out kubernetes CoreV1Api object and read_namespaced_secret()
        # method.
        v1 = mock.Mock()
        v1.read_namespaced_secret.return_value = mock.sentinel.v1_secret

        # Sentinel inputs for verification
        ns = str(mock.sentinel.ns)
        name = str(mock.sentinel.name)

        secret = keycloak_setup.k8s_get_secret(ns, name, v1=v1)

        # Verify expected secret returned
        self.assertIs(secret, mock.sentinel.v1_secret)

        # Verify that read_namespaced_secret called with expected inputs
        v1.read_namespaced_secret.assert_called_once_with(name, ns)

    def test_k8s_get_secret_not_found(self):
        # Mocks out kubernetes CoreV1Api object and read_namespaced_secret()
        # method.
        v1 = mock.Mock()
        v1.read_namespaced_secret.side_effect = rest.ApiException(404)

        # Sentinel inputs for verification
        ns = str(mock.sentinel.ns)
        name = str(mock.sentinel.name)

        secret = keycloak_setup.k8s_get_secret(ns, name, v1=v1)

        # Verify return secret is None
        self.assertIsNone(secret)

        # Verify that read_namespaced_secret called with expected inputs
        v1.read_namespaced_secret.assert_called_once_with(name, ns)

    def test_k8s_get_secret_fails(self):
        # Mocks out kubernetes CoreV1Api object and read_namespaced_secret()
        # method.
        v1 = mock.Mock()
        v1.read_namespaced_secret.side_effect = rest.ApiException(401)

        # Sentinel inputs for verification
        ns = str(mock.sentinel.ns)
        name = str(mock.sentinel.name)

        # Verify exception is raised
        self.assertRaises(
            rest.ApiException,
            keycloak_setup.k8s_get_secret, ns, name, v1=v1,
        )

        # Verify that read_namespaced_secret called with expected inputs
        v1.read_namespaced_secret.assert_called_once_with(name, ns)

    def test_k8s_apply_secret(self):
        # Mock CoreV1Api() object
        v1 = mock.Mock()
        # Force k8s_get_secret to return None to create a new secret
        v1.read_namespaced_secret.return_value = None
        v1.create_namespaced_secret.return_value = None

        ns = str(mock.sentinel.ns)
        name = str(mock.sentinel.secret_name)
        data = {'key': 'value'}

        secret = keycloak_setup.k8s_apply_secret(ns, name, data, v1=v1)

        # Verify create_namespaced_secret() called
        v1.create_namespaced_secret.assert_called_once_with(ns, secret)

        # Verify created secret
        self.assertEqual(secret.metadata.name, name)
        self.assertEqual(secret.metadata.namespace, ns)
        self.assertEqual(secret.data['key'], base64.b64encode(bytes('value', 'utf-8')).decode("ascii"))

    def test_k8s_apply_secret_conflict(self):
        # Mock CoreV1Api() object
        v1 = mock.Mock()
        # Force k8s_get_secret to return None to create a new secret
        v1.read_namespaced_secret.return_value = None
        # Cause create_namespaced_secret() to raise 409
        v1.create_namespaced_secret.side_effect = rest.ApiException(409)

        ns = str(mock.sentinel.ns)
        name = str(mock.sentinel.secret_name)
        data = {'key': 'value'}

        keycloak_setup.k8s_apply_secret(ns, name, data, v1=v1)
        # No exception raised is expected for 409, but still verify
        # create_namespaced_secret() called
        v1.create_namespaced_secret.assert_called_once_with(ns, mock.ANY)

    def test_k8s_apply_secret_raises(self):
        # Mock CoreV1Api() object
        v1 = mock.Mock()
        # Force k8s_get_secret to return None to create a new secret
        v1.read_namespaced_secret.return_value = None
        # Cause create_namespaced_secret() to raise non-409
        v1.create_namespaced_secret.side_effect = rest.ApiException(401)

        ns = str(mock.sentinel.ns)
        name = str(mock.sentinel.secret_name)
        data = {'key': 'value'}

        self.assertRaises(
            rest.ApiException,
            keycloak_setup.k8s_apply_secret, ns, name, data, v1=v1,
        )

        # Verify create_namespaced_secret() called
        v1.create_namespaced_secret.assert_called_once_with(ns, mock.ANY)

    def test_k8s_apply_secret_no_change(self):
        existing_secret = mock.MagicMock()
        existing_secret.data = {'key': base64.b64encode(bytes('value', 'utf-8')).decode("ascii")}

        # Mock CoreV1Api() object
        v1 = mock.Mock()
        # Force k8s_get_secret to return a mocked secret
        v1.read_namespaced_secret.return_value = existing_secret
        # Ensure that patched_namespaced_secret() isn't called
        v1.patch_namespaced_secret.side_effect = RuntimeError('called')

        ns = str(mock.sentinel.ns)
        name = str(mock.sentinel.secret_name)
        data = {'key': 'value'}

        self.assertIs(
            existing_secret,
            keycloak_setup.k8s_apply_secret(ns, name, data, v1=v1)
        )

    def test_k8s_apply_secret_update(self):
        existing_secret = mock.MagicMock()
        existing_secret.data = {'key': base64.b64encode(bytes('old-value', 'utf-8')).decode("ascii")}

        # Mock CoreV1Api() object
        v1 = mock.Mock()
        # Force k8s_get_secret to return a mocked secret
        v1.read_namespaced_secret.return_value = existing_secret
        v1.patch_namespaced_secret.return_value = None

        ns = str(mock.sentinel.ns)
        name = str(mock.sentinel.secret_name)
        data = {'key': 'new-value'}

        secret = keycloak_setup.k8s_apply_secret(ns, name, data, v1=v1)

        # Verify patched_namespaced_secret() called
        v1.patch_namespaced_secret.assert_called_once_with(name, ns, secret)

        # Verify patched secret has new value
        self.assertEqual(secret.data['key'], base64.b64encode(bytes('new-value', 'utf-8')).decode("ascii"))

    def test_read_keycloak_master_admin_secrets_no_files_default(self):
        tmp_dir = self.useFixture(fixtures.TempDir()).path
        ret = keycloak_setup.read_keycloak_master_admin_secrets(
            secret_dir=tmp_dir)
        exp = {
            'password': 'adminpwd', 'user': 'admin', 'client_id': 'admin-cli'}
        self.assertEqual(exp, ret)

    def test_read_keycloak_master_admin_secrets_files(self):
        tmp_dir = self.useFixture(fixtures.TempDir()).path
        with open('{}/client-id'.format(tmp_dir), 'w') as f:
            f.write(str(mock.sentinel.client_id))
        with open('{}/user'.format(tmp_dir), 'w') as f:
            f.write(str(mock.sentinel.user))
        with open('{}/password'.format(tmp_dir), 'w') as f:
            f.write(str(mock.sentinel.password))

        ret = keycloak_setup.read_keycloak_master_admin_secrets(
            secret_dir=tmp_dir)
        exp = {
            'password': str(mock.sentinel.password),
            'user': str(mock.sentinel.user),
            'client_id': str(mock.sentinel.client_id),
        }
        self.assertEqual(exp, ret)

    def test_main(self):
        self.useFixture(fixtures.EnvironmentVariable(
            'KEYCLOAK_OAUTH2_PROXY_CLIENT_PROXIED_HOSTS', '[]'))

        self.useFixture(fixtures.MockPatchObject(
            keycloak_setup.kubernetes.config, 'load_incluster_config'))
        rkmas_ret = {
            'client_id': str(mock.sentinel.client_id),
            'user': str(mock.sentinel.user),
            'password': str(mock.sentinel.password),
        }
        rkmas_mock = self.useFixture(
            fixtures.MockPatchObject(
                keycloak_setup, 'read_keycloak_master_admin_secrets',
                return_value=rkmas_ret)).mock
        kcs_mock = self.useFixture(
            fixtures.MockPatchObject(keycloak_setup, 'KeycloakSetup',
                                     autospec=True)).mock

        client_mock = self.useFixture(
            fixtures.MockPatchObject(keycloak_setup, 'KeycloakClient',
                                     autospec=True)).mock

        keycloak_setup.main()

        rkmas_mock.assert_called_once_with()

        exp_clients_to_cleanup = ['gatekeeper']
        exp_secrets_to_cleanup = [{'name': 'keycloak-gatekeeper-client', 'namespaces': ['services']}]
        kcs_mock.assert_called_once_with(
            keycloak_base=None,
            cluster_keycloak_base=None,
            kc_master_admin_client_id=str(mock.sentinel.client_id),
            kc_master_admin_password=str(mock.sentinel.password),
            kc_master_admin_username=str(mock.sentinel.user),
            customer_access_url=None,
            clients_to_cleanup=exp_clients_to_cleanup,
            secrets_to_cleanup=exp_secrets_to_cleanup,
        )

        kcs_mock.return_value.run.assert_called_once_with()
        client_mock.assert_called()

    def test_get_wlm_client(self):
        cluster_keycloak_base = 'https://api-gw-service-nmn.local/keycloak'
        kcs = keycloak_setup.KeycloakSetup()
        wlm_client = keycloak_setup.get_wlm_client(kcs, cluster_keycloak_base)

        self.assertEqual(wlm_client.id, 'wlm-client')
        self.assertEqual(wlm_client.realm, 'shasta')
        self.assertEqual(wlm_client.k8s_secret_name, 'wlm-client-auth')
        self.assertEqual(wlm_client.k8s_secret_namespaces, ['default'])
        self.assertFalse(wlm_client.public_client)
        self.assertFalse(wlm_client.standard_flow_enabled)
        self.assertFalse(wlm_client.implicit_flow_enabled)
        self.assertFalse(wlm_client.direct_access_grants_enabled)
        self.assertTrue(wlm_client.service_accounts_enabled)
