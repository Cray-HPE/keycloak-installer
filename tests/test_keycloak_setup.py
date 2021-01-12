# Copyright 2020 Hewlett Packard Enterprise Development LP

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
        kc_clients_uuid_url = kc_clients_url + "?clientId=" + client.id
        responses.add(
            responses.GET, kc_clients_uuid_url, status=200, json=[{'id': "12345"}],
            headers={'location': str(mock.sentinel.location)})

        # call to get keycloak client secret, usign 12345 as keycloak id
        kc_clients_secret_url = '{}/admin/realms/shasta/clients/{}/client-secret'.format(kc_base, '12345')
        responses.add(
            responses.GET, kc_clients_secret_url, status=200, json={'value': "secret"},
            headers={'location': str(mock.sentinel.location)})

        # Test create and create_k8s_secrets
        client.create()
        client.create_k8s_secrets()

        k8s_secret_create_mock.assert_called_with(client.k8s_secret_namespaces[0],
                                                  client.k8s_secret_name,
                                                  {'client-id': client.id, 'client-secret': 'secret'})

        # verify calls, there should be three:
        # - one to create client
        # - one to get the keycloak ID for client
        # - one to get the keycloak secret for the client

        self.assertEqual(3, len(responses.calls))
        self.assertEqual(kc_clients_url, responses.calls[0].request.url)

        exp_req_body = {
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
        self.assertEqual(kc_clients_secret_url, responses.calls[2].request.url)

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

        # verify overall call count
        self.assertEqual(4, len(responses.calls))

        # Verify calls to create roles
        exp_req_body = {'name': 'user'}
        self.assertEqual(exp_req_body, json.loads(responses.calls[2].request.body))
        exp_req_body = {'name': 'admin'}
        self.assertEqual(exp_req_body, json.loads(responses.calls[3].request.body))

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

        kcs_mock.assert_called_once_with(
            keycloak_base=None,
            cluster_keycloak_base=None,
            kc_master_admin_client_id=str(mock.sentinel.client_id),
            kc_master_admin_password=str(mock.sentinel.password),
            kc_master_admin_username=str(mock.sentinel.user),
            customer_access_url=None,
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
