#
# MIT License
#
# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP
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

import fixtures
import kubernetes.client
import mock
import requests
import responses
import testtools

from keycloak_setup import keycloak_localize


class TestKeycloakLocalize(testtools.TestCase):
    def test_run(self):
        cf_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_configure_ldap_user_federation')).mock
        clu_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_create_local_users')).mock
        clg_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_create_local_groups')).mock
        cas_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_assignments')).mock
        fetch_users_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_users')).mock
        fetch_groups_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_groups')).mock

        kl = keycloak_localize.KeycloakLocalize()
        kl.run()

        cf_mock.assert_called_once_with()
        clu_mock.assert_called_once_with()
        clg_mock.assert_called_once_with()
        cas_mock.assert_called_once_with()
        fetch_users_mock.assert_called_once_with()
        fetch_groups_mock.assert_called_once_with()

    def test_s3_client_property(self):
        bc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.boto3, 'client')).mock

        kl = keycloak_localize.KeycloakLocalize(
            user_export_storage_url=mock.sentinel.url,
            user_export_storage_access_key=mock.sentinel.ak,
            user_export_storage_secret_key=mock.sentinel.sk,
        )
        s3_client = kl._s3_client

        self.assertIs(s3_client, kl._s3_client)

        bc_mock.assert_called_once_with(
            's3',
            endpoint_url=mock.sentinel.url,
            aws_access_key_id=mock.sentinel.ak,
            aws_secret_access_key=mock.sentinel.sk,
        )

    def test_core_v1_property(self):
        kc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.kubernetes.client, 'CoreV1Api')).mock

        kl = keycloak_localize.KeycloakLocalize()
        core_v1 = kl._core_v1
        self.assertIs(core_v1, kl._core_v1)
        kc_mock.assert_called_once_with()

    def test_create_assignments_no_assignments(self):
        kl = keycloak_localize.KeycloakLocalize(local_role_assignments={})
        kl._create_assignments()

    def test_create_assignments_assignments(self):
        # _create_assignments() calls _create_assignment for each assignment.
        ca_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_assignment')).mock

        assignments = {mock.sentinel.a1, mock.sentinel.a2}
        kl = keycloak_localize.KeycloakLocalize(
            local_role_assignments=assignments)
        kl._create_assignments()

        ca_mock.assert_any_call(mock.sentinel.a1)
        ca_mock.assert_any_call(mock.sentinel.a2)
        self.assertEqual(2, ca_mock.call_count)

    def test_configure_ldap_user_federation_no_ldap(self):
        # When LDAP isn't configured (no connection URL), _configure_ldap_ does
        # nothing
        fc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_fetch_component_by_name')).mock

        kl = keycloak_localize.KeycloakLocalize()
        kl._configure_ldap_user_federation()

        fc_mock.assert_not_called()

    def test_configure_ldap_user_federation_already_exists(self):
        # When the query indicates the federation was already created then
        # nothing to do.
        fc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_fetch_component_by_name')).mock
        fc_mock.return_value = {'id': 'something'}

        kl = keycloak_localize.KeycloakLocalize(
            ldap_connection_url=str(mock.sentinel.ldap_url)
        )
        kl._configure_ldap_user_federation()

        fc_mock.assert_called_once_with(kl.ldap_federation_name)

    def test_configure_ldap_user_federation_needs_creating(self):
        # When the query indicates the federation doesn't exist then
        # the federation is created.
        fc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_fetch_component_by_name')).mock
        fc_mock.return_value = None

        cl_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_create_ldap_user_federation')).mock
        ruam_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_remove_ldap_user_attribute_mappers')).mock
        cuam_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_create_ldap_user_attribute_mappers')).mock
        clgm_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_create_ldap_group_mapper')).mock
        clrm_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_create_ldap_role_mapper')).mock
        sync_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_trigger_full_user_sync')).mock

        kl = keycloak_localize.KeycloakLocalize(
            ldap_connection_url=str(mock.sentinel.ldap_url)
        )
        kl._configure_ldap_user_federation()

        fc_mock.assert_called_once_with(kl.ldap_federation_name)
        cl_mock.assert_called_once_with()
        ruam_mock.assert_called_once_with()
        cuam_mock.assert_called_once_with()
        clgm_mock.assert_called_once_with()
        clrm_mock.assert_called_once_with()
        sync_mock.assert_called_once_with()

    def test_configure_ldap_user_federation_cleanup_on_error(self):
        # When configuration hits a problem and an exception is raised there's
        # an attempt to clean up and the original Exception is re-raised.
        fc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_fetch_component_by_name')).mock
        fc_mock.return_value = None

        cl_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_create_ldap_user_federation')).mock

        ruam_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_remove_ldap_user_attribute_mappers')).mock
        ruam_mock.side_effect = Exception()

        dl_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_delete_ldap_user_federation')).mock

        kl = keycloak_localize.KeycloakLocalize(
            ldap_connection_url=str(mock.sentinel.ldap_url)
        )
        self.assertRaises(Exception, kl._configure_ldap_user_federation)

        cl_mock.assert_called_once_with()
        dl_mock.assert_called_once_with()

    def test_create_local_users(self):
        cu_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_local_user')).mock

        local_users = [mock.sentinel.user1, mock.sentinel.user2]
        kl = keycloak_localize.KeycloakLocalize(local_users=local_users)
        kl._create_local_users()

        cu_mock.assert_any_call(mock.sentinel.user1)
        cu_mock.assert_any_call(mock.sentinel.user2)
        self.assertEqual(2, cu_mock.call_count)

    @responses.activate
    def test_create_local_user_success(self):
        url = 'http://keycloak.services:8080/keycloak/admin/realms/shasta/users'
        responses.add(responses.POST, url, status=204, json={})

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        user = {
            'name': str(mock.sentinel.name),
            'firstName': str(mock.sentinel.first_name),
            'password': str(mock.sentinel.password),
            'loginShell': str(mock.sentinel.login_shell),
            'homeDirectory': str(mock.sentinel.home_directory),
            'uidNumber': str(mock.sentinel.uid_number),
            'gidNumber': str(mock.sentinel.gid_number),
        }
        kl._create_local_user(user)

        exp_req_body = {
            'username': str(mock.sentinel.name),
            'enabled': True,
            'firstName': str(mock.sentinel.first_name),
            'credentials': [
                {'type': 'password', 'value': str(mock.sentinel.password), },
            ],
            'attributes': {
                'loginShell': [str(mock.sentinel.login_shell), ],
                'homeDirectory': [str(mock.sentinel.home_directory), ],
                'uidNumber': [str(mock.sentinel.uid_number), ],
                'gidNumber': [str(mock.sentinel.gid_number), ],
            },
        }
        self.assertEqual(
            exp_req_body, json.loads(responses.calls[0].request.body))

    @responses.activate
    def test_create_local_user_already_exists(self):
        url = 'http://keycloak.services:8080/keycloak/admin/realms/shasta/users'
        responses.add(responses.POST, url, status=409, json={})

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        user = {
            'name': str(mock.sentinel.name),
            'firstName': str(mock.sentinel.first_name),
            'password': str(mock.sentinel.password),
            'loginShell': str(mock.sentinel.login_shell),
            'homeDirectory': str(mock.sentinel.home_directory),
            'uidNumber': str(mock.sentinel.uid_number),
            'gidNumber': str(mock.sentinel.gid_number),
        }
        kl._create_local_user(user)
        # No exception is raised since 409 indicates already exists.

    @responses.activate
    def test_create_local_user_error(self):
        url = 'http://keycloak.services:8080/keycloak/admin/realms/shasta/users'
        responses.add(responses.POST, url, status=500, json={})

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        user = {
            'name': str(mock.sentinel.name),
            'firstName': str(mock.sentinel.first_name),
            'password': str(mock.sentinel.password),
            'loginShell': str(mock.sentinel.login_shell),
            'homeDirectory': str(mock.sentinel.home_directory),
            'uidNumber': str(mock.sentinel.uid_number),
            'gidNumber': str(mock.sentinel.gid_number),
        }
        self.assertRaises(requests.exceptions.HTTPError, kl._create_local_user, user)

    def test_create_local_groups(self):
        cg_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_local_group')).mock

        local_groups = [mock.sentinel.group1, mock.sentinel.group2]
        kl = keycloak_localize.KeycloakLocalize(local_groups=local_groups)
        kl._create_local_groups()

        cg_mock.assert_any_call(mock.sentinel.group1)
        cg_mock.assert_any_call(mock.sentinel.group2)
        self.assertEqual(2, cg_mock.call_count)

    @responses.activate
    def test_create_local_group_success(self):
        am_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_add_member')).mock

        url = 'http://keycloak.services:8080/keycloak/admin/realms/shasta/groups'
        sample_id = '16178977-7389-49b2-b4d8-c42fe0b4bf8f'
        sample_location_url = (
            'https://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'groups/{}'.format(sample_id))
        responses.add(
            responses.POST, url, status=204, json={},
            headers={'location': sample_location_url})

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        group = {
            'name': str(mock.sentinel.name),
            'gid': str(mock.sentinel.gid),
            'members': [str(mock.sentinel.user1), str(mock.sentinel.user2), ],
        }
        kl._create_local_group(group)

        exp_req_body = {
            'name': str(mock.sentinel.name),
            'attributes': {
                'cn': [str(mock.sentinel.name), ],
                'gidNumber': [str(mock.sentinel.gid), ],
                'memberUid': [str(mock.sentinel.user1), str(mock.sentinel.user2), ],
            }
        }
        self.assertEqual(
            exp_req_body, json.loads(responses.calls[0].request.body))

        am_mock.assert_any_call(sample_id, str(mock.sentinel.user1))
        am_mock.assert_any_call(sample_id, str(mock.sentinel.user2))
        self.assertEqual(2, am_mock.call_count)

    @responses.activate
    def test_create_local_group_already_exists(self):
        am_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_add_member')).mock

        url = 'http://keycloak.services:8080/keycloak/admin/realms/shasta/groups'
        # Keycloak responds with 409 Conflict when a group with the name already exists.
        responses.add(responses.POST, url, status=409, json={})

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        group = {
            'name': str(mock.sentinel.name),
            'gid': str(mock.sentinel.gid),
            'members': [str(mock.sentinel.user1), str(mock.sentinel.user2), ],
        }
        kl._create_local_group(group)

        self.assertEqual(0, am_mock.call_count)

    @responses.activate
    def test_create_local_group_error(self):
        am_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_add_member')).mock

        url = 'http://keycloak.services:8080/keycloak/admin/realms/shasta/groups'
        responses.add(responses.POST, url, status=500, json={})

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        group = {
            'name': str(mock.sentinel.name),
            'gid': str(mock.sentinel.gid),
            'members': [str(mock.sentinel.user1), str(mock.sentinel.user2), ],
        }
        self.assertRaises(
            requests.exceptions.HTTPError, kl._create_local_group, group)

        self.assertEqual(0, am_mock.call_count)

    @responses.activate
    def test_add_member_user_exists(self):
        fun_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_user_by_name')).mock
        fun_mock.return_value = {'id': str(mock.sentinel.user_id), }

        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/users/'
            '{}/groups/{}'.format(mock.sentinel.user_id, mock.sentinel.group_id))
        responses.add(responses.PUT, url)

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        kl._add_member(
            str(mock.sentinel.group_id), str(mock.sentinel.member_name))

        self.assertEqual(1, len(responses.calls))

    def test_add_member_no_user(self):
        # When the user isn't found, _add_member raises UnrecoverableError.
        fun_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_user_by_name')).mock
        fun_mock.side_effect = keycloak_localize.NotFound

        kl = keycloak_localize.KeycloakLocalize()
        self.assertRaises(
            keycloak_localize.UnrecoverableError, kl._add_member,
            str(mock.sentinel.group_id), str(mock.sentinel.member_name))

    def test_create_assignment_group(self):
        fc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_fetch_client_by_client_id')).mock
        fr_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_client_role')).mock
        cga_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_create_group_assignment')).mock

        kl = keycloak_localize.KeycloakLocalize()
        grp_assignment = {
            'group': str(mock.sentinel.group),
            'client': str(mock.sentinel.client),
            'role': str(mock.sentinel.role),
        }
        kl._create_assignment(grp_assignment)

        fc_mock.assert_called_once_with(str(mock.sentinel.client))
        fr_mock.assert_called_once_with(
            fc_mock.return_value, str(mock.sentinel.role))
        cga_mock.assert_called_once_with(
            str(mock.sentinel.group), fc_mock.return_value,
            fr_mock.return_value)

    def test_create_assignment_user(self):
        fc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_fetch_client_by_client_id')).mock
        fr_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_client_role')).mock
        cua_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_create_user_assignment')).mock

        kl = keycloak_localize.KeycloakLocalize()
        user_assignment = {
            'user': str(mock.sentinel.user),
            'client': str(mock.sentinel.client),
            'role': str(mock.sentinel.role),
        }
        kl._create_assignment(user_assignment)

        fc_mock.assert_called_once_with(str(mock.sentinel.client))
        fr_mock.assert_called_once_with(
            fc_mock.return_value, str(mock.sentinel.role))
        cua_mock.assert_called_once_with(
            str(mock.sentinel.user), fc_mock.return_value,
            fr_mock.return_value)

    @responses.activate
    def test_create_group_assignment_group_exists(self):
        group_name = str(mock.sentinel.group_name)
        group_id = str(mock.sentinel.group_id)
        client_id = str(mock.sentinel.client_id)

        fg_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_group')).mock
        fg_mock.return_value = {
            'name': group_name,
            'id': group_id,
        }

        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/groups/'
            '{}/role-mappings/clients/{}'.format(group_id, client_id))
        responses.add(responses.POST, url, status=204, json={})

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        client = {
            'id': client_id,
            'name': str(mock.sentinel.client_name),
        }
        client_role = {
            'id': str(mock.sentinel.role_id),
            'name': str(mock.sentinel.role_name),
        }
        kl._create_group_assignment(group_name, client, client_role)

        fg_mock.assert_called_once_with(group_name)

        exp_req_body = [
            {
                'id': str(mock.sentinel.role_id),
                'name': str(mock.sentinel.role_name),
                'composite': False,
                'clientRole': True,
                'containerId': client_id,
            },
        ]
        self.assertEqual(
            exp_req_body, json.loads(responses.calls[0].request.body))

    def test_create_group_assignment_group_not_found(self):
        # When the group isn't found, an UnrecoverableError is raised.
        group_name = str(mock.sentinel.group_name)
        client_id = str(mock.sentinel.client_id)

        fg_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_group')).mock
        fg_mock.side_effect = keycloak_localize.NotFound()

        kl = keycloak_localize.KeycloakLocalize()
        client = {
            'id': client_id,
            'name': str(mock.sentinel.client_name),
        }
        client_role = {
            'id': str(mock.sentinel.role_id),
            'name': str(mock.sentinel.role_name),
        }
        self.assertRaises(
            keycloak_localize.UnrecoverableError, kl._create_group_assignment,
            group_name, client, client_role)

    @responses.activate
    def test_create_user_assignment_user_found(self):
        user_name = str(mock.sentinel.user_name)
        user_id = str(mock.sentinel.user_id)
        client_id = str(mock.sentinel.client_id)

        fu_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_user_by_name')).mock
        fu_mock.return_value = {
            'name': user_name,
            'id': user_id,
        }

        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/users/'
            '{}/role-mappings/clients/{}'.format(user_id, client_id))
        responses.add(responses.POST, url, status=204, json={})

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        client = {
            'id': client_id,
            'name': str(mock.sentinel.client_name),
        }
        client_role = {
            'id': str(mock.sentinel.role_id),
            'name': str(mock.sentinel.role_name),
        }
        kl._create_user_assignment(user_name, client, client_role)

        fu_mock.assert_called_once_with(user_name)

        exp_req_body = [
            {
                'id': str(mock.sentinel.role_id),
                'name': str(mock.sentinel.role_name),
                'composite': False,
                'clientRole': True,
                'containerId': client_id,
            },
        ]
        self.assertEqual(
            exp_req_body, json.loads(responses.calls[0].request.body))

    def test_create_user_assignment_user_not_found(self):
        # When the user doesn't exist an Unrecoverable error is raised.
        user_name = str(mock.sentinel.user_name)
        client_id = str(mock.sentinel.client_id)

        fu_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_user_by_name')).mock
        fu_mock.side_effect = keycloak_localize.NotFound()

        kl = keycloak_localize.KeycloakLocalize()
        client = {
            'id': client_id,
            'name': str(mock.sentinel.client_name),
        }
        client_role = {
            'id': str(mock.sentinel.role_id),
            'name': str(mock.sentinel.role_name),
        }
        self.assertRaises(
            keycloak_localize.UnrecoverableError, kl._create_user_assignment,
            user_name, client, client_role)

    @responses.activate
    def test_fetch_client_by_client_id(self):
        client_id = str(mock.sentinel.client_id)

        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/clients'
            '?clientId={}'.format(client_id))
        exp_client = {
            'id': str(mock.sentinel.id),
        }
        resp_data = [
            exp_client,
        ]
        responses.add(responses.GET, url, json=resp_data)

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()

        client = kl._fetch_client_by_client_id(client_id)

        self.assertEqual(exp_client, client)

    @responses.activate
    def test_fetch_client_role(self):
        client_id = str(mock.sentinel.client_id)
        role_name = str(mock.sentinel.role_name)

        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'clients/{}/roles/{}'.format(client_id, role_name))
        resp_data = {
            'id': str(mock.sentinel.role_id),
        }
        responses.add(responses.GET, url, json=resp_data)

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()

        client = {
            'clientId': client_id,
            'id': str(mock.sentinel.client_id),
        }
        client_role = kl._fetch_client_role(client, role_name)

        self.assertEqual(resp_data, client_role)

    @responses.activate
    def test_fetch_group_found(self):
        group_name = str(mock.sentinel.group_name)
        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'groups?search={}'.format(group_name))
        exp_group = {
            'name': group_name,
            'id': str(mock.sentinel.id),
        }
        resp_data = [
            exp_group,
        ]
        responses.add(responses.GET, url, json=resp_data)

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()

        group = kl._fetch_group(group_name)
        self.assertEqual(exp_group, group)

    @responses.activate
    def test_fetch_group_not_found(self):
        # When a group with the given name doesn't exist NotFound is raised.
        group_name = str(mock.sentinel.group_name)
        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'groups?search={}'.format(group_name))
        resp_data = []
        responses.add(responses.GET, url, json=resp_data)

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()

        self.assertRaises(
            keycloak_localize.NotFound, kl._fetch_group, group_name)

    @responses.activate
    def test_fetch_user_by_name_found(self):
        user_name = str(mock.sentinel.user_name)
        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'users?username={}'.format(user_name))
        resp_user = {
            'id': str(mock.sentinel.id),
        }
        resp_data = [
            resp_user,
        ]
        responses.add(responses.GET, url, json=resp_data)

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()

        user = kl._fetch_user_by_name(user_name)
        self.assertEqual(resp_user, user)

    @responses.activate
    def test_fetch_user_by_name_not_found(self):
        # When there's no user with the name NotFound is raised.
        user_name = str(mock.sentinel.user_name)
        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'users?username={}'.format(user_name))
        resp_data = []
        responses.add(responses.GET, url, json=resp_data)

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()

        self.assertRaises(
            keycloak_localize.NotFound, kl._fetch_user_by_name, user_name)

    def test_create_ldap_user_federation_no_bind_dn(self):
        cc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_component')).mock

        kl = keycloak_localize.KeycloakLocalize(
            ldap_connection_url=str(mock.sentinel.ldap_url),
            ldap_search_base=str(mock.sentinel.search_base),
        )
        kl._create_ldap_user_federation()

        exp_config = {
            'priority': ['1'],
            'editMode': ['READ_ONLY'],
            'syncRegistrations': ['false'],
            'vendor': ['other'],
            'usernameLDAPAttribute': ['uid'],
            'rdnLDAPAttribute': ['uid'],
            'uuidLDAPAttribute': ['uid'],
            'userObjectClasses': ['posixAccount'],
            'connectionUrl': [str(mock.sentinel.ldap_url), ],
            'usersDn': [str(mock.sentinel.search_base), ],
            'authType': ['none'],
            'searchScope': ['2'],
            'useTruststoreSpi': ['ldapsOnly'],
            'connectionPooling': ['true'],
            'pagination': ['true'],
            'allowKerberosAuthentication': ['false'],
            'batchSizeForSync': ['4000'],
            'fullSyncPeriod': ['-1'],
            'changedSyncPeriod': ['-1'],
            'debug': ['true'],
            'enabled': ['true'],
        }
        cc_mock.assert_called_once_with(
            name='shasta-user-federation-ldap',
            provider_id='ldap',
            provider_type='org.keycloak.storage.UserStorageProvider',
            config=exp_config,
        )
        self.assertIs(kl._ldap_federation_object_id, cc_mock.return_value)

    def test_create_ldap_user_federation_bind_dn(self):
        cc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_component')).mock

        kl = keycloak_localize.KeycloakLocalize(
            ldap_connection_url=str(mock.sentinel.ldap_url),
            ldap_search_base=str(mock.sentinel.search_base),
            ldap_bind_dn=str(mock.sentinel.bind_dn),
            ldap_bind_credentials=str(mock.sentinel.bind_pw),
        )
        kl._create_ldap_user_federation()

        exp_config = {
            'priority': ['1'],
            'editMode': ['READ_ONLY'],
            'syncRegistrations': ['false'],
            'vendor': ['other'],
            'usernameLDAPAttribute': ['uid'],
            'rdnLDAPAttribute': ['uid'],
            'uuidLDAPAttribute': ['uid'],
            'userObjectClasses': ['posixAccount'],
            'connectionUrl': [str(mock.sentinel.ldap_url), ],
            'usersDn': [str(mock.sentinel.search_base), ],
            'authType': ['none'],
            'searchScope': ['2'],
            'useTruststoreSpi': ['ldapsOnly'],
            'connectionPooling': ['true'],
            'pagination': ['true'],
            'allowKerberosAuthentication': ['false'],
            'batchSizeForSync': ['4000'],
            'fullSyncPeriod': ['-1'],
            'changedSyncPeriod': ['-1'],
            'debug': ['true'],
            'enabled': ['true'],
            'bindDn': [str(mock.sentinel.bind_dn), ],
            'bindCredential': [str(mock.sentinel.bind_pw), ]
        }
        cc_mock.assert_called_once_with(
            name='shasta-user-federation-ldap',
            provider_id='ldap',
            provider_type='org.keycloak.storage.UserStorageProvider',
            config=exp_config,
        )
        self.assertIs(kl._ldap_federation_object_id, cc_mock.return_value)

    def test_delete_ldap_user_federation(self):
        dc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_delete_component')).mock

        kl = keycloak_localize.KeycloakLocalize()
        kl._ldap_federation_object_id = mock.sentinel.lfoi
        kl._delete_ldap_user_federation()

        dc_mock.assert_called_once_with(mock.sentinel.lfoi)

    def test_remove_ldap_user_attribute_mappers(self):
        rm_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_remove_ldap_user_attribute_mapper')).mock

        user_attribute_mappers = [
            str(mock.sentinel.uam1), str(mock.sentinel.uam2),
        ]

        kl = keycloak_localize.KeycloakLocalize(
            ldap_user_attribute_mappers_to_remove=user_attribute_mappers
        )
        kl._remove_ldap_user_attribute_mappers()

        rm_mock.assert_any_call(str(mock.sentinel.uam1))
        rm_mock.assert_any_call(str(mock.sentinel.uam2))

    def test_remove_ldap_user_attribute_mapper_exists(self):
        fc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_fetch_component_by_name')).mock
        fc_mock.return_value = {
            'id': str(mock.sentinel.m_id),
        }
        dc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_delete_component')).mock

        kl = keycloak_localize.KeycloakLocalize()
        kl._ldap_federation_object_id = str(mock.sentinel.fid)
        kl._remove_ldap_user_attribute_mapper(str(mock.sentinel.uam_name))

        fc_mock.assert_called_once_with(
            str(mock.sentinel.uam_name), parent_id=str(mock.sentinel.fid))
        dc_mock.assert_called_once_with(str(mock.sentinel.m_id))

    def test_remove_ldap_user_attribute_mapper_no_exist(self):
        fc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_fetch_component_by_name')).mock
        fc_mock.return_value = None
        dc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_delete_component')).mock

        kl = keycloak_localize.KeycloakLocalize()
        kl._remove_ldap_user_attribute_mapper(str(mock.sentinel.uam_name))

        dc_mock.assert_not_called()

    def test_create_ldap_user_attribute_mappers(self):
        cla_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize,
            '_create_ldap_user_attribute_mapper')).mock

        user_attribute_mappers = [
            str(mock.sentinel.uam1), str(mock.sentinel.uam2),
        ]

        kl = keycloak_localize.KeycloakLocalize(
            ldap_user_attribute_mappers=user_attribute_mappers
        )
        kl._create_ldap_user_attribute_mappers()

        cla_mock.assert_any_call(str(mock.sentinel.uam1))
        cla_mock.assert_any_call(str(mock.sentinel.uam2))

    def test_create_ldap_user_attribute_mapper(self):
        cc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_component')).mock

        kl = keycloak_localize.KeycloakLocalize()
        kl._ldap_federation_object_id = str(mock.sentinel.lfoi)
        kl._create_ldap_user_attribute_mapper(str(mock.sentinel.mapper_name))

        cc_mock.assert_called_once_with(
            name=str(mock.sentinel.mapper_name),
            provider_id='user-attribute-ldap-mapper',
            provider_type='org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
            parent_id=str(mock.sentinel.lfoi),
            config={
                'ldap.attribute': [
                    str(mock.sentinel.mapper_name),
                ],
                'is.mandatory.in.ldap': [
                    'false',
                ],
                'always.read.value.from.ldap': [
                    'false'
                ],
                'read.only': [
                    'true'
                ],
                'user.model.attribute': [
                    str(mock.sentinel.mapper_name),
                ],
            },
        )

    @responses.activate
    def test_create_component_no_parent_id(self):
        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'components')
        sample_component_id = '16178977-7389-49b2-b4d8-c42fe0b4bf8f'
        sample_location_url = (
            'https://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'components/{}'.format(sample_component_id))
        responses.add(
            responses.POST, url, status=204, json={},
            headers={'location': sample_location_url})

        sample_config = {
            str(mock.sentinel.attr1): str(mock.sentinel.val1),
        }
        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        component_id = kl._create_component(
            name=str(mock.sentinel.name),
            provider_id=str(mock.sentinel.provider_id),
            provider_type=str(mock.sentinel.provider_type),
            config=sample_config
        )

        self.assertEqual(sample_component_id, component_id)
        exp_req_body = {
            'providerId': str(mock.sentinel.provider_id),
            'providerType': str(mock.sentinel.provider_type),
            'name': str(mock.sentinel.name),
            'config': sample_config,
        }
        self.assertEqual(
            exp_req_body, json.loads(responses.calls[0].request.body))

    @responses.activate
    def test_create_component_parent_id(self):
        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'components')
        sample_component_id = '16178977-7389-49b2-b4d8-c42fe0b4bf8f'
        sample_location_url = (
            'https://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'components/{}'.format(sample_component_id))
        responses.add(
            responses.POST, url, status=204, json={},
            headers={'location': sample_location_url})

        sample_config = {
            str(mock.sentinel.attr1): str(mock.sentinel.val1),
        }
        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        component_id = kl._create_component(
            name=str(mock.sentinel.name),
            provider_id=str(mock.sentinel.provider_id),
            provider_type=str(mock.sentinel.provider_type),
            parent_id=str(mock.sentinel.parent_id),
            config=sample_config
        )

        self.assertEqual(sample_component_id, component_id)
        exp_req_body = {
            'providerId': str(mock.sentinel.provider_id),
            'providerType': str(mock.sentinel.provider_type),
            'name': str(mock.sentinel.name),
            'parentId': str(mock.sentinel.parent_id),
            'config': sample_config,
        }
        self.assertEqual(
            exp_req_body, json.loads(responses.calls[0].request.body))

    @responses.activate
    def test_fetch_component_by_name_found(self):
        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'components?name={}'.format(str(mock.sentinel.c_name)))
        sample_component = {
            'name': str(mock.sentinel.c_name),
            'id': str(mock.sentinel.c_id),
            # All the other fields.
        }
        responses.add(responses.GET, url, json=[sample_component])

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        component = kl._fetch_component_by_name(str(mock.sentinel.c_name))
        self.assertEqual(sample_component, component)

    @responses.activate
    def test_fetch_component_by_name_no_match(self):
        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'components?name={}'.format(str(mock.sentinel.c_name)))
        responses.add(responses.GET, url, json=[])

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        component = kl._fetch_component_by_name(str(mock.sentinel.c_name))
        self.assertIsNone(component)

    @responses.activate
    def test_fetch_component_by_name_with_parent_id(self):
        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'components?name={}&parent={}'.format(
                str(mock.sentinel.c_name), str(mock.sentinel.c_id)))
        responses.add(responses.GET, url, json=[])

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        # This raises if the parameter isn't on the URL
        kl._fetch_component_by_name(
            str(mock.sentinel.c_name), parent_id=str(mock.sentinel.c_id))

    @responses.activate
    def test_delete_component(self):
        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'components/{}'.format(str(mock.sentinel.c_id)))
        responses.add(responses.DELETE, url, status=204)

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        kl._delete_component(str(mock.sentinel.c_id))

        self.assertEqual(1, len(responses.calls))

    def test_create_ldap_group_mapper(self):
        cc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_component')).mock

        kl = keycloak_localize.KeycloakLocalize(
            ldap_search_base=str(mock.sentinel.search_base),
            ldap_group_name_ldap_attr=str(mock.sentinel.group_name_ldap_attr),
            ldap_group_object_class=str(mock.sentinel.group_object_class),
            ldap_preserve_group_inheritance=str(mock.sentinel.preserve_group_inheritance),
            ldap_group_membership_attribute=str(mock.sentinel.membership_ldap_attr),
            ldap_group_membership_attr_type=str(mock.sentinel.membership_attr_type),
            ldap_group_membership_ldap_attr=str(mock.sentinel.member_user_ldap_attr),
            ldap_group_filter=str(mock.sentinel.groups_ldap_filter),
            ldap_edit_mode=str(mock.sentinel.edit_mode),
            ldap_user_roles_retrieve_strategy=str(mock.sentinel.user_roles_retrieve_strategy),
            ldap_mapped_group_attrs=str(mock.sentinel.mapped_group_attributes),
            ldap_groups_drop_during_sync=str(mock.sentinel.drop_groups_during_sync)
        )
        kl._ldap_federation_object_id = str(mock.sentinel.lfoi)
        kl._create_ldap_group_mapper()

        cc_mock.assert_called_once_with(
            name='group-attribute-ldap-mapper',
            provider_id='group-ldap-mapper',
            provider_type='org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
            parent_id=str(mock.sentinel.lfoi),
            config={
                'groups.dn': [
                    str(mock.sentinel.search_base),
                ],
                'group.name.ldap.attribute': [
                    str(mock.sentinel.group_name_ldap_attr),
                ],
                'group.object.classes': [
                    str(mock.sentinel.group_object_class),
                ],
                'preserve.group.inheritance': [
                    str(mock.sentinel.preserve_group_inheritance),
                ],
                'membership.ldap.attribute': [
                    str(mock.sentinel.membership_ldap_attr),
                ],
                'membership.attribute.type': [
                    str(mock.sentinel.membership_attr_type),
                ],
                'membership.user.ldap.attribute': [
                    str(mock.sentinel.member_user_ldap_attr),
                ],
                'groups.ldap.filter': [
                    str(mock.sentinel.groups_ldap_filter),
                ],
                'mode': [
                    str(mock.sentinel.edit_mode),
                ],
                'user.roles.retrieve.strategy': [
                    str(mock.sentinel.user_roles_retrieve_strategy),
                ],
                'mapped.group.attributes': [
                    str(mock.sentinel.mapped_group_attributes),
                ],
                'drop.non.existing.groups.during.sync': [
                    str(mock.sentinel.drop_groups_during_sync),
                ],
            },
        )

    def test_create_ldap_role_mapper_no_dn(self):
        # When the role_mapper_dn isn't set then the role mapper isn't added.
        cc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_component')).mock
        kl = keycloak_localize.KeycloakLocalize(ldap_role_mapper_dn='')
        kl._create_ldap_role_mapper()
        cc_mock.assert_not_called()

    def test_create_ldap_role_mapper_has_dn(self):
        cc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_component')).mock

        kl = keycloak_localize.KeycloakLocalize(
            ldap_role_mapper_dn=str(mock.sentinel.dn),
            ldap_role_mapper_name_ldap_attr=str(mock.sentinel.ldap_attr),
            ldap_role_mapper_object_class=str(mock.sentinel.object_class),
            ldap_role_mapper_membership_ldap_attr=str(mock.sentinel.membership_ldap_attr),
            ldap_role_mapper_membership_attr_type=str(mock.sentinel.membership_attr_type),
            ldap_role_mapper_membership_user_ldap_attr=str(mock.sentinel.membership_user_ldap_attr),
            ldap_role_mapper_roles_ldap_filter=str(mock.sentinel.roles_ldap_filter),
            ldap_role_mapper_mode=str(mock.sentinel.mode),
            ldap_role_mapper_retrieve_strategy=str(mock.sentinel.retrieve_strategy),
            ldap_role_mapper_memberof_attr=str(mock.sentinel.memberof_attr),
            ldap_role_mapper_use_realm_roles_mapping=str(mock.sentinel.use_realm_roles_mapping),
            ldap_role_mapper_client_id=str(mock.sentinel.client_id)
        )
        kl._ldap_federation_object_id = str(mock.sentinel.lfoi)
        kl._create_ldap_role_mapper()

        cc_mock.assert_called_once_with(
            name='role-mapper-shasta',
            provider_id='role-ldap-mapper',
            provider_type='org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
            parent_id=str(mock.sentinel.lfoi),
            config={
                'roles.dn': [str(mock.sentinel.dn)],
                'role.name.ldap.attribute': [str(mock.sentinel.ldap_attr)],
                'role.object.classes': [str(mock.sentinel.object_class)],
                'membership.ldap.attribute': [str(mock.sentinel.membership_ldap_attr)],
                'membership.attribute.type': [str(mock.sentinel.membership_attr_type)],
                'membership.user.ldap.attribute': [str(mock.sentinel.membership_user_ldap_attr)],
                'roles.ldap.filter': [str(mock.sentinel.roles_ldap_filter)],
                'mode': [str(mock.sentinel.mode)],
                'user.roles.retrieve.strategy': [str(mock.sentinel.retrieve_strategy)],
                'memberof.ldap.attribute': [str(mock.sentinel.memberof_attr)],
                'use.realm.roles.mapping': [str(mock.sentinel.use_realm_roles_mapping)],
                'client.id': [str(mock.sentinel.client_id)],
            },
        )

    @responses.activate
    def test_trigger_full_user_sync_enabled(self):
        example_federation_id = str(mock.sentinel.federation_id)
        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'user-storage/{}/sync?action=triggerFullSync'.format(
                example_federation_id))

        responses.add(
            responses.POST, url, status=200,
            json=[{'added': 1465, 'status': '1465 updated users'}])

        kl = keycloak_localize.KeycloakLocalize(ldap_do_full_sync=True)
        kl._kc_master_admin_client_cache = requests.Session()
        kl._ldap_federation_object_id = example_federation_id
        kl._trigger_full_user_sync()

        self.assertEqual(url, responses.calls[0].request.url)

    @responses.activate
    def test_trigger_full_user_sync_disabled(self):
        kl = keycloak_localize.KeycloakLocalize(ldap_do_full_sync=False)
        kl._kc_master_admin_client_cache = requests.Session()
        kl._trigger_full_user_sync()  # Any request will fail

    @responses.activate
    def test_trigger_full_user_sync_error(self):
        # When Keycloak returns a 500 error during the sync an
        # UnrecoverableError is raised.
        example_federation_id = str(mock.sentinel.federation_id)
        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'user-storage/{}/sync?action=triggerFullSync'.format(
                example_federation_id))

        responses.add(
            responses.POST, url, status=500,
            json=[{'error': 'unknown_error'}])  # This is the response when the bindDN is incorrect...

        kl = keycloak_localize.KeycloakLocalize(ldap_do_full_sync=True)
        kl._kc_master_admin_client_cache = requests.Session()
        kl._ldap_federation_object_id = example_federation_id
        self.assertRaises(
            keycloak_localize.UnrecoverableError, kl._trigger_full_user_sync)

    def test_fetch_users_once(self):
        ftu_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_total_users')).mock
        ftu_mock.return_value = 0

        fup_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_users_page')).mock
        fup_mock.return_value = [mock.sentinel.user, ]

        fmt_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_format_user_passwd_entry')).mock
        fmt_mock.return_value = str(mock.sentinel.user_fmt)

        s3c_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_s3_client',
            new_callable=mock.PropertyMock)).mock
        cpc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_passwd_configmaps')).mock

        kl = keycloak_localize.KeycloakLocalize(
            user_export_storage_bucket=mock.sentinel.bucket,
            user_export_storage_passwd_object=mock.sentinel.passwd,
        )
        kl.total_keycloak_users = 1
        kl._fetch_users()

        fup_mock.assert_called_once_with(0)
        fmt_mock.assert_called_once_with(mock.sentinel.user)

        exp_result = '\n'.join([str(mock.sentinel.user_fmt), ])

        s3c_mock.return_value.upload_fileobj.assert_called_once_with(
            mock.ANY,
            mock.sentinel.bucket,
            mock.sentinel.passwd,
            ExtraArgs={'ACL': 'public-read'}
        )

        user_data_sent = s3c_mock.return_value.upload_fileobj.call_args[0][0].read()
        self.assertEqual(exp_result, user_data_sent.decode('utf-8'))

        cpc_mock.assert_called_once_with(exp_result)

    def test_fetch_users_multi_pages(self):
        ftu_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_total_users')).mock
        ftu_mock.return_value = 0

        fup_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_users_page')).mock
        page1 = [mock.sentinel.user1, mock.sentinel.user2, mock.sentinel.user3]
        page2 = [mock.sentinel.user4]
        fup_mock.side_effect = [page1, page2, Exception()]

        fmt_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_format_user_passwd_entry')).mock
        fmt_mock.side_effect = [
            str(mock.sentinel.user1_fmt),
            None,  # Simulate a user that couldn't be formatted.
            str(mock.sentinel.user3_fmt),
            str(mock.sentinel.user4_fmt),
            Exception()
        ]

        s3c_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_s3_client',
            new_callable=mock.PropertyMock)).mock
        cpc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_passwd_configmaps')).mock

        kl = keycloak_localize.KeycloakLocalize(
            user_export_storage_bucket=mock.sentinel.bucket,
            user_export_storage_passwd_object=mock.sentinel.passwd,
        )
        kl.fetch_users_page_size = len(page1)
        kl.total_keycloak_users = len(page1) + len(page2)
        kl._fetch_users()

        fup_mock.assert_has_calls([mock.call(0), mock.call(3)])
        fmt_calls = [
            mock.call(mock.sentinel.user1), mock.call(mock.sentinel.user2),
            mock.call(mock.sentinel.user3), mock.call(mock.sentinel.user4)]
        fmt_mock.assert_has_calls(fmt_calls)

        exp_result = '\n'.join([
            str(mock.sentinel.user1_fmt), str(mock.sentinel.user3_fmt),
            str(mock.sentinel.user4_fmt),
        ])

        s3c_mock.return_value.upload_fileobj.assert_called_once_with(
            mock.ANY,
            mock.sentinel.bucket,
            mock.sentinel.passwd,
            ExtraArgs={'ACL': 'public-read'}
        )

        user_data_sent = s3c_mock.return_value.upload_fileobj.call_args[0][0].read()
        self.assertEqual(exp_result, user_data_sent.decode('utf-8'))

        cpc_mock.assert_called_once_with(exp_result)

    @responses.activate
    def test_fetch_users_page_some_users(self):
        first = 0
        max = 50

        url = (
            f'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            f'users?first={first}&max={max}')
        sample_user_1 = {'username': 'user1'}
        sample_user_2 = {'username': 'user2'}
        resp_data = [sample_user_1, sample_user_2, ]

        responses.add(responses.GET, url, status=200, json=resp_data)

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        res = kl._fetch_users_page(first)

        self.assertEqual(res, resp_data)

    @responses.activate
    def test_fetch_users_page_no_users(self):
        first = 0
        max = 50

        url = (
            f'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            f'users?first={first}&max={max}')
        resp_data = []

        responses.add(responses.GET, url, status=200, json=resp_data)

        kl = keycloak_localize.KeycloakLocalize()
        kl._kc_master_admin_client_cache = requests.Session()
        res = kl._fetch_users_page(first)

        self.assertEqual(res, resp_data)

    def test_format_user_passwd_entry_user_name_source_username(self):
        sample_user = {
            'id': '23dfbd85-22c3-4515-8a97-655dcd574d2d',
            'createdTimestamp': 1585236398589,
            'username': 'test_user_1',
            'enabled': True,
            'totp': False,
            'emailVerified': False,
            'firstName': 'First Name',
            'federationLink': 'b4bf6a68-cf16-4f7e-ba04-1b69c2b7eed1',
            'attributes': {
                'loginShell': [
                    '/bin/bash'
                ],
                'homeDirectory': [
                    '/home/users/Test.User.1'
                ],
                'LDAP_ENTRY_DN': [
                    'uid=test_user_1,ou=People,dc=datacenter,dc=cray,dc=com'
                ],
                'uidNumber': [
                    '5534'
                ],
                'gidNumber': [
                    '12790'
                ],
                'modifyTimestamp': [
                    '20170607185637Z'
                ],
                'createTimestamp': [
                    '20170515145508Z'
                ],
                'LDAP_ID': [
                    'test_user_1'
                ],
            },
            'disableableCredentialTypes': [],
            'requiredActions': [],
            'notBefore': 0,
            'access': {
                'manageGroupMembership': True,
                'view': True,
                'mapRoles': True,
                'impersonate': True,
                'manage': True
            },
        }

        kl = keycloak_localize.KeycloakLocalize()
        res = kl._format_user_passwd_entry(sample_user)
        exp_res = 'test_user_1::5534:12790:First Name:/home/users/Test.User.1:/bin/bash'
        self.assertEqual(exp_res, res)

    def test_format_user_passwd_entry_user_name_source_homeDirectory(self):
        sample_user = {
            'id': '23dfbd85-22c3-4515-8a97-655dcd574d2d',
            'createdTimestamp': 1585236398589,
            'username': 'test_user_1',
            'enabled': True,
            'totp': False,
            'emailVerified': False,
            'firstName': 'First Name',
            'federationLink': 'b4bf6a68-cf16-4f7e-ba04-1b69c2b7eed1',
            'attributes': {
                'loginShell': [
                    '/bin/bash'
                ],
                'homeDirectory': [
                    '/home/users/Test.User.1'
                ],
                'LDAP_ENTRY_DN': [
                    'uid=test_user_1,ou=People,dc=datacenter,dc=cray,dc=com'
                ],
                'uidNumber': [
                    '5534'
                ],
                'gidNumber': [
                    '12790'
                ],
                'modifyTimestamp': [
                    '20170607185637Z'
                ],
                'createTimestamp': [
                    '20170515145508Z'
                ],
                'LDAP_ID': [
                    'test_user_1'
                ],
            },
            'disableableCredentialTypes': [],
            'requiredActions': [],
            'notBefore': 0,
            'access': {
                'manageGroupMembership': True,
                'view': True,
                'mapRoles': True,
                'impersonate': True,
                'manage': True
            },
        }

        kl = keycloak_localize.KeycloakLocalize(user_export_name_source='homeDirectory')
        res = kl._format_user_passwd_entry(sample_user)
        exp_res = 'Test.User.1::5534:12790:First Name:/home/users/Test.User.1:/bin/bash'
        self.assertEqual(exp_res, res)

    def test_format_user_passwd_entry_no_attributes(self):
        sample_user = {
            'username': 'test_user_1',
        }

        kl = keycloak_localize.KeycloakLocalize()
        self.assertIsNone(kl._format_user_passwd_entry(sample_user))

    def test_format_user_passwd_entry_no_uidNumber(self):
        sample_user = {
            'username': 'test_user_1',
            'attributes': {
                'loginShell': ['/bin/bash', ],
                'homeDirectory': ['/home/users/Test.User.1', ],
                'gidNumber': ['12790', ],
            },
        }

        kl = keycloak_localize.KeycloakLocalize()
        self.assertIsNone(kl._format_user_passwd_entry(sample_user))

    def test_format_user_passwd_entry_no_gidNumber(self):
        sample_user = {
            'username': 'test_user_1',
            'attributes': {
                'loginShell': ['/bin/bash', ],
                'homeDirectory': ['/home/users/Test.User.1', ],
                'uidNumber': ['12345', ],
            },
        }

        kl = keycloak_localize.KeycloakLocalize()
        self.assertIsNone(kl._format_user_passwd_entry(sample_user))

    def test_format_user_passwd_entry_no_homeDirectory(self):
        sample_user = {
            'username': 'test_user_1',
            'attributes': {
                'loginShell': ['/bin/bash', ],
                'uidNumber': ['12345', ],
                'gidNumber': ['12790', ],
            },
        }

        kl = keycloak_localize.KeycloakLocalize()
        self.assertIsNone(kl._format_user_passwd_entry(sample_user))

    def test_format_user_passwd_entry_no_loginShell(self):
        sample_user = {
            'username': 'test_user_1',
            'attributes': {
                'homeDirectory': ['/home/users/Test.User.1', ],
                'uidNumber': ['12345', ],
                'gidNumber': ['12790', ],
            },
        }

        kl = keycloak_localize.KeycloakLocalize()
        self.assertIsNone(kl._format_user_passwd_entry(sample_user))

    def test_create_passwd_configmaps(self):
        ac_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_apply_configmap')).mock

        namespaces = [
            str(mock.sentinel.namespace1),
            str(mock.sentinel.namespace2),
        ]
        kl = keycloak_localize.KeycloakLocalize(
            user_export_namespaces=namespaces,
            user_export_passwd_configmap_name=str(mock.sentinel.name),
        )
        kl._create_passwd_configmaps(str(mock.sentinel.passwd))

        ac_mock.assert_any_call(
            str(mock.sentinel.name), str(mock.sentinel.namespace1),
            'keycloak-users', str(mock.sentinel.passwd))
        ac_mock.assert_any_call(
            str(mock.sentinel.name), str(mock.sentinel.namespace2),
            'keycloak-users', str(mock.sentinel.passwd))
        self.assertEqual(2, ac_mock.call_count)

    def test_fetch_groups_disabled(self):
        kl = keycloak_localize.KeycloakLocalize(
            user_export_groups=False,
        )
        kl._kc_master_admin_client_cache = requests.Session()
        kl._fetch_groups()  # This would raise exception if it tried to fetch.

    @responses.activate
    def test_fetch_groups_enabled(self):
        s3c_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_s3_client',
            new_callable=mock.PropertyMock)).mock
        cgc_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_groups_configmaps')).mock

        url = (
            'http://keycloak.services:8080/keycloak/admin/realms/shasta/'
            'groups?briefRepresentation=false&max=-1')

        sample_group_1 = {
            'id': '19279262-0f24-416e-9189-3dfb7a952b2e',
            'name': str(mock.sentinel.g1_name),
            'path': '/{}'.format(str(mock.sentinel.g1_name)),
            'attributes': {
                'cn': [
                    str(mock.sentinel.g1_cn),
                ],
                'gidNumber': [
                    str(mock.sentinel.g1_id),
                ],
                'memberUid': [
                    str(mock.sentinel.g1_u1),
                    str(mock.sentinel.g1_u2),
                ]
            },
            'realmRoles': [],
            'clientRoles': {},
            'subGroups': [],
        }

        sample_group_2 = {
            'id': '19279262-0f24-416e-9189-3dfb7a952b2f',
            'name': str(mock.sentinel.g2_name),
            'path': '/{}'.format(str(mock.sentinel.g2_name)),
            'attributes': {
                'cn': [
                    str(mock.sentinel.g2_cn),
                ],
                'gidNumber': [
                    str(mock.sentinel.g2_id),
                ],
                'memberUid': [
                    str(mock.sentinel.g2_u1),
                    str(mock.sentinel.g2_u2),
                ]
            },
            'realmRoles': [],
            'clientRoles': {},
            'subGroups': [],
        }

        sample_group_3 = {
            'id': '19279262-0f24-416e-9189-3dfb7a952b2f',
            'name': str(mock.sentinel.g2_name),
            'path': '/{}'.format(str(mock.sentinel.g2_name)),
            'attributes': {
                'cn': [
                    str(mock.sentinel.g2_cn),
                ],
                'gidNumber': [
                    str(mock.sentinel.g2_id),
                ],
                # Some entries didn't have memberUid for some reason.
            },
            'realmRoles': [],
            'clientRoles': {},
            'subGroups': [],
        }

        sample_group_4 = {
            'id': '19279262-0f24-416e-9189-3dfb7a952b2f',
            'name': str(mock.sentinel.g2_name),
            'path': '/{}'.format(str(mock.sentinel.g2_name)),
            'attributes': {
                'cn': [
                    str(mock.sentinel.g2_cn),
                ],
                # Some entries didn't have gidNumber if they are local groups.
            },
            'realmRoles': [],
            'clientRoles': {},
            'subGroups': [],
        }

        sample_group_5 = {
            'id': '19279262-0f24-416e-9189-3dfb7a952b2f',
            'name': str(mock.sentinel.g2_name),
            'path': '/{}'.format(str(mock.sentinel.g2_name)),
            'attributes': {
                # Some entries are local groups with no attributes.
            },
            'realmRoles': [],
            'clientRoles': {},
            'subGroups': [],
        }

        responses.add(
            responses.GET, url, status=200,
            json=[sample_group_1, sample_group_2, sample_group_3, sample_group_4, sample_group_5])

        kl = keycloak_localize.KeycloakLocalize(
            user_export_groups=True,
            user_export_storage_bucket=mock.sentinel.bucket,
            user_export_storage_groups_object=mock.sentinel.passwd,
        )
        kl._kc_master_admin_client_cache = requests.Session()
        kl._fetch_groups()

        exp_data = '\n'.join([
            '{}::{}:{}'.format(
                mock.sentinel.g1_cn, mock.sentinel.g1_id,
                ','.join([str(mock.sentinel.g1_u1), str(mock.sentinel.g1_u2)])),
            '{}::{}:{}'.format(
                mock.sentinel.g2_cn, mock.sentinel.g2_id,
                ','.join([str(mock.sentinel.g2_u1), str(mock.sentinel.g2_u2)])),
            '{}::{}:'.format(mock.sentinel.g2_cn, mock.sentinel.g2_id,),
            '{}::{}:'.format(mock.sentinel.g2_name, 100000811,),
            '{}::{}:'.format(mock.sentinel.g2_name, 100000811,),
        ])

        s3c_mock.return_value.upload_fileobj.assert_called_once_with(
            mock.ANY,
            mock.sentinel.bucket,
            mock.sentinel.passwd,
            ExtraArgs={'ACL': 'public-read'}
        )

        data_sent = s3c_mock.return_value.upload_fileobj.call_args[0][0].read()
        self.assertEqual(exp_data, data_sent.decode('utf-8'))

        cgc_mock.assert_called_once_with(exp_data)

    def test_create_groups_configmaps(self):
        ac_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_apply_configmap')).mock

        namespaces = [
            str(mock.sentinel.namespace1),
            str(mock.sentinel.namespace2),
        ]
        kl = keycloak_localize.KeycloakLocalize(
            user_export_namespaces=namespaces,
            user_export_groups_configmap_name=str(mock.sentinel.name),
        )
        kl._create_groups_configmaps(str(mock.sentinel.groups))

        ac_mock.assert_any_call(
            str(mock.sentinel.name), str(mock.sentinel.namespace1),
            'keycloak-groups', str(mock.sentinel.groups))
        ac_mock.assert_any_call(
            str(mock.sentinel.name), str(mock.sentinel.namespace2),
            'keycloak-groups', str(mock.sentinel.groups))
        self.assertEqual(2, ac_mock.call_count)

    def test_apply_configmap_exists(self):
        fcm_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_configmap')).mock
        scm_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_sync_configmap')).mock

        kl = keycloak_localize.KeycloakLocalize()
        kl._apply_configmap(
            mock.sentinel.name, mock.sentinel.namespace, mock.sentinel.key_name,
            mock.sentinel.data)

        fcm_mock.assert_called_once_with(mock.sentinel.name, mock.sentinel.namespace)
        scm_mock.assert_called_once_with(
            mock.sentinel.name, mock.sentinel.namespace, mock.sentinel.key_name,
            mock.sentinel.data, fcm_mock.return_value)

    def test_apply_configmap_not_found(self):
        fcm_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_fetch_configmap', return_value=None)).mock
        ccm_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_create_configmap')).mock

        kl = keycloak_localize.KeycloakLocalize()
        kl._apply_configmap(
            mock.sentinel.name, mock.sentinel.namespace, mock.sentinel.key_name,
            mock.sentinel.data)

        fcm_mock.assert_called_once_with(mock.sentinel.name, mock.sentinel.namespace)
        ccm_mock.assert_called_once_with(
            mock.sentinel.name, mock.sentinel.namespace, mock.sentinel.key_name,
            mock.sentinel.data)

    def test_fetch_configmap_exists(self):
        c_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_core_v1',
            new_callable=mock.PropertyMock)).mock

        kl = keycloak_localize.KeycloakLocalize()
        configmap = kl._fetch_configmap(
            str(mock.sentinel.name), str(mock.sentinel.namespace))

        c_mock.return_value.read_namespaced_config_map.assert_called_once_with(
            str(mock.sentinel.name), str(mock.sentinel.namespace))
        self.assertIs(
            c_mock.return_value.read_namespaced_config_map.return_value,
            configmap)

    def test_fetch_configmap_not_found(self):
        c_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_core_v1',
            new_callable=mock.PropertyMock)).mock
        c_mock.return_value.read_namespaced_config_map.side_effect = (
            kubernetes.client.rest.ApiException(404))

        kl = keycloak_localize.KeycloakLocalize()
        configmap = kl._fetch_configmap(
            str(mock.sentinel.name), str(mock.sentinel.namespace))
        self.assertIsNone(configmap)

    def test_fetch_configmap_error(self):
        c_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_core_v1',
            new_callable=mock.PropertyMock)).mock
        c_mock.return_value.read_namespaced_config_map.side_effect = (
            kubernetes.client.rest.ApiException(500))

        kl = keycloak_localize.KeycloakLocalize()
        self.assertRaises(
            kubernetes.client.rest.ApiException,
            kl._fetch_configmap, str(mock.sentinel.name), str(mock.sentinel.namespace))

    def test_create_configmap(self):
        c_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_core_v1',
            new_callable=mock.PropertyMock)).mock

        kl = keycloak_localize.KeycloakLocalize()
        kl._create_configmap(
            str(mock.sentinel.name), str(mock.sentinel.namespace),
            str(mock.sentinel.key_name), str(mock.sentinel.data))

        c_mock.return_value.create_namespaced_config_map.assert_called_once_with(
            str(mock.sentinel.namespace), mock.ANY
        )
        cm_param = c_mock.return_value.create_namespaced_config_map.call_args[0][1]
        self.assertEqual(str(mock.sentinel.name), cm_param.metadata.name)
        self.assertEqual(str(mock.sentinel.namespace), cm_param.metadata.namespace)
        self.assertEqual(
            str(mock.sentinel.data), cm_param.data[str(mock.sentinel.key_name)])

    def test_sync_configmap_no_change(self):
        current_configmap = mock.MagicMock()
        current_configmap.data = {
            str(mock.sentinel.key_name): str(mock.sentinel.data),
        }

        kl = keycloak_localize.KeycloakLocalize()
        kl._sync_configmap(
            mock.sentinel.name, mock.sentinel.namespace,
            str(mock.sentinel.key_name), str(mock.sentinel.data),
            current_configmap)

    def test_sync_configmap_changed(self):
        c_mock = self.useFixture(fixtures.MockPatchObject(
            keycloak_localize.KeycloakLocalize, '_core_v1',
            new_callable=mock.PropertyMock)).mock

        current_configmap = mock.MagicMock()
        current_configmap.data = {
            str(mock.sentinel.key_name): str(mock.sentinel.data2),
        }

        kl = keycloak_localize.KeycloakLocalize()
        kl._sync_configmap(
            mock.sentinel.name, mock.sentinel.namespace,
            str(mock.sentinel.key_name), str(mock.sentinel.data),
            current_configmap)

        c_mock.return_value.patch_namespaced_config_map.assert_called_once_with(
            mock.sentinel.name, mock.sentinel.namespace, mock.ANY)

        cm_param = c_mock.return_value.patch_namespaced_config_map.call_args[0][2]
        self.assertEqual(
            str(mock.sentinel.data), cm_param.data[str(mock.sentinel.key_name)])
