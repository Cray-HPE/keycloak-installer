#!/usr/bin/env python
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
import io
import json
import logging
import os
import sys
import time

import boto3
import kubernetes.client
import kubernetes.config
import oauthlib.oauth2.rfc6749.errors
import requests_oauthlib


DEFAULT_KEYCLOAK_BASE = 'http://keycloak.services:8080/keycloak'
DEFAULT_KEYCLOAK_MASTER_ADMIN_CLIENT_ID = 'admin-cli'
DEFAULT_KEYCLOAK_MASTER_ADMIN_USERNAME = 'admin'
DEFAULT_KEYCLOAK_MASTER_ADMIN_PASSWORD = 'adminpwd'

DEFAULT_LDAP_CONNECTION_URL = ''
DEFAULT_LDAP_PROVIDER_ID = 'ldap'
DEFAULT_LDAP_FEDERATION_NAME = 'shasta-user-federation-ldap'
DEFAULT_LDAP_PRIORITY = '1'
DEFAULT_LDAP_EDIT_MODE = 'READ_ONLY'
DEFAULT_LDAP_SYNC_REGISTRATIONS = 'false'
DEFAULT_LDAP_VENDOR = 'other'
DEFAULT_LDAP_USERNAME_LDAP_ATTRIBUTE = 'uid'
DEFAULT_LDAP_RDN_LDAP_ATTRIBUTE = 'uid'
DEFAULT_LDAP_UUID_LDAP_ATTRIBUTE = 'uid'
DEFAULT_LDAP_USER_OBJECT_CLASSES = 'posixAccount'
DEFAULT_LDAP_AUTH_TYPE = 'none'
DEFAULT_LDAP_BIND_DN = ''
DEFAULT_LDAP_BIND_CREDENTIALS = ''
DEFAULT_LDAP_SEARCH_BASE = 'cn=Users'
DEFAULT_LDAP_SEARCH_SCOPE = '2'
DEFAULT_LDAP_USE_TRUSTSTORE_SPI = 'ldapsOnly'
DEFAULT_LDAP_CONNECTION_POOLING = 'true'
DEFAULT_LDAP_PAGINATION = 'true'
DEFAULT_LDAP_ALLOW_KERBEROS_AUTHENTICATION = 'false'
DEFAULT_LDAP_BATCH_SIZE_FOR_SYNC = '4000'
DEFAULT_LDAP_FULL_SYNC_PERIOD = '-1'
DEFAULT_LDAP_CHANGED_SYNC_PERIOD = '-1'
DEFAULT_LDAP_DEBUG = 'true'
DEFAULT_LDAP_USER_ATTRIBUTE_MAPPERS = (
    ['uidNumber', 'gidNumber', 'loginShell', 'homeDirectory'])
DEFAULT_LDAP_USER_ATTRIBUTE_MAPPERS_TO_REMOVE = []
DEFAULT_LDAP_GROUP_NAME_LDAP_ATTR = 'cn'
DEFAULT_LDAP_GROUP_OBJECT_CLASS = 'posixGroup'
DEFAULT_LDAP_PRESERVE_GROUP_INHERITANCE = 'false'
DEFAULT_LDAP_GROUP_MEMBERSHIP_ATTRIBUTE = 'memberUid'
DEFAULT_LDAP_GROUP_MEMBERSHIP_ATTR_TYPE = 'UID'
DEFAULT_LDAP_GROUP_MEMBERSHIP_LDAP_ATTR = 'uid'
DEFAULT_LDAP_GROUP_FILTER = ''
DEFAULT_LDAP_USER_ROLES_RETRIEVE_STRATEGY = 'LOAD_GROUPS_BY_MEMBER_ATTRIBUTE'
DEFAULT_LDAP_MAPPED_GROUP_ATTRS = 'cn,gidNumber,memberUid'
DEFAULT_LDAP_GROUPS_DROP_DURING_SYNC = 'false'
DEFAULT_LDAP_ROLE_MAPPER_DN = ''
DEFAULT_LDAP_ROLE_MAPPER_NAME_LDAP_ATTR = 'cn'
DEFAULT_LDAP_ROLE_MAPPER_OBJECT_CLASS = 'groupOfNames'
DEFAULT_LDAP_ROLE_MAPPER_MEMBERSHIP_LDAP_ATTR = 'member'
DEFAULT_LDAP_ROLE_MAPPER_MEMBERSHIP_ATTR_TYPE = 'DN'
DEFAULT_LDAP_ROLE_MAPPER_MEMBERSHIP_USER_LDAP_ATTR = 'sAMAccountName'
DEFAULT_LDAP_ROLE_MAPPER_ROLE_LDAP_FILTER = ''
DEFAULT_LDAP_ROLE_MAPPER_MODE = 'READ_ONLY'
DEFAULT_LDAP_ROLE_MAPPER_RETRIEVE_STRATEGY = 'LOAD_ROLES_BY_MEMBER_ATTRIBUTE'
DEFAULT_LDAP_ROLE_MAPPER_MEMBEROF_ATTR = 'memberOf'
DEFAULT_LDAP_ROLE_MAPPER_USE_REALM_ROLES_MAPPING = 'false'
DEFAULT_LDAP_ROLE_MAPPER_CLIENT_ID = 'shasta'
DEFAULT_LDAP_DO_FULL_SYNC = True

DEFAULT_USER_EXPORT_STORAGE_URL = 'http://rgw.local:8080'  # TODO: should be https!
DEFAULT_USER_EXPORT_STORAGE_BUCKET = 'wlm'
DEFAULT_USER_EXPORT_STORAGE_PASSWD_OBJECT = 'etc/passwd'
DEFAULT_USER_EXPORT_GROUPS = True
DEFAULT_USER_EXPORT_STORAGE_GROUPS_OBJECT = 'etc/group'
DEFAULT_USER_EXPORT_NAMESPACES = ['user', 'default']
DEFAULT_USER_EXPORT_PASSWD_CONFIGMAP_NAME = 'keycloak-users'
DEFAULT_USER_EXPORT_GROUPS_CONFIGMAP_NAME = 'keycloak-groups'


DEFAULT_LOCAL_ROLE_ASSIGNMENTS = {}

LOGGER = logging.getLogger('keycloak_localize')


class NotFound(Exception):
    pass


class UnrecoverableError(Exception):
    pass


class KeycloakLocalize(object):
    MASTER_REALM_NAME = 'master'
    SHASTA_REALM_NAME = 'shasta'

    def __init__(
            self,
            keycloak_base=DEFAULT_KEYCLOAK_BASE,
            kc_master_admin_client_id=DEFAULT_KEYCLOAK_MASTER_ADMIN_CLIENT_ID,
            kc_master_admin_username=DEFAULT_KEYCLOAK_MASTER_ADMIN_USERNAME,
            kc_master_admin_password=DEFAULT_KEYCLOAK_MASTER_ADMIN_PASSWORD,
            ldap_connection_url=DEFAULT_LDAP_CONNECTION_URL,
            ldap_provider_id=DEFAULT_LDAP_PROVIDER_ID,
            ldap_federation_name=DEFAULT_LDAP_FEDERATION_NAME,
            ldap_priority=DEFAULT_LDAP_PRIORITY,
            ldap_edit_mode=DEFAULT_LDAP_EDIT_MODE,
            ldap_sync_registrations=DEFAULT_LDAP_SYNC_REGISTRATIONS,
            ldap_vendor=DEFAULT_LDAP_VENDOR,
            ldap_username_ldap_attribute=DEFAULT_LDAP_USERNAME_LDAP_ATTRIBUTE,
            ldap_rdn_ldap_attribute=DEFAULT_LDAP_RDN_LDAP_ATTRIBUTE,
            ldap_uuid_ldap_attribute=DEFAULT_LDAP_UUID_LDAP_ATTRIBUTE,
            ldap_user_object_classes=DEFAULT_LDAP_USER_OBJECT_CLASSES,
            ldap_auth_type=DEFAULT_LDAP_AUTH_TYPE,
            ldap_bind_dn=DEFAULT_LDAP_BIND_DN,
            ldap_bind_credentials=DEFAULT_LDAP_BIND_CREDENTIALS,
            ldap_search_base=DEFAULT_LDAP_SEARCH_BASE,
            ldap_search_scope=DEFAULT_LDAP_SEARCH_SCOPE,
            ldap_use_truststore_spi=DEFAULT_LDAP_USE_TRUSTSTORE_SPI,
            ldap_connection_pooling=DEFAULT_LDAP_CONNECTION_POOLING,
            ldap_pagination=DEFAULT_LDAP_PAGINATION,
            ldap_allow_kerberos_authentication=DEFAULT_LDAP_ALLOW_KERBEROS_AUTHENTICATION,
            ldap_batch_size_for_sync=DEFAULT_LDAP_BATCH_SIZE_FOR_SYNC,
            ldap_full_sync_period=DEFAULT_LDAP_FULL_SYNC_PERIOD,
            ldap_changed_sync_period=DEFAULT_LDAP_CHANGED_SYNC_PERIOD,
            ldap_debug=DEFAULT_LDAP_DEBUG,
            ldap_user_attribute_mappers=DEFAULT_LDAP_USER_ATTRIBUTE_MAPPERS,
            ldap_user_attribute_mappers_to_remove=DEFAULT_LDAP_USER_ATTRIBUTE_MAPPERS_TO_REMOVE,
            ldap_group_name_ldap_attr=DEFAULT_LDAP_GROUP_NAME_LDAP_ATTR,
            ldap_group_object_class=DEFAULT_LDAP_GROUP_OBJECT_CLASS,
            ldap_preserve_group_inheritance=DEFAULT_LDAP_PRESERVE_GROUP_INHERITANCE,
            ldap_group_membership_attribute=DEFAULT_LDAP_GROUP_MEMBERSHIP_ATTRIBUTE,
            ldap_group_membership_attr_type=DEFAULT_LDAP_GROUP_MEMBERSHIP_ATTR_TYPE,
            ldap_group_membership_ldap_attr=DEFAULT_LDAP_GROUP_MEMBERSHIP_LDAP_ATTR,
            ldap_group_filter=DEFAULT_LDAP_GROUP_FILTER,
            ldap_user_roles_retrieve_strategy=DEFAULT_LDAP_USER_ROLES_RETRIEVE_STRATEGY,
            ldap_mapped_group_attrs=DEFAULT_LDAP_MAPPED_GROUP_ATTRS,
            ldap_groups_drop_during_sync=DEFAULT_LDAP_GROUPS_DROP_DURING_SYNC,
            ldap_role_mapper_dn=DEFAULT_LDAP_ROLE_MAPPER_DN,
            ldap_role_mapper_name_ldap_attr=DEFAULT_LDAP_ROLE_MAPPER_NAME_LDAP_ATTR,
            ldap_role_mapper_object_class=DEFAULT_LDAP_ROLE_MAPPER_OBJECT_CLASS,
            ldap_role_mapper_membership_ldap_attr=DEFAULT_LDAP_ROLE_MAPPER_MEMBERSHIP_LDAP_ATTR,
            ldap_role_mapper_membership_attr_type=DEFAULT_LDAP_ROLE_MAPPER_MEMBERSHIP_ATTR_TYPE,
            ldap_role_mapper_membership_user_ldap_attr=DEFAULT_LDAP_ROLE_MAPPER_MEMBERSHIP_USER_LDAP_ATTR,
            ldap_role_mapper_roles_ldap_filter=DEFAULT_LDAP_ROLE_MAPPER_ROLE_LDAP_FILTER,
            ldap_role_mapper_mode=DEFAULT_LDAP_ROLE_MAPPER_MODE,
            ldap_role_mapper_retrieve_strategy=DEFAULT_LDAP_ROLE_MAPPER_RETRIEVE_STRATEGY,
            ldap_role_mapper_memberof_attr=DEFAULT_LDAP_ROLE_MAPPER_MEMBEROF_ATTR,
            ldap_role_mapper_use_realm_roles_mapping=DEFAULT_LDAP_ROLE_MAPPER_USE_REALM_ROLES_MAPPING,
            ldap_role_mapper_client_id=DEFAULT_LDAP_ROLE_MAPPER_CLIENT_ID,
            ldap_do_full_sync=DEFAULT_LDAP_DO_FULL_SYNC,
            local_users=None,
            local_groups=None,
            user_export_storage_access_key=None,
            user_export_storage_secret_key=None,
            user_export_storage_url=DEFAULT_USER_EXPORT_STORAGE_URL,
            user_export_storage_bucket=DEFAULT_USER_EXPORT_STORAGE_BUCKET,
            user_export_storage_passwd_object=DEFAULT_USER_EXPORT_STORAGE_PASSWD_OBJECT,
            user_export_name_source=None,
            user_export_groups=DEFAULT_USER_EXPORT_GROUPS,
            user_export_storage_groups_object=DEFAULT_USER_EXPORT_STORAGE_GROUPS_OBJECT,
            user_export_namespaces=DEFAULT_USER_EXPORT_NAMESPACES,
            user_export_passwd_configmap_name=DEFAULT_USER_EXPORT_PASSWD_CONFIGMAP_NAME,
            user_export_groups_configmap_name=DEFAULT_USER_EXPORT_GROUPS_CONFIGMAP_NAME,
            local_role_assignments=DEFAULT_LOCAL_ROLE_ASSIGNMENTS):
        self.keycloak_base = keycloak_base
        self.kc_master_admin_client_id = kc_master_admin_client_id
        self.kc_master_admin_username = kc_master_admin_username
        self.kc_master_admin_password = kc_master_admin_password

        self.ldap_connection_url = ldap_connection_url
        self.ldap_provider_id = ldap_provider_id
        self.ldap_federation_name = ldap_federation_name
        self.ldap_priority = ldap_priority
        self.ldap_edit_mode = ldap_edit_mode
        self.ldap_sync_registrations = ldap_sync_registrations
        self.ldap_vendor = ldap_vendor
        self.ldap_username_ldap_attribute = ldap_username_ldap_attribute
        self.ldap_rdn_ldap_attribute = ldap_rdn_ldap_attribute
        self.ldap_uuid_ldap_attribute = ldap_uuid_ldap_attribute
        self.ldap_user_object_classes = ldap_user_object_classes
        self.ldap_auth_type = ldap_auth_type
        self.ldap_bind_dn = ldap_bind_dn
        self.ldap_bind_credentials = ldap_bind_credentials
        self.ldap_search_base = ldap_search_base
        self.ldap_search_scope = ldap_search_scope
        self.ldap_use_truststore_spi = ldap_use_truststore_spi
        self.ldap_connection_pooling = ldap_connection_pooling
        self.ldap_pagination = ldap_pagination
        self.ldap_allow_kerberos_authentication = (
            ldap_allow_kerberos_authentication)
        self.ldap_batch_size_for_sync = ldap_batch_size_for_sync
        self.ldap_full_sync_period = ldap_full_sync_period
        self.ldap_changed_sync_period = ldap_changed_sync_period
        self.ldap_debug = ldap_debug
        self.ldap_user_attribute_mappers = ldap_user_attribute_mappers
        self.ldap_user_attribute_mappers_to_remove = ldap_user_attribute_mappers_to_remove
        self.ldap_group_name_ldap_attr = ldap_group_name_ldap_attr
        self.ldap_group_object_class = ldap_group_object_class
        self.ldap_preserve_group_inheritance = ldap_preserve_group_inheritance
        self.ldap_group_membership_attribute = ldap_group_membership_attribute
        self.ldap_group_membership_attr_type = ldap_group_membership_attr_type
        self.ldap_group_membership_ldap_attr = ldap_group_membership_ldap_attr
        self.ldap_group_filter = ldap_group_filter
        self.ldap_user_roles_retrieve_strategy = ldap_user_roles_retrieve_strategy
        self.ldap_mapped_group_attrs = ldap_mapped_group_attrs
        self.ldap_groups_drop_during_sync = ldap_groups_drop_during_sync
        self.ldap_role_mapper_dn = ldap_role_mapper_dn
        self.ldap_role_mapper_name_ldap_attr = ldap_role_mapper_name_ldap_attr
        self.ldap_role_mapper_object_class = ldap_role_mapper_object_class
        self.ldap_role_mapper_membership_ldap_attr = ldap_role_mapper_membership_ldap_attr
        self.ldap_role_mapper_membership_attr_type = ldap_role_mapper_membership_attr_type
        self.ldap_role_mapper_membership_user_ldap_attr = ldap_role_mapper_membership_user_ldap_attr
        self.ldap_role_mapper_roles_ldap_filter = ldap_role_mapper_roles_ldap_filter
        self.ldap_role_mapper_mode = ldap_role_mapper_mode
        self.ldap_role_mapper_retrieve_strategy = ldap_role_mapper_retrieve_strategy
        self.ldap_role_mapper_memberof_attr = ldap_role_mapper_memberof_attr
        self.ldap_role_mapper_use_realm_roles_mapping = ldap_role_mapper_use_realm_roles_mapping
        self.ldap_role_mapper_client_id = ldap_role_mapper_client_id
        self.ldap_do_full_sync = ldap_do_full_sync

        self.local_users = local_users
        self.local_groups = local_groups

        self.fetch_users_page_size = 50
        self.total_keycloak_users = 0

        self.user_export_storage_access_key = user_export_storage_access_key
        self.user_export_storage_secret_key = user_export_storage_secret_key
        self.user_export_storage_url = user_export_storage_url
        self.user_export_storage_bucket = user_export_storage_bucket
        self.user_export_storage_passwd_object = user_export_storage_passwd_object
        self.user_export_name_source = user_export_name_source
        self.user_export_groups = user_export_groups
        self.user_export_storage_groups_object = user_export_storage_groups_object
        self.user_export_namespaces = user_export_namespaces
        self.user_export_passwd_configmap_name = user_export_passwd_configmap_name
        self.user_export_groups_configmap_name = user_export_groups_configmap_name

        self.local_role_assignments = local_role_assignments

        self._kc_master_admin_client_cache = None
        self._ldap_federation_object_id = None
        self._s3_client_cache = None
        self._core_v1_cache = None

    def run(self):
        self._configure_ldap_user_federation()
        self._create_local_users()
        self._create_local_groups()
        self._create_assignments()
        self._fetch_users()
        self._fetch_groups()

    def reset_keycloak_master_admin_session(self):
        LOGGER.info("Resetting Keycloak master admin session.")
        self._kc_master_admin_client_cache = None

    @property
    def _kc_master_admin_client(self):
        if self._kc_master_admin_client_cache:
            return self._kc_master_admin_client_cache

        kc_master_token_endpoint = (
            '{}/realms/{}/protocol/openid-connect/token'.format(
                self.keycloak_base, self.MASTER_REALM_NAME))

        kc_master_client = oauthlib.oauth2.LegacyApplicationClient(
            client_id=self.kc_master_admin_client_id)

        client = requests_oauthlib.OAuth2Session(
            client=kc_master_client, auto_refresh_url=kc_master_token_endpoint,
            auto_refresh_kwargs={
                'client_id': self.kc_master_admin_client_id,
            },
            token_updater=lambda t: LOGGER.info("Refreshed Keycloak master admin token"))
        client.verify = False
        LOGGER.info("Fetching initial KC master admin token.")
        client.fetch_token(
            token_url=kc_master_token_endpoint,
            client_id=self.kc_master_admin_client_id,
            username=self.kc_master_admin_username,
            password=self.kc_master_admin_password)

        self._kc_master_admin_client_cache = client
        return self._kc_master_admin_client_cache

    @property
    def _s3_client(self):
        if self._s3_client_cache:
            return self._s3_client_cache
        LOGGER.info(
            'Connecting to s3 with url: %s access_key: %s',
            self.user_export_storage_url, self.user_export_storage_access_key)
        self._s3_client_cache = boto3.client(
            's3',
            endpoint_url=self.user_export_storage_url,
            aws_access_key_id=self.user_export_storage_access_key,
            aws_secret_access_key=self.user_export_storage_secret_key)
        return self._s3_client_cache

    @property
    def _core_v1(self):
        if self._core_v1_cache:
            return self._core_v1_cache
        self._core_v1_cache = kubernetes.client.CoreV1Api()
        return self._core_v1_cache

    def _configure_ldap_user_federation(self):
        if not self.ldap_connection_url:
            LOGGER.info("LDAP connection URL not set, will not configure LDAP.")
            return
        if self._fetch_component_by_name(self.ldap_federation_name):
            LOGGER.info("LDAP user federation already exists.")
            return
        self._create_ldap_user_federation()
        try:
            self._remove_ldap_user_attribute_mappers()
            self._create_ldap_user_attribute_mappers()
            self._create_ldap_group_mapper()
            self._create_ldap_role_mapper()
            self._trigger_full_user_sync()
        except Exception:
            LOGGER.info("Configuring LDAP failed, trying to clean up...")
            self._delete_ldap_user_federation()
            raise

    def _create_local_users(self):
        LOGGER.info("Creating local users...")
        for user in (self.local_users or []):
            self._create_local_user(user)
        LOGGER.info("Created local users.")

    def _create_local_user(self, user):
        url = (
            '{}/admin/realms/{}/users'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME))
        req_body = {
            'username': user['name'],
            'enabled': True,
            'firstName': user['firstName'],
            'credentials': [
                {
                    'type': 'password',
                    'value': user['password'],
                },
            ],
            'attributes': {
                'loginShell': [
                    user['loginShell'],
                ],
                'homeDirectory': [
                    user['homeDirectory'],
                ],
                'uidNumber': [
                    user['uidNumber'],
                ],
                'gidNumber': [
                    user['gidNumber'],
                ],
            },
        }
        response = self._kc_master_admin_client.post(url, json=req_body)
        if response.status_code == 409:
            LOGGER.info("User %r already exists", user['name'])
            return
        response.raise_for_status()
        LOGGER.info("Created user %r", user['name'])

    def _create_local_groups(self):
        LOGGER.info("Creating local groups...")
        for group in (self.local_groups or []):
            self._create_local_group(group)
        LOGGER.info("Created local groups.")

    def _create_local_group(self, group):
        url = (
            '{}/admin/realms/{}/groups'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME))
        req_body = {
            'name': group['name'],
            'attributes': {
                'cn': [
                    group['name'],
                ],
                'gidNumber': [
                    group['gid'],
                ],
                'memberUid': group['members'],
            }
        }
        LOGGER.info("Creating group %r", req_body)
        response = self._kc_master_admin_client.post(url, json=req_body)
        if response.status_code == 409:
            LOGGER.info("Group %r already exists.", group['name'])
            return
        response.raise_for_status()
        group_id = response.headers['location'].rpartition('/')[2]
        LOGGER.info("Created group %r. id=%s", group['name'], group_id)
        for member in group['members']:
            self._add_member(group_id, member)

    def _add_member(self, group_id, member_name):
        LOGGER.info("Adding %r to group %r...", member_name, group_id)
        try:
            user_id = self._fetch_user_by_name(member_name)['id']
        except NotFound:
            raise UnrecoverableError(
                f"Cannot add {member_name!r} to group because a user with that "
                "name doesn't exist in Keycloak.")

        url = (
            '{}/admin/realms/{}/users/{}/groups/{}'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME, user_id, group_id))
        response = self._kc_master_admin_client.put(url)
        response.raise_for_status()
        LOGGER.info("Adding %r to group %r.", member_name, group_id)

    def _create_assignments(self):
        for a in self.local_role_assignments:
            self._create_assignment(a)

    def _create_assignment(self, assignment):
        client_id = assignment['client']
        client = self._fetch_client_by_client_id(client_id)

        role_name = assignment['role']
        client_role = self._fetch_client_role(client, role_name)

        if 'group' in assignment:
            group_name = assignment['group']
            self._create_group_assignment(group_name, client, client_role)
        else:
            user_name = assignment['user']
            self._create_user_assignment(user_name, client, client_role)

    def _create_group_assignment(self, group_name, client, client_role):
        LOGGER.info(
            "Assigning %s on %s to group %s...", client_role['name'],
            client['id'], group_name)
        try:
            group = self._fetch_group(group_name)
        except NotFound:
            raise UnrecoverableError(
                f"Cannot assign a role to group {group_name!r} because a group "
                "with that name doesn't exist in Keycloak.")

        url = (
            '{}/admin/realms/{}/groups/{}/role-mappings/clients/{}'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME, group['id'],
                client['id']))
        req_body = [
            {
                'id': client_role['id'],
                'name': client_role['name'],
                'composite': False,
                'clientRole': True,
                'containerId': client['id'],
            },
        ]
        # Note that if this is attempted when the role assignment already
        # exists, keycloak just returns 204 again.
        response = self._kc_master_admin_client.post(url, json=req_body)
        response.raise_for_status()
        LOGGER.info(
            "Assigned %s on %s to group %s", client_role['name'], client['id'],
            group_name)

    def _create_user_assignment(self, user_name, client, client_role):
        LOGGER.info(
            "Assigning %s on %s to user %s...", client_role['name'],
            client['id'], user_name)
        try:
            user = self._fetch_user_by_name(user_name)
        except NotFound:
            raise UnrecoverableError(
                f"Cannot assign a role to user {user_name!r} because a user "
                "with that name doesn't exist in Keycloak.")

        url = (
            '{}/admin/realms/{}/users/{}/role-mappings/clients/{}'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME, user['id'],
                client['id']))
        req_body = [
            {
                'id': client_role['id'],
                'name': client_role['name'],
                'composite': False,
                'clientRole': True,
                'containerId': client['id'],
            },
        ]
        # Note that if this is attempted when the role assignment already
        # exists, keycloak just returns 204 again.
        response = self._kc_master_admin_client.post(url, json=req_body)
        response.raise_for_status()
        LOGGER.info(
            "Assigned %s on %s to user %s", client_role['name'], client['id'],
            user_name)

    def _fetch_client_by_client_id(self, client_id):
        LOGGER.info("Fetching client %s...", client_id)
        url = (
            '{}/admin/realms/{}/clients?clientId={}'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME, client_id))
        response = self._kc_master_admin_client.get(url)
        response.raise_for_status()
        client = response.json()[0]
        LOGGER.info("ID for %s client is %s", client_id, client['id'])
        return client

    def _fetch_client_role(self, client, role_name):
        LOGGER.info(
            "Fetching role %s for client %s...", role_name, client['clientId'])
        url = (
            '{}/admin/realms/{}/clients/{}/roles/{}'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME, client['id'],
                role_name))
        response = self._kc_master_admin_client.get(url)
        response.raise_for_status()
        client_role = response.json()
        LOGGER.info(
            "Got role %s for client %s: %s", role_name, client['clientId'],
            client_role)
        return client_role

    def _fetch_group(self, group_name):
        LOGGER.info("Fetching group for %s...", group_name)
        url = (
            '{}/admin/realms/{}/groups?search={}'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME, group_name))
        response = self._kc_master_admin_client.get(url)
        response.raise_for_status()
        groups = response.json()
        # Note that the search parameter just limits the result to groups
        # matching the value as a prefix, so we need to find the exact match
        # here.
        group_match = [g for g in groups if g['name'] == group_name]
        if not group_match:
            raise NotFound()
        group = group_match[0]
        LOGGER.info("ID for %s group is %s", group_name, group['id'])
        return group

    def _fetch_user_by_name(self, user_name):
        LOGGER.info("Fetching user for %s...", user_name)
        url = (
            '{}/admin/realms/{}/users?username={}'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME, user_name))
        response = self._kc_master_admin_client.get(url)
        response.raise_for_status()
        user_matches = response.json()
        if not user_matches:
            raise NotFound()
        user = user_matches[0]
        LOGGER.info("ID for %s user is %s", user_name, user['id'])
        return user

    def _create_ldap_user_federation(self):
        LOGGER.info(
            "Created LDAP user federation with bind DN %r...",
            self.ldap_bind_dn)
        config = {
            'priority': [self.ldap_priority, ],
            'editMode': [self.ldap_edit_mode, ],
            'syncRegistrations': [self.ldap_sync_registrations, ],
            'vendor': [self.ldap_vendor, ],
            'usernameLDAPAttribute': [self.ldap_username_ldap_attribute, ],
            'rdnLDAPAttribute': [self.ldap_rdn_ldap_attribute, ],
            'uuidLDAPAttribute': [self.ldap_uuid_ldap_attribute, ],
            'userObjectClasses': [self.ldap_user_object_classes, ],
            'connectionUrl': [self.ldap_connection_url, ],
            'usersDn': [self.ldap_search_base, ],
            'authType': [self.ldap_auth_type, ],
            'searchScope': [self.ldap_search_scope, ],
            'useTruststoreSpi': [self.ldap_use_truststore_spi, ],
            'connectionPooling': [self.ldap_connection_pooling, ],
            'pagination': [self.ldap_pagination, ],
            'allowKerberosAuthentication': [self.ldap_allow_kerberos_authentication, ],
            'batchSizeForSync': [self.ldap_batch_size_for_sync, ],
            'fullSyncPeriod': [self.ldap_full_sync_period, ],
            'changedSyncPeriod': [self.ldap_changed_sync_period, ],
            'debug': [self.ldap_debug, ],
        }
        if self.ldap_bind_dn and self.ldap_bind_credentials:
            config['bindDn'] = [self.ldap_bind_dn, ]
            config['bindCredential'] = [self.ldap_bind_credentials, ]
        self._ldap_federation_object_id = self._create_component(
            name=self.ldap_federation_name,
            provider_id=self.ldap_provider_id,
            provider_type='org.keycloak.storage.UserStorageProvider',
            config=config)
        LOGGER.info("Created LDAP user federation.")

    def _delete_ldap_user_federation(self):
        self._delete_component(self._ldap_federation_object_id)

    def _remove_ldap_user_attribute_mappers(self):
        for mapper_name in self.ldap_user_attribute_mappers_to_remove:
            self._remove_ldap_user_attribute_mapper(mapper_name)

    def _remove_ldap_user_attribute_mapper(self, mapper_name):
        LOGGER.info("Removing %r LDAP user attribute mapper...", mapper_name)
        mapper = self._fetch_component_by_name(
            mapper_name, parent_id=self._ldap_federation_object_id)
        if not mapper:
            LOGGER.info(
                "%r attribute doesn't exist already, nothing to do.", mapper_name)
            return
        self._delete_component(mapper['id'])

    def _create_ldap_user_attribute_mappers(self):
        for m in self.ldap_user_attribute_mappers:
            self._create_ldap_user_attribute_mapper(m)

    def _create_ldap_user_attribute_mapper(self, attribute_name):
        config = {
            'ldap.attribute': [attribute_name, ],
            'is.mandatory.in.ldap': ['false', ],
            'always.read.value.from.ldap': ['false', ],
            'read.only': ['true', ],
            'user.model.attribute': [attribute_name, ],
        }
        self._create_component(
            name=attribute_name,
            provider_id='user-attribute-ldap-mapper',
            provider_type='org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
            parent_id=self._ldap_federation_object_id,
            config=config,
        )
        LOGGER.info(
            "Created LDAP user attribute mapper for %r.", attribute_name)

    def _create_component(
            self, name, provider_id, provider_type, parent_id=None, config=None):
        url = (
            '{}/admin/realms/{}/components'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME))

        req_body = {
            'providerId': provider_id,
            'providerType': provider_type,
            'name': name,
            'config': config,
        }
        if parent_id:
            req_body['parentId'] = parent_id

        response = self._kc_master_admin_client.post(url, json=req_body)
        response.raise_for_status()
        component_id = response.headers['location'].rpartition('/')[2]
        return component_id

    def _fetch_component_by_name(self, name, parent_id=None):
        LOGGER.info("Fetching %r component...", name)
        url = (
            '{}/admin/realms/{}/components'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME))
        params = {'name': name}
        if parent_id:
            params['parent'] = parent_id
        response = self._kc_master_admin_client.get(url, params=params)
        response.raise_for_status()
        components = response.json()
        if components:
            component = components[0]
            LOGGER.info("Component %r has ID %r.", name, component['id'])
            return component
        LOGGER.info("%r component not found.", name)
        return None

    def _delete_component(self, component_id):
        LOGGER.info("Deleting component with ID %r...", component_id)
        url = (
            '{}/admin/realms/{}/components/{}'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME, component_id))
        response = self._kc_master_admin_client.delete(url)
        response.raise_for_status()

    def _create_ldap_group_mapper(self):
        config = {
            'groups.dn': [self.ldap_search_base],
            'group.name.ldap.attribute': [self.ldap_group_name_ldap_attr],
            'group.object.classes': [self.ldap_group_object_class],
            'preserve.group.inheritance': [self.ldap_preserve_group_inheritance],
            'membership.ldap.attribute': [self.ldap_group_membership_attribute],
            'membership.attribute.type': [self.ldap_group_membership_attr_type],
            'membership.user.ldap.attribute': [self.ldap_group_membership_ldap_attr],
            'groups.ldap.filter': [self.ldap_group_filter],
            'mode': [self.ldap_edit_mode],
            'user.roles.retrieve.strategy': [self.ldap_user_roles_retrieve_strategy],
            'mapped.group.attributes': [self.ldap_mapped_group_attrs],
            'drop.non.existing.groups.during.sync': [self.ldap_groups_drop_during_sync],
        }
        self._create_component(
            name='group-attribute-ldap-mapper',
            provider_id='group-ldap-mapper',
            provider_type='org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
            parent_id=self._ldap_federation_object_id,
            config=config,
        )
        LOGGER.info("Created LDAP group attribute mapper.")

    def _create_ldap_role_mapper(self):
        if not self.ldap_role_mapper_dn:
            LOGGER.info("Not creating LDAP role mapper because it's not configured")
            return

        config = {
            'roles.dn': [self.ldap_role_mapper_dn],
            'role.name.ldap.attribute': [self.ldap_role_mapper_name_ldap_attr],
            'role.object.classes': [self.ldap_role_mapper_object_class],
            'membership.ldap.attribute': [self.ldap_role_mapper_membership_ldap_attr],
            'membership.attribute.type': [self.ldap_role_mapper_membership_attr_type],
            'membership.user.ldap.attribute': [self.ldap_role_mapper_membership_user_ldap_attr],
            'roles.ldap.filter': [self.ldap_role_mapper_roles_ldap_filter],
            'mode': [self.ldap_role_mapper_mode],
            'user.roles.retrieve.strategy': [self.ldap_role_mapper_retrieve_strategy],
            'memberof.ldap.attribute': [self.ldap_role_mapper_memberof_attr],
            'use.realm.roles.mapping': [self.ldap_role_mapper_use_realm_roles_mapping],
            'client.id': [self.ldap_role_mapper_client_id],
        }
        self._create_component(
            name='role-mapper-shasta',
            provider_id='role-ldap-mapper',
            provider_type='org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
            parent_id=self._ldap_federation_object_id,
            config=config,
        )
        LOGGER.info("Created LDAP role mapper.")

    def _trigger_full_user_sync(self):
        if not self.ldap_do_full_sync:
            LOGGER.info("Skipping LDAP user sync.")
            return
        LOGGER.info("Triggering full user sync operation...")
        url = (
            '{}/admin/realms/{}/user-storage/{}/sync'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME,
                self._ldap_federation_object_id))
        response = self._kc_master_admin_client.post(
            url, params={'action': 'triggerFullSync'})
        try:
            response.raise_for_status()
        except Exception:
            raise UnrecoverableError(
                "User sync operator failed with "
                f"status code={response.status_code} {response.reason}, "
                f"text=\n{response.text}")
        LOGGER.info(
            "Full user sync operation completed, status_code='%s %s' result=%s",
            response.status_code, response.reason, response.content)

    def _fetch_users(self):
        LOGGER.info("Fetching all users from Keycloak to build the passwd file...")

        self._fetch_total_users(self)

        passwd_fmts = []
        first = 0

        while True:
            users = self._fetch_users_page(first)
            for user in users:
                passwd_fmt = self._format_user_passwd_entry(user)
                if passwd_fmt:
                    passwd_fmts.append(passwd_fmt)

            if len(passwd_fmts) == self.total_keycloak_users:
                break

            first = first + self.fetch_users_page_size

        passwd_fmt_str = '\n'.join(passwd_fmts)

        LOGGER.info("Users:\n%s", passwd_fmt_str)
        LOGGER.info(
            "Sending user info to storage. bucket: %r passwd: %r",
            self.user_export_storage_bucket,
            self.user_export_storage_passwd_object)

        self._s3_client.upload_fileobj(
            io.BytesIO(passwd_fmt_str.encode('utf-8')),
            self.user_export_storage_bucket,
            self.user_export_storage_passwd_object,
            ExtraArgs={'ACL': 'public-read'})

        LOGGER.info("Sent user info to storage.")

        self._create_passwd_configmaps(passwd_fmt_str)

    def _fetch_users_page(self, first):
        LOGGER.info(
            "Fetching %s users from Keycloak starting at %s...", self.fetch_users_page_size, first)
        url = f'{self.keycloak_base}/admin/realms/{self.SHASTA_REALM_NAME}/users'
        response = self._kc_master_admin_client.get(
            url, params={'first': first, 'max': self.fetch_users_page_size})
        response.raise_for_status()
        users = response.json()
        LOGGER.info("Got %s users", len(users))
        if users:
            LOGGER.info("first: %r -> last: %r", users[0]['username'], users[-1]['username'])
        return users

    def _fetch_total_users(self):
        LOGGER.info(
            "Fetching total users from Keycloak")
        url = f'{self.keycloak_base}/admin/realms/{self.SHASTA_REALM_NAME}/users'
        response = self._kc_master_admin_client.get(url)
        response.raise_for_status()
        total_users = response.text()
        LOGGER.info("Got %s users", total_users)
        self.total_keycloak_users = total_users

    def _format_user_passwd_entry(self, user):
        if 'attributes' not in user:
            LOGGER.info("Skipping %s, no attributes.", user['username'])
            return

        attrs = user['attributes']
        if ('uidNumber' not in attrs or 'gidNumber' not in attrs or 'homeDirectory' not in attrs or 'loginShell' not in attrs):
            LOGGER.info("Skipping %s, missing attributes.", user['username'])
            return

        if self.user_export_name_source == 'homeDirectory':
            # Extract the last element of the homeDirectory field.
            username = attrs['homeDirectory'][0].rsplit('/', 1)[-1]
        else:
            username = user['username']

        return (
            '{}::{}:{}:{}:{}:{}'.format(
                username,
                attrs['uidNumber'][0],
                attrs['gidNumber'][0],
                user['firstName'],
                attrs['homeDirectory'][0],
                attrs['loginShell'][0]))

    def _create_passwd_configmaps(self, users_pwd_str):
        for namespace in self.user_export_namespaces:
            self._apply_configmap(
                self.user_export_passwd_configmap_name, namespace,
                'keycloak-users', users_pwd_str)

    def _fetch_groups(self):
        if not self.user_export_groups:
            LOGGER.info("Will not setup groups since it's not configured.")
            return
        LOGGER.info("Fetching groups to load into S3 and ConfigMap...")
        url = (
            '{}/admin/realms/{}/groups'.format(
                self.keycloak_base, self.SHASTA_REALM_NAME))
        response = self._kc_master_admin_client.get(
            url, params={'max': '-1', 'briefRepresentation': 'false'})
        # TODO: follow-on work to use paging, it's safer.
        response.raise_for_status()
        groups = response.json()

        groups_fmt = []
        for group in groups:
            attrs = group['attributes']
            if 'memberUid' in attrs:
                members = ','.join(attrs['memberUid'])
            else:
                members = ''
            groups_fmt.append(
                '{}::{}:{}'.format(attrs['cn'][0], attrs['gidNumber'][0], members))
        groups_str = '\n'.join(groups_fmt)

        LOGGER.info("Groups:\n%s", groups_str)
        LOGGER.info(
            "Sending groups info to storage. bucket: %r groups: %r",
            self.user_export_storage_bucket,
            self.user_export_storage_groups_object)

        self._s3_client.upload_fileobj(
            io.BytesIO(groups_str.encode('utf-8')),
            self.user_export_storage_bucket,
            self.user_export_storage_groups_object,
            ExtraArgs={'ACL': 'public-read'})

        LOGGER.info("Sent groups info to storage.")
        self._create_groups_configmaps(groups_str)

    def _create_groups_configmaps(self, groups):
        for namespace in self.user_export_namespaces:
            self._apply_configmap(
                self.user_export_groups_configmap_name, namespace,
                'keycloak-groups', groups)

    def _apply_configmap(self, name, namespace, key_name, data):
        configmap = self._fetch_configmap(name, namespace)
        if configmap:
            # Already exists, might need to update.
            self._sync_configmap(name, namespace, key_name, data, configmap)
            return
        # Otherwise the configmap didn't exist.
        self._create_configmap(name, namespace, key_name, data)

    def _fetch_configmap(self, name, namespace):
        LOGGER.info(
            'Fetching current %s ConfigMap in namespace %s...', name, namespace)
        try:
            return self._core_v1.read_namespaced_config_map(name, namespace)
        except kubernetes.client.rest.ApiException as e:
            if e.status != 404:
                LOGGER.error(
                    'read_namespaced_config_map %r in namespace %r returned an '
                    'unexpected result %s',
                    name, namespace, e)
                raise
        LOGGER.info(
            "The %s ConfigMap in namespace %s wasn't found (probably "
            "because this is a fresh install).",
            name, namespace)
        return None

    def _create_configmap(self, name, namespace, key_name, data):
        LOGGER.info("Creating ConfigMap %r in namespace %r...", name, namespace)

        configmap = kubernetes.client.V1ConfigMap(
            metadata=kubernetes.client.V1ObjectMeta(
                name=name,
                namespace=namespace,
            ),
            data={key_name: data},
        )
        self._core_v1.create_namespaced_config_map(namespace, configmap)

    def _sync_configmap(
            self, name, namespace, key_name, data, current_configmap):
        if current_configmap.data.get(key_name) == data:
            LOGGER.info("The data in the ConfigMap is current, nothing to do.")
            return
        LOGGER.info("Patching the ConfigMap, it's out of date.")
        configmap = kubernetes.client.V1ConfigMap(
            data={key_name: data},
        )
        self._core_v1.patch_namespaced_config_map(name, namespace, configmap)


def read_keycloak_master_admin_secrets(
        secret_dir='/mnt/keycloak-master-admin-auth-vol'):
    try:
        with open('{}/client-id'.format(secret_dir)) as f:
            client_id = f.read()
        with open('{}/user'.format(secret_dir)) as f:
            user = f.read()
        with open('{}/password'.format(secret_dir)) as f:
            password = f.read()

        return {
            'client_id': client_id,
            'user': user,
            'password': password
        }
    except Exception:
        LOGGER.warning(
            'Expected keycloak secrets but not found, using defaults')
        return {
            'client_id': DEFAULT_KEYCLOAK_MASTER_ADMIN_CLIENT_ID,
            'user': DEFAULT_KEYCLOAK_MASTER_ADMIN_USERNAME,
            'password': DEFAULT_KEYCLOAK_MASTER_ADMIN_PASSWORD,
        }


def read_user_export_storage_secrets(secret_dir='/mnt/ceph-access-vol'):
    LOGGER.info("Reading user export secret from %s...", secret_dir)
    with open('{}/access_key'.format(secret_dir)) as f:
        access_key = f.read()
    with open('{}/secret_key'.format(secret_dir)) as f:
        secret_key = f.read()
    return {
        'access_key': access_key,
        'secret_key': secret_key
    }
    LOGGER.info(
        "User export secret from %s access_key=", secret_dir, access_key)


def main():
    log_format = "%(asctime)-15s - %(levelname)-7s - %(name)s - %(message)s"
    logging.basicConfig(level=logging.INFO, format=log_format)

    # Load K8s configuration
    kubernetes.config.load_incluster_config()

    keycloak_base = os.environ.get('KEYCLOAK_BASE', DEFAULT_KEYCLOAK_BASE)

    ldap_connection_url = os.environ.get(
        'LDAP_CONNECTION_URL', DEFAULT_LDAP_CONNECTION_URL)
    ldap_provider_id = os.environ.get('LDAP_PROVIDER_ID', DEFAULT_LDAP_PROVIDER_ID)
    ldap_federation_name = os.environ.get(
        'LDAP_FEDERATION_NAME', DEFAULT_LDAP_FEDERATION_NAME)
    ldap_priority = os.environ.get('LDAP_PRIORITY', DEFAULT_LDAP_PRIORITY)
    ldap_edit_mode = os.environ.get('LDAP_EDIT_MODE', DEFAULT_LDAP_EDIT_MODE)
    ldap_sync_registrations = os.environ.get(
        'LDAP_SYNC_REGISTRATIONS', DEFAULT_LDAP_SYNC_REGISTRATIONS)
    ldap_vendor = os.environ.get('LDAP_LDAP_VENDOR', DEFAULT_LDAP_VENDOR)
    ldap_username_ldap_attribute = os.environ.get(
        'LDAP_USERNAME_LDAP_ATTRIBUTE', DEFAULT_LDAP_USERNAME_LDAP_ATTRIBUTE)
    ldap_rdn_ldap_attribute = os.environ.get(
        'LDAP_RDN_LDAP_ATTRIBUTE', DEFAULT_LDAP_RDN_LDAP_ATTRIBUTE)
    ldap_uuid_ldap_attribute = os.environ.get(
        'LDAP_UUID_LDAP_ATTRIBUTE', DEFAULT_LDAP_UUID_LDAP_ATTRIBUTE)
    ldap_user_object_classes = os.environ.get(
        'LDAP_USER_OBJECT_CLASSES', DEFAULT_LDAP_USER_OBJECT_CLASSES)
    ldap_auth_type = os.environ.get('LDAP_AUTH_TYPE', DEFAULT_LDAP_AUTH_TYPE)
    ldap_bind_dn = os.environ.get('LDAP_BIND_DN', DEFAULT_LDAP_BIND_DN)
    ldap_bind_credentials = os.environ.get(
        'LDAP_BIND_CREDENTIALS', DEFAULT_LDAP_BIND_CREDENTIALS)
    ldap_search_base = os.environ.get('LDAP_SEARCH_BASE', DEFAULT_LDAP_SEARCH_BASE)
    ldap_search_scope = os.environ.get('LDAP_SEARCH_SCOPE', DEFAULT_LDAP_SEARCH_SCOPE)
    ldap_use_truststore_spi = os.environ.get(
        'LDAP_USE_TRUSTSTORE_SPI', DEFAULT_LDAP_USE_TRUSTSTORE_SPI)
    ldap_connection_pooling = os.environ.get(
        'LDAP_CONNECTION_POOLING', DEFAULT_LDAP_CONNECTION_POOLING)
    ldap_pagination = os.environ.get('LDAP_PAGINATION', DEFAULT_LDAP_PAGINATION)
    ldap_allow_kerberos_authentication = os.environ.get(
        'LDAP_ALLOW_KERBEROS_AUTHENTICATION', DEFAULT_LDAP_ALLOW_KERBEROS_AUTHENTICATION)
    ldap_batch_size_for_sync = os.environ.get(
        'LDAP_BATCH_SIZE_FOR_SYNC', DEFAULT_LDAP_BATCH_SIZE_FOR_SYNC)
    ldap_full_sync_period = os.environ.get(
        'LDAP_FULL_SYNC_PERIOD', DEFAULT_LDAP_FULL_SYNC_PERIOD)
    ldap_changed_sync_period = os.environ.get(
        'LDAP_CHANGED_SYNC_PERIOD', DEFAULT_LDAP_CHANGED_SYNC_PERIOD)
    ldap_debug = os.environ.get('LDAP_DEBUG', DEFAULT_LDAP_DEBUG)
    ldap_user_attribute_mappers_str = os.environ.get('LDAP_USER_ATTRIBUTE_MAPPERS')
    if ldap_user_attribute_mappers_str:
        ldap_user_attribute_mappers = json.loads(ldap_user_attribute_mappers_str)
    else:
        ldap_user_attribute_mappers = DEFAULT_LDAP_USER_ATTRIBUTE_MAPPERS
    ldap_user_attribute_mappers_to_remove_str = os.environ.get(
        'LDAP_USER_ATTRIBUTE_MAPPERS_TO_REMOVE')
    if ldap_user_attribute_mappers_to_remove_str:
        ldap_user_attribute_mappers_to_remove = json.loads(
            ldap_user_attribute_mappers_to_remove_str)
    else:
        ldap_user_attribute_mappers_to_remove = (
            DEFAULT_LDAP_USER_ATTRIBUTE_MAPPERS_TO_REMOVE)
    ldap_group_name_ldap_attr = os.environ.get(
        'LDAP_GROUP_NAME_LDAP_ATTR', DEFAULT_LDAP_GROUP_NAME_LDAP_ATTR)
    ldap_group_object_class = os.environ.get(
        'LDAP_GROUP_OBJECT_CLASS', DEFAULT_LDAP_GROUP_OBJECT_CLASS)
    ldap_preserve_group_inheritance = os.environ.get(
        'LDAP_PRESERVE_GROUP_INHERITANCE', DEFAULT_LDAP_PRESERVE_GROUP_INHERITANCE)
    ldap_group_membership_attribute = os.environ.get(
        'LDAP_GROUP_MEMBERSHIP_ATTRIBUTE', DEFAULT_LDAP_GROUP_MEMBERSHIP_ATTRIBUTE)
    ldap_group_membership_attr_type = os.environ.get(
        'LDAP_GROUP_MEMBERSHIP_ATTR_TYPE', DEFAULT_LDAP_GROUP_MEMBERSHIP_ATTR_TYPE)
    ldap_group_membership_ldap_attr = os.environ.get(
        'LDAP_GROUP_MEMBERSHIP_LDAP_ATTR', DEFAULT_LDAP_GROUP_MEMBERSHIP_LDAP_ATTR)
    ldap_group_filter = os.environ.get(
        'LDAP_GROUP_FILTER', DEFAULT_LDAP_GROUP_FILTER)
    ldap_user_roles_retrieve_strategy = os.environ.get(
        'LDAP_USER_ROLES_RETRIEVE_STRATEGY', DEFAULT_LDAP_USER_ROLES_RETRIEVE_STRATEGY)
    ldap_mapped_group_attrs = os.environ.get(
        'LDAP_MAPPED_GROUP_ATTRS', DEFAULT_LDAP_MAPPED_GROUP_ATTRS)
    ldap_groups_drop_during_sync = os.environ.get(
        'LDAP_GROUPS_DROP_DURING_SYNC', DEFAULT_LDAP_GROUPS_DROP_DURING_SYNC)
    ldap_role_mapper_dn = os.environ.get(
        'LDAP_ROLE_MAPPER_DN', DEFAULT_LDAP_ROLE_MAPPER_DN)
    ldap_role_mapper_name_ldap_attr = os.environ.get(
        'LDAP_ROLE_MAPPER_NAME_LDAP_ATTR', DEFAULT_LDAP_ROLE_MAPPER_NAME_LDAP_ATTR)
    ldap_role_mapper_object_class = os.environ.get(
        'LDAP_ROLE_MAPPER_OBJECT_CLASS', DEFAULT_LDAP_ROLE_MAPPER_OBJECT_CLASS)
    ldap_role_mapper_membership_ldap_attr = os.environ.get(
        'LDAP_ROLE_MAPPER_MEMBERSHIP_LDAP_ATTR', DEFAULT_LDAP_ROLE_MAPPER_MEMBERSHIP_LDAP_ATTR)
    ldap_role_mapper_membership_attr_type = os.environ.get(
        'LDAP_ROLE_MAPPER_MEMBERSHIP_ATTR_TYPE', DEFAULT_LDAP_ROLE_MAPPER_MEMBERSHIP_ATTR_TYPE)
    ldap_role_mapper_membership_user_ldap_attr = os.environ.get(
        'LDAP_ROLE_MAPPER_MEMBERSHIP_USER_LDAP_ATTR', DEFAULT_LDAP_ROLE_MAPPER_MEMBERSHIP_USER_LDAP_ATTR)
    ldap_role_mapper_roles_ldap_filter = os.environ.get(
        'LDAP_ROLE_MAPPER_ROLE_LDAP_FILTER', DEFAULT_LDAP_ROLE_MAPPER_ROLE_LDAP_FILTER)
    ldap_role_mapper_mode = os.environ.get(
        'LDAP_ROLE_MAPPER_MODE', DEFAULT_LDAP_ROLE_MAPPER_MODE)
    ldap_role_mapper_retrieve_strategy = os.environ.get(
        'LDAP_ROLE_MAPPER_RETRIEVE_STRATEGY', DEFAULT_LDAP_ROLE_MAPPER_RETRIEVE_STRATEGY)
    ldap_role_mapper_memberof_attr = os.environ.get(
        'LDAP_ROLE_MAPPER_MEMBEROF_ATTR', DEFAULT_LDAP_ROLE_MAPPER_MEMBEROF_ATTR)
    ldap_role_mapper_use_realm_roles_mapping = os.environ.get(
        'LDAP_ROLE_MAPPER_USE_REALM_ROLES_MAPPING', DEFAULT_LDAP_ROLE_MAPPER_USE_REALM_ROLES_MAPPING)
    ldap_role_mapper_client_id = os.environ.get(
        'LDAP_ROLE_MAPPER_CLIENT_ID', DEFAULT_LDAP_ROLE_MAPPER_CLIENT_ID)
    ldap_do_full_sync_str = os.environ.get('LDAP_DO_FULL_SYNC')
    if ldap_do_full_sync_str:
        ldap_do_full_sync = (ldap_do_full_sync_str.upper() == "TRUE")
    else:
        ldap_do_full_sync = DEFAULT_LDAP_DO_FULL_SYNC

    try:
        local_users = json.load(open('/mnt/local-users/local-users'))
    except IOError as e:
        if e.errno != 2:
            raise
        LOGGER.info("No local users because the /mnt/local-users/local-users file doesn't exist")
        local_users = None

    try:
        local_groups = json.load(open('/mnt/local-groups/local-groups'))
    except IOError as e:
        if e.errno != 2:
            raise
        LOGGER.info("No local groups because the /mnt/local-groups/local-groups file doesn't exist")
        local_groups = None

    user_export_storage_url = os.environ.get(
        'USER_EXPORT_STORAGE_URL', DEFAULT_USER_EXPORT_STORAGE_URL)
    user_export_storage_bucket = os.environ.get(
        'USER_EXPORT_STORAGE_BUCKET', DEFAULT_USER_EXPORT_STORAGE_BUCKET)
    user_export_storage_passwd_object = os.environ.get(
        'USER_EXPORT_STORAGE_PASSWD_OBJECT', DEFAULT_USER_EXPORT_STORAGE_PASSWD_OBJECT)
    user_export_name_source = os.environ.get('USER_EXPORT_NAME_SOURCE')
    user_export_groups_str = os.environ.get('USER_EXPORT_GROUPS')
    if user_export_groups_str:
        user_export_groups = (user_export_groups_str.upper() == "TRUE")
    else:
        user_export_groups = DEFAULT_USER_EXPORT_GROUPS
    user_export_storage_groups_object = os.environ.get(
        'USER_EXPORT_STORAGE_GROUPS_OBJECT', DEFAULT_USER_EXPORT_STORAGE_GROUPS_OBJECT)
    user_export_namespaces_str = os.environ.get('USER_EXPORT_NAMESPACES')
    if user_export_namespaces_str:
        user_export_namespaces = json.loads(user_export_namespaces_str)
    else:
        user_export_namespaces = DEFAULT_USER_EXPORT_NAMESPACES
    user_export_passwd_configmap_name = os.environ.get(
        'USER_EXPORT_PASSWD_CONFIGMAP', DEFAULT_USER_EXPORT_PASSWD_CONFIGMAP_NAME)
    user_export_groups_configmap_name = os.environ.get(
        'USER_EXPORT_GROUPS_CONFIGMAP', DEFAULT_USER_EXPORT_GROUPS_CONFIGMAP_NAME)

    local_role_assignments_str = os.environ['LOCAL_ROLE_ASSIGNMENTS']
    local_role_assignments = json.loads(local_role_assignments_str)

    kc_master_admin_secrets = read_keycloak_master_admin_secrets()
    user_export_storage_secrets = read_user_export_storage_secrets()

    kl = KeycloakLocalize(
        keycloak_base=keycloak_base,
        kc_master_admin_client_id=kc_master_admin_secrets['client_id'],
        kc_master_admin_username=kc_master_admin_secrets['user'],
        kc_master_admin_password=kc_master_admin_secrets['password'],
        ldap_connection_url=ldap_connection_url,
        ldap_provider_id=ldap_provider_id,
        ldap_federation_name=ldap_federation_name,
        ldap_priority=ldap_priority,
        ldap_edit_mode=ldap_edit_mode,
        ldap_sync_registrations=ldap_sync_registrations,
        ldap_vendor=ldap_vendor,
        ldap_username_ldap_attribute=ldap_username_ldap_attribute,
        ldap_rdn_ldap_attribute=ldap_rdn_ldap_attribute,
        ldap_uuid_ldap_attribute=ldap_uuid_ldap_attribute,
        ldap_user_object_classes=ldap_user_object_classes,
        ldap_auth_type=ldap_auth_type,
        ldap_bind_dn=ldap_bind_dn,
        ldap_bind_credentials=ldap_bind_credentials,
        ldap_search_base=ldap_search_base,
        ldap_search_scope=ldap_search_scope,
        ldap_use_truststore_spi=ldap_use_truststore_spi,
        ldap_connection_pooling=ldap_connection_pooling,
        ldap_pagination=ldap_pagination,
        ldap_allow_kerberos_authentication=ldap_allow_kerberos_authentication,
        ldap_batch_size_for_sync=ldap_batch_size_for_sync,
        ldap_full_sync_period=ldap_full_sync_period,
        ldap_changed_sync_period=ldap_changed_sync_period,
        ldap_debug=ldap_debug,
        ldap_user_attribute_mappers=ldap_user_attribute_mappers,
        ldap_user_attribute_mappers_to_remove=ldap_user_attribute_mappers_to_remove,
        ldap_group_name_ldap_attr=ldap_group_name_ldap_attr,
        ldap_group_object_class=ldap_group_object_class,
        ldap_preserve_group_inheritance=ldap_preserve_group_inheritance,
        ldap_group_membership_attribute=ldap_group_membership_attribute,
        ldap_group_membership_attr_type=ldap_group_membership_attr_type,
        ldap_group_membership_ldap_attr=ldap_group_membership_ldap_attr,
        ldap_group_filter=ldap_group_filter,
        ldap_user_roles_retrieve_strategy=ldap_user_roles_retrieve_strategy,
        ldap_mapped_group_attrs=ldap_mapped_group_attrs,
        ldap_groups_drop_during_sync=ldap_groups_drop_during_sync,
        ldap_role_mapper_dn=ldap_role_mapper_dn,
        ldap_role_mapper_name_ldap_attr=ldap_role_mapper_name_ldap_attr,
        ldap_role_mapper_object_class=ldap_role_mapper_object_class,
        ldap_role_mapper_membership_ldap_attr=ldap_role_mapper_membership_ldap_attr,
        ldap_role_mapper_membership_attr_type=ldap_role_mapper_membership_attr_type,
        ldap_role_mapper_membership_user_ldap_attr=ldap_role_mapper_membership_user_ldap_attr,
        ldap_role_mapper_roles_ldap_filter=ldap_role_mapper_roles_ldap_filter,
        ldap_role_mapper_mode=ldap_role_mapper_mode,
        ldap_role_mapper_retrieve_strategy=ldap_role_mapper_retrieve_strategy,
        ldap_role_mapper_memberof_attr=ldap_role_mapper_memberof_attr,
        ldap_role_mapper_use_realm_roles_mapping=ldap_role_mapper_use_realm_roles_mapping,
        ldap_role_mapper_client_id=ldap_role_mapper_client_id,
        ldap_do_full_sync=ldap_do_full_sync,
        local_users=local_users,
        local_groups=local_groups,
        user_export_storage_access_key=user_export_storage_secrets['access_key'],
        user_export_storage_secret_key=user_export_storage_secrets['secret_key'],
        user_export_storage_url=user_export_storage_url,
        user_export_storage_bucket=user_export_storage_bucket,
        user_export_storage_passwd_object=user_export_storage_passwd_object,
        user_export_name_source=user_export_name_source,
        user_export_groups=user_export_groups,
        user_export_storage_groups_object=user_export_storage_groups_object,
        user_export_namespaces=user_export_namespaces,
        user_export_passwd_configmap_name=user_export_passwd_configmap_name,
        user_export_groups_configmap_name=user_export_groups_configmap_name,
        local_role_assignments=local_role_assignments,
    )

    while True:
        try:
            kl.run()
            break
        except UnrecoverableError as e:
            LOGGER.error(
                'keycloak-localize failed with an unrecoverable error: %s', e)
            sys.exit(1)
        except oauthlib.oauth2.rfc6749.errors.OAuth2Error:
            LOGGER.warning(
                "keycloak-localize failed due to unexpected OAuth2Error. "
                "Will reset token and try again",
                exc_info=True)
            kl.reset_keycloak_master_admin_session()
            time.sleep(10)
        except Exception:
            LOGGER.warning(
                'keycloak-localize failed, will try again', exc_info=True)
            time.sleep(10)

    LOGGER.info('keycloak-localize complete')


if __name__ == '__main__':
    main()
