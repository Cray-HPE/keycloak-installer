#!/usr/bin/env python
#
# MIT License
#
# (C) Copyright 2020-2023 Hewlett Packard Enterprise Development LP
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
import base64
import json
import logging
import os
import re
import time

import kubernetes.client
import kubernetes.config
import oauthlib.oauth2.rfc6749.errors
import requests
import requests_oauthlib


DEFAULT_KEYCLOAK_BASE = 'http://keycloak.services:8080/keycloak'
DEFAULT_CLUSTER_KEYCLOAK_BASE = (
    'https://api-gateway.default.svc.cluster.local/keycloak')

DEFAULT_KEYCLOAK_MASTER_ADMIN_CLIENT_ID = 'admin-cli'
DEFAULT_KEYCLOAK_MASTER_ADMIN_USERNAME = 'admin'
DEFAULT_KEYCLOAK_MASTER_ADMIN_PASSWORD = 'adminpwd'

# Namespaces must be JSON serializable via json.loads()

DEFAULT_ADMIN_CLIENT_ID = 'admin-client'
DEFAULT_ADMIN_CLIENT_SECRET_NAME = 'admin-client-auth'
DEFAULT_ADMIN_CLIENT_SECRET_NAMESPACES = json.dumps(['default'])

DEFAULT_SYSTEM_COMPUTE_CLIENT_ID = 'system-compute-client'
DEFAULT_SYSTEM_COMPUTE_CLIENT_SECRET_NAME = 'system-compute-client-auth'
DEFAULT_SYSTEM_COMPUTE_CLIENT_SECRET_NAMESPACES = json.dumps(['default'])

DEFAULT_SYSTEM_PXE_CLIENT_ID = 'system-pxe-client'
DEFAULT_SYSTEM_PXE_CLIENT_SECRET_NAME = 'system-pxe-client-auth'
DEFAULT_SYSTEM_PXE_CLIENT_SECRET_NAMESPACES = json.dumps(['default'])

DEFAULT_SYSTEM_NEXUS_CLIENT_ID = 'system-nexus-client'
DEFAULT_SYSTEM_NEXUS_CLIENT_SECRET_NAME = 'system-nexus-client-auth'
DEFAULT_SYSTEM_NEXUS_CLIENT_SECRET_NAMESPACES = json.dumps(['default'])

DEFAULT_SYSTEM_SLINGSHOT_CLIENT_ID = 'system-slingshot-client'
DEFAULT_SYSTEM_SLINGSHOT_CLIENT_SECRET_NAME = 'system-slingshot-client-auth'
DEFAULT_SYSTEM_SLINGSHOT_CLIENT_SECRET_NAMESPACES = json.dumps(['services'])

DEFAULT_GATEKEEPER_CLIENT_ID = 'gatekeeper'
DEFAULT_GATEKEEPER_CLIENT_SECRET_NAME = 'keycloak-gatekeeper-client'
DEFAULT_GATEKEEPER_CLIENT_SECRET_NAMESPACES = json.dumps(['services'])
DEFAULT_GATEKEEPER_REDIRECT_URIS = []

DEFAULT_WLM_CLIENT_ID = 'wlm-client'
DEFAULT_WLM_CLIENT_SECRET_NAME = 'wlm-client-auth'
DEFAULT_WLM_CLIENT_SECRET_NAMESPACES = json.dumps(['default'])

DEFAULT_OIDC_CLIENT_ID = 'kubernetes-api-oidc-client'

LOGGER = logging.getLogger('keycloak_setup')


class KeycloakSetup(object):
    MASTER_REALM_NAME = 'master'
    SHASTA_REALM_NAME = 'shasta'

    PUBLIC_CLIENT_ID = 'shasta'
    DEPRECATED_PUBLIC_CLIENT_ID = 'cray'

    def __init__(
            self,
            keycloak_base=None,
            cluster_keycloak_base=None,
            kc_master_admin_client_id=None,
            kc_master_admin_username=None,
            kc_master_admin_password=None,
            customer_access_url=None,
            clients_to_cleanup=None,
            secrets_to_cleanup=None,
    ):
        self.keycloak_base = keycloak_base or DEFAULT_KEYCLOAK_BASE
        self.cluster_keycloak_base = cluster_keycloak_base or DEFAULT_CLUSTER_KEYCLOAK_BASE
        self.kc_master_admin_client_id = kc_master_admin_client_id or DEFAULT_KEYCLOAK_MASTER_ADMIN_CLIENT_ID
        self.kc_master_admin_username = kc_master_admin_username or DEFAULT_KEYCLOAK_MASTER_ADMIN_USERNAME
        self.kc_master_admin_password = kc_master_admin_password or DEFAULT_KEYCLOAK_MASTER_ADMIN_PASSWORD
        self._kc_master_admin_client_cache = None
        self.customer_access_url = customer_access_url or DEFAULT_CLUSTER_KEYCLOAK_BASE
        self.clients_to_cleanup = clients_to_cleanup or []
        self.secrets_to_cleanup = secrets_to_cleanup or []
        self._k8s_corev1_cache = None

    def run(self):
        self._setup_keycloak()

    def run_post_clients(self):
        self._cleanup_clients()
        self._cleanup_secrets()
        self._check_features()

    def reset_keycloak_master_admin_session(self):
        LOGGER.info("Resetting Keycloak master admin session.")
        self._kc_master_admin_client_cache = None

    @property
    def kc_master_admin_client(self):
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
        LOGGER.info("Fetching initial Keycloak master admin token...")
        client.fetch_token(
            token_url=kc_master_token_endpoint,
            client_id=self.kc_master_admin_client_id,
            username=self.kc_master_admin_username,
            password=self.kc_master_admin_password)
        LOGGER.info("Got initial Keycloak master admin token.")

        self._kc_master_admin_client_cache = client
        return self._kc_master_admin_client_cache

    @property
    def _k8s_corev1(self):
        if self._k8s_corev1_cache:
            return self._k8s_corev1_cache
        self._k8s_corev1_cache = kubernetes.client.CoreV1Api()
        return self._k8s_corev1_cache

    def _setup_keycloak(self):
        try:
            self._wait_keycloak_ready()
        except Exception:
            self.reset_keycloak_master_admin_session()
            raise
        try:
            self.create_realm(self.SHASTA_REALM_NAME)
        except Exception:
            # This was the first time the token was used to perform operations
            # so if this fails then getting a fresh token next time might help.
            self.reset_keycloak_master_admin_session()
            raise

    def _wait_keycloak_ready(self):
        while True:
            # Calling multiple times since there's replicas, should LB over a few.
            uptime_ms = min([self._get_uptime_ms() for i in range(6)])
            # Keycloak is generally ready after a couple of minutes, add a 30 sec
            # buffer, so 150 sec.
            if uptime_ms >= 150000:
                self.reset_keycloak_master_admin_session()
                return
            sleep_ms = 150000 - uptime_ms
            if sleep_ms < 5000:
                sleep_ms = 5000
            sleep_time = sleep_ms / 1000.0
            LOGGER.info("Delaying for %s sec", sleep_time)
            time.sleep(sleep_time)
            self.reset_keycloak_master_admin_session()

    def _get_uptime_ms(self):
        LOGGER.info('Fetching keycloak uptime...')
        url = '{}/admin/serverinfo'.format(self.keycloak_base)
        response = self.kc_master_admin_client.get(url)
        response.raise_for_status()
        uptime_ms = response.json()['systemInfo']['uptimeMillis']
        LOGGER.info('keycloak uptime is %s', uptime_ms)
        return uptime_ms

    def create_realm(self, realm):
        LOGGER.info('Create realm: %s', realm)
        url = '{}/admin/realms'.format(self.keycloak_base)
        # TODO: lifespan values below to ease the AuthN transition for token users, remove SOON!
        request_data = {
            'realm': realm,
            'enabled': True,
            'ssoSessionIdleTimeout': 31536000,
            # UAI and PALs have a use case where the token is used in a batch
            # script that winds up running whenever the job gets scheduled,
            # which may be days after it's submitted.
            'ssoSessionMaxLifespan': 31536000,
            'accessTokenLifespan': 31536000,
            'accessTokenLifespanForImplicitFlow': 31536000,
            'roles': {
                'realm': [
                    {
                        'name': 'tenant-admin',
                    },
                ]
            }
        }
        response = self.kc_master_admin_client.post(url, json=request_data)
        if response.status_code not in [200, 201, 409]:
            response.raise_for_status()

    def create_client_scopes(self):
        LOGGER.info('Create openid client scope in: %s', self.SHASTA_REALM_NAME)
        url = f'{self.keycloak_base}/admin/realms/{self.SHASTA_REALM_NAME}/client-scopes'
        request_data = {
            "name": "openid",
            "description": "OpenID Connect scope for add OpenID scope to all access tokens",
            "attributes": {
                "consent.screen.text": "",
                "display.on.consent.screen": "true",
                "include.in.token.scope": "true",
                "gui.order": ""
            },
            "protocol": "openid-connect"
        }
        response = self.kc_master_admin_client.post(url, json=request_data)
        if response.status_code not in [200, 201, 409]:
            response.raise_for_status()

        LOGGER.info('Set the openid client scope to default')
        scope_id = self.calc_client_scope_id('openid')
        default_client_scope_url = f'{self.keycloak_base}/admin/realms/{self.SHASTA_REALM_NAME}/default-default-client-scopes/{scope_id}'
        default_scopes = self.kc_master_admin_client.put(default_client_scope_url)
        if default_scopes.status_code not in [200, 201, 409]:
            default_scopes.raise_for_status()

    def calc_client_scope_id(self, client_scope):
        LOGGER.info("Fetching %r client scope id from keycloak...", client_scope)
        url = f'{self.keycloak_base}/admin/realms/{self.SHASTA_REALM_NAME}/client-scopes'
        scopes = self.kc_master_admin_client.get(url)
        if scopes.status_code not in [200, 201]:
            scopes.raise_for_status()
        client_scopes = scopes.json()
        for scope in client_scopes:
            if scope['name'] == client_scope:
                scope_id = scope['id']
        return scope_id

    def calc_client_url(self, client_id):
        LOGGER.info("Fetching %r client URL from keycloak...", client_id)

        query_url = f'{self.keycloak_base}/admin/realms/{self.SHASTA_REALM_NAME}/clients'
        query_params = {'clientId': client_id}
        response = self.kc_master_admin_client.get(
            query_url, params=query_params)
        response.raise_for_status()

        response_data = response.json()
        if not response_data:
            LOGGER.info("Client %r not found.", client_id)
            return None

        kc_client = response_data[0]

        url = f'{self.keycloak_base}/admin/realms/{self.SHASTA_REALM_NAME}/clients/{kc_client["id"]}'
        LOGGER.info('Client %r has URL %r.', client_id, url)
        return url

    def _cleanup_clients(self):
        for client_id in self.clients_to_cleanup:
            self._cleanup_client(client_id)

    def _cleanup_client(self, client_id):
        LOGGER.info("Cleaning up client %r...", client_id)
        client_url = self.calc_client_url(client_id)
        if not client_url:
            LOGGER.info("Client %r already doesn't exist.", client_id)
            return

        response = self.kc_master_admin_client.delete(client_url)
        if response.status_code != 204:
            LOGGER.warning(
                "Failed to delete client %r using %r. Ignoring this error."
                " Response=%s", client_id, client_url, response)
            return
        LOGGER.info("Client %r deleted.", client_id)

    def _cleanup_secrets(self):
        for secret_spec in self.secrets_to_cleanup:
            self._cleanup_secret(
                secret_spec['name'], secret_spec['namespaces'])

    def _cleanup_secret(self, secret_name, namespaces):
        for ns in namespaces:
            self._delete_secret(secret_name, ns)

    def _delete_secret(self, secret_name, namespace):
        LOGGER.info('Deleting %r Secret in namespace %r...',
                    secret_name, namespace)
        try:
            self._k8s_corev1.delete_namespaced_secret(secret_name, namespace)
            LOGGER.info("Deleted the %r secret from namespace %r.",
                        secret_name, namespace)
        except kubernetes.client.rest.ApiException as e:
            if e.status != 404:
                LOGGER.error(
                    'delete_namespaced_secret in namespace %s returned an '
                    'unexpected result %s',
                    namespace, e)
                raise
            LOGGER.info(
                "The %r secret in namespace %r already doesn't exit.", secret_name, namespace)

    def _check_features(self):
        LOGGER.info("Checking for tenant-admin realm role...")

        url = f'{self.keycloak_base}/admin/realms/{self.SHASTA_REALM_NAME}/roles'
        realm_role = {"name": "tenant-admin"}

        realm_role_response = self.kc_master_admin_client.post(url, json=realm_role)

        if realm_role_response.status_code != 409:
            LOGGER.info("tenant-admin realm role created.")
        LOGGER.info("tenant-admin realm role exists.")

        LOGGER.info("Checking for group mapper in %r client...", self.PUBLIC_CLIENT_ID)

        client_url = f'{self.calc_client_url(self.PUBLIC_CLIENT_ID)}/protocol-mappers/models'
        protocol_mapper = {
            'name': 'keycloak-group-mapper',
            'protocol': 'openid-connect',
            'protocolMapper': 'oidc-group-membership-mapper',
            'config': {
                'full.path': False,
                'id.token.claim': True,
                'access.token.claim': True,
                'claim.name': 'groups',
                'userinfo.token.claim': True,
            },
        }

        client_pm_response = self.kc_master_admin_client.post(client_url, json=protocol_mapper)

        if client_pm_response.status_code != 409:
            LOGGER.info("%r group mapper created.", self.PUBLIC_CLIENT_ID)
        LOGGER.info("%r group mapper exists.", self.PUBLIC_CLIENT_ID)

        LOGGER.info("Checking public clients have the proper client scopes")

        pub_client_url = f'{self.calc_client_url(self.PUBLIC_CLIENT_ID)}/default-client-scopes/{self.calc_client_scope_id("openid")}'
        deprecated_pub_client_url = f'{self.calc_client_url(self.DEPRECATED_PUBLIC_CLIENT_ID)}/default-client-scopes/{self.calc_client_scope_id("openid")}'
        pub_client_scope = self.kc_master_admin_client.put(pub_client_url)
        if pub_client_scope.status_code not in [200, 201, 409]:
            pub_client_scope.raise_for_status()
        deprecated_pub_client = self.kc_master_admin_client.put(deprecated_pub_client_url)
        if deprecated_pub_client.status_code not in [200, 201, 409]:
            deprecated_pub_client.raise_for_status()


class KeycloakClient(object):

    """Class to assist in Keycloak Client Creation.

    *Preparing to Create Client*

    After init, set keycloak client request attributes
    using the following properties (bool):

    - standard_flow_enabled (default False)
    - implicit_flow_enabled (default False)
    - direct_access_grants_enabled (default False)
    - service_accounts_enabled (default False)
    - public_client (default False)
    - create_roles_for_public_client (default True)
    - create_monitor_read_only_role (default False)
    - authorization_services_enabled (default False)

    Noting there is no request validation (e.g., combination of
    flows enabled, etc).

    You can use the set_req_attr() method to add
    additional attributes (e.g., ProtocolMappers).

    All request attributes are only honored by the create() method, and
    .create() is not intended/designed to be re-entrant. Also note the absence
    of any other CRUD-like operations against clients.

    *Creating a Client*

    Once the object is configured as desired, run .create(). Note that .create()
    attempts to handle the scenario where the client already exists.

    *Creating K8S Client Secret*

    A K8S secret will be created/updated if the k8s_secret_name is set.
    The secret data attributes that get created by default are client-id
    and client-secret. Use the set_k8s_secret_attr() method to add additional
    attributes to the secret. The secret will be created in each namespace
    specified by k8s_secret_namespaces. To create the secret(s) in K8S,
    call the .create_k8s_secrets() method after a successful .create().

    *Exception Handling*

    Natively raises the exceptions listed below. Allows pass-through
    exceptions to propagate unhandled via interaction with KeycloakSetup
    object.

    :param KeycloakSetup kas: KeycloakSetup object
    :param str realm: keycloak realm
    :param str client_id: Oauth client ID (not the keycloak client 'UUID')
    :param str k8s_secret_name: name of k8s secret to create
    :param collections.iterable k8s_secret_namespace: namespaces where secret should be created
    :raises ValueError: on bad parameter use
    :raises TypeError: on bad parameter type"""

    def __init__(self,
                 kas,
                 realm,
                 client_id,
                 k8s_secret_name=None,
                 k8s_secret_namespaces=None):

        # Type checking, use issubclass vs. isinstance to
        # support the use of mock for testing

        if not issubclass(type(kas), KeycloakSetup):
            raise TypeError("invalid kas (keycloak setup)")

        if not issubclass(type(realm), (str,)):
            raise TypeError("invalid realm")

        if not issubclass(type(client_id), (str,)):
            raise TypeError("invalid client_id")

        if k8s_secret_name is not None:
            if not issubclass(type(k8s_secret_name), (str,)):
                raise TypeError("invalid k8s_secret_name")

        if k8s_secret_namespaces is not None:
            if not issubclass(type(k8s_secret_namespaces), list):
                raise TypeError("invalid k8s_secret_namespaces")

            for ns in k8s_secret_namespaces:
                if not issubclass(type(ns), (str,)):
                    raise TypeError(
                        "invalid k8s_secret_namespace at index {}".format(
                            k8s_secret_namespaces.index(ns))
                    )

        # Value checking

        if k8s_secret_name is not None:
            if k8s_secret_namespaces is None:
                raise ValueError(
                    "must set k8s_secret namespaces if k8s_secret_name is set")

        if k8s_secret_namespaces is not None:
            if k8s_secret_name is None:
                raise ValueError(
                    "must set k8s_secret name if k8s_secret_namespace is set")

        # Force str() in the event mock is in use

        # https://tools.ietf.org/html/rfc6749#page-71
        if re.match('([ -~]+)$', str(client_id)) is None:
            raise ValueError("invalid client_id")

        # use same char set for realm
        if re.match('([ -~]+)$', str(realm)) is None:
            raise ValueError("invalid realm")

        valid_dns_ptn = '(^(?![0-9]+\.)(?!-)[A-Za-z0-9\-]{1,63}(?<![\-])\.)*((?![0-9]\.+)(?!-)[A-Za-z0-9\-]{1,63}(?<![\-])\.)*((?![0-9]+$)(?!-)[A-Za-z0-9\-]{1,63}(?<![\-])){1}$'  # noqa: W605

        if k8s_secret_name is not None:

            if re.match(valid_dns_ptn, k8s_secret_name) is None:
                raise ValueError("invalid k8s_secret_name")

            for ns in k8s_secret_namespaces:
                if re.match(valid_dns_ptn, ns) is None:
                    raise ValueError("invalid k8s_secret_namespace at index {}".format(
                        k8s_secret_namespaces.index(ns))
                    )

        # Populate object state

        self._kas = kas
        self._k8s_secret_name = k8s_secret_name
        self._k8s_secret_namespaces = k8s_secret_namespaces
        self._id = client_id
        self._realm = realm

        # Keycloak client attributes
        # available via properties (getter/setter)
        self._standard_flow_enabled = False
        self._implicit_flow_enabled = False
        self._direct_access_grants_enabled = False
        self._service_accounts_enabled = False
        self._public_client = False
        self._create_roles_for_public_client = True
        self._create_monitor_read_only_role = False
        self._authorization_services_enabled = False

        # Enables 'extended' keycloak client req attributes
        self._kc_ext_attr = dict()

        # K8S secret 'extended' attributes for secret create/update
        self._k8s_secret_ext_attr = dict()

        # Client URL (e.g., /{realm}/clients/{id}),
        # set during .create()
        self._url = None

        # Allow the creation of client roles
        self._client_roles = []

        # Allow setting service account client roles
        self._service_account_client_roles = dict()

    @property
    def kas(self):
        return self._kas

    @property
    def realm(self):
        return self._realm

    @property
    # given scope, not concerned about overriding
    # build-in id() function. Note that this is the
    # OAuth client-id, not the UUID that keycloak assigns.
    def id(self):
        return self._id

    @property
    def k8s_secret_name(self):
        return self._k8s_secret_name

    @property
    def k8s_secret_namespaces(self):
        return self._k8s_secret_namespaces

    # Core KeyCloak client create attributes

    # standardFlowEnabled

    @property
    def standard_flow_enabled(self):
        return self._standard_flow_enabled

    @standard_flow_enabled.setter
    def standard_flow_enabled(self, v):
        if not isinstance(v, bool):
            raise TypeError
        self._standard_flow_enabled = v

    # implicitFlowEnabled

    @property
    def implicit_flow_enabled(self):
        return self._implicit_flow_enabled

    @implicit_flow_enabled.setter
    def implicit_flow_enabled(self, v):
        if not isinstance(v, bool):
            raise TypeError
        self._implicit_flow_enabled = v

    # directAccessGrantsEnabled

    @property
    def direct_access_grants_enabled(self):
        return self._direct_access_grants_enabled

    @direct_access_grants_enabled.setter
    def direct_access_grants_enabled(self, v):
        if not isinstance(v, bool):
            raise TypeError
        self._direct_access_grants_enabled = v

    # serviceAccountsEnabled

    @property
    def service_accounts_enabled(self):
        return self._service_accounts_enabled

    @service_accounts_enabled.setter
    def service_accounts_enabled(self, v):
        if not isinstance(v, bool):
            raise TypeError
        self._service_accounts_enabled = v

    # authorizationServicesEnabled

    @property
    def authorization_services_enabled(self):
        return self._authorization_services_enabled

    @authorization_services_enabled.setter
    def authorization_services_enabled(self, v):
        if not isinstance(v, bool):
            raise TypeError
        self._authorization_services_enabled = v

    # createRolesForPublicClient

    @property
    def create_roles_for_public_client(self):
        return self._create_roles_for_public_client

    @create_roles_for_public_client.setter
    def create_roles_for_public_client(self, v):
        if not isinstance(v, bool):
            raise TypeError
        self._create_roles_for_public_client = v

    # createMonitorReadOnlyRole

    @property
    def create_monitor_read_only_role(self):
        return self._create_monitor_read_only_role

    @create_monitor_read_only_role.setter
    def create_monitor_read_only_role(self, v):
        if not isinstance(v, bool):
            raise TypeError
        self._create_monitor_read_only_role = v

    # publicClient

    @property
    def public_client(self):
        return self._public_client

    @public_client.setter
    def public_client(self, v):
        if not isinstance(v, bool):
            raise TypeError
        self._public_client = v

    # client_roles (none by default)

    @property
    def client_roles(self):
        return self._client_roles

    @client_roles.setter
    def client_roles(self, v):
        """Expects ["client-role",...]
        Adds the above new client role(s) to the new client.
        """
        if not isinstance(v, list):
            raise TypeError

        for role in v:
            if not issubclass(type(role), (str)):
                raise TypeError(
                    f'Expecting a string for the client role {role!r}.')

        self._client_roles = v

    # Allow setting of extended attributes
    # for client create request and k8s secret
    # create

    def set_req_attr(self, attr, value):
        """Set an extended create attribute,
        attr must be a valid dictionary key"""

        self._kc_ext_attr[attr] = value

    def set_k8s_secret_attr(self, attr, value):
        """Set an extended attribute on K8S secret,
        attr must be a valid dictionary key"""

        self._k8s_secret_ext_attr[attr] = value

    def create(self):
        """Attempt to create the client via keycloak. Retrieve the keycloak
        id if client created or client already exists.

        :raises ValueError: if attempt to override reserved client request attributes."""

        LOGGER.info('Create Keycloak client %s', self.id)

        config = {
            'clientId': self.id,
            'standardFlowEnabled': self.standard_flow_enabled,
            'implicitFlowEnabled': self.implicit_flow_enabled,
            'directAccessGrantsEnabled': self.direct_access_grants_enabled,
            'serviceAccountsEnabled': self.service_accounts_enabled,
            'publicClient': self.public_client,
            'authorizationServicesEnabled': self.authorization_services_enabled,
        }

        # Verify the extended attributes don't contain
        # the reserved fields, above. Add them to config
        # otherwise.
        if set(config.keys()).intersection(set(self._kc_ext_attr.keys())):
            raise ValueError(
                "cannot override reserved kc client create request attrs")
        config.update(self._kc_ext_attr)

        # Attempt to create the client
        create_url = '{}/admin/realms/{}/clients'.format(
            self.kas.keycloak_base, self.realm)
        response = self.kas.kc_master_admin_client.post(
            create_url, json=config)

        if response.status_code == 201:
            LOGGER.info('Created client %s', self.id)
        elif response.status_code == 409:
            LOGGER.info('Keycloak client %s already exists', self.id)
        else:
            response.raise_for_status()

        self._url = self.kas.calc_client_url(self.id)
        if not self._url:
            raise Exception(f"Failed to fetch URL for client {self.id}!")

        # Create any required service account roles
        self.add_service_account_roles()

        # Create any requested client roles
        for client_role in self.client_roles:
            self.create_role(client_role)

    def create_k8s_secrets(self):
        """Create K8S Secrets for the client, if secret name is set. Must
        be called after .create() for client URL to be set."""

        if self._k8s_secret_name is None:
            LOGGER.info(
                "k8s secret name not set for client {}, not creating..".format(self.id))
        else:

            secret_data = {
                'client-id': None,
                'client-secret': None
            }

            # verify extended secret attributes don't contain
            # the reserved fields, above. Add them to secret
            # def otherwise.

            if set(secret_data.keys()).intersection(set(self._k8s_secret_ext_attr.keys())):
                raise ValueError("cannot override reserved k8s secret attrs")
            secret_data.update(self._k8s_secret_ext_attr)

            secret_data['client-id'] = self.id

            if self._url is None:
                raise ValueError(
                    "attempting to set role but client URL is not set.")

            LOGGER.info('Fetching %s secret...', self.id)
            response = self.kas.kc_master_admin_client.get(
                '{}/client-secret'.format(self._url))
            response.raise_for_status()

            if response.json().get('value') is None:
                LOGGER.info('Client secret is not set yet, setting...')
                response = self.kas.kc_master_admin_client.post(
                    '{}/client-secret'.format(self._url))
                response.raise_for_status()

            secret_data['client-secret'] = response.json()['value']

            for namespace in self._k8s_secret_namespaces:
                k8s_apply_secret(namespace, self._k8s_secret_name, secret_data)

    def create_role(self, role):
        """Create role for the client. Must be called after .create()
        for client URL to be set."""

        if not issubclass(type(role), (str,)):
            raise TypeError("invalid role")

        if re.match('([ -~]+)$', str(role)) is None:
            raise ValueError("invalid role")

        if self._url is None:
            raise ValueError(
                "attempting to set role but client URL is not set.")

        LOGGER.info('Creating %s role in %s client...', role, self._url)

        request_data = {
            'name': role,
        }

        response = self.kas.kc_master_admin_client.post(
            '{}/roles'.format(self._url), json=request_data)

        if response.status_code == 201:
            LOGGER.info('%s role created in %s', role, self._url)
        elif response.status_code == 409:
            LOGGER.info('%s role already exists in %s', role, self._url)
        else:
            response.raise_for_status()

    def add_service_account_roles(self):
        """Add any requested service account roles to the client.
        The operation is idempotent.
        """
        LOGGER.info('Requested service account roles for client %s: %s',
                    self._id, self._service_account_client_roles)

        role_dict = self._service_account_client_roles
        if not role_dict:
            LOGGER.info('No additional service account roles will be added.')
            return

        # Get the ID of this new client's user entry.
        client_user_name = f'service-account-{self._id}'
        client_user_id = ''
        url = f'{self.kas.keycloak_base}/admin/realms/{self.realm}/users?username={client_user_name}'
        response = self.kas.kc_master_admin_client.get(url)
        LOGGER.info("User ID query %s reply was: %s", url, response)
        LOGGER.debug("The full response was: %s", response.text)

        # Raise for HTTP errors (400-600) here.  Note that the response code will be 200 if zero or more
        # users were found for the requested username.
        response.raise_for_status()

        # Loop the returned list of users checking for an exact match.
        # This handles cases where multiple users might be returned because the match is not
        # exact and can't be set to exact.  The list will be empty if no user is found.
        for user in response.json():
            username = user['username']
            LOGGER.debug("Found user %s", username)

            if username == client_user_name:
                client_user_id = user['id']
                LOGGER.info(
                    "Found the requetsed user %s with the ID: %s", username, user["id"])
                break

        # If we don't find the client user we can not go further in this process.  Log it and
        # return.
        if not client_user_id:
            LOGGER.error("Unable to complete adding service account roles since we did not find "
                         "the expected user name %s for the cleint user.", client_user_name)
            return

        # Iterate the list of clients that have roles we need to add.
        for client in role_dict:

            # Get the client's ID from the client name (specified by clientId)
            url = f'{self.kas.keycloak_base}/admin/realms/{self.realm}/clients?clientId={client}'
            response = self.kas.kc_master_admin_client.get(url)
            LOGGER.info("Role client ID query %s reply was: %s", url, response)
            LOGGER.debug("The full response was: %s", response.text)

            # Raise for HTTP errors (400-600) here.
            response.raise_for_status()

            # If the client was not found the list will be empty.  In this case just continue on
            # to the next requested client (if any).
            if not response.json():
                LOGGER.error("Did not find the client: %s  Unable to add any requested client role for "
                             "this client.", client)
                continue

            client_id = response.json()[0]['id']
            LOGGER.info("The client %s has a client_id=%s", client, client_id)

            # Get the list of requested client roles
            requested_roles = role_dict[client]

            # Get the ID for each client role and assign to the service-account-${client} user by
            # ID (client_user_id determined above)
            client_role_list = []
            LOGGER.info("The roles %s on the client %s were requested",
                        requested_roles, client)
            for client_role in requested_roles:
                LOGGER.info("Getting the role ID for %s", client_role)
                url = f'{self.kas.keycloak_base}/admin/realms/{self.realm}/clients/{client_id}/roles/{client_role}'
                response = self.kas.kc_master_admin_client.get(url)
                LOGGER.info("Role ID query %s reply was: %s", url, response)
                LOGGER.debug("The full response was: %s", response.text)

                # Raise for HTTP errors (400-600) here.
                # If the client_id or client_role is not found the repsonse will be 404.
                if response.status_code == 404:
                    LOGGER.error(
                        'Was not able to find the client role %s', client_role)
                response.raise_for_status()

                client_role_id = response.json()['id']
                LOGGER.info("The client role %s has a client_role_id=%s",
                            client_role, client_role_id)
                client_role_entry = {
                    'id': client_role_id,
                    'name': client_role,
                    'clientRole': True
                }
                LOGGER.info("Preparing to add the client role %s",
                            client_role_entry)
                client_role_list.append(client_role_entry)

            # Post the client role list to the users endpoint
            # client_user_id == the user entry ID for this client's service account user
            # client_id == the client ID of the client owning any role(s) to be added to the service account user
            url = f'{self.kas.keycloak_base}/admin/realms/{self.realm}/users/{client_user_id}/role-mappings/clients/{client_id}'
            response = self.kas.kc_master_admin_client.post(
                url, json=client_role_list)
            LOGGER.info("Role mapping post %s reply was: %s", url, response)

            # Riase for HTTP errors (400-600) here.
            response.raise_for_status()

            # This should be a 204 for an insert or update and is idempotent so
            # responses other than this are considered an error and should be reviewed.
            if response.status_code == 204:
                LOGGER.info('Created client role mapping.')
            else:
                LOGGER.error('Unexpected response code of %s while trying to add one or more '
                             'service account roles to the client user ID \'%s\'. '
                             'The client is \'%s\'. The client role list is: %s',
                             response.status_code, client_user_id, client_id, client_role_list)


def create_keycloak_client_from_spec(client_id, spec, kas, customer_access_url):
    secret_name = None
    secret_namespaces = None

    if 'secret' in spec:
        secret_name = spec['secret']['name']
        secret_namespaces = spec['secret']['namespaces']

    keycloak_client = (
        KeycloakClient(
            kas,
            kas.SHASTA_REALM_NAME,
            client_id,
            secret_name,
            secret_namespaces
        ))

    if secret_name:
        keycloak_client.set_k8s_secret_attr(
            'discovery-url',
            f'{customer_access_url}/realms/{kas.SHASTA_REALM_NAME}'
        )

    keycloak_client.standard_flow_enabled = (
        spec.get('standardFlowEnabled', False))
    keycloak_client.implicit_flow_enabled = (
        spec.get('implicitFlowEnabled', False))
    keycloak_client.direct_access_grants_enabled = (
        spec.get('directAccessGrantsEnabled', False))
    keycloak_client.service_accounts_enabled = (
        spec.get('serviceAccountsEnabled', False))
    keycloak_client.authorization_services_enabled = (
        spec.get('authorizationServicesEnabled', False))
    keycloak_client.create_roles_for_public_client = (
        spec.get('createRolesForPublicClient', True))
    keycloak_client.create_monitor_read_only_role = (
        spec.get('createMonitorReadOnlyRole', False))

    type = spec.get('type', 'confidential')
    if type == 'public':
        keycloak_client.public_client = True

    proxied_hosts = spec.get('proxiedHosts')
    if proxied_hosts:
        redirect_uris = [
            f'https://{hostname}/oauth/callback'
            for hostname in proxied_hosts
        ]
        keycloak_client.set_req_attr('redirectUris', redirect_uris)

    return keycloak_client


def k8s_apply_secret(namespace, secret_name, secret_data, v1=None):
    if v1 is None:
        v1 = kubernetes.client.CoreV1Api()

    secret_data_encoded = {k: base64.b64encode(
        bytes(v, 'utf-8')).decode("ascii") for k, v in list(secret_data.items())}

    # Check if existing secret is up-to-date
    existing_secret = k8s_get_secret(namespace, secret_name, v1=v1)
    if existing_secret:
        if existing_secret.data == secret_data_encoded:
            LOGGER.info(
                'Secret %s already exists in namespace %s with expected '
                'values.', secret_name, namespace)
            return existing_secret
        # Update existing secret
        LOGGER.info(
            'Patching existing secret %s in namespace %s...',
            secret_name, namespace)
        secret = kubernetes.client.V1Secret(data=secret_data_encoded)
        v1.patch_namespaced_secret(secret_name, namespace, secret)
        return secret

    # Create new secret
    LOGGER.info(
        'Creating secret %s in namespace %s...', secret_name,
        namespace)
    secret = kubernetes.client.V1Secret(
        api_version='v1',
        kind='Secret',
        metadata=kubernetes.client.V1ObjectMeta(
            name=secret_name,
            namespace=namespace,
        ),
        type='Opaque',
        data=secret_data_encoded,
    )
    try:
        v1.create_namespaced_secret(namespace, secret)
    except kubernetes.client.rest.ApiException as e:
        if e.status != 409:
            LOGGER.error(
                'create_namespaced_secret in namespace %s returned an '
                'unexpected result %s',
                namespace, e)
            raise
        # The secret already exists. This is probably because
        # a replica was running at the same time.
        LOGGER.info(
            'Got conflict creating secret %s in namespace %s.',
            secret_name, namespace)
    return secret


def k8s_get_secret(namespace, secret_name, v1=None):
    if v1 is None:
        v1 = kubernetes.client.CoreV1Api()
    LOGGER.info('Fetching current %s Secret in namespace %s...',
                secret_name, namespace)
    try:
        return v1.read_namespaced_secret(secret_name, namespace)
    except kubernetes.client.rest.ApiException as e:
        if e.status != 404:
            LOGGER.error(
                'read_namespaced_secret in namespace %s returned an '
                'unexpected result %s',
                namespace, e)
            raise
    LOGGER.info(
        "The %s secret in namespace %s wasn't found (probably because this "
        "is a clean install), will create one.", secret_name,
        namespace)
    return None


def read_keycloak_master_admin_secrets(
        secret_dir='/mnt/keycloak-master-admin-auth-vol'):
    try:
        # FIXME: document these requirements in README
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


def get_wlm_client(kas, cluster_keycloak_base):
    wlm_client = \
        KeycloakClient(
            kas,
            kas.SHASTA_REALM_NAME,
            os.environ.get('KEYCLOAK_WLM_CLIENT_ID',
                           DEFAULT_WLM_CLIENT_ID),
            os.environ.get('KEYCLOAK_WLM_CLIENT_SECRET_NAME',
                           DEFAULT_WLM_CLIENT_SECRET_NAME),
            [n for n in json.loads(
                os.environ.get('KEYCLOAK_WLM_CLIENT_SECRET_NAMESPACES',
                               DEFAULT_WLM_CLIENT_SECRET_NAMESPACES))]
        )

    # Set core client attributes
    wlm_client.service_accounts_enabled = True

    # add protocol mappers
    wlm_pm = [
        {
            'name': 'wlm-role',
            'protocol': 'openid-connect',
            'protocolMapper': 'oidc-hardcoded-role-mapper',
            'consentRequired': False,
            'config': {
                'role': 'shasta.wlm',
            },
        }
    ]

    wlm_client.set_req_attr('protocolMappers', wlm_pm)

    # add endpoint to secret
    wlm_client.set_k8s_secret_attr(
        'endpoint',
        '{}/realms/{}/protocol/openid-connect/token'.format(cluster_keycloak_base,
                                                            kas.SHASTA_REALM_NAME)
    )

    return wlm_client


def init_logging():
    # Format logs for stdout
    log_format = "%(asctime)-15s - %(levelname)-7s - %(name)s - %(message)s"
    requested_log_level = os.environ.get('KEYCLOAK_SETUP_LOG_LEVEL', 'INFO')
    log_level = logging.getLevelName(requested_log_level)

    if type(log_level) != int:
        print(
            f'WARNING: Log level {requested_log_level} is not valid. Falling back to INFO')
        log_level = logging.INFO
    logging.basicConfig(level=log_level, format=log_format)


def main():

    # Configure logging
    init_logging()

    # Load K8s configuration
    kubernetes.config.load_incluster_config()

    # ---------------------------------------------------------------
    # Keycloak Setup Definition
    # ---------------------------------------------------------------

    # Configure keycloak setup
    keycloak_base = os.environ.get('KEYCLOAK_BASE')
    cluster_keycloak_base = os.environ.get('CLUSTER_KEYCLOAK_BASE')

    # URL for customer access (e.g., from browser)
    customer_access_url = os.environ.get('KEYCLOAK_CUSTOMER_ACCESS_URL')

    kc_master_admin_secrets = read_keycloak_master_admin_secrets()

    gatekeeper_client_id = os.environ.get(
        'KEYCLOAK_GATEKEEPER_CLIENT_ID', DEFAULT_GATEKEEPER_CLIENT_ID)
    clients_to_cleanup = [
        gatekeeper_client_id,
    ]

    gatekeeper_client_secret_name = os.environ.get(
        'KEYCLOAK_GATEKEEPER_CLIENT_SECRET_NAME',
        DEFAULT_GATEKEEPER_CLIENT_SECRET_NAME)
    gatekeeper_client_secret_namespaces_str = os.environ.get(
        'KEYCLOAK_GATEKEEPER_CLIENT_SECRET_NAMESPACES',
        DEFAULT_GATEKEEPER_CLIENT_SECRET_NAMESPACES)
    gatekeeper_client_secret_namespaces = json.loads(
        gatekeeper_client_secret_namespaces_str)
    secrets_to_cleanup = [
        {
            'name': gatekeeper_client_secret_name,
            'namespaces': gatekeeper_client_secret_namespaces,
        },
    ]

    kas = KeycloakSetup(
        keycloak_base=keycloak_base,
        cluster_keycloak_base=cluster_keycloak_base,
        kc_master_admin_client_id=kc_master_admin_secrets['client_id'],
        kc_master_admin_username=kc_master_admin_secrets['user'],
        kc_master_admin_password=kc_master_admin_secrets['password'],
        customer_access_url=customer_access_url,
        clients_to_cleanup=clients_to_cleanup,
        secrets_to_cleanup=secrets_to_cleanup)

    # ---------------------------------------------------------------
    # Keycloak Client Definitions
    # ---------------------------------------------------------------

    clients = list()

    # ---- Admin Client ----

    admin_client = \
        KeycloakClient(
            kas,
            kas.SHASTA_REALM_NAME,
            os.environ.get('KEYCLOAK_ADMIN_CLIENT_ID',
                           DEFAULT_ADMIN_CLIENT_ID),
            os.environ.get('KEYCLOAK_ADMIN_CLIENT_SECRET_NAME',
                           DEFAULT_ADMIN_CLIENT_SECRET_NAME),
            [n for n in json.loads(
                os.environ.get('KEYCLOAK_ADMIN_CLIENT_SECRET_NAMESPACES',
                               DEFAULT_ADMIN_CLIENT_SECRET_NAMESPACES))]
        )

    clients.append(admin_client)

    # Set core client attributes
    admin_client.direct_access_grants_enabled = True
    admin_client.service_accounts_enabled = True

    # add protocol mappers
    admin_pm = [
        {
            'name': 'admin-role',
            'protocol': 'openid-connect',
            'protocolMapper': 'oidc-hardcoded-role-mapper',
            'consentRequired': False,
            'config': {
                'role': 'shasta.admin',
            },
        },
    ]

    admin_client.set_req_attr('protocolMappers',
                              admin_pm)

    # add endpoint to secret
    admin_client.set_k8s_secret_attr(
        'endpoint',
        '{}/realms/{}/protocol/openid-connect/token'.format(cluster_keycloak_base,
                                                            kas.SHASTA_REALM_NAME)
    )

    # ---- OIDC Client ----

    k8s_oidc_client = \
        KeycloakClient(
            kas,
            kas.SHASTA_REALM_NAME,
            os.environ.get('KEYCLOAK_OIDC_CLIENT_ID',
                           DEFAULT_OIDC_CLIENT_ID),
        )

    clients.append(k8s_oidc_client)

    # Set core client attributes
    k8s_oidc_client.direct_access_grants_enabled = True
    k8s_oidc_client.service_accounts_enabled = False
    k8s_oidc_client.standard_flow_enabled = True
    k8s_oidc_client.implicit_flow_enabled = False
    k8s_oidc_client.direct_access_grants_enabled = True
    k8s_oidc_client.public_client = True
    k8s_oidc_client.create_roles_for_public_client = False
    k8s_oidc_client.create_monitor_read_only_role = False

    # add protocol mappers
    k8s_oidc_pms = [
        {
            'name': 'kubernetes-api-oidc-group-mapper',
            'protocol': 'openid-connect',
            'protocolMapper': 'oidc-group-membership-mapper',
            'consentRequired': False,
            'config': {
                'full.path': False,
                'id.token.claim': True,
                'access.token.claim': True,
                'claim.name': 'groups',
                'userinfo.token.claim': True,
            },
        },
        {
            'name': 'kubernetes-api-oidc-name-mapper',
            'protocolMapper': 'oidc-usermodel-attribute-mapper',
            'protocol': 'openid-connect',
            'config': {
                'user.attribute': 'username',
                'claim.name': 'name',
                'id.token.claim': True,
                'access.token.claim': True,
                'userinfo.token.claim': True,
            },
        },
    ]

    k8s_oidc_client.set_req_attr('protocolMappers',
                                 k8s_oidc_pms)

    k8s_oidc_client_attrs = {
        "access.token.lifespan": "14400",
    }

    k8s_oidc_client.set_req_attr('attributes',
                                 k8s_oidc_client_attrs)

    # ---- System Compute Client ----

    system_compute_client = \
        KeycloakClient(
            kas,
            kas.SHASTA_REALM_NAME,
            os.environ.get('KEYCLOAK_SYSTEM_COMPUTE_CLIENT_ID',
                           DEFAULT_SYSTEM_COMPUTE_CLIENT_ID),
            os.environ.get('KEYCLOAK_SYSTEM_COMPUTE_CLIENT_SECRET_NAME',
                           DEFAULT_SYSTEM_COMPUTE_CLIENT_SECRET_NAME),
            [n for n in json.loads(
                os.environ.get('KEYCLOAK_SYSTEM_COMPUTE_CLIENT_SECRET_NAMESPACES',
                               DEFAULT_SYSTEM_COMPUTE_CLIENT_SECRET_NAMESPACES))]
        )

    clients.append(system_compute_client)

    # Set core client attributes
    system_compute_client.service_accounts_enabled = True

    # add protocol mappers
    system_compute_pm = [
        {
            'name': 'system-compute-role',
            'protocol': 'openid-connect',
            'protocolMapper': 'oidc-hardcoded-role-mapper',
            'consentRequired': False,
            'config': {
                'role': 'shasta.system-compute',
            },
        },
    ]

    system_compute_client.set_req_attr('protocolMappers',
                                       system_compute_pm)

    # add endpoint to secret
    system_compute_client.set_k8s_secret_attr(
        'endpoint',
        '{}/realms/{}/protocol/openid-connect/token'.format(cluster_keycloak_base,
                                                            kas.SHASTA_REALM_NAME)
    )

    # ---- System PXE Client ----

    system_pxe_client = \
        KeycloakClient(
            kas,
            kas.SHASTA_REALM_NAME,
            os.environ.get('KEYCLOAK_SYSTEM_PXE_CLIENT_ID',
                           DEFAULT_SYSTEM_PXE_CLIENT_ID),
            os.environ.get('KEYCLOAK_SYSTEM_PXE_CLIENT_SECRET_NAME',
                           DEFAULT_SYSTEM_PXE_CLIENT_SECRET_NAME),
            [n for n in json.loads(
                os.environ.get('KEYCLOAK_SYSTEM_PXE_CLIENT_SECRET_NAMESPACES',
                               DEFAULT_SYSTEM_PXE_CLIENT_SECRET_NAMESPACES))]
        )

    clients.append(system_pxe_client)

    # Set core client attributes
    system_pxe_client.service_accounts_enabled = True

    # add protocol mappers
    system_pxe_client_pm = [
        {
            'name': 'system-pxe-role',
            'protocol': 'openid-connect',
            'protocolMapper': 'oidc-hardcoded-role-mapper',
            'consentRequired': False,
            'config': {
                'role': 'shasta.system-pxe',
            },
        },
    ]

    system_pxe_client.set_req_attr('protocolMappers',
                                   system_pxe_client_pm)

    # add endpoint to secret
    system_pxe_client.set_k8s_secret_attr(
        'endpoint',
        '{}/realms/{}/protocol/openid-connect/token'.format(cluster_keycloak_base,
                                                            kas.SHASTA_REALM_NAME)
    )

    # ---- System NEXUS Client ----
    # This client is for use by the Nexus Keycloak plugin which enables
    # Nexus to authenticate wth Keycloak realm users.
    # https://github.com/flytreeleft/nexus3-keycloak-plugin

    system_nexus_client = \
        KeycloakClient(
            kas,
            kas.SHASTA_REALM_NAME,
            os.environ.get('KEYCLOAK_SYSTEM_NEXUS_CLIENT_ID',
                           DEFAULT_SYSTEM_NEXUS_CLIENT_ID),
            os.environ.get('KEYCLOAK_SYSTEM_NEXUS_CLIENT_SECRET_NAME',
                           DEFAULT_SYSTEM_NEXUS_CLIENT_SECRET_NAME),
            json.loads(
                os.environ.get('KEYCLOAK_SYSTEM_NEXUS_CLIENT_SECRET_NAMESPACES',
                               DEFAULT_SYSTEM_NEXUS_CLIENT_SECRET_NAMESPACES))
        )

    clients.append(system_nexus_client)

    # Set core client attributes as noted in the documentation
    # at https://github.com/flytreeleft/nexus3-keycloak-plugin
    system_nexus_client.service_accounts_enabled = True
    system_nexus_client.direct_access_grants_enabled = True
    system_nexus_client.standard_flow_enabled = True
    system_nexus_client.authorization_services_enabled = True

    # Set the redirect URI to something (not used by the plugin but required by Keycloak)
    system_nexus_client.set_req_attr('redirectUris', ['https://notused'])

    # add protocol mappers
    system_nexus_client_pm = [
        {
            'name': 'system-nexus-role',
            'protocol': 'openid-connect',
            'protocolMapper': 'oidc-hardcoded-role-mapper',
            'consentRequired': False,
            'config': {
                'role': 'shasta.system-nexus',
            },
        },
    ]

    system_nexus_client.set_req_attr('protocolMappers',
                                     system_nexus_client_pm)

    # add endpoint to secret
    system_nexus_client.set_k8s_secret_attr(
        'endpoint',
        f'{cluster_keycloak_base}/realms/{kas.SHASTA_REALM_NAME}/protocol/openid-connect/token'
    )

    # Add the required service account roles (by the plugin) to this client.
    system_nexus_client._service_account_client_roles = \
        {"realm-management": ["view-clients", "view-realm", "view-users"]}

    # Create new client role(s).
    system_nexus_client.client_roles = ['nx-admin', 'nx-anonymous']

    # ---- System Slingshot Client ----
    # This client is used by the Slingshot Fabric Manager Northbound API consumer which enables
    # Slingshot Fabric Manager to authenticate wth Keycloak realm users.

    system_slingshot_client = \
        KeycloakClient(
            kas,
            kas.SHASTA_REALM_NAME,
            os.environ.get('KEYCLOAK_SYSTEM_SLINGSHOT_CLIENT_ID',
                           DEFAULT_SYSTEM_SLINGSHOT_CLIENT_ID),
            os.environ.get('KEYCLOAK_SYSTEM_SLINGSHOT_CLIENT_SECRET_NAME',
                           DEFAULT_SYSTEM_SLINGSHOT_CLIENT_SECRET_NAME),
            json.loads(
                os.environ.get('KEYCLOAK_SYSTEM_SLINGSHOT_CLIENT_SECRET_NAMESPACES',
                               DEFAULT_SYSTEM_SLINGSHOT_CLIENT_SECRET_NAMESPACES))
        )

    clients.append(system_slingshot_client)

    # Set core client attributes
    system_slingshot_client.service_accounts_enabled = True

    # add protocol mappers
    system_slingshot_client_pm = [
        {
            'name': 'system-slingshot-role',
            'protocol': 'openid-connect',
            'protocolMapper': 'oidc-hardcoded-role-mapper',
            'consentRequired': False,
            'config': {
                'role': 'shasta.system-slingshot',
            },
        },
    ]

    system_slingshot_client.set_req_attr('protocolMappers', system_slingshot_client_pm)

    # add endpoint to secret
    system_slingshot_client.set_k8s_secret_attr(
        'endpoint',
        f'{cluster_keycloak_base}/realms/{kas.SHASTA_REALM_NAME}/protocol/openid-connect/token'
    )

    # Create new client role(s).
    system_slingshot_client.client_roles = ['slingshot-admin', 'slingshot-guest', 'slingshot-operator', 'slingshot-security']

    # ---- WLM Client ----

    clients.append(get_wlm_client(kas, cluster_keycloak_base))

    # ---- Public Clients ----

    # Don't create K8S secrets
    public_client_deprecated = \
        KeycloakClient(
            kas,
            kas.SHASTA_REALM_NAME,
            kas.DEPRECATED_PUBLIC_CLIENT_ID
        )

    public_client_deprecated.public_client = True
    public_client_deprecated.direct_access_grants_enabled = True

    clients.append(public_client_deprecated)

    public_client_deprecated_pm = [
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
            'name': '{}-aud-mapper'.format(public_client_deprecated.id),
            'protocolMapper': 'oidc-audience-mapper',
            'protocol': 'openid-connect',
            'config': {
                'included.client.audience': public_client_deprecated.id,
                'id.token.claim': True,
                'access.token.claim': True,
            },
        },
    ]

    public_client_deprecated.set_req_attr('protocolMappers',
                                          public_client_deprecated_pm)

    public_client = \
        KeycloakClient(
            kas,
            kas.SHASTA_REALM_NAME,
            kas.PUBLIC_CLIENT_ID
        )

    public_client.public_client = True
    public_client.direct_access_grants_enabled = True
    public_client.create_monitor_read_only_role = True

    clients.append(public_client)

    public_client_pm = [
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
            'name': 'keycloak-group-mapper',
            'protocol': 'openid-connect',
            'protocolMapper': 'oidc-group-membership-mapper',
            'config': {
                'full.path': False,
                'id.token.claim': True,
                'access.token.claim': True,
                'claim.name': 'groups',
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
            'name': '{}-aud-mapper'.format(public_client.id),
            'protocolMapper': 'oidc-audience-mapper',
            'protocol': 'openid-connect',
            'config': {
                'included.client.audience': public_client.id,
                'id.token.claim': True,
                'access.token.claim': True,
            },
        },
    ]

    public_client.set_req_attr('protocolMappers',
                               public_client_pm)

    # Extra clients
    client_specs_json = os.environ.get('KEYCLOAK_CLIENTS')
    if client_specs_json:
        client_specs = json.loads(client_specs_json)
    else:
        client_specs = {}

    for client_id in client_specs:
        keycloak_client = (
            create_keycloak_client_from_spec(
                client_id, client_specs[client_id], kas, customer_access_url))
        clients.append(keycloak_client)

    # Keep retrying. Might fail because Keycloak hasn't started up yet.
    while True:
        try:
            kas.run()
            kas.create_client_scopes()
            for client in clients:
                client.create()
                if not client.public_client:
                    client.create_k8s_secrets()
                else:
                    # assign admin, user, and monitor-ro roles to public clients (unless specified not to)
                    if client.create_roles_for_public_client:
                        client.create_role('admin')
                        client.create_role('user')
                    if client.create_monitor_read_only_role:
                        client.create_role('monitor-ro')
            kas.run_post_clients()
            break
        except requests.exceptions.HTTPError as e:
            if (e.response is not None) and (e.response.status_code == 401):
                LOGGER.warning(
                    "Keycloak setup failed due to 401 Unauthorized error, "
                    "will try again in 120 sec", exc_info=True)
                # Give more time for replicas to do initial cluster formation.
                kas.reset_keycloak_master_admin_session()
                time.sleep(120)
            else:
                LOGGER.warning(
                    "Keycloak setup failed due to unexpected HTTP error, "
                    "will try again in 10 sec", exc_info=True)
                time.sleep(10)
        except oauthlib.oauth2.rfc6749.errors.OAuth2Error:
            LOGGER.warning(
                "Keycloak setup failed due to unexpected OAuth2Error. "
                "Will reset token and try again", exc_info=True)
            kas.reset_keycloak_master_admin_session()
            time.sleep(10)
        except Exception:
            LOGGER.warning(
                "Keycloak setup failed, will try again in 10 sec", exc_info=True)
            time.sleep(10)

    LOGGER.info("Keycloak setup complete")


if __name__ == '__main__':
    main()
