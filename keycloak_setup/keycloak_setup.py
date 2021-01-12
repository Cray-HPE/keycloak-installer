#!/usr/bin/env python
# Copyright 2020 Hewlett Packard Enterprise Development LP

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

DEFAULT_GATEKEEPER_CLIENT_ID = 'gatekeeper'
DEFAULT_GATEKEEPER_CLIENT_SECRET_NAME = 'keycloak-gatekeeper-client'
DEFAULT_GATEKEEPER_CLIENT_SECRET_NAMESPACES = json.dumps(['services'])
DEFAULT_GATEKEEPER_REDIRECT_URIS = []

DEFAULT_WLM_CLIENT_ID = 'wlm-client'
DEFAULT_WLM_CLIENT_SECRET_NAME = 'wlm-client-auth'
DEFAULT_WLM_CLIENT_SECRET_NAMESPACES = json.dumps(['default'])

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
    ):
        self.keycloak_base = keycloak_base or DEFAULT_KEYCLOAK_BASE
        self.cluster_keycloak_base = cluster_keycloak_base or DEFAULT_CLUSTER_KEYCLOAK_BASE
        self.kc_master_admin_client_id = kc_master_admin_client_id or DEFAULT_KEYCLOAK_MASTER_ADMIN_CLIENT_ID
        self.kc_master_admin_username = kc_master_admin_username or DEFAULT_KEYCLOAK_MASTER_ADMIN_USERNAME
        self.kc_master_admin_password = kc_master_admin_password or DEFAULT_KEYCLOAK_MASTER_ADMIN_PASSWORD
        self._kc_master_admin_client_cache = None
        self.customer_access_url = customer_access_url or DEFAULT_CLUSTER_KEYCLOAK_BASE

    def run(self):
        self._setup_keycloak()

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
        }
        response = self.kc_master_admin_client.post(url, json=request_data)
        if response.status_code not in [200, 201, 409]:
            response.raise_for_status()


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

        # Enables 'extended' keycloak client req attributes
        self._kc_ext_attr = dict()

        # K8S secret 'extended' attributes for secret create/update
        self._k8s_secret_ext_attr = dict()

        # Client URL (e.g., /{realm}/clients/{id}),
        # set during .create()
        self._url = None

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

    # publicClient

    @property
    def public_client(self):
        return self._public_client

    @public_client.setter
    def public_client(self, v):
        if not isinstance(v, bool):
            raise TypeError
        self._public_client = v

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
            'publicClient': self.public_client
        }

        # Verify the extended attributes don't contain
        # the reserved fields, above. Add them to config
        # otherwise.
        if set(config.keys()).intersection(set(self._kc_ext_attr.keys())):
            raise ValueError(
                "cannot override reserved kc client create request attrs")
        config.update(self._kc_ext_attr)

        # Attempt to create the client
        create_url = '{}/admin/realms/{}/clients'.format(self.kas.keycloak_base, self.realm)
        response = self.kas.kc_master_admin_client.post(create_url, json=config)

        if response.status_code == 201:
            LOGGER.info('Created client %s', self.id)
        elif response.status_code == 409:
            LOGGER.info('Keycloak client %s already exists', self.id)
        else:
            response.raise_for_status()

        # Get the keycloak URL for the client
        LOGGER.info('Fetching %s client URL from keycloak...', self.id)

        query_url = '{}/admin/realms/{}/clients?clientId={}'.format(
            self.kas.keycloak_base, self.realm, self.id,
        )

        response = self.kas.kc_master_admin_client.get(query_url)
        response.raise_for_status()

        # Set the keycloak URL for the client, required
        # to create k8s secrets or roles
        self._url = '{}/admin/realms/{}/clients/{}'.format(self.kas.keycloak_base,
                                                           self.realm,
                                                           response.json()[0]['id'])

        LOGGER.info('Client ({}), URL {}'.format(self.id, self._url))

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
                raise ValueError("attempting to set role but client URL is not set.")

            LOGGER.info('Fetching %s secret...', self.id)
            response = self.kas.kc_master_admin_client.get('{}/client-secret'.format(self._url))
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
            raise ValueError("attempting to set role but client URL is not set.")

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


def k8s_apply_secret(namespace, secret_name, secret_data, v1=None):
    if v1 is None:
        v1 = kubernetes.client.CoreV1Api()

    secret_data_encoded = {k: base64.b64encode(bytes(v, 'utf-8')).decode("ascii") for k, v in list(secret_data.items())}

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
    LOGGER.info('Fetching current %s Secret in namespace %s...', secret_name, namespace)
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
        with open('{}/client-id'.format(secret_dir)) as f:  # FIXME: document these requirements in README
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


def main():

    # Configure logging
    log_format = "%(asctime)-15s - %(levelname)-7s - %(name)s - %(message)s"
    logging.basicConfig(level=logging.INFO, format=log_format)

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

    kas = KeycloakSetup(
        keycloak_base=keycloak_base,
        cluster_keycloak_base=cluster_keycloak_base,
        kc_master_admin_client_id=kc_master_admin_secrets['client_id'],
        kc_master_admin_username=kc_master_admin_secrets['user'],
        kc_master_admin_password=kc_master_admin_secrets['password'],
        customer_access_url=customer_access_url)

    # ---------------------------------------------------------------
    # Keycloak Client Definitions
    # ---------------------------------------------------------------

    clients = list()

    # ---- Gatekeeper Client ----

    gatekeeper_client = \
        KeycloakClient(
            kas,
            kas.SHASTA_REALM_NAME,
            os.environ.get('KEYCLOAK_GATEKEEPER_CLIENT_ID',
                           DEFAULT_GATEKEEPER_CLIENT_ID),
            os.environ.get('KEYCLOAK_GATEKEEPER_CLIENT_SECRET_NAME',
                           DEFAULT_GATEKEEPER_CLIENT_SECRET_NAME),
            [n for n in json.loads(
                os.environ.get('KEYCLOAK_GATEKEEPER_CLIENT_SECRET_NAMESPACES',
                               DEFAULT_GATEKEEPER_CLIENT_SECRET_NAMESPACES))]
        )

    clients.append(gatekeeper_client)

    # Set core client attributes
    gatekeeper_client.standard_flow_enabled = True
    gatekeeper_client.service_accounts_enabled = True

    # load and set redirect URIs
    gatekeeper_redirect_uris = None
    gatekeeper_proxied_hosts = os.environ.get('KEYCLOAK_GATEKEEPER_PROXIED_HOSTS')
    if gatekeeper_proxied_hosts:
        gatekeeper_proxied_hosts = json.loads(gatekeeper_proxied_hosts)
        gatekeeper_redirect_uris = [
            'https://{}/oauth/callback'.format(hostname)
            for hostname in gatekeeper_proxied_hosts
        ]

    gatekeeper_client.set_req_attr('redirectUris',
                                   gatekeeper_redirect_uris)

    # add protocol mappers
    gatekeeper_pm = [
        # XXX Not sure which protocol mappers are necessary for gatekeeper client
        {
            'name': 'admin-role',
            'protocol': 'openid-connect',
            'protocolMapper': 'oidc-hardcoded-role-mapper',
            'consentRequired': False,
            'config': {
                'role': 'shasta.admin',
            },
        }, {
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
        }, {
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
        }, {
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
        }, {
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
        }, {
            'name': '{}-aud-mapper'.format(gatekeeper_client.id),
            'protocolMapper': 'oidc-audience-mapper',
            'protocol': 'openid-connect',
            'config': {
                'included.client.audience': gatekeeper_client.id,
                'id.token.claim': True,
                'access.token.claim': True,
            },
        },
    ]

    gatekeeper_client.set_req_attr('protocolMappers',
                                   gatekeeper_pm)

    # add discovery URL to secret
    gatekeeper_client.set_k8s_secret_attr(
        'discovery-url',
        '{}/realms/{}'.format(customer_access_url, kas.SHASTA_REALM_NAME)
    )

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
        }, {
            'name': '{}-aud-mapper'.format(gatekeeper_client.id),
            'protocolMapper': 'oidc-audience-mapper',
            'protocol': 'openid-connect',
            'config': {
                'included.client.audience': gatekeeper_client.id,
                'id.token.claim': False,
                'access.token.claim': True,
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
        }, {
            'name': '{}-aud-mapper'.format(gatekeeper_client.id),
            'protocolMapper': 'oidc-audience-mapper',
            'protocol': 'openid-connect',
            'config': {
                'included.client.audience': gatekeeper_client.id,
                'id.token.claim': False,
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
        }, {
            'name': '{}-aud-mapper'.format(gatekeeper_client.id),
            'protocolMapper': 'oidc-audience-mapper',
            'protocol': 'openid-connect',
            'config': {
                'included.client.audience': gatekeeper_client.id,
                'id.token.claim': False,
                'access.token.claim': True,
            },
        },
    ]

    public_client.set_req_attr('protocolMappers',
                               public_client_pm)

    # Keep retrying. Might fail because Keycloak hasn't started up yet.
    while True:
        try:
            kas.run()
            for client in clients:
                client.create()
                if not client.public_client:
                    client.create_k8s_secrets()
                else:  # assign admin and user roles to public clients
                    client.create_role('admin')
                    client.create_role('user')

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
