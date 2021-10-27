This is the Keycloak installer. See the [roles](roles/keycloak/README.md)

## keycloak deploy

See the README.md files in

- roles/keycloak : Sets variables
- roles/keycloak_loftsman_init : Creates customizations for Helm chart
- roles/keycloak_deploy : Deploys other Keycloak K8s objects and customizes
  setup for the cray-keycloak-gatekeeper chart (in cray-charts)
- roles/keycloak-manifest : Deploys helm manifest for the cray-keycloak-gatekeeper chart
- roles/keycloak_localize : Run during localization phase

The Helm chart is in kubernetes/keycloak.

The keycloak-localize.yml playbook runs the keycloak_localize role.

## keycloak-setup docker image

### keycloak_setup.py

Keycloak must have an administrative user in the master realm that can create
a new realm and create clients in the realm. The client-id, username, and
password for the user are read from the Keycloak master administrator
authentication volume as described below.

A `shasta` realm is created in Keycloak.
The realm is configured to override the default token timeouts.

* SSO Session Idle : 365 Days (Required for UAI & PALS use case)
* SSO Session Max : 365 Days
* Access Token Lifespan : 365 Days
* Access Token Lifespan For Implicit Flow : 365 Days

A Client called `admin-client` is created in Keycloak. The Client is
confidential (so it has a client secret and can be used for client credentials
flow). The client is created with a *Hardcoded Role* mapper that adds the
*shasta.admin* role to the token.

A Client called `system-compute-client` is created in Keycloak. The client is
confidential, and service account use enabled (to enable client credentials flow).
The client is created with a *Hardcoded Role* mapper that adds the
*shasta.system-compute* role to the token. The client and role is
configured to support the system services necessary for compute node operation.

A Client called `system-nexus-client` is created in Keycloak. The client is
used by the Nexus Keycloak plugin (https://github.com/flytreeleft/nexus3-keycloak-plugin)
to allow Nexus to authenticate wth Keycloak realm users.  
The client is created with the realm-managment service account roles of view-clients,
view-realm and view-users as required by the plugin. The client also has an nx-admin role which provides Nexus admin level access when the client role is assigned to a user.

A Client called `system-pxe-client` is created in Keycloak. The client is
confidential, and service account use enabled (to enable client credentials flow).
The client is created with a *Hardcoded Role* mapper that adds the
*shasta.system-pxe* role to the token. The client and role is
configured to support the system services necessary for pxe boot of compute nodes.

A Client called `wlm-client` is created in Keycloak. The client is
confidential, and service account use enabled (to enable client credentials flow).
The client is created with a *Hardcoded Role* mapper that adds the
*shasta.wlm* role to the token. The client and role is configured to support
workload manager use of various system management APIs.

A Client called `gatekeeper` is created in Keycloak. This client is used by
the keycloak-gatekeeper ingress to facilitate authentication for web UIs,
before forwarding traffic to the Istio ingress gateway, which uses OPA and
enforces authorization. This client is configured to support specific
services by requiring valid redirect URIs to be explicitly defined. Also,
the keycloak-gatekeeper-client secret is created to enable keycloak-gatekeeper
to connect to Keycloak.

A Client called `shasta` is created in Keycloak. This client is public and is
meant to be used when accessing the Cray services. This client has protocol
mappers that make the uid and gid attributes for the user available to the
microservice in the ID token and via the OAuth2 userinfo endpoint. The client
also has 2 roles created: `admin` and `user`.

Note that there's also a `cray` public client that's the same as the `shasta`
client. This client is being phased out in favor of the `shasta` client.

Also creates an admin-client secret that other pods can use to get a token.

Adds a protocol mapper called `aud-bug-workaround-script` to the `roles`
client-scope that adds the issuer to the `aud` claim as required by the
keycloak-gatekeeper. This is a workaround as described in this keycloak bug:
https://issues.jboss.org/browse/KEYCLOAK-8954?focusedCommentId=13695636&page=com.atlassian.jira.plugin.system.issuetabpanels%3Acomment-tabpanel#comment-13695636 .
Without this workaround attempts to use keycloak-gatekeeper ingress are failing
with authentication errors and the following error in the keycloak-gatekeeper
log:

```
unable to verify the id token	{"error": "oidc: JWT claims invalid: invalid claims, cannot find 'client_id' in 'aud' claim, aud=[shasta account], client_id=gatekeeper"}
```

#### Environment variables

- KEYCLOAK_BASE: Direct URL to keycloak service. Defaults to
  `http://keycloak.services:8080/keycloak`.
- CLUSTER_KEYCLOAK_BASE : Cluster URL to Keycloak. Defaults to
  `https://api-gateway.default.svc.cluster.local/keycloak`.
- KEYCLOAK_ADMIN_CLIENT: Name of the admin client. Defaults to `admin-client`.
- KEYCLOAK_ADMIN_CLIENT_SECRET_NAME: Name of the secret that stores the admin
  client info. Defaults to `admin-client-auth`.
- KEYCLOAK_ADMIN_CLIENT_SECRET_NAMESPACES: JSON-encoded list of namespaces
  that the admin client secret will be created in. Defaults to `['default']`.
- KEYCLOAK_SYSTEM_COMPUTE_CLIENT: Name of the system:compute client. Defaults to `system-compute-client`.
- KEYCLOAK_SYSTEM_COMPUTE_CLIENT_SECRET_NAME: Name of the secret that stores the system:compute
  client info. Defaults to `system-compute-client-auth`.
- KEYCLOAK_SYSTEM_COMPUTE_CLIENT_SECRET_NAMESPACES: JSON-encoded list of namespaces
  that the system:compute client secret will be created in. Defaults to `['default']`.
- KEYCLOAK_SYSTEM_PXE_CLIENT: Name of the system:pxe client. Defaults to `system-pxe-client`.
- KEYCLOAK_SYSTEM_PXE_CLIENT_SECRET_NAME: Name of the secret that stores the system:pxe
  client info. Defaults to `system-pxe-client-auth`.
- KEYCLOAK_SYSTEM_PXE_CLIENT_SECRET_NAMESPACES: JSON-encoded list of namespaces
  that the system:pxe client secret will be created in. Defaults to `['default']`.
- KEYCLOAK_GATEKEEPER_CLIENT_ID: Name of the keycloak-gatekeeper client.
  Defaults to `gatekeeper`.
- KEYCLOAK_GATEKEEPER_CLIENT_SECRET_NAME: Name of the secret that stores the
  gatekeeper client info. Defaults to `keycloak-gatekeeper-client`.
- KEYCLOAK_GATEKEEPER_CLIENT_SECRET_NAMESPACES: JSON-encoded list of namespaces
  that the gatekeeper client secret will be created in. Defaults to
  `['services']`.
- KEYCLOAK_GATEKEEPER_PROXIED_HOSTS: JSON-encoded list of hostnames that the
  keycloak-gatekeeper ingress will proxy. Used to set the list of valid
  redirect URIs for the gatekeeper client.
- KEYCLOAK_CUSTOMER_ACCESS_URL: The URL used to access Keycloak from the
  customer access network (CAN). Necessary to properly configure
  keycloak-gatekeeper ingress to connect to Keycloak and redirect users to
  Keycloak for login.
- KEYCLOAK_WLM_CLIENT_ID: Name of the WLM client.
  Defaults to `wlm-client`.
- KEYCLOAK_WLM_CLIENT_SECRET_NAME: Name of the secret that stores the
  WLM client info. Defaults to `wlm-client-auth`.
- KEYCLOAK_WLM_CLIENT_SECRET_NAMESPACES: JSON-encoded list of namespaces
  that the WLM client secret will be created in. Defaults to `["default"]`.

### keycloak_localize.py

This will typically run during the localization phase.

#### Local users and groups

If there's a `/mnt/local-users/local-users` file then local users will be created.
If that file doesn't exist then no local users will be created.
The format of this file is like:

```
[
  {
    "name": "user1",
    "firstName": "User One",
    "password": "user1pwd",
    "loginShell": "/bin/bash",
    "homeDirectory": "/home/username",
    "uidNumber": "1234",
    "gidNumber": "123"
  }
]
```

If there's a `/mnt/local-groups/local-groups` file then local groups will be created.
If that file doesn't exist then no local groups will be created.
The format of this file is like:

```
[
  {
    "name": "shasta_admins",
    "gid": "123",
    "members": ["user1", "user2"]
  }
]
```

#### Local role assignments

Currently it creates role assignments for users or groups on clients in
Keycloak. The role assignments to create are taken from the
`LOCAL_ROLE_ASSIGNMENTS` environment variable.

The format of the `LOCAL_ROLE_ASSIGNMENTS` value is a JSON-formatted string
containing an array of objects where the fields in the objects are:

- `user`: A user name
- `group`: A group name
- `client`: A client name
- `role`: A role name

Only one of `user` or `group` must be present.

#### Environment variables

- LOCAL_ROLE_ASSIGNMENTS : JSON-formatted array as described above.

### Common environment variables

- KEYCLOAK_BASE : URL to Keycloak, defaults to
  `http://keycloak.services:8080/keycloak`. Note that if this is an http URL,
  will also have to set `OAUTHLIB_INSECURE_TRANSPORT`.

### Keycloak master administrator authentication volume

Both scripts read a config volume.
The following files are read from the `/mnt/keycloak-master-admin-auth-vol`
directory:

- `client-id` : The OAuth2 client ID for administrating the Keycloak master
  realm
- `user` : The username for the Keycloak master realm administrator
- `password` : The password for the Keycloak master realm administrator

Note that if this directory doesn't exist or any of the files aren't present,
default values will be used: `admin-cli`, `admin`, and `adminpwd`.

### Running tests

```
make test
```

The coverage report will be in `results/coverage`.
