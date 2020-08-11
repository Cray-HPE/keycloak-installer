Keycloak Localize
----

This is run by the keycloak-localize.yml playbook to update the
`keycloak-certs` Kubernetes Secret with the customer's LDAP server CA
certificates. This is necessary when the customer is using secure `ldaps` and
the LDAP server has a self-signed certificate. The customer can set the new
Keycloak CA certificates by

1) Create a keystore file with the CA certificate, the password must be
   `password`
2) Base-64 encode a keystore file
3) Set the base-64 string in the customer_var.yml file in the
   `ldap_server_keystore` value

Here's an example:

```
$ keytool -importcert -trustcacerts \
 -file ~/Downloads/myad-pub-cert.cer -alias myad \
 -keystore certs.jks -storepass password -noprompt
$ base64 < certs.jks > certs.jks.b64
```

Then put the contents of the certs.jks.b64 file in customer_var.yml:

```
ldap_server_keystore: >
    /u3+7QA...yAA==
```
