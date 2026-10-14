## OID4VC ACA-Py Plugin Demo

This is a demo for developers to test and validate the current plugin functionality and to provide a fully working example of the functionality including w3c and ietf status lists. **Do not use for production deployments** 

You will need NGROK to run this demo with a valid Authentication Token
The .env file contains token secrets for the Auth Server

```
cp .env.example .env
export NGROK_AUTHTOKEN=....
docker compose up
```

**Important** The ngrok config only works with the paid version

### Demo Functionality

* Issue credentials via OpendID4VCI 1.0 - JWT, SD-JWT and mDOC
* Present Proof via OpendID4VP - JWT, SD-JWT (Not working, in development)
* Update the status of a JWT or SD-JWT credential
* Refresh an SD-JWT credetial
* Display credential records

### Current Status of the Demo

This demo works with the Bifold wallet and the Paradym wallet (exception of JWT type). Note, for mDOC support in Bifold core you need to import a trusted certificate created from the DID. Support for mDOC in Bifold is under active development.

Verification in the oid4vc plugin is still supporting an earlier draft of OID4VP and won't likely work with any modern wallet.

Overall the demo needs to be refactored due to the additional functionality added to index.js

### Credential Refresh

When a credential is refreshed it is updated and made available to the /credential endpoint.

To retrieve the credential a refresh token is required. In the future, dPOP will also be required.

You will need a mechanism to trigger the refresh in your wallet. One mechanism is to monitor the status of the credential via the credential status list. Bifold supports this option if configured to do so.
With Keycloak as the authorization server, no refresh token is issued, so
credential refresh is not available.

### Keycloak as the authorization server

By default the demo uses the reference authorization server
([`../auth_server`](../auth_server)). To use Keycloak instead, add the
Keycloak override:

```
docker compose -f docker-compose.yaml -f docker-compose.keycloak.yaml up --build
```

This adds a Keycloak service, built from [`../keycloak`](../keycloak/README.md)
with the OID4VCI pre-authorized code extension, and an ngrok tunnel for it
(`ngrok.keycloak.yml`). At startup the demo app:

1. creates a realm `oid4vci-<wallet id>` for its issuer tenant through the
   Keycloak admin API, with the generic holder user and the wallet client(s);
2. sets the tenant's authorization server to that realm
   (`PUT /oid4vci/issuer/configuration` with `"type": "keycloak"`).

Wallets then get their access token from Keycloak (through its ngrok URL)
instead of the reference authorization server. Keycloak redeems the
pre-authorized code on the issuer's admin API
(`/oid4vci/tenant/<wallet id>/pre-auth/redeem`), authenticating with a client
assertion signed by the realm key. Issuance in the UI is unchanged: JWT,
SD-JWT and mdoc offers work as before. The navigation bar shows which
authorization server is in use.

Settings (in `.env`, see `.env.example`):

| Variable | Default | Meaning |
|---|---|---|
| `KEYCLOAK_REQUIRE_ATTESTATION` | `false` | Require wallet attestation (ABCA). Off so any wallet works. |
| `KEYCLOAK_WALLET_CLIENT_ID` | — | Your wallet's `client_id`, registered as an attestation-based client |
| `KEYCLOAK_ATTESTER_JWKS` / `KEYCLOAK_ATTESTER_JWKS_URL` | — | Your wallet provider's attester public keys (a one-line JWKS JSON, or a JWKS URL) |
| `KEYCLOAK_REQUIRE_DPOP` | `true` | Require DPoP on the token request. Set `false` for wallets that don't send DPoP. |
| `KEYCLOAK_ADMIN_USERNAME` / `KEYCLOAK_ADMIN_PASSWORD` | `admin` / `admin` | Keycloak admin account |
| `KEYCLOAK_NGROK_URL` | from ngrok | Static Keycloak URL, if you have one |

To use wallet attestation, set `KEYCLOAK_REQUIRE_ATTESTATION=true`,
`KEYCLOAK_WALLET_CLIENT_ID` and one of the attester settings. The demo app
then adds a trust identity provider for the attester and an
attestation-based client for the wallet. Wallets without attestation are
rejected in that mode.

The Keycloak admin console is at <http://localhost:8180>. The scripted
end-to-end test for the same flow is in
[`../keycloak/e2e`](../keycloak/README.md#end-to-end-test).
