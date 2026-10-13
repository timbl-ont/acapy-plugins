# Keycloak as the OID4VCI authorization server

This directory lets Keycloak act as the wallet-facing OAuth authorization
server for the OID4VC plugin's **pre-authorized code flow**. Keycloak checks
wallet attestation (attestation-based client authentication, "ABCA") and DPoP.
The plugin stays the Credential Issuer and the resource server, and keeps
ownership of the offer, the pre-authorized code, the `tx_code` and the
exchange.

Keycloak's experimental digital-credential features (`oid4vc-vci`,
`oid4vc-vci-preauth-code`) are **not** used. The extension also does not need
a Keycloak user per holder.

| Path | What |
|---|---|
| [`extension/`](extension) | Keycloak extension: a custom grant type for `urn:ietf:params:oauth:grant-type:pre-authorized_code` (Java, Keycloak 26.8.0) |
| [`oid4vc_keycloak/`](oid4vc_keycloak) | ACA-Py plugin that registers the `keycloak` authorization server provider with the OID4VC plugin |
| [`demo/`](demo) | Docker Compose demo: Keycloak + issuer + a scripted wallet |

## How it works

```mermaid
sequenceDiagram
  autonumber
  participant C as Controller
  participant P as Plugin (issuer / RS)
  participant W as Wallet
  participant K as Keycloak + extension
  C->>P: create exchange + offer (tx_code optional)
  P-->>W: credential offer (opaque pre-authorized_code, tx_code object)
  W->>P: GET issuer metadata → authorization_servers = [Keycloak realm]
  W->>K: POST /token  grant=pre-authorized_code, code, tx_code, client_id<br/>OAuth-Client-Attestation + PoP, DPoP proof
  K->>K: DPoP proof validated (TokenEndpoint)
  K->>K: checkClient() → ABCA; require the DPoP proof
  K->>P: POST /oid4vci/pre-auth/redeem {code, tx_code, client_id}<br/>Authorization: Bearer <realm-signed oid4vci-redeem+jwt>
  P->>P: verify assertion (realm JWKS), check tx_code + attempt limit, mark code redeemed
  P-->>K: {refresh_id, credential_configuration_ids, expires_in}
  K-->>W: DPoP-bound access token (cnf.jkt, refresh_id, aud = issuer), no refresh token
  W->>P: POST /nonce
  W->>P: POST /credential  Authorization: DPoP <at>, DPoP proof
  P->>P: validate token (realm JWKS: iss, aud, exp) + DPoP proof (htm, htu, ath, cnf.jkt)
  P-->>W: credential
```

Why it is split this way:

- **The plugin owns the code and the `tx_code`.** The code is an opaque random
  string. Nothing in it lets anyone test a `tx_code` guess offline. Guesses can
  only be made online through Keycloak, and the plugin locks the code after
  `max_tx_code_attempts` failures (default 5).
- **Keycloak authenticates the wallet and binds the token.** The extension
  calls `checkClient()` (Keycloak's token endpoint skips it for this grant
  type), which runs the ABCA authenticator. It then requires the DPoP proof
  that Keycloak has already validated. Keycloak's DPoP protocol mapper adds
  `cnf.jkt` to the token.
- **No per-holder users.** Every token is issued for one generic
  `oid4vci-holder` user in a *transient* session; nothing is persisted. The
  exchange is identified by the `refresh_id` claim (configurable), not `sub`.
- **The code is redeemed only after client authentication and DPoP pass**, so
  an unauthenticated request cannot burn a code or use up a `tx_code` attempt.

## Configuring Keycloak

### 1. Build and install the extension

```bash
cd oid4vc/keycloak/extension
mvn -B package
cp target/keycloak-oid4vci-pre-auth.jar /opt/keycloak/providers/
```

The extension uses Keycloak's grant type SPI (`OAuth2GrantTypeSpi`), which is
**internal** to Keycloak and may change between releases. Keep the Keycloak
version pinned (`keycloak.version` in `pom.xml`, currently 26.8.0) and re-test
on every upgrade. Keycloak logs a warning at startup that the SPI is internal;
this is expected.

### 2. Server features

| Feature | Setting | Why |
|---|---|---|
| `dpop` | on (Keycloak default) | DPoP proof validation and `cnf.jkt` binding |
| `client-auth-abca` | **on** (experimental) | Wallet attestation. Required by default; see `oid4vci.require.client.attestation` |
| `oid4vc-vci-preauth-code` | **off** | Registers a grant type with the same id as this extension |
| `oid4vc-vci` | off | Not used |

```bash
kc.sh build --features=client-auth-abca,dpop
```

The extension logs a warning at startup if `oid4vc-vci-preauth-code` is
enabled or `client-auth-abca` is disabled.

Configure a fixed hostname (`KC_HOSTNAME`). The realm issuer appears in the
access token `iss`, in the ABCA PoP `aud` and in the redeem assertion, so it
must not depend on which hostname a caller used.

### 3. Realm

Use one realm per issuer tenant. All settings are realm attributes, so each
realm can point at its own plugin tenant:

| Realm attribute | Default | Meaning |
|---|---|---|
| `oid4vci.redeem.url` | — (required) | Plugin redeem endpoint, e.g. `http://issuer:8082/oid4vci/pre-auth/redeem` or `.../tenant/{wallet_id}/oid4vci/pre-auth/redeem`. Can be an internal URL. |
| `oid4vci.credential.issuer` | — (required) | The plugin's Credential Issuer Identifier (`credential_issuer` in the offer). Added to the access token `aud`, and the `aud` of the redeem assertion. |
| `oid4vci.require.client.attestation` | `true` | Require ABCA. When `false`, any client authentication the realm accepts is enough. |
| `oid4vci.require.dpop` | `true` | Require a DPoP proof on the token request. |
| `oid4vci.anonymous.client.id` | unset | Public client used when the wallet sends no `client_id`. Honoured only when attestation is not required. |
| `oid4vci.holder.username` | `oid4vci-holder` | The generic holder user. |
| `oid4vci.refresh.id.claim` | `refresh_id` | Access token claim that carries the plugin exchange's `refresh_id`. |
| `oid4vci.redeem.timeout.ms` | `5000` | Timeout for the redeem call. |

Also create:

- **The generic holder user** (`oid4vci-holder`): enabled, no credentials, no
  roles. It cannot log in.
- **A trusted attester for each wallet provider**: an identity provider of
  type `default-trust`, holding the attester's public keys, either inline
  (`useJwksUrl=false`, `publicKeySignatureVerifier` = a JWKS JSON) or as a JWKS
  URL (`useJwksUrl=true`, `jwksUrl`). X.509 trust (`useX509`,
  `trustedCertificates`) is also supported.
- **A client for each wallet provider**:
  - `clientAuthenticatorType: attestation-based`;
  - the attribute `attester_trust_idps` = the alias(es) of its trust IdP(s);
  - `dpop.bound.access.tokens: true`;
  - standard, direct and service-account flows all disabled;
  - no default client scopes, to keep the token small.

The realm's client authentication flow must include the `attestation-based`
authenticator. Realms created while `client-auth-abca` is enabled get it
automatically.

[`demo/realm-oid4vci.json`](demo/realm-oid4vci.json) is a complete, importable
example.

The access token carries:

- `iss`: the realm;
- `aud`: includes the credential issuer;
- `sub`: the generic holder user;
- `refresh_id`;
- `credential_configuration_ids`;
- `cnf.jkt`.

Its lifetime is capped at the plugin's `expires_in` (300 s). No refresh token
is issued, and the token response contains no `c_nonce`.

## Configuring the plugin

Load the provider plugin next to `oid4vc`:

```bash
aca-py start ... --plugin oid4vc --plugin oid4vc_keycloak
```

Select Keycloak, either for the whole agent:

```bash
OID4VCI_AUTH_SERVER='{"type": "keycloak", "public_url": "https://kc.example.com/realms/oid4vci"}'
```

or per tenant, with `PUT /oid4vci/issuer/configuration`:

```json
{
  "authorization_servers": [
    {
      "type": "keycloak",
      "public_url": "https://kc.example.com/realms/issuer-abc123",
      "private_url": "http://keycloak:8080/realms/issuer-abc123"
    }
  ]
}
```

| Setting | Default | Meaning |
|---|---|---|
| `public_url` | — (required) | Realm issuer URL. Advertised in `authorization_servers` and checked against the token `iss`. |
| `private_url` | `public_url` | Internal realm URL used to fetch the JWKS. |
| `jwks_uri` | `{private_url}/protocol/openid-connect/certs` | Realm JWKS. |
| `issuer` | `public_url` | Expected `iss`, if it differs from `public_url`. |
| `audience` | credential issuer URL | Expected `aud`. |
| `refresh_id_claim` | `refresh_id` | Must match the realm's `oid4vci.refresh.id.claim`. |
| `require_dpop` | `true` | Reject access tokens that are not DPoP-bound. |

Keep the Nonce Endpoint enabled (`enable_nonce_endpoint`, the default),
because Keycloak does not return `c_nonce`.

The redeem endpoint (`POST {issuer}/oid4vci/pre-auth/redeem`) is served on
the public OID4VCI port, but only for tenants whose authorization server is
Keycloak; for any other tenant it returns 404. Requests must carry a JWT
that:

- has `typ` `oid4vci-redeem+jwt`;
- is signed by the realm, with `iss` = the realm and `aud` = the credential
  issuer;
- lives at most 5 minutes and has a single-use `jti`.

Also restrict the endpoint at the network level so that only Keycloak can
reach it.

## Demo

[`demo/`](demo) runs Keycloak (built with the extension), an issuer agent and
a scripted wallet on one Docker network:

```bash
cd oid4vc/keycloak/demo
docker compose up --build -d keycloak issuer
docker compose run --rm wallet
docker compose down
```

The wallet script ([`demo/test_wallet.py`](demo/test_wallet.py)):

1. creates a credential configuration and an offer with a `tx_code`
   through the admin API;
2. discovers Keycloak from the issuer metadata;
3. shows that a token request **without** a wallet attestation, and one with
   a **wrong** `tx_code`, are rejected;
4. gets a DPoP-bound token with a wallet attestation, its PoP, a DPoP proof
   and the `tx_code`;
5. calls `/nonce` and `/credential` with the token and a DPoP proof;
6. shows that the DPoP-bound token is rejected when sent as a `Bearer` token.

The Keycloak admin console is at <http://localhost:8180> (`admin` / `admin`).

`demo/attester-demo-key.json` is a **demo-only** wallet attester key. Its
public half is trusted by the demo realm. Never reuse it.

## Limitations and open questions

- **Internal SPI.** The grant type SPI may break on Keycloak upgrades. Pin
  the version.
- **ABCA is experimental in Keycloak.** Keycloak 26.8.0 does not check the
  attestation PoP `jti` for replay, and does not yet support a
  server-provided challenge (both are upstream TODOs). Until it does, ABCA
  relies on the PoP being freshly signed for this AS (`aud`); there is no
  replay protection within the attestation's lifetime.
- **Replay caches are per process.** The plugin's DPoP `jti` cache and its
  redeem-assertion `jti` cache are held in memory. Multiple plugin instances
  behind a load balancer need shared storage for full replay protection.
- **No resource-server `DPoP-Nonce`** (RFC 9449 §9) yet.
- **Wallet behaviour.** Wallets must send `client_id` and the ABCA headers in
  the pre-authorized code token request. A wallet that relies on anonymous
  access (`pre-authorized_grant_anonymous_access_supported`) needs
  `oid4vci.require.client.attestation=false` and
  `oid4vci.anonymous.client.id`.
- **AS metadata.** Keycloak's discovery document does not list the custom
  grant in `grant_types_supported`. Most wallets just use the
  `token_endpoint`.
- **`authorization_details`** sent in the token request is ignored. The
  credential configuration comes from the offer.
- **Authorization code flow** (e.g. with an upstream IdP such as Okta) is not
  covered by this extension. See [the design notes](../docs/auth-server-providers.md#future-authorization-code-flow).
