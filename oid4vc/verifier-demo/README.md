# Standalone SD-JWT VC verifier demo

A one-button verifier for the ID card issued by [`../demo`](../demo/README.md). Press **Verify**, and the page shows an OpenID4VP QR code. On success it shows a green check, the holder's name, an 18+ flag and the portrait (if shared), plus the credential type, issuer and dates. No API traffic is shown.

The stack is an ACA-Py agent running the oid4vc plugins as a verifier, its own ngrok agent, and a small Node app (`app/`). It is independent of `../demo` and uses different host ports, so both can run at the same time. Running two ngrok agents at once needs a paid ngrok plan.

## Run

1. Build the `oid4vc` image if you haven't already. `docker compose build agent` builds it from this repo (`../docker/Dockerfile`), the same image `../demo` uses.
2. `cp .env.example .env` and set `NGROK_AUTHTOKEN`.
3. `docker compose up --build` (or `podman compose up --build`).
4. Open the URL from the log line `Verifier ready: open https://….ngrok…` (the `verifier` tunnel; the ngrok inspector is on <http://localhost:4041>). <http://localhost:3003> also works on the host. Uncomment `domain:` in `ngrok.yml` to get stable URLs.

Before you verify, issue an **ID card** (`IDCard` or `IDCardX5c`) to the wallet from `../demo`. Import `../demo/reader-ca/reader_root.pem` into the wallet so it shows the verifier as trusted.

## What it does

At startup `app/server.js` provisions a verifier tenant on the agent:

* It registers `../demo/sdjwt-x5c/issuer_ca.pem` as an `sd_jwt_issuer` trust anchor, so x5c-signed ID cards verify. did:jwk-signed ones verify through DID resolution.
* It mints a 90-day reader certificate over a new did:jwk P-256 key, signed by `../demo/reader-ca`, and registers it with `POST /oid4vp/x509-identity`. Requests are signed JARs with `client_id = x509_san_dns:<agent ngrok host>`, which Multipaz requires.
* It creates one DCQL query for `dc+sd-jwt`, `vct` `ExampleIDCard`: `given_name`, `family_name`, `age_is_over_18`, `picture`. Its `claim_sets` make `picture` optional.

The browser only calls `POST /api/verify`, which creates a request and returns the QR, and `GET /api/verify/:id`. The second route polls `GET /oid4vp/presentation/{id}` and returns just the state, the shown claims and the portrait (only an image `data:` URL). Errors are returned if verification failed.

| Port | Service |
| --- | --- |
| 3003 | Verifier UI |
| 3011 | Agent admin API (debugging) |
| 4041 | ngrok inspector |

Demo only: the agent uses insecure keys and an unauthenticated admin API.
