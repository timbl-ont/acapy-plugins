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
* SD-JWT ID card portrait: a selectively disclosable `picture` claim, a `data:image/jpeg;base64,…` URL as in the EUDI PID rulebook (the form is prefilled with a sample JPEG)
* Display credential records

### Current Status of the Demo

This demo works with the Bifold wallet and the Paradym wallet (exception of JWT type). Note, for mDOC support in Bifold core you need to import a trusted certificate created from the DID. Support for mDOC in Bifold is under active development.

Verification in the oid4vc plugin is still supporting an earlier draft of OID4VP and won't likely work with any modern wallet.

Overall the demo needs to be refactored due to the additional functionality added to index.js

### Credential Refresh

When a credential is refreshed it is updated and made available to the /credential endpoint.

To retrieve the credential a refresh token is required. In the future, dPOP will also be required.

You will need a mechanism to trigger the refresh in your wallet. One mechanism is to monitor the status of the credential via the credential status list. Bifold supports this option if configured to do so.
### SD-JWT VC with an X.509 chain (x5c)

Tick **Sign with X.509 certificate (x5c)** on the SD-JWT issue page to issue `IDCardX5c`: the same ID card, but its JWS header carries `x5c` (leaf first) instead of `kid`. Uses ES256 and has no status list.

* On first use, `sdjwt-x5c/mint-issuer-cert.sh` mints a 90-day leaf certificate over the issuer did:jwk P-256 public key (`openssl -force_pubkey`; the private key stays in ACA-Py). The leaf is signed by the committed demo CA `sdjwt-x5c/issuer_ca.pem`. Its SAN `URI`s are the issuer URL (`https://<issuer ngrok>/tenant/<wallet id>`) and the issuer did:jwk, with a matching `DNS` SAN. The plugin sets the credential's `iss` to the exchange's DID, so `iss` is the did:jwk; wallets that require an HTTPS `iss` with `x5c` may reject it.
* The chain is stored in the supported credential's `vc_additional_data.x5c_cert_chain`, which the `sd_jwt_vc` plugin turns into the `x5c` header. The SD-JWT create route can't set that field, so the demo creates the record and then completes it with `PUT /oid4vci/credential-supported/records/jwt/{id}`.
* Import `sdjwt-x5c/issuer_ca.pem` (or `.der`) into the wallet as a trusted issuer certificate.
* After the wallet accepts the credential, check its signature, chain and `iss`/SAN match from the issuer log:

```
docker compose logs issuer | node sdjwt-x5c/verify-sdjwt-x5c.mjs
```
