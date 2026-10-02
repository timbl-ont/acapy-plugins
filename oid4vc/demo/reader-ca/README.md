# Demo mDoc Reader (Verifier) Trust

This directory holds the demo **Reader Root CA** that anchors the verifier's
reader-authentication certificate for OID4VP presentations, demonstrating
ISO 18013-5-style reader trust without a full trust-list (VICAL/RICAL)
infrastructure.

## Files

| File | Purpose |
|---|---|
| `gen-reader-root.sh` | One-time generation of the root CA (P-256, CA:TRUE/pathlen:0) |
| `reader_root.key` | Root CA private key — **demo only**, never use in production |
| `reader_root.pem` | Root CA certificate — import this into the wallet |
| `reader_root.der` | Same certificate in DER for wallets that expect DER |

## How trust is established

1. **Wallet side (manual, once):** import `reader_root.pem` (or `.der`)
   directly into the wallet as a trusted reader certificate.
2. **Verifier side (automatic, every startup):** the demo frontend
   (`initializeVerifierX509Identity` in `frontend/index.js`) mints a leaf
   reader-authentication certificate over the tenant's `did:jwk` signing key
   and registers it via `POST /oid4vp/x509-identity`. The leaf follows the
   ISO 18013-5 Annex B reader profile: `digitalSignature` key usage, critical
   EKU `1.0.18013.5.1.6` (mdoc reader auth), and a `dNSName` SAN matching the
   current ngrok hostname. The leaf is regenerated per session because the
   ngrok hostname changes; the root stays stable so the wallet import stays
   valid.
3. **Presentation requests** are then signed as JWS with the `x5c` chain
   (leaf + root) and `client_id = x509_san_dns:<ngrok-host>`. The wallet
   validates the chain against the imported root and checks that the SAN
   matches the `response_uri` host.

## Regenerating the root

Delete `reader_root.*` and re-run `./gen-reader-root.sh`. Any wallet that
imported the old root must import the new one.
