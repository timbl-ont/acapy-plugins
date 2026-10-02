#!/bin/bash
# Generates the demo mDoc Reader Root CA used to anchor verifier (reader
# authentication) certificates, loosely following the ISO 18013-5 Annex B
# reader CA profile: P-256, CA:TRUE with pathlen:0, keyCertSign+cRLSign.
#
# Run once; outputs land beside this script:
#   reader_root.key  - CA private key (demo only, do not use in production)
#   reader_root.pem  - CA certificate (import this into the wallet)
#   reader_root.der  - CA certificate in DER, for wallets that expect DER
#
# The per-session reader-auth leaf certificate is generated automatically by
# the demo frontend at startup (see initializeVerifierX509Identity in
# frontend/index.js) because its SAN must match the current ngrok hostname.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -f reader_root.pem ]]; then
  echo "reader_root.pem already exists — delete it first to regenerate." >&2
  echo "Note: regenerating invalidates the root previously imported into wallets." >&2
  exit 1
fi

SUBJECT="/C=CA/ST=Ontario/O=Demo mDoc Verifier/CN=Demo mDoc Reader Root CA"

openssl ecparam -name prime256v1 -genkey -noout -out reader_root.key

openssl req -x509 -new -key reader_root.key \
  -sha256 -days 3650 \
  -subj "$SUBJECT" \
  -out reader_root.pem \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

openssl x509 -in reader_root.pem -outform DER -out reader_root.der

echo "Reader Root CA generated:"
openssl x509 -in reader_root.pem -noout -subject -dates -ext basicConstraints,keyUsage
echo
echo "Import reader_root.pem (or reader_root.der) into the wallet as a trusted reader certificate."
