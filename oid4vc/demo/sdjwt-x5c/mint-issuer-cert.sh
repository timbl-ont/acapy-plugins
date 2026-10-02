#!/bin/bash
# Mints an SD-JWT VC issuer certificate over an existing P-256 public key, so
# the private key never leaves the wallet. The leaf is signed by the demo
# SD-JWT issuer CA beside this script (generated on first run if missing).
#
# Usage: mint-issuer-cert.sh <public-key.pem> <issuer-url>
#   Prints the chain (leaf, then CA) as PEM on stdout.
#
# The leaf carries SAN URI=<issuer-url> and DNS=<issuer host> so it matches the
# SD-JWT `iss` claim. Set OPENSSL to override the binary (LibreSSL won't work).
set -euo pipefail

OPENSSL="${OPENSSL:-openssl}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_KEY="$SCRIPT_DIR/issuer_ca.key"
CA_PEM="$SCRIPT_DIR/issuer_ca.pem"

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <public-key.pem> <issuer-url>" >&2
  exit 1
fi
PUB_KEY="$1"
ISSUER_URL="$2"
HOST="$(echo "$ISSUER_URL" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')"

if [[ ! -f "$CA_PEM" ]]; then
  "$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
  "$OPENSSL" req -x509 -new -key "$CA_KEY" -sha256 -days 3650 \
    -subj "/C=CA/ST=Ontario/O=Demo SD-JWT VC Issuer/CN=Demo SD-JWT VC Issuer CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$CA_PEM"
  echo "Generated $CA_PEM — import it into the wallet as a trusted issuer certificate." >&2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/ext.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectAltName=URI:${ISSUER_URL},DNS:${HOST}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

# A throwaway key/CSR carries the subject; -force_pubkey swaps in the real key.
"$OPENSSL" req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$WORK/dummy.key" -subj "/C=CA/ST=Ontario/O=Demo SD-JWT VC Issuer/CN=${HOST}" \
  -out "$WORK/leaf.csr" 2>/dev/null
"$OPENSSL" x509 -req -in "$WORK/leaf.csr" -force_pubkey "$PUB_KEY" \
  -CA "$CA_PEM" -CAkey "$CA_KEY" -set_serial "0x$("$OPENSSL" rand -hex 8)" \
  -sha256 -days 90 -extfile "$WORK/ext.cnf" -out "$WORK/leaf.pem" 2>/dev/null

cat "$WORK/leaf.pem" "$CA_PEM"
