# MSO MDOC Credential Format

Implementation of ISO/IEC 18013-5:2021 compliant mobile document (mDoc) credential format for ACA-Py.

## Overview

This module provides support for issuing and verifying mobile documents (mDocs) as defined in ISO 18013-5, including mobile driver's licenses (mDL) and other identity credentials. The implementation uses the `isomdl-uniffi` library for core mDoc operations and integrates with ACA-Py's credential issuance framework.

## Features

- **ISO 18013-5 Compliance**: Full compliance with the international standard for mobile documents
- **CBOR Encoding**: Efficient binary encoding using CBOR (RFC 8949)
- **COSE Signing**: Cryptographic protection using COSE (RFC 8152/9052)
- **Selective Disclosure**: Privacy-preserving attribute disclosure
- **OpenID4VCI Integration**: Seamless integration with OpenID for Verifiable Credential Issuance

## Protocol Support

- ISO/IEC 18013-5:2021 - Mobile driving licence (mDL) application
- RFC 8152 - CBOR Object Signing and Encryption (COSE)
- RFC 9052 - CBOR Object Signing and Encryption (COSE): Structures and Process
- RFC 8949 - Concise Binary Object Representation (CBOR)
- OpenID4VCI 1.0 - Verifiable Credential Issuance Protocol

## Installation

The mso_mdoc module is included as part of the oid4vc plugin. Dependencies are managed through UV:

```toml
dependencies = [
    "cbor2>=5.4.3",
    "cwt>=1.6.0",
    "pycose>=1.0.0",
    "isomdl-uniffi @ git+https://github.com/Indicio-tech/isomdl-uniffi.git@feat/x509#subdirectory=python",
]
```

## Usage

### Credential Issuance

The module automatically registers the `MsoMdocCredProcessor` with the credential processor registry:

```python
from mso_mdoc.cred_processor import MsoMdocCredProcessor

# The processor handles mso_mdoc format credentials
processor = MsoMdocCredProcessor()
```

### Profiles and namespaces

A credential subject is keyed by namespace. Each element value is encoded as CBOR
in Python (`mdoc/namespaces/`), and isomdl-uniffi's `PreparedMdoc.new_from_cbor`
builds the mdoc from those bytes. A document can carry any number of namespaces.

| Profile | Doctype | Required namespaces | Standard optional namespaces |
|---|---|---|---|
| ISO/IEC 18013-5 mDL | `org.iso.18013.5.1.mDL` | `org.iso.18013.5.1` | `org.iso.18013.5.1.aamva` |
| AAMVA mDL | `org.iso.18013.5.1.mDL` | `org.iso.18013.5.1`, `org.iso.18013.5.1.aamva` | |
| ISO/IEC TS 23220-4 photo ID | `org.iso.23220.photoid.1` | `org.iso.23220.1` | `org.iso.23220.photoid.1` |

- The AAMVA profile applies when the credential configuration's claims declare the
  `org.iso.18013.5.1.aamva` namespace.
- The four standard namespaces have schemas that validate every element and write
  the ISO CBOR types: `full-date` as tag 1004, `tdate` as tag 0, byte strings for
  portraits, and the photo ID `birth_date` map (`{"birth_date": ..., "approximate_mask": ...}`).
  Unknown elements and missing mandatory elements are refused when the exchange is
  created, and error messages never contain element values.
- Any other namespace is issuer-defined. It must be declared in the configuration's
  `claims`, and each element may name its CBOR type with an internal `value_type`
  (`tstr`, `bstr`, `full-date`, `tdate`, `uint`, `int`, `bool`, or `json`, the default).
- A flat mDL subject (elements at the top level) is still accepted and mapped to
  `org.iso.18013.5.1`; other doctypes need a subject keyed by namespace.

```json
{
  "org.iso.23220.1": {
    "family_name": "Smith",
    "given_name": "Alice",
    "birth_date": {"birth_date": "1990-04-01", "approximate_mask": "00000011"},
    "portrait": "<base64>",
    "issue_date": "2026-01-01",
    "expiry_date": "2036-01-01",
    "issuing_authority": "Ontario",
    "issuing_country": "CA",
    "age_over_18": true
  },
  "org.iso.23220.photoid.1": {"person_id": "1234567890"}
}
```

### Configuration

Create a credential configuration with
`POST /oid4vci/credential-supported/create/mso-mdoc`, and change it with
`PUT /oid4vci/credential-supported/records/mso-mdoc/{supported_cred_id}`:

```json
{
  "format": "mso_mdoc",
  "id": "org.iso.23220.photoid.1",
  "doctype": "org.iso.23220.photoid.1",
  "document_signer": {"key_type": "wallet", "multikey": "zDnae..."},
  "validity_info": {"valid_from": 0, "valid_until": 2592000, "expected_update": 604800},
  "claims": {"ca.on.photoid.1": {"health_number": {"value_type": "tstr", "mandatory": true}}},
  "cryptographic_binding_methods_supported": ["jwk"],
  "credential_signing_alg_values_supported": ["ES256"]
}
```

- `document_signer` (required) says where the document signer (DS) key and
  certificate come from:
  - `{"key_type": "wallet", "multikey": ...}`: a P-256 key in the ACA-Py wallet,
    which may be held by an external signer. The certificate chain comes from the
    `x509_certs` plugin, purpose `mdoc_ds`. The plugin never sees the private key.
  - `{"key_type": "pem", "signing_key_id": ...}`: a legacy key and certificate
    created with `/mso-mdoc/signing-keys`.
- `validity_info` sets the MSO `validityInfo`, in seconds after signing.
  `valid_from` defaults to 0 and `valid_until` to 30 days; `expected_update` is
  optional. The DS certificate must be valid until `validUntil`.
- Revocation uses the `status_list` plugin, as for the other formats. Load it as the
  status handler (`OID4VCI_STATUS_HANDLER=status_list.v1_0.status_handler`) and
  create a status list definition with `list_type` `ietf` and the configuration's
  `supported_cred_id` (`POST /status-list/defs`). Each mdoc then carries a Token
  Status List reference in the MSO `status`, recorded against its exchange, and
  `PATCH /status-list/defs/{def_id}/creds/{exchange_id}` revokes it.

**Breaking changes:**
- `signing_key_id` was removed, and there is no fallback to a signing key found by
  doctype. Add `document_signer` to existing configurations with the `PUT` endpoint.
- `status_list_def_id` and `status_list_base_uri` were removed in favour of status
  list definitions, as above.

## Architecture

### Core Components

- **`cred_processor.py`**: Credential processor implementing the `Issuer`,
  `CredVerifier` and `PresVerifier` interfaces
- **`mdoc/namespaces/`**: Profiles, namespace schemas and CBOR encoders
- **`mdoc/issuer.py`**: Issuance through `PreparedMdoc.new_from_cbor`, the document
  signer and `PreparedMdoc.complete`
- **`document_signer.py`**: Wallet and legacy PEM document signers
- **`mdoc/cred_verifier.py`**, **`mdoc/pres_verifier.py`**: Credential and
  presentation verification
- **`routes.py`**, **`trust_anchor_routes.py`**: Admin API

### Key Management

1. Create a P-256 wallet key: `POST /wallet/keys {"alg": "p256"}`.
2. Request a CSR for it with `POST /x509/csr` and have your IACA sign it as a DS
   certificate (ISO/IEC 18013-5 Annex B).
3. Store the leaf-first chain with `POST /x509/certificates` and purpose `mdoc_ds`.
   A self-signed root at the end of the chain is left out of the mdoc x5chain.
4. Set `document_signer` on the credential configuration.

## API Endpoints

The module provides REST API endpoints for mDoc operations:

### Sign mDoc
```
POST /oid4vc/mdoc/sign
```

Request body:
```json
{
    "payload": {
        "doctype": "org.iso.18013.5.1.mDL",
        "claims": {
            "org.iso.18013.5.1": {
                "family_name": "Doe",
                "given_name": "John",
                "birth_date": "1990-01-01",
                "age_over_18": true
            }
        }
    },
    "headers": {
        "alg": "ES256"
    },
    "verificationMethod": "did:key:z6Mkn6z3Eg2mrgQmripNPGDybZYYojwZw1VPjRkCzbNV7JfN#0"
}
```

### Verify mDoc
```
POST /oid4vc/mdoc/verify
```

Request body:
```json
{
    "mDoc": "<base64-encoded-mdoc>",
    "nonce": "optional-nonce"
}
```

## Testing

Comprehensive test coverage including:
- Unit tests for all components
- Integration tests with real mDoc operations
- Real functional tests with actual cryptographic operations
- Compliance tests against ISO 18013-5 requirements

Run tests:
```bash
cd oid4vc
uv run pytest mso_mdoc/tests/ -v
```

Test categories:
- **Unit Tests**: Individual component testing
- **Integration Tests**: Cross-component functionality
- **Real Tests**: Actual mDoc operations with isomdl-uniffi
- **Storage Tests**: Persistent storage operations
- **Security Tests**: Cryptographic validation

## Security Considerations

- All cryptographic operations use industry-standard libraries
- Keys are generated using secure random sources (P-256 ECDSA)
- Private keys are stored securely in ACA-Py's encrypted wallet
- No hardcoded credentials or keys
- Full compliance with ISO 18013-5 security requirements
- COSE signing for tamper detection

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure `isomdl-uniffi` is properly installed
2. **Key Generation Failures**: Check that the wallet is properly initialized
3. **CBOR Encoding Errors**: Verify data types match ISO 18013-5 requirements
4. **Signature Verification Failures**: Ensure proper key material and algorithm support

### Debug Mode

Enable debug logging for detailed operation information:

```python
import logging

logging.getLogger("mso_mdoc").setLevel(logging.DEBUG)
```

## Contributing

When contributing to this module:

1. **Ensure ISO 18013-5 compliance** - All changes must maintain standard compliance
2. **Add comprehensive tests** - Both unit and integration tests for new features
3. **Update documentation** - Keep API documentation current
4. **Run security scans** - Use `bandit` to check for security issues
5. **Format code** - Use `black` and `isort` for consistent formatting
6. **Type hints** - Maintain complete type annotations

### Development Setup

```bash
# Install development dependencies
uv sync --dev

# Run tests
cd oid4vc
uv run pytest mso_mdoc/tests/

# Run security scan
uv run bandit -r mso_mdoc/ -x "*/tests/*"

# Format code
uv run black mso_mdoc/
uv run isort mso_mdoc/
```

## License

This module is part of the Aries ACA-Py plugins project and follows the same licensing terms.

## References

- [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html) - Mobile driving licence (mDL) application
- [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [RFC 8152 - CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152)
- [RFC 8949 - Concise Binary Object Representation (CBOR)](https://tools.ietf.org/html/rfc8949)
