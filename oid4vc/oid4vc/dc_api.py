"""OpenID4VP over the W3C Digital Credentials API: response encryption.

Implements Response Mode ``dc_api.jwt`` (OpenID4VP 1.0 Appendix A.2 and
Section 8.3). Each DC-API request gets an ephemeral P-256 key, advertised to the
wallet in ``client_metadata.jwks``. The wallet returns the Authorization Response
as a compact JWE using ECDH-ES direct key agreement, which the verifier decrypts
with the stored private key.
"""

import base64
import json
from typing import Any, Dict, Optional, Tuple

from acapy_agent.core.profile import ProfileSession
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageNotFoundError
from aries_askar import Key, KeyAlg
from aries_askar.ecdh import EcdhEs

RESPONSE_KEY_RECORD_TYPE = "OID4VP.dc_api_response_key"
JWE_ALG = "ECDH-ES"
SUPPORTED_ENC = ("A128GCM", "A256GCM")
ORIGIN_PREFIX = "origin:"


class ResponseDecryptionError(Exception):
    """Raised when a ``dc_api.jwt`` response cannot be decrypted."""


def is_dc_api_presentation(record: Any) -> bool:
    """Return whether a presentation record was created for the DC-API.

    DC-API presentations store the response audience ``origin:<origin>`` as
    their ``client_id`` (OpenID4VP 1.0 Appendix A.4). The ``origin:`` prefix is
    reserved for that purpose and is never a valid request Client Identifier
    (Section 5.9.3), so it reliably marks DC-API records.
    """
    return (getattr(record, "client_id", None) or "").startswith(ORIGIN_PREFIX)


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json_obj(value: Any) -> Dict[str, Any]:
    if isinstance(value, bytes):
        value = value.decode()
    return json.loads(value)


async def create_response_key(
    session: ProfileSession, presentation_id: str
) -> Dict[str, Any]:
    """Create and store an ephemeral response-encryption key.

    Returns the public JWK, with ``kid``, ``use`` and ``alg`` set, for inclusion
    in ``client_metadata.jwks``.
    """
    key = Key.generate(KeyAlg.P256)
    kid = key.get_jwk_thumbprint()
    storage = session.inject(BaseStorage)
    await storage.add_record(
        StorageRecord(
            type=RESPONSE_KEY_RECORD_TYPE,
            id=presentation_id,
            value=json.dumps({"kid": kid, "jwk": _json_obj(key.get_jwk_secret())}),
        )
    )
    public_jwk = _json_obj(key.get_jwk_public())
    public_jwk.update({"kid": kid, "use": "enc", "alg": JWE_ALG})
    return public_jwk


async def load_response_key(
    session: ProfileSession, presentation_id: str
) -> Optional[Tuple[Key, str]]:
    """Load the response-encryption key and kid for a presentation, if any."""
    storage = session.inject(BaseStorage)
    try:
        record = await storage.get_record(RESPONSE_KEY_RECORD_TYPE, presentation_id)
    except StorageNotFoundError:
        return None
    value = json.loads(record.value)
    return Key.from_jwk(value["jwk"]), value["kid"]


async def delete_response_key(session: ProfileSession, presentation_id: str) -> None:
    """Delete the response-encryption key for a presentation, if present."""
    storage = session.inject(BaseStorage)
    try:
        record = await storage.get_record(RESPONSE_KEY_RECORD_TYPE, presentation_id)
    except StorageNotFoundError:
        return
    await storage.delete_record(record)


def decrypt_response(jwe: str, key: Key, kid: str) -> Dict[str, Any]:
    """Decrypt a ``dc_api.jwt`` Authorization Response.

    Accepts only a compact JWE with ``alg`` ECDH-ES (direct key agreement,
    RFC 7518 Section 4.6) on P-256, ``enc`` A128GCM or A256GCM, and the ``kid``
    of the key issued for the request (OpenID4VP 1.0 Section 8.3). Returns the
    decrypted Authorization Response parameters.
    """
    parts = jwe.split(".")
    if len(parts) != 5:
        raise ResponseDecryptionError("Response is not a compact-serialized JWE")
    protected_b64, encrypted_key, iv_b64, ciphertext_b64, tag_b64 = parts

    try:
        header = json.loads(_b64url_decode(protected_b64))
    except Exception as err:
        raise ResponseDecryptionError("Invalid JWE protected header") from err
    if not isinstance(header, dict):
        raise ResponseDecryptionError("Invalid JWE protected header")

    if header.get("alg") != JWE_ALG:
        raise ResponseDecryptionError(f"Unsupported JWE alg {header.get('alg')!r}")
    enc = header.get("enc")
    if enc not in SUPPORTED_ENC:
        raise ResponseDecryptionError(f"Unsupported JWE enc {enc!r}")
    if header.get("kid") != kid:
        raise ResponseDecryptionError(
            "JWE kid does not match the encryption key issued for this request"
        )
    if "zip" in header:
        raise ResponseDecryptionError("Compressed JWE responses are not supported")
    if encrypted_key:
        raise ResponseDecryptionError(
            "ECDH-ES direct key agreement requires an empty JWE encrypted key"
        )
    epk = header.get("epk")
    if not isinstance(epk, dict) or epk.get("kty") != "EC" or epk.get("crv") != "P-256":
        raise ResponseDecryptionError("JWE epk must be an EC P-256 public key")

    try:
        apu = _b64url_decode(header["apu"]) if "apu" in header else b""
        apv = _b64url_decode(header["apv"]) if "apv" in header else b""
        plaintext = EcdhEs(enc, apu, apv).decrypt_direct(
            enc,
            Key.from_jwk(epk),
            key,
            _b64url_decode(ciphertext_b64),
            nonce=_b64url_decode(iv_b64),
            tag=_b64url_decode(tag_b64),
            aad=protected_b64.encode("ascii"),
        )
        payload = json.loads(plaintext)
    except Exception as err:
        raise ResponseDecryptionError("Could not decrypt the JWE response") from err

    if not isinstance(payload, dict):
        raise ResponseDecryptionError("Decrypted response is not a JSON object")
    return payload
