"""Minimal JOSE helpers: JWS verification against a JWK, RFC 7638 thumbprints, JWKS.

ACA-Py's ``jwt_verify`` resolves keys through the wallet and askar, which only
supports EdDSA and ES256. Tokens issued by an external authorization server
(e.g. Keycloak, RS256 by default) and DPoP proofs (any asymmetric algorithm)
need a verifier that works from a bare public JWK; this module provides one on
top of ``cryptography``.
"""

import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Any, Mapping, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

LOGGER = logging.getLogger(__name__)

# Asymmetric JWS algorithms accepted for externally issued JWTs and proofs.
ASYMMETRIC_ALGS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
        "Ed25519",
    }
)

_HASHES = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
_EC_CURVES = {
    "P-256": (ec.SECP256R1, 32),
    "P-384": (ec.SECP384R1, 48),
    "P-521": (ec.SECP521R1, 66),
}
_EC_ALG_CURVE = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}

# JWK members that only appear in private keys.
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


class JoseError(ValueError):
    """Raised when a JWS cannot be parsed or verified."""


def b64url_decode(value: str) -> bytes:
    """Decode unpadded base64url."""
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as err:
        raise JoseError("invalid base64url encoding") from err


def b64url_encode(value: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def decode_jws(token: str) -> Tuple[dict, dict, bytes, bytes]:
    """Split a compact JWS into (header, payload, signing_input, signature).

    Does not verify anything.
    """
    if not isinstance(token, str):
        raise JoseError("JWS must be a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise JoseError("JWS must have three parts")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        raise JoseError("JWS header or payload is not JSON") from err
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JoseError("JWS header and payload must be JSON objects")
    return header, payload, f"{parts[0]}.{parts[1]}".encode(), b64url_decode(parts[2])


def _int(value: str) -> int:
    return int.from_bytes(b64url_decode(value), "big")


def public_key_from_jwk(jwk: Mapping[str, Any]):
    """Build a ``cryptography`` public key from a public JWK."""
    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            return rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
        if kty == "EC":
            curve_cls, _ = _EC_CURVES[jwk["crv"]]
            return ec.EllipticCurvePublicNumbers(
                _int(jwk["x"]), _int(jwk["y"]), curve_cls()
            ).public_key()
        if kty == "OKP":
            raw = b64url_decode(jwk["x"])
            if jwk.get("crv") == "Ed25519":
                return ed25519.Ed25519PublicKey.from_public_bytes(raw)
            if jwk.get("crv") == "Ed448":
                return ed448.Ed448PublicKey.from_public_bytes(raw)
    except (KeyError, ValueError) as err:
        raise JoseError(f"invalid {kty} JWK") from err
    raise JoseError(f"unsupported JWK kty/crv: {kty}/{jwk.get('crv')}")


def verify_signature(
    alg: str, jwk: Mapping[str, Any], signing_input: bytes, signature: bytes
) -> bool:
    """Verify a JWS signature with the given public JWK."""
    if alg not in ASYMMETRIC_ALGS:
        raise JoseError(f"unsupported alg: {alg}")
    key = public_key_from_jwk(jwk)
    try:
        if alg.startswith(("RS", "PS")):
            if not isinstance(key, rsa.RSAPublicKey):
                raise JoseError(f"{alg} requires an RSA key")
            hash_alg = _HASHES[alg[2:]]()
            pad = (
                padding.PKCS1v15()
                if alg.startswith("RS")
                else padding.PSS(
                    mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size
                )
            )
            key.verify(signature, signing_input, pad, hash_alg)
        elif alg.startswith("ES"):
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise JoseError(f"{alg} requires an EC key")
            if jwk.get("crv") != _EC_ALG_CURVE[alg]:
                raise JoseError(f"{alg} requires curve {_EC_ALG_CURVE[alg]}")
            size = _EC_CURVES[jwk["crv"]][1]
            if len(signature) != 2 * size:
                return False
            der = encode_dss_signature(
                int.from_bytes(signature[:size], "big"),
                int.from_bytes(signature[size:], "big"),
            )
            key.verify(der, signing_input, ec.ECDSA(_HASHES[alg[2:]]()))
        else:  # EdDSA / Ed25519
            if not isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                raise JoseError(f"{alg} requires an OKP key")
            key.verify(signature, signing_input)
    except InvalidSignature:
        return False
    return True


def verify_jws(
    token: str, jwk: Mapping[str, Any], allowed_algs=ASYMMETRIC_ALGS
) -> Tuple[dict, dict]:
    """Verify a compact JWS against a JWK; return (header, payload)."""
    header, payload, signing_input, signature = decode_jws(token)
    alg = header.get("alg")
    if alg not in allowed_algs:
        raise JoseError(f"alg not allowed: {alg}")
    if not verify_signature(alg, jwk, signing_input, signature):
        raise JoseError("invalid signature")
    return header, payload


HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def verify_hmac_jws(token: str, secret: str) -> Tuple[dict, dict]:
    """Verify an HMAC-signed compact JWS (``client_secret_jwt``)."""
    header, payload, signing_input, signature = decode_jws(token)
    digest = HMAC_ALGS.get(header.get("alg"))
    if digest is None:
        raise JoseError(f"alg not allowed: {header.get('alg')}")
    expected = hmac.new(secret.encode(), signing_input, digest).digest()
    if not hmac.compare_digest(expected, signature):
        raise JoseError("invalid signature")
    return header, payload


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """Compute the RFC 7638 SHA-256 JWK thumbprint (base64url)."""
    kty = jwk.get("kty")
    if kty == "RSA":
        members = ("e", "kty", "n")
    elif kty == "EC":
        members = ("crv", "kty", "x", "y")
    elif kty == "OKP":
        members = ("crv", "kty", "x")
    else:
        raise JoseError(f"unsupported JWK kty: {kty}")
    try:
        canonical = {m: jwk[m] for m in members}
    except KeyError as err:
        raise JoseError(f"JWK missing required member {err}") from err
    data = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
    return b64url_encode(hashlib.sha256(data).digest())


def check_time_claims(payload: Mapping[str, Any], leeway: int = 30) -> None:
    """Validate exp/nbf (exp required)."""
    now = time.time()
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        raise JoseError("token has no exp")
    if exp + leeway < now:
        raise JoseError("token expired")
    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and nbf - leeway > now:
        raise JoseError("token not yet valid")


def audience_matches(aud: Any, expected: str) -> bool:
    """Return True if ``expected`` is (one of) the token audience(s)."""
    if isinstance(aud, str):
        return aud == expected
    if isinstance(aud, list):
        return expected in aud
    return False


class JWKSCache:
    """Small async JWKS cache keyed by JWKS URI.

    Keys are refetched after ``ttl`` seconds, or immediately (rate limited) when
    a token references an unknown ``kid`` to pick up key rotation.
    """

    def __init__(self, ttl: int = 300, min_refresh_interval: int = 10):
        """Initialize the cache."""
        self.ttl = ttl
        self.min_refresh_interval = min_refresh_interval
        self._entries: dict[str, tuple[float, list[dict]]] = {}

    async def _fetch(self, jwks_uri: str) -> list[dict]:
        from .app_resources import AppResources  # noqa: PLC0415

        resp = await AppResources.get_http_client().get(jwks_uri)
        if resp.status != 200:
            raise JoseError(f"JWKS fetch from {jwks_uri} failed: HTTP {resp.status}")
        body = await resp.json(content_type=None)
        keys = body.get("keys") if isinstance(body, dict) else None
        if not isinstance(keys, list):
            raise JoseError(f"JWKS at {jwks_uri} has no keys")
        self._entries[jwks_uri] = (time.monotonic(), keys)
        return keys

    @staticmethod
    def _select(keys: list[dict], kid: str | None, alg: str | None) -> dict | None:
        candidates = [
            k
            for k in keys
            if k.get("use", "sig") == "sig"
            and (kid is None or k.get("kid") == kid)
            and (alg is None or k.get("alg") in (None, alg))
        ]
        if not candidates or (kid is None and len(candidates) > 1):
            return None
        return candidates[0]

    async def get_key(self, jwks_uri: str, kid: str | None, alg: str | None) -> dict:
        """Return the JWK for ``kid`` from ``jwks_uri``."""
        entry = self._entries.get(jwks_uri)
        now = time.monotonic()
        if entry is None or now - entry[0] > self.ttl:
            keys = await self._fetch(jwks_uri)
        else:
            keys = entry[1]
        key = self._select(keys, kid, alg)
        stale = entry is not None and now - entry[0] > self.min_refresh_interval
        if key is None and stale:
            key = self._select(await self._fetch(jwks_uri), kid, alg)
        if key is None:
            raise JoseError(f"no matching key in JWKS for kid {kid!r}")
        return key

    async def verify(self, jwks_uri: str, token: str) -> Tuple[dict, dict]:
        """Verify ``token`` against the JWKS at ``jwks_uri``."""
        header, _, _, _ = decode_jws(token)
        key = await self.get_key(jwks_uri, header.get("kid"), header.get("alg"))
        return verify_jws(token, key)


class ReplayCache:
    """In-memory single-use identifier cache (per process).

    Deployments with several plugin instances behind a load balancer need
    shared storage for full replay protection; within one instance this is exact.
    """

    def __init__(self, max_entries: int = 100_000):
        """Initialize the cache."""
        self.max_entries = max_entries
        self._seen: dict[str, float] = {}

    def check_and_add(self, value: str, expires_at: float) -> bool:
        """Record ``value``; return False if it was already seen and not expired."""
        now = time.time()
        if len(self._seen) >= self.max_entries:
            self._seen = {k: v for k, v in self._seen.items() if v > now}
        seen_until = self._seen.get(value)
        if seen_until is not None and seen_until > now:
            return False
        self._seen[value] = expires_at
        return True
