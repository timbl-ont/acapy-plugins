"""Keycloak as the wallet-facing authorization server.

Keycloak (with the extension in ``oid4vc/keycloak/extension``) serves the
pre-authorized code token request: it authenticates the wallet with
attestation-based client authentication (ABCA), requires a DPoP proof, and
redeems the plugin-issued code through the plugin's back-channel redeem
endpoint. The plugin validates the resulting access tokens locally against the
realm JWKS.

Authorization server entry settings::

    {
      "type": "keycloak",
      "public_url": "https://kc.example.com/realms/oid4vci",   # realm issuer
      "private_url": "http://keycloak:8080/realms/oid4vci",    # optional, for JWKS
      "jwks_uri": "...",   # optional, default {private_url}/protocol/openid-connect/certs
      "issuer": "...",     # optional, expected iss (default public_url)
      "audience": "...",   # optional, expected aud (default credential issuer URL)
      "refresh_id_claim": "refresh_id",   # optional
      "require_dpop": true         # optional
    }
"""

import logging
import time
from typing import Any, Mapping, Optional

from aiohttp import web

from oid4vc.auth_providers import (
    AuthContext,
    AuthServerConfigError,
    AuthServerProvider,
    BackChannelAuthError,
    InvalidTokenError,
)
from oid4vc.jose_util import (
    JoseError,
    JWKSCache,
    ReplayCache,
    audience_matches,
    check_time_claims,
    decode_jws,
)
from oid4vc.jwt import JWTVerifyResult

LOGGER = logging.getLogger(__name__)

# JWS typ of the assertion Keycloak signs for back-channel redeem requests.
REDEEM_ASSERTION_TYP = "oid4vci-redeem+jwt"
# Maximum lifetime accepted for a redeem assertion (seconds).
REDEEM_ASSERTION_MAX_LIFETIME = 300


class KeycloakProvider(AuthServerProvider):
    """Keycloak realm as the authorization server."""

    type = "keycloak"
    supports_redeem = True

    def __init__(self, jwks_cache: Optional[JWKSCache] = None):
        """Initialize the provider."""
        self._jwks = jwks_cache or JWKSCache()
        self._redeem_jtis = ReplayCache()

    @staticmethod
    def _public_url(ctx: AuthContext) -> str:
        public_url = ctx.setting("public_url")
        if not public_url:
            raise AuthServerConfigError(
                "Keycloak authorization server entry needs public_url (the realm issuer)"
            )
        return public_url.rstrip("/")

    def _issuer(self, ctx: AuthContext) -> str:
        return ctx.setting("issuer", self._public_url(ctx))

    def _jwks_uri(self, ctx: AuthContext) -> str:
        base = (ctx.setting("private_url") or self._public_url(ctx)).rstrip("/")
        return ctx.setting("jwks_uri", f"{base}/protocol/openid-connect/certs")

    async def _verify_realm_jwt(self, ctx: AuthContext, token: str):
        return await self._jwks.verify(self._jwks_uri(ctx), token)

    def authorization_servers(self, ctx: AuthContext) -> Optional[list[str]]:
        """Advertise the realm as the authorization server."""
        return [self._public_url(ctx)]

    def require_dpop(self, ctx: AuthContext) -> bool:
        """DPoP-bound tokens are required unless disabled."""
        return bool(ctx.setting("require_dpop", True))

    def exchange_key(self, ctx: AuthContext, payload: Mapping[str, Any]) -> Optional[str]:
        """The exchange is identified by a session-note claim, not ``sub``."""
        return payload.get(ctx.setting("refresh_id_claim", "refresh_id"))

    async def validate_access_token(
        self, ctx: AuthContext, token: str
    ) -> JWTVerifyResult:
        """Validate a Keycloak access token against the realm JWKS."""
        try:
            header, payload = await self._verify_realm_jwt(ctx, token)
            check_time_claims(payload)
        except JoseError as err:
            LOGGER.info("Keycloak access token rejected: %s", err)
            raise InvalidTokenError("Token verification failed") from err

        if header.get("typ") == REDEEM_ASSERTION_TYP:
            raise InvalidTokenError("Not an access token")
        if payload.get("iss") != self._issuer(ctx):
            raise InvalidTokenError("Token issuer mismatch")
        audience = ctx.setting("audience", ctx.issuer_url)
        if not audience_matches(payload.get("aud"), audience):
            raise InvalidTokenError("Token audience mismatch")
        if not self.exchange_key(ctx, payload):
            raise InvalidTokenError("Token does not reference a credential exchange")
        return JWTVerifyResult(headers=header, payload=payload, verified=True)

    async def authenticate_back_channel(
        self, ctx: AuthContext, request: web.Request
    ) -> None:
        """Verify the realm-signed assertion on a redeem request.

        ``Authorization: Bearer <jwt>`` with ``typ`` = ``oid4vci-redeem+jwt``,
        ``iss`` = realm issuer, ``aud`` = credential issuer identifier, short
        ``exp`` and a single-use ``jti``.
        """
        auth = request.headers.get("Authorization", "")
        scheme, _, assertion = auth.partition(" ")
        if scheme.lower() != "bearer" or not assertion:
            raise BackChannelAuthError("missing bearer assertion")
        try:
            header, _, _, _ = decode_jws(assertion)
            if header.get("typ") != REDEEM_ASSERTION_TYP:
                raise BackChannelAuthError(f"assertion typ is not {REDEEM_ASSERTION_TYP}")
            _, payload = await self._verify_realm_jwt(ctx, assertion)
            check_time_claims(payload, leeway=10)
        except JoseError as err:
            raise BackChannelAuthError(f"invalid assertion: {err}") from err

        if payload.get("iss") != self._issuer(ctx):
            raise BackChannelAuthError("assertion issuer mismatch")
        if not audience_matches(payload.get("aud"), ctx.issuer_url):
            raise BackChannelAuthError("assertion audience mismatch")
        iat = payload.get("iat")
        if (
            not isinstance(iat, (int, float))
            or payload["exp"] - iat > REDEEM_ASSERTION_MAX_LIFETIME
            or iat > time.time() + 10
        ):
            raise BackChannelAuthError("assertion lifetime is not acceptable")
        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti:
            raise BackChannelAuthError("assertion has no jti")
        if not self._redeem_jtis.check_and_add(jti, payload["exp"] + 10):
            raise BackChannelAuthError("assertion jti replayed")
