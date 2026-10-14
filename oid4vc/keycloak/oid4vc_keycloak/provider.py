"""Keycloak as the wallet-facing authorization server.

Keycloak (with the extension in ``oid4vc/keycloak/extension``) serves the
pre-authorized code token request: it authenticates the wallet with
attestation-based client authentication (ABCA), requires a DPoP proof, and
redeems the plugin-issued code through the redeem endpoint on the plugin's
admin API. The plugin validates the resulting access tokens locally against
the realm JWKS.

Authorization server entry settings::

    {
      "type": "keycloak",
      "public_url": "https://kc.example.com/realms/oid4vci",   # realm issuer
      "private_url": "http://keycloak:8080/realms/oid4vci",    # optional, for JWKS
      "jwks_uri": "...",   # optional, default {private_url}/protocol/openid-connect/certs
      "issuer": "...",     # optional, expected iss (default public_url)
      "audience": "...",   # optional, expected aud (default credential issuer URL)
      "refresh_id_claim": "refresh_id",   # optional
      "require_dpop": true,               # optional
      "redeem_client": {                  # optional: redeem call authentication
        "auth_method": "private_key_jwt", # | client_secret_jwt | client_secret_post
        "client_id": "...",               # default: the realm issuer
        "client_secret": "...",           # for the client_secret_* methods
        "jwks_uri": "...",                # default: the realm JWKS
        "audience": "..."                 # default: the redeem URL as received
      }
    }
"""

import logging
from typing import Any, Mapping, Optional

from oid4vc.auth_providers import (
    AuthContext,
    AuthServerConfigError,
    AuthServerProvider,
    InvalidTokenError,
)
from oid4vc.auth_providers.client_auth import (
    PRIVATE_KEY_JWT,
    BackChannelClient,
    authenticate_client,
)
from oid4vc.jose_util import (
    JoseError,
    JWKSCache,
    ReplayCache,
    audience_matches,
    check_time_claims,
)
from oid4vc.jwt import JWTVerifyResult

LOGGER = logging.getLogger(__name__)


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

        if payload.get("iss") != self._issuer(ctx):
            raise InvalidTokenError("Token issuer mismatch")
        audience = ctx.setting("audience", ctx.issuer_url)
        if not audience_matches(payload.get("aud"), audience):
            raise InvalidTokenError("Token audience mismatch")
        if not self.exchange_key(ctx, payload):
            raise InvalidTokenError("Token does not reference a credential exchange")
        return JWTVerifyResult(headers=header, payload=payload, verified=True)

    def redeem_client(self, ctx: AuthContext) -> BackChannelClient:
        """Expected client authentication for redeem calls from this realm."""
        conf = ctx.setting("redeem_client", {}) or {}
        return BackChannelClient(
            client_id=conf.get("client_id") or self._issuer(ctx),
            auth_method=conf.get("auth_method") or PRIVATE_KEY_JWT,
            client_secret=conf.get("client_secret"),
            jwks_uri=conf.get("jwks_uri") or self._jwks_uri(ctx),
            audience=conf.get("audience"),
        )

    async def authenticate_back_channel(
        self,
        ctx: AuthContext,
        params: Mapping[str, str],
        endpoint_url: str,
    ) -> None:
        """Authenticate a redeem call from the realm (RFC 7523 client auth)."""
        await authenticate_client(
            self.redeem_client(ctx),
            params,
            endpoint_url,
            jwks_cache=self._jwks,
            replay_cache=self._redeem_jtis,
        )
