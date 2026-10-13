import time
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from oid4vc.auth_providers import AuthContext, BackChannelAuthError, InvalidTokenError
from oid4vc.jose_util import JWKSCache
from oid4vc.tests.jose_helpers import public_jwk, rsa_key, sign

from oid4vc_keycloak.provider import REDEEM_ASSERTION_TYP, KeycloakProvider

REALM = "https://kc.example/realms/oid4vci"
ISSUER = "https://issuer.example"
JWKS_URI = "http://keycloak:8080/realms/oid4vci/protocol/openid-connect/certs"


@pytest.fixture
def realm_key():
    return rsa_key()


@pytest.fixture
def provider(realm_key):
    cache = JWKSCache()
    jwk = {**public_jwk(realm_key), "kid": "realm-1", "alg": "RS256", "use": "sig"}
    cache._entries[JWKS_URI] = (time.monotonic(), [jwk])
    return KeycloakProvider(jwks_cache=cache)


@pytest.fixture
def ctx():
    profile = SimpleNamespace(settings={})
    return AuthContext(
        profile,
        MagicMock(endpoint=ISSUER),
        {
            "type": "keycloak",
            "public_url": REALM,
            "private_url": "http://keycloak:8080/realms/oid4vci",
        },
    )


def _token(key, typ="JWT", **claims):
    payload = {
        "iss": REALM,
        "aud": [ISSUER, "account"],
        "exp": int(time.time()) + 60,
        "iat": int(time.time()),
        "sub": "generic-holder",
        "refresh_id": "refresh-1",
        "cnf": {"jkt": "thumb"},
        **claims,
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    return sign({"typ": typ, "kid": "realm-1"}, payload, key, "RS256")


@pytest.mark.asyncio
async def test_valid_access_token(provider, ctx, realm_key):
    result = await provider.validate_access_token(ctx, _token(realm_key))
    assert result.verified
    assert provider.exchange_key(ctx, result.payload) == "refresh-1"
    assert provider.require_dpop(ctx)
    assert provider.authorization_servers(ctx) == [REALM]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://evil.example/realms/x"},
        {"aud": "https://other-issuer.example"},
        {"exp": int(time.time()) - 3600},
        {"refresh_id": None},
    ],
)
async def test_rejected_access_tokens(provider, ctx, realm_key, claims):
    with pytest.raises(InvalidTokenError):
        await provider.validate_access_token(ctx, _token(realm_key, **claims))


@pytest.mark.asyncio
async def test_token_signed_by_other_key(provider, ctx):
    with pytest.raises(InvalidTokenError):
        await provider.validate_access_token(ctx, _token(rsa_key()))


@pytest.mark.asyncio
async def test_redeem_assertion_is_not_an_access_token(provider, ctx, realm_key):
    with pytest.raises(InvalidTokenError):
        await provider.validate_access_token(
            ctx, _token(realm_key, typ=REDEEM_ASSERTION_TYP)
        )


@pytest.mark.asyncio
async def test_custom_claim_and_dpop_settings(provider, realm_key):
    ctx = AuthContext(
        SimpleNamespace(settings={}),
        MagicMock(endpoint=ISSUER),
        {
            "type": "keycloak",
            "public_url": REALM,
            "jwks_uri": JWKS_URI,
            "refresh_id_claim": "exchange",
            "require_dpop": False,
        },
    )
    result = await provider.validate_access_token(
        ctx, _token(realm_key, refresh_id=None, exchange="ex-9")
    )
    assert provider.exchange_key(ctx, result.payload) == "ex-9"
    assert not provider.require_dpop(ctx)


def _assertion(key, **claims):
    now = int(time.time())
    payload = {
        "iss": REALM,
        "aud": ISSUER,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
        **claims,
    }
    return sign({"typ": REDEEM_ASSERTION_TYP, "kid": "realm-1"}, payload, key, "RS256")


def _req(assertion):
    return SimpleNamespace(headers={"Authorization": f"Bearer {assertion}"})


@pytest.mark.asyncio
async def test_back_channel_auth(provider, ctx, realm_key):
    assertion = _assertion(realm_key)
    await provider.authenticate_back_channel(ctx, _req(assertion))
    with pytest.raises(BackChannelAuthError, match="replayed"):
        await provider.authenticate_back_channel(ctx, _req(assertion))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "https://other-issuer.example"},
        {"iss": "https://evil.example"},
        {"exp": int(time.time()) + 3600},
        {"jti": None},
    ],
)
async def test_back_channel_auth_rejected(provider, ctx, realm_key, claims):
    assertion = _assertion(realm_key, **claims)
    with pytest.raises(BackChannelAuthError):
        await provider.authenticate_back_channel(ctx, _req(assertion))


@pytest.mark.asyncio
async def test_back_channel_auth_requires_assertion_typ(provider, ctx, realm_key):
    with pytest.raises(BackChannelAuthError):
        await provider.authenticate_back_channel(ctx, _req(_token(realm_key)))
    with pytest.raises(BackChannelAuthError):
        await provider.authenticate_back_channel(ctx, SimpleNamespace(headers={}))
