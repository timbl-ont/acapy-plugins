import importlib
import json
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web

from oid4vc.auth_providers import AuthContext, AuthServerProvider, BackChannelAuthError
from oid4vc.jose_util import jwk_thumbprint
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential

from ..jose_helpers import dpop_proof, ec_key, public_jwk

_redeem_module = importlib.import_module("oid4vc.public_routes.redeem")
_token_module = importlib.import_module("oid4vc.public_routes.token")


class _RedeemingProvider(AuthServerProvider):
    type = "test-redeem"
    supports_redeem = True

    def __init__(self, authenticated=True):
        self.authenticated = authenticated

    async def authenticate_back_channel(self, ctx, request):
        if not self.authenticated:
            raise BackChannelAuthError("nope")


def _request(context, body=None, headers=None, path="/oid4vci/pre-auth/redeem"):
    request = MagicMock()
    request.__getitem__ = lambda _, k: {"context": context}[k]
    request.headers = headers or {}
    request.path = path
    request.json = AsyncMock(return_value=body or {})
    return request


async def _offer(context, pin=None):
    async with context.profile.session() as session:
        supported = SupportedCredential(format="jwt_vc_json", identifier="MyCred")
        await supported.save(session)
        record = OID4VCIExchangeRecord(
            state=OID4VCIExchangeRecord.STATE_OFFER_CREATED,
            verification_method="did:example:123#k",
            issuer_id="did:example:123",
            supported_cred_id=supported.supported_cred_id,
            credential_subject={"name": "alice"},
            code="code-xyz",
            pin=pin,
        )
        await record.save(session)
    return record


def _use_provider(monkeypatch, context, provider):
    monkeypatch.setattr(
        _redeem_module,
        "resolve_auth_provider",
        AsyncMock(return_value=(provider, AuthContext(context.profile, MagicMock(), {}))),
    )


@pytest.mark.asyncio
async def test_redeem_success(monkeypatch, context):
    record = await _offer(context, pin="4321")
    _use_provider(monkeypatch, context, _RedeemingProvider())
    resp = await _redeem_module.redeem_pre_auth_code_route(
        cast(
            web.Request,
            _request(
                context,
                {"pre_authorized_code": "code-xyz", "tx_code": "4321", "client_id": "w"},
            ),
        )
    )
    body = json.loads(resp.body)
    assert resp.status == 200
    assert body["refresh_id"] == record.refresh_id
    assert body["credential_configuration_ids"] == ["MyCred"]

    # Single use
    resp = await _redeem_module.redeem_pre_auth_code_route(
        cast(
            web.Request,
            _request(context, {"pre_authorized_code": "code-xyz", "tx_code": "4321"}),
        )
    )
    assert resp.status == 400
    assert json.loads(resp.body)["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_redeem_unauthenticated(monkeypatch, context):
    await _offer(context)
    _use_provider(monkeypatch, context, _RedeemingProvider(authenticated=False))
    resp = await _redeem_module.redeem_pre_auth_code_route(
        cast(web.Request, _request(context, {"pre_authorized_code": "code-xyz"}))
    )
    assert resp.status == 401
    # The code was not consumed
    async with context.profile.session() as session:
        rec = await OID4VCIExchangeRecord.retrieve_by_code(session, "code-xyz")
    assert rec.code_redeemed_at is None


@pytest.mark.asyncio
async def test_redeem_not_available_for_builtin(context):
    # No authorization server configured -> built-in provider -> no redeem endpoint
    with pytest.raises(web.HTTPNotFound):
        await _redeem_module.redeem_pre_auth_code_route(
            cast(web.Request, _request(context, {"pre_authorized_code": "x"}))
        )


@pytest.mark.asyncio
async def test_builtin_token_binds_dpop(monkeypatch, context):
    record = await _offer(context)
    sign = AsyncMock(return_value="tok")
    monkeypatch.setattr(_token_module, "jwt_sign", sign)
    monkeypatch.setattr(
        _token_module,
        "retrieve_or_create_did_jwk",
        AsyncMock(return_value=MagicMock(did="did:jwk:fake")),
    )
    key = ec_key()
    request = _request(
        context,
        headers={"DPoP": dpop_proof(key, htu="http://localhost:8020/token")},
        path="/token",
    )
    request.post = AsyncMock(
        return_value={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": record.code,
        }
    )
    resp = await _token_module.token(cast(web.Request, request))
    body = json.loads(resp.body)
    assert resp.status == 200
    assert body["token_type"] == "DPoP"
    payload = sign.call_args.kwargs["payload"]
    assert payload["cnf"] == {"jkt": jwk_thumbprint(public_jwk(key))}


@pytest.mark.asyncio
async def test_builtin_token_invalid_dpop_keeps_code(monkeypatch, context):
    record = await _offer(context)
    request = _request(
        context,
        headers={"DPoP": dpop_proof(ec_key(), htu="https://elsewhere.example/token")},
        path="/token",
    )
    request.post = AsyncMock(
        return_value={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": record.code,
        }
    )
    resp = await _token_module.token(cast(web.Request, request))
    assert resp.status == 400
    assert json.loads(resp.body)["error"] == "invalid_dpop_proof"
    async with context.profile.session() as session:
        rec = await OID4VCIExchangeRecord.retrieve_by_code(session, record.code)
    assert rec.code_redeemed_at is None
