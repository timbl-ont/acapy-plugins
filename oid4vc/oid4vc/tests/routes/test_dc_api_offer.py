"""Tests for the DC-API credential offer route (get_dc_api_cred_offer)."""

import json
from unittest.mock import MagicMock

import pytest
from aiohttp import web

from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.public_routes.metadata import (
    credential_issuer_metadata,
    openid_configuration,
)
from oid4vc.routes.credential_offer import get_dc_api_cred_offer

PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


class Request:
    """Minimal stand-in for an aiohttp request."""

    def __init__(self, context, query=None):
        self._context = context
        self.query = query or {}
        self.match_info = {}
        self.headers = {}
        self.method = "GET"
        self.path = "/oid4vci/dc-api/credential-offer"

    def __getitem__(self, key):
        if key == "context":
            return self._context
        raise KeyError(key)


async def _exchange(context, state=OID4VCIExchangeRecord.STATE_CREATED) -> str:
    supported = SupportedCredential(
        format="jwt_vc_json",
        identifier="UniversityDegree",
        format_data={
            "credentialSubject": {"name": "alice"},
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        },
    )
    async with context.profile.session() as session:
        await supported.save(session)
        exchange = OID4VCIExchangeRecord(
            state=state,
            verification_method="did:example:issuer#0",
            issuer_id="did:example:issuer",
            supported_cred_id=supported.supported_cred_id,
            credential_subject={"name": "alice"},
            refresh_id="refresh-1",
        )
        await exchange.save(session)
    return exchange.exchange_id


async def _offer(context, exchange_id) -> dict:
    resp = await get_dc_api_cred_offer(Request(context, {"exchange_id": exchange_id}))
    return json.loads(resp.body)


@pytest.mark.asyncio
async def test_dc_api_offer(context):
    body = await _offer(context, await _exchange(context))

    assert body["protocol"] == "openid4vci-v1"
    data = body["data"]
    assert data["credential_configuration_ids"] == ["UniversityDegree"]
    assert data["grants"][PRE_AUTH]["pre-authorized_code"]

    issuer_md = data["credential_issuer_metadata"]
    assert issuer_md["credential_issuer"] == data["credential_issuer"]
    assert issuer_md["credential_endpoint"] == data["credential_issuer"] + "/credential"
    assert "UniversityDegree" in issuer_md["credential_configurations_supported"]

    # ACA-Py is its own authorization server here, so its metadata is embedded.
    as_md = data["authorization_server_metadata"]
    assert as_md["token_endpoint"] == data["credential_issuer"] + "/token"
    assert PRE_AUTH in as_md["grant_types_supported"]


@pytest.mark.asyncio
async def test_embedded_metadata_matches_well_known(context):
    """By value must equal what wallets would fetch from /.well-known/."""
    data = (await _offer(context, await _exchange(context)))["data"]

    issuer_resp = await credential_issuer_metadata(Request(context))
    as_resp = await openid_configuration(Request(context))
    assert data["credential_issuer_metadata"] == json.loads(issuer_resp.body)
    assert data["authorization_server_metadata"] == json.loads(as_resp.body)


@pytest.mark.asyncio
async def test_external_auth_server(monkeypatch, context):
    """With an external AS, only authorization_servers is conveyed."""
    provider = MagicMock(serves_token_endpoint=False)
    provider.authorization_servers.return_value = ["https://as.example"]
    monkeypatch.setattr(
        "oid4vc.public_routes.metadata._auth_provider",
        lambda profile, issuer_config: (provider, MagicMock()),
    )

    data = (await _offer(context, await _exchange(context)))["data"]
    assert "authorization_server_metadata" not in data
    issuer_md = data["credential_issuer_metadata"]
    assert issuer_md["authorization_servers"] == ["https://as.example"]
    assert "token_endpoint" not in issuer_md


@pytest.mark.asyncio
async def test_used_exchange_rejected(context):
    exchange_id = await _exchange(context, OID4VCIExchangeRecord.STATE_ISSUED)
    with pytest.raises(web.HTTPBadRequest):
        await _offer(context, exchange_id)
