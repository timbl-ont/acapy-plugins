"""Tests for the OID4VP DC-API request route (create_oid4vp_dc_api_request).

Covers the OpenID4VP 1.0 Appendix A request built for the W3C Digital
Credentials API: DCQL only, Response Mode ``dc_api.jwt`` with a per-request
encryption key, unsigned (client_id omitted) and signed (JAR, x509_san_dns)
variants, the ``origin:`` response audience, and the mdoc fail-closed rule.
"""

import json
from typing import cast
from unittest.mock import AsyncMock

import pytest
from acapy_agent.storage.base import BaseStorage, StorageRecord
from aiohttp import web

from oid4vc.dc_api import RESPONSE_KEY_RECORD_TYPE
from oid4vc.models.dcql_query import DCQLQuery
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.routes.vp_request import (
    X509_IDENTITY_RECORD_ID,
    X509_IDENTITY_RECORD_TYPE,
    create_oid4vp_dc_api_request,
)

VP_FORMATS = {
    "dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"]}
}
ORIGIN = "https://verifier.example"
SD_JWT_QUERY = [{"id": "pid", "format": "dc+sd-jwt"}]


async def _save_dcql(context, credentials) -> str:
    query = DCQLQuery.deserialize({"credentials": credentials})
    async with context.profile.session() as session:
        await query.save(session=session)
    return query.dcql_query_id


async def _store_x509_identity(context):
    value = json.dumps(
        {
            "cert_chain": ["MIIBfakecert"],
            "verification_method": "did:jwk:fake#0",
            "client_id": "verifier.example",
        }
    )
    async with context.profile.session() as session:
        await session.inject(BaseStorage).add_record(
            StorageRecord(
                type=X509_IDENTITY_RECORD_TYPE, id=X509_IDENTITY_RECORD_ID, value=value
            )
        )


async def _call(dummy_request, body):
    resp = await create_oid4vp_dc_api_request(
        cast(web.Request, dummy_request(json_data=body))
    )
    return json.loads(resp.body)


@pytest.mark.asyncio
async def test_unsigned_request(context, dummy_request):
    dcql_id = await _save_dcql(context, SD_JWT_QUERY)
    body = await _call(
        dummy_request,
        {
            "dcql_query_id": dcql_id,
            "vp_formats": VP_FORMATS,
            "expected_origins": [ORIGIN],
        },
    )

    assert body["protocol"] == "openid4vp-v1-unsigned"
    assert "client_id" not in body  # A.2: omitted for unsigned requests
    data = body["request"]
    assert data["response_type"] == "vp_token"
    assert data["response_mode"] == "dc_api.jwt"
    assert data["nonce"] == body["nonce"]
    assert data["dcql_query"]["credentials"][0]["id"] == "pid"
    for absent in ("client_id", "response_uri", "state", "presentation_definition"):
        assert absent not in data

    metadata = data["client_metadata"]
    assert metadata["vp_formats_supported"] == VP_FORMATS
    assert metadata["encrypted_response_enc_values_supported"] == ["A128GCM", "A256GCM"]
    (jwk,) = metadata["jwks"]["keys"]
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256"
    assert jwk["use"] == "enc" and jwk["alg"] == "ECDH-ES" and jwk["kid"]
    assert "d" not in jwk  # never leak the private key

    # The response audience is stored for later KB-JWT aud checks (A.4) and the
    # private key is stored server-side, keyed by presentation id.
    async with context.profile.session() as session:
        record = await OID4VPPresentation.retrieve_by_id(session, body["presentation_id"])
        key_record = await session.inject(BaseStorage).get_record(
            RESPONSE_KEY_RECORD_TYPE, body["presentation_id"]
        )
    assert record.client_id == f"origin:{ORIGIN}"
    assert record.nonce == body["nonce"]
    assert json.loads(key_record.value)["kid"] == jwk["kid"]
    assert body["response_uri"].endswith(f"/oid4vp/response/{body['presentation_id']}")


@pytest.mark.asyncio
async def test_signed_request(monkeypatch, context, dummy_request):
    await _store_x509_identity(context)
    dcql_id = await _save_dcql(context, SD_JWT_QUERY)
    jwt_sign = AsyncMock(return_value="eyJ.signed.jar")
    monkeypatch.setattr("oid4vc.routes.vp_request.jwt_sign", jwt_sign)

    body = await _call(
        dummy_request,
        {
            "dcql_query_id": dcql_id,
            "vp_formats": VP_FORMATS,
            "signed": True,
            "expected_origins": [ORIGIN + "/"],
        },
    )

    assert body["protocol"] == "openid4vp-v1-signed"
    assert body["client_id"] == "x509_san_dns:verifier.example"
    assert body["request"] == {"request": "eyJ.signed.jar"}  # A.3.2.1

    payload = jwt_sign.call_args.kwargs["payload"]
    assert payload["client_id"] == "x509_san_dns:verifier.example"
    assert payload["aud"] == "https://self-issued.me/v2"  # Section 5.8
    assert payload["response_mode"] == "dc_api.jwt"
    assert payload["expected_origins"] == [ORIGIN]  # normalized
    assert payload["client_metadata"]["jwks"]["keys"][0]["alg"] == "ECDH-ES"
    assert "response_uri" not in payload and "state" not in payload
    headers = jwt_sign.call_args.kwargs["headers"]
    assert headers["typ"] == "oauth-authz-req+jwt"
    assert headers["x5c"] == ["MIIBfakecert"]

    # Even for signed requests the response audience is the origin (A.4), not
    # the x509_san_dns client_id.
    async with context.profile.session() as session:
        record = await OID4VPPresentation.retrieve_by_id(session, body["presentation_id"])
    assert record.client_id == f"origin:{ORIGIN}"


@pytest.mark.asyncio
async def test_signed_requires_x509_identity(context, dummy_request):
    dcql_id = await _save_dcql(context, SD_JWT_QUERY)
    with pytest.raises(web.HTTPBadRequest):
        await _call(
            dummy_request,
            {
                "dcql_query_id": dcql_id,
                "vp_formats": VP_FORMATS,
                "signed": True,
                "expected_origins": [ORIGIN],
            },
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body_update",
    [
        {"expected_origins": []},
        {"expected_origins": ["verifier.example"]},
        {"expected_origins": [ORIGIN + "/path"]},
        {"vp_formats": {}},
        {"dcql_query_id": None},
        {"pres_def_id": "pd"},
    ],
)
async def test_invalid_input_rejected(context, dummy_request, body_update):
    dcql_id = await _save_dcql(context, SD_JWT_QUERY)
    body = {
        "dcql_query_id": dcql_id,
        "vp_formats": VP_FORMATS,
        "expected_origins": [ORIGIN],
    }
    body.update(body_update)
    with pytest.raises(web.HTTPBadRequest):
        await _call(dummy_request, body)


@pytest.mark.asyncio
async def test_unknown_dcql_query(context, dummy_request):
    with pytest.raises(web.HTTPNotFound):
        await _call(
            dummy_request,
            {
                "dcql_query_id": "missing",
                "vp_formats": VP_FORMATS,
                "expected_origins": [ORIGIN],
            },
        )


@pytest.mark.asyncio
async def test_mdoc_fails_closed_by_default(context, dummy_request):
    """mso_mdoc requires holder binding by default, which cannot be verified."""
    dcql_id = await _save_dcql(context, [{"id": "mdl", "format": "mso_mdoc"}])
    with pytest.raises(web.HTTPBadRequest) as excinfo:
        await _call(
            dummy_request,
            {
                "dcql_query_id": dcql_id,
                "vp_formats": VP_FORMATS,
                "expected_origins": [ORIGIN],
            },
        )
    assert "require_cryptographic_holder_binding" in excinfo.value.reason

    # Nothing was persisted for the rejected request.
    async with context.profile.session() as session:
        assert await OID4VPPresentation.query(session) == []


@pytest.mark.asyncio
async def test_mdoc_allowed_when_holder_binding_not_required(context, dummy_request):
    dcql_id = await _save_dcql(
        context,
        [
            {
                "id": "mdl",
                "format": "mso_mdoc",
                "require_cryptographic_holder_binding": False,
            }
        ],
    )
    body = await _call(
        dummy_request,
        {
            "dcql_query_id": dcql_id,
            "vp_formats": VP_FORMATS,
            "expected_origins": [ORIGIN],
        },
    )
    cred = body["request"]["dcql_query"]["credentials"][0]
    assert cred["require_cryptographic_holder_binding"] is False
