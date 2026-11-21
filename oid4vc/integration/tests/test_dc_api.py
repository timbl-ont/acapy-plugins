"""Integration tests for OID4VP over the W3C Digital Credentials API (DC-API).

The tests play the browser and the wallet. They obtain an SD-JWT VC with the
test OID4VCI client, build an SD-JWT+KB presentation bound to the DC-API
response audience (``origin:<origin>``) and the request nonce, encrypt the
Authorization Response to the request's ephemeral key (Response Mode
``dc_api.jwt``), and forward it to the controller submission URL, as a verifier
front-end would after ``navigator.credentials.get()`` resolves.
"""

import base64
import hashlib
import json
import time
from uuid import uuid4

import pytest
import pytest_asyncio
from acapy_controller.controller import Controller, ControllerError
from aiohttp import ClientSession
from aries_askar import Key, KeyAlg
from aries_askar.ecdh import EcdhEs

from oid4vci_client.client import OpenID4VCIClient

ORIGIN = "https://verifier.example"
VCT = "ExampleIDCard"
VP_FORMATS = {
    "vc+sd-jwt": {
        "sd-jwt_alg_values": ["ES256", "EdDSA"],
        "kb-jwt_alg_values": ["ES256", "EdDSA"],
    }
}
SD_JWT_QUERY = {
    "credentials": [
        {
            "id": "pid",
            "format": "vc+sd-jwt",
            "meta": {"vct_values": [VCT]},
            "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}],
        }
    ]
}
MDOC_QUERY = {
    "credentials": [
        {
            "id": "mdl",
            "format": "mso_mdoc",
            "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
        }
    ]
}


def b64url(data) -> str:
    if isinstance(data, dict):
        data = json.dumps(data)
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def extract_credential(response: dict) -> str:
    """Return the SD-JWT from an OID4VCI credential response."""
    if "credentials" in response:
        return response["credentials"][0]["credential"]
    return response["credential"]


def present_sd_jwt(sd_jwt: str, holder_key, aud: str, nonce: str) -> str:
    """Build an SD-JWT+KB presentation that discloses every issued claim."""
    issued = sd_jwt.rstrip("~") + "~"
    sd_hash = b64url(hashlib.sha256(issued.encode("ascii")).digest())
    assert holder_key.key.algorithm == KeyAlg.ED25519
    # The credential's cnf is kid-based (did:jwk), so the KB-JWT names the key.
    header = b64url({"alg": "EdDSA", "typ": "kb+jwt", "kid": holder_key.kid})
    payload = b64url(
        {"iat": int(time.time()), "aud": aud, "nonce": nonce, "sd_hash": sd_hash}
    )
    signature = b64url(holder_key.key.sign_message(f"{header}.{payload}".encode()))
    return f"{issued}{header}.{payload}.{signature}"


def encrypt_response(recipient_jwk: dict, payload: dict, enc: str = "A256GCM") -> str:
    """Encrypt an Authorization Response as a wallet does for dc_api.jwt."""
    recipient = Key.from_jwk(
        json.dumps({k: recipient_jwk[k] for k in ("kty", "crv", "x", "y")})
    )
    ephemeral = Key.generate(KeyAlg.P256)
    header = {
        "alg": "ECDH-ES",
        "enc": enc,
        "kid": recipient_jwk["kid"],
        "epk": json.loads(ephemeral.get_jwk_public()),
    }
    protected = b64url(header)
    sealed = EcdhEs(enc, b"", b"").encrypt_direct(
        enc, ephemeral, recipient, json.dumps(payload).encode(), aad=protected.encode()
    )
    return ".".join(
        [
            protected,
            "",
            b64url(sealed.nonce),
            b64url(sealed.ciphertext),
            b64url(sealed.tag),
        ]
    )


@pytest_asyncio.fixture
async def make_dcql_query(controller: Controller):
    """Create DCQL queries and delete them afterwards (other tests list them)."""
    created = []

    async def make(query: dict) -> str:
        record = await controller.post("/oid4vp/dcql/queries", json=query)
        created.append(record["dcql_query_id"])
        return record["dcql_query_id"]

    yield make
    for query_id in created:
        await controller.delete(f"/oid4vp/dcql/query/{query_id}")


@pytest_asyncio.fixture
async def sd_jwt_offer(controller: Controller, issuer_did: str, issuer_config: None):
    """Create an SD-JWT VC credential offer (vct ExampleIDCard)."""
    supported = await controller.post(
        "/oid4vci/credential-supported/create/sd-jwt",
        json={
            "format": "vc+sd-jwt",
            "id": f"DcApiIDCard-{uuid4()}",
            "cryptographic_binding_methods_supported": ["jwk"],
            "credential_signing_alg_values_supported": ["ES256"],
            "vct": VCT,
            "credential_metadata": {
                "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}]
            },
            "sd_list": ["/given_name", "/family_name"],
        },
    )
    exchange = await controller.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported["supported_cred_id"],
            "credential_subject": {"given_name": "Erika", "family_name": "Mustermann"},
            "verification_method": issuer_did + "#0",
        },
    )
    # The test client takes the full credential-offer response (with "offer").
    yield await controller.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
    )


async def create_dc_api_request(controller: Controller, dcql_query_id: str) -> dict:
    return await controller.post(
        "/oid4vp/dc-api/request",
        json={
            "dcql_query_id": dcql_query_id,
            "vp_formats": VP_FORMATS,
            "expected_origins": [ORIGIN],
        },
    )


async def forward_response(response_uri: str, form: dict) -> int:
    async with ClientSession() as session:
        async with session.post(response_uri, data=form) as resp:
            return resp.status


async def issue_and_present(
    controller: Controller,
    test_client: OpenID4VCIClient,
    offer: dict,
    dcql_query_id: str,
    aud: str,
) -> dict:
    """Issue an SD-JWT VC, present it over the DC-API, return the presentation."""
    did = test_client.generate_did("ed25519")
    credential = extract_credential(await test_client.receive_offer(offer, did))

    request = await create_dc_api_request(controller, dcql_query_id)
    data = request["request"]
    presentation = present_sd_jwt(
        credential, test_client.did_to_key[did], aud, data["nonce"]
    )
    jwe = encrypt_response(
        data["client_metadata"]["jwks"]["keys"][0],
        {"vp_token": {"pid": [presentation]}},
    )
    status = await forward_response(request["response_uri"], {"response": jwe})
    assert status == 200
    return await controller.get(f"/oid4vp/presentation/{request['presentation_id']}")


@pytest.mark.asyncio
async def test_dc_api_request_shape(controller: Controller, make_dcql_query):
    request = await create_dc_api_request(controller, await make_dcql_query(SD_JWT_QUERY))

    assert request["protocol"] == "openid4vp-v1-unsigned"
    data = request["request"]
    assert data["response_type"] == "vp_token"
    assert data["response_mode"] == "dc_api.jwt"
    for absent in ("client_id", "response_uri", "state"):
        assert absent not in data
    metadata = data["client_metadata"]
    assert metadata["vp_formats_supported"] == VP_FORMATS
    assert metadata["encrypted_response_enc_values_supported"] == ["A128GCM", "A256GCM"]
    (jwk,) = metadata["jwks"]["keys"]
    assert jwk["alg"] == "ECDH-ES" and jwk["crv"] == "P-256" and "d" not in jwk


@pytest.mark.asyncio
async def test_dc_api_sd_jwt_presentation(
    controller: Controller,
    test_client: OpenID4VCIClient,
    sd_jwt_offer: dict,
    make_dcql_query,
):
    record = await issue_and_present(
        controller,
        test_client,
        sd_jwt_offer,
        await make_dcql_query(SD_JWT_QUERY),
        aud=f"origin:{ORIGIN}",
    )
    assert record["state"] == "presentation-valid", record.get("errors")
    assert record["verified"] is True


@pytest.mark.asyncio
async def test_dc_api_rejects_client_id_audience(
    controller: Controller,
    test_client: OpenID4VCIClient,
    sd_jwt_offer: dict,
    make_dcql_query,
):
    """Over the DC-API the KB-JWT audience must be the origin (A.4)."""
    record = await issue_and_present(
        controller,
        test_client,
        sd_jwt_offer,
        await make_dcql_query(SD_JWT_QUERY),
        aud="x509_san_dns:verifier.example",
    )
    assert record["state"] == "presentation-invalid"


@pytest.mark.asyncio
async def test_dc_api_rejects_unencrypted_response(
    controller: Controller, make_dcql_query
):
    request = await create_dc_api_request(controller, await make_dcql_query(SD_JWT_QUERY))
    status = await forward_response(
        request["response_uri"], {"vp_token": json.dumps({"pid": ["x"]})}
    )
    assert status == 400
    record = await controller.get(f"/oid4vp/presentation/{request['presentation_id']}")
    assert record["state"] == "request-retrieved"


@pytest.mark.asyncio
async def test_dc_api_mdoc_fails_closed(controller: Controller, make_dcql_query):
    with pytest.raises(ControllerError):
        await create_dc_api_request(controller, await make_dcql_query(MDOC_QUERY))

    opted_out = {
        "credentials": [
            dict(MDOC_QUERY["credentials"][0], require_cryptographic_holder_binding=False)
        ]
    }
    request = await create_dc_api_request(controller, await make_dcql_query(opted_out))
    assert request["protocol"] == "openid4vp-v1-unsigned"
