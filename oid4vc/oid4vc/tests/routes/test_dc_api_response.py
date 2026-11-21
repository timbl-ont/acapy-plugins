"""Tests for DC-API response decryption (dc_api.jwt) and post_response.

The wallet-side JWE is built with the ``cryptography`` package directly from
RFC 7518 Section 4.6 (ECDH-ES direct key agreement, Concat KDF, AES-GCM),
independently of the aries-askar code under test, so the round trip checks
interoperability rather than self-consistency.
"""

import base64
import json
import os
from typing import cast
from unittest.mock import AsyncMock

import pytest
from aiohttp import web
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from oid4vc.dc_api import (
    ResponseDecryptionError,
    create_response_key,
    decrypt_response,
    load_response_key,
)
from oid4vc.dcql import DCQLVerifyResult
from oid4vc.models.dcql_query import DCQLQuery
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.public_routes.verification import post_response
from oid4vc.routes.vp_request import create_oid4vp_dc_api_request

VP_FORMATS = {
    "dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"]}
}
VP_TOKEN = {"pid": ["eyJhbGciOiJFUzI1NiJ9.sd-jwt~disclosure~kb-jwt"]}


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _len_prefixed(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def encrypt_jwe(
    recipient_jwk,
    payload,
    *,
    enc="A128GCM",
    kid=None,
    apu=b"",
    apv=b"",
    header_overrides=None,
) -> str:
    """Encrypt like a wallet: ECDH-ES direct key agreement + AES-GCM."""
    recipient = ec.EllipticCurvePublicNumbers(
        int.from_bytes(_b64d(recipient_jwk["x"]), "big"),
        int.from_bytes(_b64d(recipient_jwk["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral.exchange(ec.ECDH(), recipient)
    key_len = 16 if enc == "A128GCM" else 32
    other_info = (
        _len_prefixed(enc.encode())
        + _len_prefixed(apu)
        + _len_prefixed(apv)
        + (key_len * 8).to_bytes(4, "big")
    )
    cek = ConcatKDFHash(
        algorithm=hashes.SHA256(), length=key_len, otherinfo=other_info
    ).derive(shared_secret)

    numbers = ephemeral.public_key().public_numbers()
    header = {
        "alg": "ECDH-ES",
        "enc": enc,
        "kid": kid if kid is not None else recipient_jwk["kid"],
        "epk": {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64e(numbers.x.to_bytes(32, "big")),
            "y": _b64e(numbers.y.to_bytes(32, "big")),
        },
    }
    if apu:
        header["apu"] = _b64e(apu)
    if apv:
        header["apv"] = _b64e(apv)
    header.update(header_overrides or {})
    protected = _b64e(json.dumps(header).encode())
    iv = os.urandom(12)
    sealed = AESGCM(cek).encrypt(iv, json.dumps(payload).encode(), protected.encode())
    return ".".join([protected, "", _b64e(iv), _b64e(sealed[:-16]), _b64e(sealed[-16:])])


async def _new_key(profile, presentation_id="pres-1"):
    async with profile.session() as session:
        jwk = await create_response_key(session, presentation_id)
        key, kid = await load_response_key(session, presentation_id)
    return jwk, key, kid


# --- decrypt_response -------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("enc", ["A128GCM", "A256GCM"])
@pytest.mark.parametrize("apu,apv", [(b"", b""), (b"wallet-apu", b"verifier-apv")])
async def test_decrypt_round_trip(profile, enc, apu, apv):
    jwk, key, kid = await _new_key(profile)
    payload = {"vp_token": VP_TOKEN}
    jwe = encrypt_jwe(jwk, payload, enc=enc, apu=apu, apv=apv)
    assert decrypt_response(jwe, key, kid) == payload


def _tamper_ciphertext(jwe: str) -> str:
    parts = jwe.split(".")
    ct = bytearray(_b64d(parts[3]))
    ct[0] ^= 0x01
    parts[3] = _b64e(bytes(ct))
    return ".".join(parts)


def _with_encrypted_key(jwe: str) -> str:
    parts = jwe.split(".")
    parts[1] = _b64e(b"\x00" * 16)
    return ".".join(parts)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "make_jwe",
    [
        lambda jwk: encrypt_jwe(jwk, {"vp_token": VP_TOKEN}, kid="other-kid"),
        lambda jwk: encrypt_jwe(
            jwk, {"vp_token": VP_TOKEN}, header_overrides={"alg": "ECDH-ES+A128KW"}
        ),
        lambda jwk: encrypt_jwe(
            jwk, {"vp_token": VP_TOKEN}, header_overrides={"enc": "A128CBC-HS256"}
        ),
        lambda jwk: encrypt_jwe(
            jwk, {"vp_token": VP_TOKEN}, header_overrides={"zip": "DEF"}
        ),
        lambda jwk: _tamper_ciphertext(encrypt_jwe(jwk, {"vp_token": VP_TOKEN})),
        lambda jwk: _with_encrypted_key(encrypt_jwe(jwk, {"vp_token": VP_TOKEN})),
        lambda jwk: encrypt_jwe(jwk, ["not", "an", "object"]),
        lambda jwk: "eyJhbGciOiJub25lIn0.eyJ2cF90b2tlbiI6e319.",
    ],
    ids=[
        "wrong-kid",
        "wrong-alg",
        "unsupported-enc",
        "compressed",
        "tampered-ciphertext",
        "non-empty-encrypted-key",
        "non-object-payload",
        "unencrypted-jwt",
    ],
)
async def test_decrypt_rejects(profile, make_jwe):
    jwk, key, kid = await _new_key(profile)
    with pytest.raises(ResponseDecryptionError):
        decrypt_response(make_jwe(jwk), key, kid)


# --- post_response ----------------------------------------------------------


class FormRequest:
    """Minimal stand-in for an aiohttp form POST to /oid4vp/response/{id}."""

    def __init__(self, context, presentation_id, form):
        self._context = context
        self._form = form
        self.match_info = {"presentation_id": presentation_id}

    async def post(self):
        return self._form

    def __getitem__(self, key):
        if key == "context":
            return self._context
        raise KeyError(key)


async def _create_dc_api_presentation(context, dummy_request):
    query = DCQLQuery.deserialize({"credentials": [{"id": "pid", "format": "dc+sd-jwt"}]})
    async with context.profile.session() as session:
        await query.save(session=session)
    resp = await create_oid4vp_dc_api_request(
        cast(
            web.Request,
            dummy_request(
                json_data={
                    "dcql_query_id": query.dcql_query_id,
                    "vp_formats": VP_FORMATS,
                    "expected_origins": ["https://verifier.example"],
                }
            ),
        )
    )
    body = json.loads(resp.body)
    return body["presentation_id"], body["request"]["client_metadata"]["jwks"]["keys"][0]


async def _record(context, presentation_id) -> OID4VPPresentation:
    async with context.profile.session() as session:
        return await OID4VPPresentation.retrieve_by_id(session, presentation_id)


@pytest.fixture
def verify_dcql(monkeypatch):
    verify = AsyncMock(
        return_value=DCQLVerifyResult(
            verified=True, cred_query_id_to_claims={"pid": {"given_name": "Ada"}}
        )
    )
    monkeypatch.setattr(
        "oid4vc.public_routes.verification.verify_dcql_presentation", verify
    )
    return verify


@pytest.mark.asyncio
async def test_post_encrypted_dc_api_response(context, dummy_request, verify_dcql):
    pres_id, jwk = await _create_dc_api_presentation(context, dummy_request)
    jwe = encrypt_jwe(jwk, {"vp_token": VP_TOKEN})

    resp = await post_response(
        cast(web.Request, FormRequest(context, pres_id, {"response": jwe}))
    )

    assert resp.status == 200
    assert verify_dcql.call_args.kwargs["vp_token"] == VP_TOKEN
    record = await _record(context, pres_id)
    assert record.state == OID4VPPresentation.PRESENTATION_VALID
    assert record.matched_credentials == {"pid": {"given_name": "Ada"}}

    # The single-use key is gone and a second response is refused.
    async with context.profile.session() as session:
        assert await load_response_key(session, pres_id) is None
    with pytest.raises(web.HTTPBadRequest):
        await post_response(
            cast(web.Request, FormRequest(context, pres_id, {"response": jwe}))
        )


@pytest.mark.asyncio
async def test_dc_api_rejects_unencrypted_response(context, dummy_request, verify_dcql):
    pres_id, _ = await _create_dc_api_presentation(context, dummy_request)

    with pytest.raises(web.HTTPBadRequest):
        await post_response(
            cast(
                web.Request,
                FormRequest(context, pres_id, {"vp_token": json.dumps(VP_TOKEN)}),
            )
        )
    verify_dcql.assert_not_called()
    assert (await _record(context, pres_id)).state == OID4VPPresentation.REQUEST_RETRIEVED


@pytest.mark.asyncio
async def test_dc_api_bad_jwe_leaves_presentation_pending(
    context, dummy_request, verify_dcql
):
    pres_id, jwk = await _create_dc_api_presentation(context, dummy_request)
    bad = encrypt_jwe(jwk, {"vp_token": VP_TOKEN}, kid="other-kid")

    with pytest.raises(web.HTTPBadRequest):
        await post_response(
            cast(web.Request, FormRequest(context, pres_id, {"response": bad}))
        )
    verify_dcql.assert_not_called()
    assert (await _record(context, pres_id)).state == OID4VPPresentation.REQUEST_RETRIEVED
    async with context.profile.session() as session:
        assert await load_response_key(session, pres_id) is not None

    # The genuine response can still be delivered afterwards.
    good = encrypt_jwe(jwk, {"vp_token": VP_TOKEN})
    await post_response(
        cast(web.Request, FormRequest(context, pres_id, {"response": good}))
    )
    assert (
        await _record(context, pres_id)
    ).state == OID4VPPresentation.PRESENTATION_VALID


@pytest.mark.asyncio
async def test_qr_flow_dcql_response_unchanged(context, verify_dcql):
    """Non-DC-API presentations still accept the unencrypted form vp_token."""
    record = OID4VPPresentation(
        dcql_query_id="q1",
        state=OID4VPPresentation.REQUEST_RETRIEVED,
        request_id="req-1",
        client_id="did:jwk:example",
        nonce="nonce-1",
    )
    async with context.profile.session() as session:
        await record.save(session=session)

    await post_response(
        cast(
            web.Request,
            FormRequest(
                context, record.presentation_id, {"vp_token": json.dumps(VP_TOKEN)}
            ),
        )
    )
    assert verify_dcql.call_args.kwargs["vp_token"] == VP_TOKEN
