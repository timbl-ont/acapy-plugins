"""Holder binding (device authentication) in the mdoc presentation verifier.

isomdl_uniffi.verify_oid4vp_response is mocked: these tests cover what the
verifier does with its result and which request parameters it passes.
"""

from types import SimpleNamespace
from unittest import mock

import pytest
from acapy_agent.utils.testing import create_test_profile

from mso_mdoc.mdoc import pres_verifier as test_module
from mso_mdoc.mdoc.cred_verifier import MsoMdocCredVerifier
from mso_mdoc.signing_key import (
    generate_ec_p256_key_pem,
    generate_self_signed_certificate,
)
from oid4vc.cred_processor import CredProcessors
from oid4vc.dcql import DCQLQueryEvaluator
from oid4vc.models.dcql_query import DCQLQuery
from oid4vc.models.presentation import OID4VPPresentation

AuthStatus = test_module.isomdl_uniffi.AuthenticationStatus

MDL = "org.iso.18013.5.1.mDL"
PHOTO_ID = "org.iso.23220.photoid.1"
ENDPOINT = "http://localhost:8020"
CLIENT_ID = "x509_san_dns:verifier.example.com"
NONCE = "nonce-123"
PRESENTATION = "o2d2ZXJzaW9uYzEuMA"  # any base64url; the binding is mocked


@pytest.fixture
async def profile(monkeypatch):
    monkeypatch.delenv("OID4VP_ENDPOINT", raising=False)
    monkeypatch.delenv("OID4VCI_ENDPOINT", raising=False)
    yield await create_test_profile(
        {
            "plugin_config": {
                "oid4vci": {"host": "localhost", "port": 8020, "endpoint": ENDPOINT}
            }
        }
    )


@pytest.fixture
def trust_anchor():
    return generate_self_signed_certificate(generate_ec_p256_key_pem())


@pytest.fixture
def verifier(trust_anchor):
    return test_module.MsoMdocPresVerifier(trust_anchors=[trust_anchor])


def verified_data(device=AuthStatus.INVALID, issuer=AuthStatus.VALID, doc_type=MDL):
    return SimpleNamespace(
        doc_type=doc_type,
        verified_response={},
        issuer_authentication=issuer,
        device_authentication=device,
        errors=None,
    )


def mock_binding(monkeypatch, result):
    verify = mock.MagicMock(return_value=result)
    monkeypatch.setattr(test_module.isomdl_uniffi, "verify_oid4vp_response", verify)
    return verify


async def save_query(profile, credentials):
    query = DCQLQuery.deserialize({"credentials": credentials})
    async with profile.session() as session:
        await query.save(session=session)
    return query.dcql_query_id


def mdoc_query(query_id="mdl", doctype=MDL, binding=None):
    cred = {"id": query_id, "format": "mso_mdoc", "meta": {"doctype_value": doctype}}
    if binding is not None:
        cred["require_cryptographic_holder_binding"] = binding
    return cred


def dcql_record(dcql_query_id, client_id=CLIENT_ID):
    return OID4VPPresentation(
        presentation_id="pres-1",
        state=OID4VPPresentation.REQUEST_RETRIEVED,
        request_id="req-1",
        dcql_query_id=dcql_query_id,
        nonce=NONCE,
        client_id=client_id,
    )


@pytest.mark.parametrize("binding", [None, True])
@pytest.mark.parametrize("device", [AuthStatus.INVALID, AuthStatus.UNCHECKED])
async def test_device_auth_failure_rejected_when_binding_required(
    profile, verifier, monkeypatch, binding, device
):
    """Issuer VALID + device not VALID fails when the query requires binding.

    Binding is required by default (OpenID4VP 1.0 Section 6.1).
    """
    mock_binding(monkeypatch, verified_data(device=device))
    record = dcql_record(await save_query(profile, [mdoc_query(binding=binding)]))

    result = await verifier.verify_presentation(profile, PRESENTATION, record)

    assert result.verified is False
    assert "Device authentication failed" in result.payload["error"]
    assert result.payload["docType"] == MDL


async def test_issuer_only_accepted_when_query_opts_out(profile, verifier, monkeypatch):
    mock_binding(monkeypatch, verified_data(device=AuthStatus.INVALID))
    record = dcql_record(await save_query(profile, [mdoc_query(binding=False)]))

    result = await verifier.verify_presentation(profile, PRESENTATION, record)

    assert result.verified is True
    assert result.payload.claims["docType"] == MDL
    assert result.payload.claims["device_auth"] == str(AuthStatus.INVALID)


async def test_device_auth_valid_accepted(profile, verifier, monkeypatch):
    mock_binding(monkeypatch, verified_data(device=AuthStatus.VALID))
    record = dcql_record(await save_query(profile, [mdoc_query()]))

    result = await verifier.verify_presentation(profile, PRESENTATION, record)

    assert result.verified is True
    assert result.payload.claims["device_auth"] == str(AuthStatus.VALID)


async def test_issuer_auth_failure_still_rejected_when_query_opts_out(
    profile, verifier, monkeypatch
):
    mock_binding(
        monkeypatch,
        verified_data(issuer=AuthStatus.INVALID, device=AuthStatus.VALID),
    )
    record = dcql_record(await save_query(profile, [mdoc_query(binding=False)]))

    result = await verifier.verify_presentation(profile, PRESENTATION, record)

    assert result.verified is False


async def test_pres_def_always_requires_binding(profile, verifier, monkeypatch):
    """Presentation Exchange has no opt-out: device authentication is required."""
    mock_binding(monkeypatch, verified_data(device=AuthStatus.INVALID))
    record = OID4VPPresentation(
        presentation_id="pres-1",
        state=OID4VPPresentation.REQUEST_RETRIEVED,
        request_id="req-1",
        pres_def_id="pres-def-1",
        nonce=NONCE,
        client_id=CLIENT_ID,
    )

    result = await verifier.verify_presentation(profile, PRESENTATION, record)

    assert result.verified is False
    assert "Device authentication failed" in result.payload["error"]


@pytest.mark.parametrize(
    ("doc_type", "verified"),
    [(MDL, True), (PHOTO_ID, False), ("org.example.unrequested", False)],
)
async def test_opt_out_is_scoped_to_the_doctype(
    profile, verifier, monkeypatch, doc_type, verified
):
    """The waiver of an mDL query does not cover another doctype's query."""
    mock_binding(monkeypatch, verified_data(device=AuthStatus.INVALID, doc_type=doc_type))
    record = dcql_record(
        await save_query(
            profile,
            [
                mdoc_query("mdl", MDL, binding=False),
                mdoc_query("photo_id", PHOTO_ID),
            ],
        )
    )

    result = await verifier.verify_presentation(profile, PRESENTATION, record)

    assert result.verified is verified


async def test_dcql_evaluator_rejects_waiver_borrowed_across_queries(
    profile, trust_anchor, monkeypatch
):
    """An issuer-only mDL submitted for a binding-required query is rejected.

    The verifier waives binding for the mDL doctype (the mDL query opts out),
    and the DCQL evaluator then rejects the doctype for the photo ID query.
    """
    processors = CredProcessors(
        cred_verifiers={"mso_mdoc": MsoMdocCredVerifier(trust_anchors=[trust_anchor])},
        pres_verifiers={
            "mso_mdoc": test_module.MsoMdocPresVerifier(trust_anchors=[trust_anchor])
        },
    )
    profile.context.injector.bind_instance(CredProcessors, processors)
    # Either credential satisfies the query.
    dcql_query = DCQLQuery.deserialize(
        {
            "credentials": [
                mdoc_query("mdl", MDL, binding=False),
                mdoc_query("photo_id", PHOTO_ID),
            ],
            "credential_sets": [{"options": [["mdl"], ["photo_id"]]}],
        }
    )
    async with profile.session() as session:
        await dcql_query.save(session=session)
    dcql_query_id = dcql_query.dcql_query_id
    evaluator = DCQLQueryEvaluator.compile(dcql_query)
    mock_binding(monkeypatch, verified_data(device=AuthStatus.INVALID, doc_type=MDL))

    borrowed = await evaluator.verify(
        profile, {"photo_id": [PRESENTATION]}, dcql_record(dcql_query_id)
    )
    honest = await evaluator.verify(
        profile, {"mdl": [PRESENTATION]}, dcql_record(dcql_query_id)
    )

    assert borrowed.verified is False
    assert honest.verified is True


async def test_transcript_uses_request_client_id_and_oid4vp_endpoint(
    profile, verifier, monkeypatch
):
    """The transcript is rebuilt from the values the request carried.

    client_id is the record's (x509_san_dns:...), and response_uri uses
    OID4VP_ENDPOINT, as in get_request.
    """
    monkeypatch.setenv("OID4VP_ENDPOINT", "https://vp.example.com")
    verify = mock_binding(monkeypatch, verified_data(device=AuthStatus.VALID))
    record = dcql_record(await save_query(profile, [mdoc_query()]))

    result = await verifier.verify_presentation(profile, PRESENTATION, record)

    assert result.verified is True
    _, nonce, client_id, response_uri, *_ = verify.call_args.args
    assert nonce == NONCE
    assert client_id == CLIENT_ID
    assert response_uri == "https://vp.example.com/oid4vp/response/pres-1"


async def test_transcript_falls_back_to_did_jwk_without_record_client_id(
    profile, verifier, monkeypatch
):
    did_jwk = mock.AsyncMock(return_value=SimpleNamespace(did="did:jwk:verifier"))
    monkeypatch.setattr(test_module, "retrieve_or_create_did_jwk", did_jwk)
    verify = mock_binding(monkeypatch, verified_data(device=AuthStatus.VALID))
    record = dcql_record(await save_query(profile, [mdoc_query()]), client_id=None)

    result = await verifier.verify_presentation(profile, PRESENTATION, record)

    assert result.verified is True
    _, _, client_id, response_uri, *_ = verify.call_args.args
    assert client_id == "did:jwk:verifier"
    assert response_uri == f"{ENDPOINT}/oid4vp/response/pres-1"
