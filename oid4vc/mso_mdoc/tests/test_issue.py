"""Issuance round trips through PreparedMdoc.new_from_cbor and a document signer."""

import base64
import json
from datetime import UTC, date, datetime, timedelta

import cbor2
import pytest
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import P256
from acapy_agent.wallet.keys.manager import verkey_to_multikey
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID
from isomdl_uniffi import Mdoc, PreparedMdoc

from mso_mdoc.document_signer import (
    DocumentSignerError,
    PemDocumentSigner,
    WalletDocumentSigner,
    document_signer_from_config,
)
from mso_mdoc.mdoc.issuer import MsoValidity, issue_mdoc, rfc3339
from mso_mdoc.mdoc.namespaces import declared_claims, encode_document
from mso_mdoc.signing_key import (
    MdocSigningKeyRecord,
    generate_ec_p256_key_pem,
    generate_self_signed_certificate,
)
from mso_mdoc.tests.test_namespaces import (
    AAMVA_ELEMENTS,
    MDL_ELEMENTS,
    PHOTO_ID_CORE,
)

STATUS = {"status_list": {"idx": 4, "uri": "https://example.com/statuslists/1"}}


def holder_jwk() -> dict:
    numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()

    def b64url(n: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()

    return {"kty": "EC", "crv": "P-256", "x": b64url(numbers.x), "y": b64url(numbers.y)}


def decode_issuer_signed(credential: str) -> tuple[dict, dict]:
    """The MSO and the element values, by namespace, of a base64url IssuerSigned."""
    issuer_signed = cbor2.loads(
        base64.urlsafe_b64decode(credential + "=" * (-len(credential) % 4))
    )
    mso = cbor2.loads(cbor2.loads(issuer_signed["issuerAuth"][2]).value)
    values = {}
    for namespace, items in issuer_signed["nameSpaces"].items():
        values[namespace] = {}
        for item in items:
            decoded = cbor2.loads(item.value)
            values[namespace][decoded["elementIdentifier"]] = decoded["elementValue"]
    return mso, values


async def pem_signer(session) -> PemDocumentSigner:
    key_pem = generate_ec_p256_key_pem()
    record = MdocSigningKeyRecord(
        private_key_pem=key_pem,
        certificate_pem=generate_self_signed_certificate(key_pem),
        label="test",
    )
    await record.save(session)
    return PemDocumentSigner(record.id)


async def wallet_signer(session) -> WalletDocumentSigner:
    x509_certs = pytest.importorskip("x509_certs")
    from x509_certs.certs import describe, to_x5c
    from x509_certs.signing import build_self_signed

    wallet = session.inject(BaseWallet)
    key = await wallet.create_key(P256)
    multikey = verkey_to_multikey(key.verkey, alg="p256")
    cert = await build_self_signed(
        wallet, key.verkey, P256, {"common_name": "Test DS"}, days=60
    )
    await x509_certs.X509CertificateRecord(
        multikey=multikey, purpose="mdoc_ds", x5c=to_x5c([cert]), **describe(cert)
    ).save(session)
    return WalletDocumentSigner(multikey)


@pytest.mark.parametrize("make_signer", [pem_signer, wallet_signer])
async def test_photo_id_round_trip(make_signer):
    profile = await create_test_profile()
    declared = declared_claims({"ca.on.photoid.1": {"health_number": {}}})
    namespaces = encode_document(
        "org.iso.23220.photoid.1",
        {
            "org.iso.23220.1": PHOTO_ID_CORE,
            "org.iso.23220.photoid.1": {"person_id": "1234567890"},
            "ca.on.photoid.1": {"health_number": "1234-567-890"},
        },
        declared,
    )
    validity = MsoValidity.from_config(
        {"valid_from": 60, "valid_until": 7 * 86400, "expected_update": 86400}
    )
    async with profile.session() as session:
        signer = await make_signer(session)
        credential = await issue_mdoc(
            session,
            doctype="org.iso.23220.photoid.1",
            namespaces=namespaces,
            holder_jwk=holder_jwk(),
            signer=signer,
            validity=validity,
            status_claim=STATUS,
        )

    mso, values = decode_issuer_signed(credential)
    assert mso["docType"] == "org.iso.23220.photoid.1"
    assert mso["status"] == STATUS
    info = mso["validityInfo"]
    assert info["validFrom"] == validity.valid_from
    assert info["validUntil"] == validity.valid_until
    assert info["expectedUpdate"] == validity.expected_update
    assert info["validFrom"] >= info["signed"]
    assert set(values) == {
        "org.iso.23220.1",
        "org.iso.23220.photoid.1",
        "ca.on.photoid.1",
    }
    assert values["org.iso.23220.1"]["birth_date"] == {
        "birth_date": date(1990, 4, 1),
        "approximate_mask": "00000011",
    }
    assert isinstance(values["org.iso.23220.1"]["portrait"], bytes)
    assert values["ca.on.photoid.1"]["health_number"] == "1234-567-890"

    mdoc = Mdoc.new_from_base64url_encoded_issuer_signed(credential, "test")
    result = mdoc.verify_issuer_signature(None, False)
    assert result.verified, result.error
    assert json.loads(mdoc.status_list()) == STATUS


async def test_default_validity_is_30_days():
    profile = await create_test_profile()
    namespaces = encode_document(
        "org.iso.18013.5.1.mDL", {"org.iso.18013.5.1": MDL_ELEMENTS}
    )
    async with profile.session() as session:
        credential = await issue_mdoc(
            session,
            doctype="org.iso.18013.5.1.mDL",
            namespaces=namespaces,
            holder_jwk=holder_jwk(),
            signer=await pem_signer(session),
            validity=MsoValidity.from_config(None),
        )
    mso, _ = decode_issuer_signed(credential)
    info = mso["validityInfo"]
    assert info["validFrom"] == info["signed"]
    assert abs((info["validUntil"] - info["signed"]).total_seconds() - 30 * 86400) <= 1
    assert "expectedUpdate" not in info
    assert "status" not in mso


async def test_certificate_must_cover_valid_until():
    profile = await create_test_profile()
    namespaces = encode_document(
        "org.iso.18013.5.1.mDL", {"org.iso.18013.5.1": MDL_ELEMENTS}
    )
    async with profile.session() as session:
        signer = await pem_signer(session)  # certificate valid for 365 days
        with pytest.raises(DocumentSignerError, match="not valid from now until"):
            await issue_mdoc(
                session,
                doctype="org.iso.18013.5.1.mDL",
                namespaces=namespaces,
                holder_jwk=holder_jwk(),
                signer=signer,
                validity=MsoValidity.from_config({"valid_until": 400 * 86400}),
            )


async def test_wallet_signer_without_certificate():
    pytest.importorskip("x509_certs")
    profile = await create_test_profile()
    async with profile.session() as session:
        key = await session.inject(BaseWallet).create_key(P256)
        signer = WalletDocumentSigner(verkey_to_multikey(key.verkey, alg="p256"))
        with pytest.raises(DocumentSignerError, match="mdoc_ds"):
            await signer.chain_pem(session, datetime.now(UTC) + timedelta(days=1))


def test_mdl_and_aamva_match_new_mdl():
    """The Python schemas encode mDL and AAMVA values as isomdl's typed builder does."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Parity DS")])
    now = datetime.now(UTC)
    cert_pem = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=60))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    jwk = json.dumps(holder_jwk())

    def complete(prepared):
        r, s = decode_dss_signature(
            key.sign(prepared.signature_payload(), ec.ECDSA(hashes.SHA256()))
        )
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return prepared.complete(cert_pem, signature).issuer_signed_b64()

    typed = complete(
        PreparedMdoc.new_mdl(
            json.dumps(MDL_ELEMENTS), json.dumps(AAMVA_ELEMENTS), jwk, "ES256", None
        )
    )
    namespaces = encode_document(
        "org.iso.18013.5.1.mDL",
        {"org.iso.18013.5.1": MDL_ELEMENTS, "org.iso.18013.5.1.aamva": AAMVA_ELEMENTS},
    )
    from_cbor = complete(
        PreparedMdoc.new_from_cbor(
            "org.iso.18013.5.1.mDL",
            namespaces,
            jwk,
            "ES256",
            None,
            None,
            rfc3339(now + timedelta(days=30)),
            None,
        )
    )
    _, typed_values = decode_issuer_signed(typed)
    _, cbor_values = decode_issuer_signed(from_cbor)
    assert cbor_values == typed_values


def test_document_signer_config_has_no_fallback():
    with pytest.raises(DocumentSignerError, match="not configured"):
        document_signer_from_config({})
    with pytest.raises(DocumentSignerError, match="multikey"):
        document_signer_from_config({"document_signer": {"key_type": "wallet"}})
    with pytest.raises(DocumentSignerError, match="key_type"):
        document_signer_from_config({"document_signer": {"key_type": "hsm"}})
    assert isinstance(
        document_signer_from_config(
            {"document_signer": {"key_type": "pem", "signing_key_id": "abc"}}
        ),
        PemDocumentSigner,
    )


@pytest.mark.parametrize(
    "config, message",
    [
        ({"valid_from": -1}, "non-negative"),
        ({"valid_until": 10, "valid_from": 10}, "greater than"),
        ({"valid_until": True}, "non-negative"),
        ({"valid_for": 10}, "unknown keys"),
    ],
)
def test_validity_config_errors(config, message):
    with pytest.raises(ValueError, match=message):
        MsoValidity.from_config(config)


def test_validity_offsets():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    validity = MsoValidity.from_config(
        {"valid_from": 0, "valid_until": 3600, "expected_update": 600}, now=now
    )
    assert validity.valid_from is None
    assert validity.valid_until == now + timedelta(hours=1)
    assert validity.expected_update == now + timedelta(minutes=10)


@pytest.mark.parametrize(
    "entries, expected",
    [
        (None, None),
        (STATUS, STATUS),
        ([{"type": "BitstringStatusListEntry", "statusListIndex": 1}, STATUS], STATUS),
        ({"type": "BitstringStatusListEntry", "statusListIndex": 1}, None),
    ],
)
def test_mso_status_uses_the_ietf_entry(entries, expected):
    from mso_mdoc.cred_processor import mso_status

    assert mso_status(entries) == expected
