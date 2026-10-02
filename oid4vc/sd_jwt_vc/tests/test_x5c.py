"""Tests for SD-JWT VC issuance with an issuer x5c certificate chain."""

import base64
import datetime
import json

import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from aiohttp import web
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.jwt import b64_to_dict
from acapy_agent.wallet.key_type import P256, KeyTypes
from acapy_agent.wallet.util import b64_to_bytes, bytes_to_b64
from aries_askar import Key, KeyAlg
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from oid4vc.cred_processor import CredProcessorError, CredProcessors
from oid4vc.jwk import DID_JWK
from oid4vc.jwk_resolver import JwkResolver
from oid4vc.jwt import key_from_x5c
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult
from mso_mdoc.trust_anchor import TrustAnchorRecord, TrustAnchorRecordSchema
from sd_jwt_vc.cred_processor import (
    SdJwtCredIssueProcessor,
    sd_jwt_verify,
    validate_x5c_cert_chain,
    verify_x5c_trust,
)
from sd_jwt_vc.routes import (
    supported_credential_create,
    update_supported_credential_sd_jwt,
)

ENDPOINT = "https://issuer.example.com"
WALLET_ID = "538451fa-11ab-41de-b6e3-7ae3df7356d6"
ISSUER_URL = f"{ENDPOINT}/tenant/{WALLET_ID}"


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(
    subject, issuer, public_key, signing_key, san=None, ca=None, path_length=None
) -> x509.Certificate:
    """Build a cert; ca=True/False adds CA/end-entity constraints and key usage."""
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san)]),
            critical=False,
        )
    if ca is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length if ca else None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    return builder.sign(signing_key, hashes.SHA256())


def _pem(*certs: x509.Certificate) -> str:
    return "".join(
        cert.public_bytes(serialization.Encoding.PEM).decode() for cert in certs
    )


def _x5c(*certs: x509.Certificate) -> list:
    return [
        base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
        for cert in certs
    ]


def _askar_public_key(key: Key) -> ec.EllipticCurvePublicKey:
    jwk = json.loads(key.get_jwk_public())
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(b64_to_bytes(jwk["x"], urlsafe=True), "big"),
        int.from_bytes(b64_to_bytes(jwk["y"], urlsafe=True), "big"),
        ec.SECP256R1(),
    ).public_key()


def _ca(name="Test CA", issuer=None, path_length=None):
    """Return (cert, key) for a CA, self-signed unless issuer=(cert, key)."""
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_cert, issuer_key = issuer or (None, key)
    issuer_name = issuer_cert.subject.rfc4514_string()[3:] if issuer_cert else name
    cert = _cert(
        name, issuer_name, key.public_key(), issuer_key, ca=True, path_length=path_length
    )
    return cert, key


def _leaf(public_key, issuer, **kwargs) -> x509.Certificate:
    issuer_cert, issuer_key = issuer
    return _cert(
        "Test Issuer",
        issuer_cert.subject.rfc4514_string()[3:],
        public_key,
        issuer_key,
        san=ISSUER_URL,
        **{"ca": False, **kwargs},
    )


def _chain_for(public_key: ec.EllipticCurvePublicKey, ca=None) -> list:
    ca = ca or _ca()
    return _x5c(_leaf(public_key, ca), ca[0])


@pytest.fixture
async def context():
    profile = await create_test_profile(
        {
            "multitenant.enabled": True,
            "wallet.id": WALLET_ID,
            "plugin_config": {
                "oid4vci": {"host": "localhost", "port": 8020, "endpoint": ENDPOINT}
            },
        }
    )
    profile.context.injector.bind_instance(DIDResolver, DIDResolver([JwkResolver()]))
    did_methods = DIDMethods()
    did_methods.register(DID_JWK)
    profile.context.injector.bind_instance(DIDMethods, did_methods)
    profile.context.injector.bind_instance(KeyTypes, KeyTypes())
    profile.context.injector.bind_instance(
        CredProcessors, CredProcessors({"vc+sd-jwt": SdJwtCredIssueProcessor()})
    )
    yield AdminRequestContext(profile)


@pytest.fixture
async def issuer_key(context: AdminRequestContext):
    """Create a P-256 did:jwk the same way the /did/jwk/create route does."""
    key = Key.generate(KeyAlg.P256)
    async with context.session() as session:
        await session.handle.insert_key(key.get_jwk_thumbprint(), key)
        jwk = json.loads(key.get_jwk_public())
        jwk["use"] = "sig"
        did = "did:jwk:" + bytes_to_b64(json.dumps(jwk).encode(), urlsafe=True, pad=False)
        await session.inject(BaseWallet).store_did(
            DIDInfo(
                did=did,
                verkey=key.get_jwk_thumbprint(),
                metadata={},
                method=DID_JWK,
                key_type=P256,
            )
        )
    yield did, key


def _supported(x5c=None) -> SupportedCredential:
    vc_additional_data = {"vct": "ExampleID", "sd_list": ["/given_name"]}
    if x5c is not None:
        vc_additional_data["x5c_cert_chain"] = x5c
    return SupportedCredential(
        format="vc+sd-jwt",
        identifier="ExampleID",
        format_data={"vct": "ExampleID"},
        vc_additional_data=vc_additional_data,
        credential_metadata={},
    )


def _ex_record(did: str) -> OID4VCIExchangeRecord:
    return OID4VCIExchangeRecord(
        state=OID4VCIExchangeRecord.STATE_OFFER_CREATED,
        verification_method=did + "#0",
        issuer_id=did,
        supported_cred_id="456",
        credential_subject={"given_name": "Alice"},
        nonce="789",
        pin="000",
        code="111",
        token="222",
    )


POP = PopResult(
    headers=None,
    payload=None,
    verified=True,
    holder_kid="did:example:holder#0",
    holder_jwk=None,
)


def test_validate_x5c_cert_chain():
    chain = _chain_for(ec.generate_private_key(ec.SECP256R1()).public_key())
    validate_x5c_cert_chain(chain)
    validate_x5c_cert_chain(chain[:1])

    for bad in ([], "MIIB", [1], ["not base64!"], ["aGVsbG8="], chain[::-1]):
        with pytest.raises(ValueError):
            validate_x5c_cert_chain(bad)


def test_validate_supported_credential_checks_x5c():
    processor = SdJwtCredIssueProcessor()
    processor.validate_supported_credential(
        _supported(_chain_for(ec.generate_private_key(ec.SECP256R1()).public_key()))
    )
    with pytest.raises(ValueError):
        processor.validate_supported_credential(_supported(["aGVsbG8="]))


@pytest.mark.asyncio
async def test_issue_with_x5c(context, issuer_key):
    did, key = issuer_key
    x5c = _chain_for(_askar_public_key(key))

    cred = await SdJwtCredIssueProcessor().issue(
        {}, _supported(x5c), _ex_record(did), POP, context
    )

    jws = cred.split("~")[0]
    header_b64, payload_b64, sig_b64 = jws.split(".")
    headers = b64_to_dict(header_b64)
    payload = b64_to_dict(payload_b64)
    assert headers["x5c"] == x5c
    assert headers["alg"] == "ES256"
    assert "kid" not in headers
    assert payload["iss"] == ISSUER_URL
    assert key_from_x5c(x5c).verify_signature(
        f"{header_b64}.{payload_b64}".encode(), b64_to_bytes(sig_b64, urlsafe=True)
    )


@pytest.mark.asyncio
async def test_issue_with_x5c_for_other_key_fails(context, issuer_key):
    did, _ = issuer_key
    x5c = _chain_for(ec.generate_private_key(ec.SECP256R1()).public_key())

    with pytest.raises(CredProcessorError, match="does not hold the signing key"):
        await SdJwtCredIssueProcessor().issue(
            {}, _supported(x5c), _ex_record(did), POP, context
        )


@pytest.mark.asyncio
async def test_issue_without_x5c_uses_did(context, issuer_key):
    did, _ = issuer_key

    cred = await SdJwtCredIssueProcessor().issue(
        {}, _supported(), _ex_record(did), POP, context
    )

    header_b64, payload_b64, _ = cred.split("~")[0].split(".")
    assert b64_to_dict(header_b64)["kid"] == did + "#0"
    assert "x5c" not in b64_to_dict(header_b64)
    assert b64_to_dict(payload_b64)["iss"] == did


def test_verify_x5c_trust():
    public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    root = _ca("Root")
    leaf = _leaf(public_key, root)

    verify_x5c_trust(_x5c(leaf, root[0]), [_pem(root[0])])
    verify_x5c_trust(_x5c(leaf), [_pem(root[0])])
    verify_x5c_trust(_x5c(leaf), [_pem(leaf)])

    # Intermediate taken from the x5c, or from the trust anchor PEM.
    inter = _ca("Intermediate", issuer=root)
    inter_leaf = _leaf(public_key, inter)
    verify_x5c_trust(_x5c(inter_leaf, inter[0]), [_pem(root[0])])
    verify_x5c_trust(_x5c(inter_leaf), [_pem(root[0], inter[0])])

    with pytest.raises(ValueError, match="no 'sd_jwt_issuer' trust anchors"):
        verify_x5c_trust(_x5c(leaf, root[0]), [])
    with pytest.raises(ValueError, match="does not lead to a trust anchor"):
        verify_x5c_trust(_x5c(leaf, root[0]), [_pem(_ca("Root")[0])])
    with pytest.raises(ValueError, match="does not lead to a trust anchor"):
        verify_x5c_trust(_x5c(inter_leaf), [_pem(root[0])])
    with pytest.raises(ValueError, match="expired or not yet valid"):
        verify_x5c_trust(
            _x5c(leaf, root[0]),
            [_pem(root[0])],
            now=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2),
        )

    # Issuers must be CAs within their path length; leaf must sign.
    not_ca_key = ec.generate_private_key(ec.SECP256R1())
    not_ca = _cert("Not CA", "Not CA", not_ca_key.public_key(), not_ca_key)
    with pytest.raises(ValueError, match="not a valid issuing CA"):
        verify_x5c_trust(_x5c(_leaf(public_key, (not_ca, not_ca_key))), [_pem(not_ca)])
    short_root = _ca("Short Root", path_length=0)
    short_inter = _ca("Short Intermediate", issuer=short_root)
    with pytest.raises(ValueError, match="'CN=Short Root' is not a valid issuing CA"):
        verify_x5c_trust(
            _x5c(_leaf(public_key, short_inter), short_inter[0]), [_pem(short_root[0])]
        )
    with pytest.raises(ValueError, match="does not allow digitalSignature"):
        verify_x5c_trust(_x5c(_leaf(public_key, root, ca=True)), [_pem(root[0])])


def test_trust_anchor_schema_accepts_sd_jwt_issuer():
    schema = TrustAnchorRecordSchema()
    assert not schema.validate({"certificate_pem": "x", "purpose": "sd_jwt_issuer"})
    assert schema.validate({"certificate_pem": "x", "purpose": "other"})


@pytest.mark.asyncio
async def test_verify_requires_sd_jwt_issuer_trust_anchor(context, issuer_key):
    did, key = issuer_key
    ca = _ca()
    cred = await SdJwtCredIssueProcessor().issue(
        {},
        _supported(_chain_for(_askar_public_key(key), ca)),
        _ex_record(did),
        POP,
        context,
    )

    assert not (await sd_jwt_verify(context.profile, cred)).verified

    async with context.session() as session:
        await TrustAnchorRecord(certificate_pem=_pem(ca[0])).save(session)
    assert not (await sd_jwt_verify(context.profile, cred)).verified

    async with context.session() as session:
        await TrustAnchorRecord(
            certificate_pem=_pem(ca[0]), purpose="sd_jwt_issuer"
        ).save(session)
    result = await sd_jwt_verify(context.profile, cred)
    assert result.verified
    assert result.payload["iss"] == ISSUER_URL


class _Request:
    def __init__(self, context, body, match_info=None):
        self._context = context
        self._body = body
        self.headers = {"Authorization": "Bearer tenant-token"}
        self.path = "/oid4vci/credential-supported"
        self.match_info = match_info or {}

    async def json(self):
        return self._body

    def __getitem__(self, key):
        assert key == "context"
        return self._context


@pytest.mark.asyncio
async def test_routes_store_x5c_cert_chain(context):
    x5c = _chain_for(ec.generate_private_key(ec.SECP256R1()).public_key())
    body = {
        "format": "vc+sd-jwt",
        "id": "ExampleID",
        "vct": "ExampleID",
        "sd_list": ["/given_name"],
        "credential_metadata": {"display": [{"name": "Example"}]},
        "x5c_cert_chain": x5c,
    }

    created = json.loads(
        (await supported_credential_create(_Request(context, body))).body
    )
    assert created["vc_additional_data"]["x5c_cert_chain"] == x5c

    match_info = {"supported_cred_id": created["supported_cred_id"]}
    updated = json.loads(
        (
            await update_supported_credential_sd_jwt(
                _Request(context, {**body, "x5c_cert_chain": x5c[:1]}, match_info)
            )
        ).body
    )
    assert updated["vc_additional_data"]["x5c_cert_chain"] == x5c[:1]

    with pytest.raises(web.HTTPBadRequest):
        await supported_credential_create(
            _Request(context, {**body, "id": "Other", "x5c_cert_chain": ["aGVsbG8="]})
        )
