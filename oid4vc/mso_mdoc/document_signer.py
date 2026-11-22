"""Document signers: where the mdoc document signer (DS) key and certificate come from.

A credential configuration names its document signer in
``vc_additional_data.document_signer``:

``{"key_type": "wallet", "multikey": "zDn..."}``
    A P-256 key in the ACA-Py wallet, which may be held by an external signer.
    The certificate chain comes from the ``x509_certs`` plugin (purpose
    ``mdoc_ds``). The plugin never sees the private key.

``{"key_type": "pem", "signing_key_id": "..."}``
    A legacy ``MdocSigningKeyRecord`` holding a PEM private key and certificate,
    created through ``/mso-mdoc/signing-keys``.

Both sign the COSE ToBeSigned bytes of a ``PreparedMdoc`` and return the raw
64-byte ``r || s`` that COSE ES256 uses.
"""

import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, Mapping, Optional

from acapy_agent.core.profile import ProfileSession
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import P256
from acapy_agent.wallet.keys.manager import multikey_to_verkey
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from oid4vc.cred_processor import CredProcessorError

from .signing_key import MdocSigningKeyRecord

LOGGER = logging.getLogger(__name__)

KEY_TYPES = ("wallet", "pem")
DS_CERTIFICATE_PURPOSE = "mdoc_ds"


class DocumentSignerError(CredProcessorError):
    """The document signer is missing, misconfigured or unusable."""


class DocumentSigner(ABC):
    """Signs the MSO of an mdoc and supplies the certificate chain for it."""

    @abstractmethod
    async def chain_pem(self, session: ProfileSession, valid_until: datetime) -> str:
        """Leaf-first PEM chain whose leaf is valid from now until ``valid_until``."""

    @abstractmethod
    async def sign(self, session: ProfileSession, tbs: bytes) -> bytes:
        """ES256 signature over ``tbs`` as raw 64-byte ``r || s``."""


def _x509_certs():
    """The x509_certs plugin's Python API, or an error saying it is required."""
    try:
        import x509_certs  # noqa: PLC0415 — optional plugin, needed for wallet keys
    except ImportError as err:
        raise DocumentSignerError(
            "document_signer key_type 'wallet' needs the x509_certs plugin, which "
            "is not installed"
        ) from err
    return x509_certs


class WalletDocumentSigner(DocumentSigner):
    """A P-256 wallet key, with its certificate chain from ``x509_certs``."""

    def __init__(self, multikey: str):
        """Sign with the wallet key ``multikey``."""
        self.multikey = multikey

    async def chain_pem(self, session: ProfileSession, valid_until: datetime) -> str:
        """The ``mdoc_ds`` chain for the key, without a self-signed root."""
        certs = _x509_certs()
        try:
            record = await certs.select_certificate(
                session, self.multikey, DS_CERTIFICATE_PURPOSE, valid_until
            )
        except certs.X509Error as err:
            raise DocumentSignerError(str(err)) from err
        return certs.pem_chain(certs.embedded_x5c(record))

    async def sign(self, session: ProfileSession, tbs: bytes) -> bytes:
        """Sign with ``wallet.sign_message``, which may route to an external signer."""
        wallet = session.inject(BaseWallet)
        try:
            return await wallet.sign_message(tbs, multikey_to_verkey(self.multikey))
        except WalletError as err:
            raise DocumentSignerError(
                f"wallet could not sign with the document signer key: {err}"
            ) from err


class PemDocumentSigner(DocumentSigner):
    """A legacy ``MdocSigningKeyRecord`` with a PEM private key and certificate."""

    def __init__(self, signing_key_id: str):
        """Sign with the ``MdocSigningKeyRecord`` ``signing_key_id``."""
        self.signing_key_id = signing_key_id
        self._record: Optional[MdocSigningKeyRecord] = None

    async def _load(self, session: ProfileSession) -> MdocSigningKeyRecord:
        if self._record is None:
            try:
                record = await MdocSigningKeyRecord.retrieve_by_id(
                    session, self.signing_key_id
                )
            except StorageNotFoundError as err:
                raise DocumentSignerError(
                    f"document signer: no mdoc signing key {self.signing_key_id}"
                ) from err
            if not record.private_key_pem or not record.certificate_pem:
                raise DocumentSignerError(
                    f"document signer: mdoc signing key {self.signing_key_id} has no "
                    "private key or certificate"
                )
            self._record = record
        return self._record

    async def chain_pem(self, session: ProfileSession, valid_until: datetime) -> str:
        """The record's chain, checked for validity and without a self-signed root."""
        record = await self._load(session)
        try:
            certs = x509.load_pem_x509_certificates(record.certificate_pem.encode())
        except ValueError as err:
            raise DocumentSignerError(
                f"document signer: invalid certificate PEM: {err}"
            ) from err
        leaf = certs[0]
        now = datetime.now(UTC)
        if leaf.not_valid_before_utc > now or leaf.not_valid_after_utc < valid_until:
            raise DocumentSignerError(
                "document signer certificate is not valid from now until "
                f"{valid_until.isoformat()} (valid "
                f"{leaf.not_valid_before_utc.isoformat()} to "
                f"{leaf.not_valid_after_utc.isoformat()})"
            )
        if len(certs) > 1 and certs[-1].subject == certs[-1].issuer:
            certs = certs[:-1]
        return "".join(
            cert.public_bytes(serialization.Encoding.PEM).decode() for cert in certs
        )

    async def sign(self, session: ProfileSession, tbs: bytes) -> bytes:
        """ECDSA P-256 / SHA-256 with the record's key, as raw ``r || s``."""
        record = await self._load(session)
        key = serialization.load_pem_private_key(
            record.private_key_pem.encode(), password=None
        )
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise DocumentSignerError("document signer key must be P-256")
        r, s = decode_dss_signature(key.sign(tbs, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def validate_document_signer_config(config: Any) -> dict:
    """Check the shape of a ``document_signer`` configuration; return it.

    Raises ``DocumentSignerError`` when it is missing or malformed.
    """
    if not config:
        raise DocumentSignerError(
            "document_signer is not configured for this credential configuration; "
            "set it to {'key_type': 'wallet', 'multikey': ...} or "
            "{'key_type': 'pem', 'signing_key_id': ...}"
        )
    if not isinstance(config, dict):
        raise DocumentSignerError("document_signer must be an object")
    key_type = config.get("key_type")
    if key_type == "wallet":
        if not isinstance(config.get("multikey"), str) or not config["multikey"]:
            raise DocumentSignerError("document_signer key_type 'wallet' needs multikey")
    elif key_type == "pem":
        signing_key_id = config.get("signing_key_id")
        if not isinstance(signing_key_id, str) or not signing_key_id:
            raise DocumentSignerError(
                "document_signer key_type 'pem' needs signing_key_id"
            )
    else:
        raise DocumentSignerError(
            f"document_signer key_type must be one of {', '.join(KEY_TYPES)}"
        )
    return config


def document_signer_from_config(
    vc_additional_data: Optional[Mapping[str, Any]],
) -> DocumentSigner:
    """The document signer a credential configuration names.

    There is no fallback: a configuration without ``document_signer`` cannot issue.
    """
    config = validate_document_signer_config(
        (vc_additional_data or {}).get("document_signer")
    )
    if config["key_type"] == "wallet":
        return WalletDocumentSigner(config["multikey"])
    return PemDocumentSigner(config["signing_key_id"])


async def check_document_signer(session: ProfileSession, config: Any) -> list[str]:
    """Check that a ``document_signer`` configuration can be used; return warnings.

    The wallet key must exist and be P-256, and a legacy signing key record must
    exist. A wallet key without an ``mdoc_ds`` certificate yet is only a warning,
    because the certificate may be imported later.
    """
    config = validate_document_signer_config(config)
    warnings: list[str] = []
    if config["key_type"] == "wallet":
        multikey = config["multikey"]
        try:
            verkey = multikey_to_verkey(multikey)
        except Exception as err:
            raise DocumentSignerError(
                f"document_signer multikey is not a valid multikey: {err}"
            ) from err
        try:
            key_info = await session.inject(BaseWallet).get_signing_key(verkey)
        except WalletError as err:
            raise DocumentSignerError(
                f"document_signer multikey is not a key in this wallet: {err}"
            ) from err
        if key_info.key_type != P256:
            raise DocumentSignerError("document_signer wallet key must be P-256")
        certs = _x509_certs()
        records = await certs.X509CertificateRecord.query(
            session, {"multikey": multikey, "purpose": DS_CERTIFICATE_PURPOSE}
        )
        if not records:
            warnings.append(
                f"no {DS_CERTIFICATE_PURPOSE} certificate is stored for the document "
                "signer key yet; issuance fails until one is imported with "
                "POST /x509/certificates"
            )
    else:
        try:
            await MdocSigningKeyRecord.retrieve_by_id(session, config["signing_key_id"])
        except StorageNotFoundError as err:
            raise DocumentSignerError(
                f"document_signer signing_key_id {config['signing_key_id']} not found"
            ) from err
    return warnings
