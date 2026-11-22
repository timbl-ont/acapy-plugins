"""mso_mdoc issuance with isomdl-uniffi and an external document signer.

The mdoc is built in three steps, so that the plugin never needs the issuer's
private key:

1. ``PreparedMdoc.new_from_cbor`` builds the mdoc from CBOR-encoded element
   values (see ``mso_mdoc.mdoc.namespaces``), the holder's device key, the
   status list reference and the MSO validity, and returns the COSE
   ToBeSigned bytes of the MSO.
2. The document signer signs those bytes (``mso_mdoc.document_signer``): a
   wallet key through ``wallet.sign_message``, or a legacy PEM key.
3. ``PreparedMdoc.complete`` adds the signature and the document signer's
   certificate chain, and the result is serialised as IssuerSigned.

Protocol Compliance:
- OpenID4VCI 1.0 § E.1.1: mso_mdoc Credential Format
- ISO/IEC 18013-5:2021 § 9.1.2: Mobile security object (MSO) and validityInfo
- RFC 9052: COSE_Sign1 with ES256
"""

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping, Optional

from acapy_agent.core.profile import ProfileSession
from isomdl_uniffi import Mdoc, PreparedMdoc

from ..document_signer import DocumentSigner, DocumentSignerError

LOGGER = logging.getLogger(__name__)

SIGNATURE_ALGORITHM = "ES256"
DEFAULT_VALID_UNTIL_SECONDS = 30 * 24 * 60 * 60


def rfc3339(moment: datetime) -> str:
    """``moment`` in UTC as ``YYYY-MM-DDTHH:MM:SSZ``."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class MsoValidity:
    """The MSO validityInfo times. ``valid_from`` None means the signing time."""

    valid_from: Optional[datetime]
    valid_until: datetime
    expected_update: Optional[datetime]

    @classmethod
    def from_config(
        cls, validity_info: Optional[Mapping[str, Any]], now: Optional[datetime] = None
    ) -> "MsoValidity":
        """Times from a ``validity_info`` configuration of seconds after signing.

        ``valid_from`` defaults to 0 (the signing time), ``valid_until`` to 30
        days, and ``expected_update`` to none. Raises ``ValueError`` for values
        that are not non-negative integers or a ``valid_until`` that is not
        later than ``valid_from``.
        """
        config = dict(validity_info or {})
        unknown = set(config) - {"valid_from", "valid_until", "expected_update"}
        if unknown:
            raise ValueError(
                f"validity_info has unknown keys: {', '.join(sorted(unknown))}"
            )

        def seconds(key: str, default: Optional[int]) -> Optional[int]:
            value = config.get(key, default)
            if value is None:
                return None
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"validity_info {key} must be a non-negative integer")
            return value

        from_s = seconds("valid_from", 0)
        until_s = seconds("valid_until", DEFAULT_VALID_UNTIL_SECONDS)
        update_s = seconds("expected_update", None)
        if until_s <= from_s:
            raise ValueError("validity_info valid_until must be greater than valid_from")

        now = (now or datetime.now(UTC)).replace(microsecond=0)
        return cls(
            valid_from=now + timedelta(seconds=from_s) if from_s else None,
            valid_until=now + timedelta(seconds=until_s),
            expected_update=(
                now + timedelta(seconds=update_s) if update_s is not None else None
            ),
        )


async def issue_mdoc(
    session: ProfileSession,
    *,
    doctype: str,
    namespaces: Mapping[str, Mapping[str, bytes]],
    holder_jwk: Mapping[str, Any],
    signer: DocumentSigner,
    validity: MsoValidity,
    status_claim: Optional[Mapping[str, Any]] = None,
) -> str:
    """Issue an mdoc and return it as base64url IssuerSigned.

    ``namespaces`` holds CBOR-encoded element values by namespace and element
    identifier. ``status_claim`` (``{"status_list": {"idx": ..., "uri": ...}}``)
    is stored as the MSO ``status``.
    """
    chain_pem = await signer.chain_pem(session, validity.valid_until)

    prepared = PreparedMdoc.new_from_cbor(
        doctype,
        {ns: dict(elements) for ns, elements in namespaces.items()},
        json.dumps(dict(holder_jwk)),
        SIGNATURE_ALGORITHM,
        json.dumps(dict(status_claim)) if status_claim else None,
        rfc3339(validity.valid_from) if validity.valid_from else None,
        rfc3339(validity.valid_until),
        rfc3339(validity.expected_update) if validity.expected_update else None,
    )

    signature = await signer.sign(session, prepared.signature_payload())
    if len(signature) != 64:
        raise DocumentSignerError(
            f"{SIGNATURE_ALGORITHM} document signer returned {len(signature)} bytes; "
            "expected the raw 64-byte r || s"
        )

    mdoc = prepared.complete(chain_pem, signature)
    LOGGER.info(
        "Issued mdoc %s via PreparedMdoc.new_from_cbor with namespaces %s",
        doctype,
        sorted(namespaces),
    )
    # issuer_signed_b64() serialises IssuerSigned with the ISO 18013-5 § 8.3 keys
    # (camelCase, nameSpaces as arrays) as base64url without padding, which is
    # what OID4VCI 1.0 § 7.3.1 expects.
    return mdoc.issuer_signed_b64()


def parse_mdoc(cbor_data: str) -> Mdoc:
    """Parse a CBOR-encoded mDoc string into an Mdoc object."""
    try:
        return Mdoc.from_string(cbor_data)
    except Exception as ex:
        LOGGER.error("Failed to parse mdoc: %s", ex)
        raise ValueError(f"Failed to parse mdoc: {ex}") from ex
