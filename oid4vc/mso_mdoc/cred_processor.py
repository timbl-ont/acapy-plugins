"""mso_mdoc credential processor.

Glues together the signing-key resolution, payload preparation, and isomdl
binding layers to implement ISO/IEC 18013-5:2021 compliant mDoc issuance and
verification inside the OID4VCI plugin framework.
"""

import base64
import json
import logging
import re
from typing import Any, Dict, List, Optional

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile

from oid4vc.cred_processor import (
    BatchIssuance,
    CredProcessorError,
    CredVerifier,
    Issuer,
    PresVerifier,
)
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult
from oid4vc.status_handler import StatusHandler

from .document_signer import (
    document_signer_from_config,
    validate_document_signer_config,
)
from .mdoc.cred_verifier import MsoMdocCredVerifier
from .mdoc.issuer import MsoValidity, issue_mdoc
from .mdoc.namespaces import (
    DocumentEncodingError,
    declared_claims,
    encode_document,
    validate_claims_config,
)
from .mdoc.pres_verifier import MsoMdocPresVerifier
from .trust_anchor import TrustAnchorRecord

__all__ = ["MsoMdocCredProcessor"]

LOGGER = logging.getLogger(__name__)


def mso_status(status: Any) -> Optional[Dict[str, Any]]:
    """The MSO ``status`` from the status handler's entries for a credential.

    An mdoc carries an IETF Token Status List reference,
    ``{"status_list": {"idx": ..., "uri": ...}}``, which status list definitions
    with ``list_type`` ``ietf`` produce. Other entries (W3C Bitstring Status
    List) cannot go in the MSO and are ignored with a warning.
    """
    entries = status if isinstance(status, list) else ([status] if status else [])
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("status_list"), dict):
            return {"status_list": entry["status_list"]}
    if entries:
        LOGGER.warning(
            "mso_mdoc status needs a status list definition with list_type 'ietf'; "
            "ignoring %d other status entr%s",
            len(entries),
            "y" if len(entries) == 1 else "ies",
        )
    return None


async def _get_trust_anchors(
    profile: Profile,
    doctype: Optional[str] = None,
) -> List[str]:
    """Collect trust anchor PEMs from TrustAnchorRecord storage.

    Queries ``TrustAnchorRecord`` records with ``purpose="iaca"``.  When
    *doctype* is provided, records whose ``doctype`` tag matches OR whose
    ``doctype`` tag is ``None`` ("wildcard") are both included.
    """
    anchors: List[str] = []

    async with profile.session() as session:
        records = await TrustAnchorRecord.query(session, tag_filter={"purpose": "iaca"})
        for record in records:
            # When doctype is unspecified, include all anchors (no filtering).
            # When doctype is specified, include only exact matches and wildcards
            # (records stored without a doctype that apply to all credential types).
            if doctype is None or record.doctype is None or record.doctype == doctype:
                if record.certificate_pem:
                    anchors.append(record.certificate_pem)

    return anchors


class MsoMdocCredProcessor(Issuer, CredVerifier, PresVerifier):
    """Credential processor class for mso_mdoc credential format."""

    # COSE algorithm name → integer identifier mapping (RFC 8152 / IANA COSE registry)
    _COSE_ALG: dict = {"ES256": -7, "ES384": -35, "ES512": -36, "ES256K": -47}

    def credential_metadata(self, supported_cred: dict) -> dict:
        """Shape issuer metadata for mso_mdoc format.

        Lifts ``doctype`` from ``format_data`` to the top level, converts the
        namespace-keyed claims dict to the spec-compliant flat array, moves
        ``display`` into ``credential_metadata``, and converts COSE algorithm
        string names to integer identifiers per OID4VCI 1.0 / ISO 18013-5.
        """
        format_data = supported_cred.pop("format_data", None) or {}
        supported_cred.pop("vc_additional_data", None)  # trust anchors etc. are internal

        doctype = format_data.get("doctype")
        claims = format_data.get("claims")

        # Convert COSE algorithm string names to integer identifiers
        # (e.g. "ES256" → -7).  Numeric strings ("-7") are already converted
        # by to_issuer_metadata(); this handles name-form values like "ES256".
        algs = supported_cred.get("credential_signing_alg_values_supported")
        if algs:
            supported_cred["credential_signing_alg_values_supported"] = [
                self._COSE_ALG.get(a, a) if isinstance(a, str) else a for a in algs
            ]

        # Convert namespace-keyed claims dict to flat path-array per OID4VCI spec
        if isinstance(claims, dict):
            claims_list = []
            for namespace, claim_map in claims.items():
                if isinstance(claim_map, dict):
                    for claim_name, descriptor in claim_map.items():
                        entry: dict = {"path": [namespace, claim_name]}
                        if isinstance(descriptor, dict):
                            if "mandatory" in descriptor:
                                entry["mandatory"] = descriptor["mandatory"]
                            if "display" in descriptor:
                                entry["display"] = descriptor["display"]
                        claims_list.append(entry)
            claims = claims_list

        if claims:
            cred_meta = supported_cred.setdefault("credential_metadata", {})
            cred_meta["claims"] = claims

        # Move top-level display into credential_metadata per OID4VCI 1.0 §12.2.4
        display = supported_cred.pop("display", None)
        if display is not None:
            cred_meta = supported_cred.setdefault("credential_metadata", {})
            cred_meta["display"] = display

        if doctype:
            return {"doctype": doctype, **supported_cred}
        return supported_cred

    def __init__(self):
        """Initialize the processor."""

    def _validate_and_get_doctype(
        self, body: Dict[str, Any], supported: SupportedCredential
    ) -> str:
        """Validate and extract doctype from request and configuration.

        Validates the document type identifier according to ISO 18013-5 § 8.3.2.1.2.1
        requirements and OpenID4VCI 1.0 § E.1.1 specification.

        Args:
            body: Request body containing credential issuance parameters
            supported: Supported credential configuration with format data

        Returns:
            Validated doctype string (e.g., "org.iso.18013.5.1.mDL")

        Raises:
            CredProcessorError: If doctype validation fails with detailed context
        """
        doctype_from_request = body.get("doctype")
        doctype_from_config = (
            supported.format_data.get("doctype") if supported.format_data else None
        )

        if not doctype_from_request and not doctype_from_config:
            raise CredProcessorError(
                "Document type (doctype) is required for mso_mdoc format. "
                "Provide doctype in request body or credential configuration. "
                "See OpenID4VCI 1.0 § E.1.1 and ISO 18013-5 § 8.3.2.1.2.1"
            )

        # Use doctype from request if provided, otherwise from configuration
        doctype = doctype_from_request or doctype_from_config

        if doctype_from_request and doctype_from_config:
            if doctype_from_request != doctype_from_config:
                raise CredProcessorError(
                    f"Document type mismatch: request contains '{doctype_from_request}' "
                    f"but credential configuration specifies '{doctype_from_config}'. "
                    "Ensure consistency between request and credential configuration."
                )

        # Validate doctype format (basic ISO format check)
        if not doctype or not isinstance(doctype, str):
            raise CredProcessorError(
                "Invalid doctype format: expected non-empty string, "
                f"got {type(doctype).__name__}"
            )

        if not doctype.startswith("org.iso."):
            LOGGER.warning(
                "Document type '%s' does not follow ISO format convention (org.iso.*)",
                doctype,
            )

        return doctype

    def _extract_device_key(
        self, pop: PopResult, ex_record: OID4VCIExchangeRecord
    ) -> Optional[str]:
        """Extract device authentication key from proof of possession or exchange record.

        Extracts and validates the device key for holder binding according to
        ISO 18013-5 § 9.1.3.4 device authentication requirements and
        OpenID4VCI proof of possession mechanisms.

        Args:
            pop: Proof of possession result containing holder key information
            ex_record: Exchange record with credential issuance context

        Returns:
            Serialized device key string (JWK JSON or key identifier),
            or None if unavailable

        Raises:
            CredProcessorError: If device key format is invalid or unsupported
        """
        # Priority order: holder JWK > holder key ID > verification method from record
        device_candidate = (
            pop.holder_jwk or pop.holder_kid or ex_record.verification_method
        )

        if isinstance(device_candidate, dict):
            # The device key embedded in the mDoc MSO must contain ONLY public
            # parameters; passing 'd' to the Rust isomdl library would leak
            # the holder's private key into the issued credential.
            _PUBLIC_JWK_FIELDS = frozenset(("kty", "crv", "x", "y", "n", "e"))
            public_only = {
                k: v for k, v in device_candidate.items() if k in _PUBLIC_JWK_FIELDS
            }
            return json.dumps(public_only)
        elif isinstance(device_candidate, str):
            # If a DID with fragment, prefer fragment (key id); otherwise raw string
            m = re.match(r"did:(.+?):(.+?)(?:#(.*))?$", device_candidate)
            if m:
                method = m.group(1)
                identifier = m.group(2)
                fragment = m.group(3)

                if method == "jwk":
                    # did:jwk encodes the holder's public JWK as a base64url
                    # value in the DID identifier itself (i.e. between
                    # "did:jwk:" and "#0").  ACA-Py uses this method natively
                    # when a wallet generates ephemeral keys.
                    #
                    # Without special handling the generic DID regex returns
                    # only the fragment "0", and json.loads("0") silently
                    # produces the integer 0 — which the Rust isomdl library
                    # then receives as the holder key, causing an opaque
                    # failure with no hint that the root cause is a
                    # mis-parsed DID method.
                    try:
                        # Base64url may be missing padding — add it back.
                        padding = "=" * (-len(identifier) % 4)
                        jwk_bytes = base64.urlsafe_b64decode(identifier + padding)
                        return jwk_bytes.decode("utf-8")
                    except Exception as exc:
                        raise CredProcessorError(
                            f"Invalid did:jwk identifier — could not decode "
                            f"embedded JWK from '{device_candidate}': {exc}"
                        ) from exc

                return fragment if fragment else device_candidate
            else:
                return device_candidate

        return None

    @staticmethod
    def _declared_claims(supported: SupportedCredential) -> Dict[str, Dict[str, dict]]:
        """Claims the configuration declares, by namespace and element."""
        return declared_claims(
            (supported.format_data or {}).get("claims"),
            (supported.credential_metadata or {}).get("claims"),
        )

    @staticmethod
    def _holder_jwk(pop: PopResult, device_key_str: Optional[str]) -> Dict[str, Any]:
        """The holder's P-256 device key as a public JWK (kty, crv, x, y only).

        isomdl rejects other members such as ``alg`` and ``use``, and the device
        key in the MSO must never carry private parameters.
        """
        jwk = pop.holder_jwk
        if not isinstance(jwk, dict) and device_key_str:
            try:
                jwk = json.loads(device_key_str)
            except (json.JSONDecodeError, TypeError):
                raise CredProcessorError(
                    "Holder key identifier provided but a full EC JWK is required "
                    "for mso_mdoc device key binding. Provide holder_jwk in the "
                    "proof of possession."
                ) from None
        if not isinstance(jwk, dict):
            raise CredProcessorError(
                "No device key available: provide holder_jwk, holder_kid, or "
                "verification_method"
            )
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            raise CredProcessorError(
                "mso_mdoc requires a P-256 EC holder key, got "
                f"kty={jwk.get('kty')} crv={jwk.get('crv')}"
            )
        return {k: jwk[k] for k in ("kty", "crv", "x", "y") if k in jwk}

    async def _status_claim(
        self,
        context: AdminRequestContext,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        batch: BatchIssuance | None,
    ) -> Optional[Dict[str, Any]]:
        """Assign a Token Status List entry through the configured status handler.

        Like the other formats, the entry is recorded against the exchange, so
        ``PATCH /status-list/defs/{def_id}/creds/{exchange_id}`` revokes the
        credential. Returns None without a status handler or a status list
        definition for the credential configuration.
        """
        status_handler = context.inject_or(StatusHandler)
        if not status_handler:
            return None
        if batch:
            status = await batch.assign_status(
                status_handler.assign_status_entries,
                context,
                supported.supported_cred_id,
                ex_record.exchange_id,
            )
        else:
            status = await status_handler.assign_status_entries(
                context, supported.supported_cred_id, ex_record.exchange_id
            )
        return mso_status(status)

    async def issue(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
        *,
        batch: BatchIssuance | None = None,
    ):
        """Return signed credential in CBOR format.

        Issues an ISO 18013-5 compliant mDoc credential using the mobile
        security object (MSO) format. The credential is CBOR-encoded and
        follows the issuerSigned structure defined in ISO 18013-5.

        Protocol Compliance:
        - OpenID4VCI 1.0 § 7.3.1: Credential Response for mso_mdoc format
        - OpenID4VCI 1.0 Appendix E.1.1: mso_mdoc Credential format identifier
        - ISO 18013-5 § 8.3: Mobile document structure
        - ISO 18013-5 § 9.1.2: IssuerSigned data structure
        - ISO 18013-5 § 9.1.3: Mobile security object (MSO)
        - RFC 8949: CBOR encoding for binary efficiency
        - RFC 8152: COSE signing for cryptographic protection

        OpenID4VCI 1.0 § E.1.1: mso_mdoc Format
        https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-E.1.1
        """
        if not supported.format_data:
            raise CredProcessorError("Supported credential must have format_data")

        try:
            doctype = self._validate_and_get_doctype(body, supported)
            device_key_str = self._extract_device_key(pop, ex_record)
            holder_jwk = self._holder_jwk(pop, device_key_str)

            # Encode the subject as CBOR element values per namespace; the
            # profile for the doctype validates the standard namespaces.
            namespaces = encode_document(
                doctype,
                ex_record.credential_subject,
                self._declared_claims(supported),
            )

            additional = supported.vc_additional_data or {}
            signer = document_signer_from_config(additional)
            validity = MsoValidity.from_config(additional.get("validity_info"))

            status_claim = await self._status_claim(context, supported, ex_record, batch)

            async with context.profile.session() as session:
                mso_mdoc = await issue_mdoc(
                    session,
                    doctype=doctype,
                    namespaces=namespaces,
                    holder_jwk=holder_jwk,
                    signer=signer,
                    validity=validity,
                    status_claim=status_claim,
                )

            LOGGER.info(
                "Issued mso_mdoc credential with doctype: %s, format: %s",
                doctype,
                supported.format,
            )

        except Exception as ex:
            # Log full exception for debugging before raising a generic error
            LOGGER.exception("mso_mdoc issuance error: %s", ex)
            # Surface the underlying exception text in the CredProcessorError
            raise CredProcessorError(f"Failed to issue mso_mdoc credential: {ex}") from ex

        return mso_mdoc

    def validate_credential_subject(self, supported: SupportedCredential, subject: dict):
        """Validate the credential subject by encoding it.

        Callers get an actionable error when the exchange is created rather than
        at issuance. Errors name the namespace and element, never the value.
        """
        if not subject:
            raise CredProcessorError("Credential subject cannot be empty")
        if not isinstance(subject, dict):
            raise CredProcessorError("Credential subject must be a dictionary")

        doctype = (supported.format_data or {}).get("doctype", "")
        try:
            encode_document(doctype, subject, self._declared_claims(supported))
        except DocumentEncodingError as err:
            raise CredProcessorError(f"Invalid mso_mdoc credential subject: {err}")
        return True

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate a supported MSO MDOC Credential."""
        if not supported.format_data:
            raise CredProcessorError("format_data is required for mso_mdoc format")

        # Validate doctype presence and format
        self._validate_and_get_doctype({}, supported)

        try:
            validate_claims_config(supported.format_data.get("claims"))
        except DocumentEncodingError as err:
            raise CredProcessorError(f"Invalid claims: {err}")

        additional = supported.vc_additional_data or {}
        validate_document_signer_config(additional.get("document_signer"))
        try:
            MsoValidity.from_config(additional.get("validity_info"))
        except ValueError as err:
            raise CredProcessorError(str(err))

        return True

    async def verify_credential(
        self,
        profile: Profile,
        credential: Any,
    ):
        """Verify an mso_mdoc credential."""
        trust_anchors = await _get_trust_anchors(profile)
        verifier = MsoMdocCredVerifier(trust_anchors=trust_anchors)
        return await verifier.verify_credential(profile, credential)

    async def verify_presentation(
        self,
        profile: Profile,
        presentation: Any,
        presentation_record: "OID4VPPresentation",
    ):
        """Verify an mso_mdoc presentation."""
        trust_anchors = await _get_trust_anchors(profile)
        verifier = MsoMdocPresVerifier(trust_anchors=trust_anchors)
        return await verifier.verify_presentation(
            profile, presentation, presentation_record
        )
