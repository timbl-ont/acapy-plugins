"""mso_mdoc OID4VP presentation verifier."""

import json
import logging
from typing import Any, List, Optional

import isomdl_uniffi
from acapy_agent.core.profile import Profile
from cryptography import x509 as _x509

from oid4vc.cred_processor import PresVerifier, VerifyResult
from oid4vc.did_utils import retrieve_or_create_did_jwk
from oid4vc.models.dcql_query import CredentialQuery, DCQLQuery
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.utils import oid4vp_response_uri

from .utils import check_status_list_claim, flatten_trust_anchors
from .cred_verifier import PreverifiedMdocClaims
from .mdoc_item import (
    _decode_presentation_bytes,
    _normalize_presentation_input,
    extract_verified_claims,
)

LOGGER = logging.getLogger(__name__)


async def _get_oid4vp_verification_params(
    profile: Profile,
    presentation_record: "OID4VPPresentation",
) -> tuple[str, str, str]:
    """Get the OID4VP request parameters the wallet bound its device signature to.

    The mdoc SessionTranscript (OpenID4VP 1.0 Appendix B.2.6.1) hashes the
    request's ``client_id`` (including its Client Identifier Prefix), ``nonce``
    and ``response_uri``. They must equal the values in the request the wallet
    received, or honest device authentication fails.

    Args:
        profile: The profile
        presentation_record: The presentation record

    Returns:
        Tuple of (nonce, client_id, response_uri)
    """
    nonce = presentation_record.nonce

    # The request stored its client_id on the record: x509_san_dns:<host> when an
    # X.509 verifier identity is registered, otherwise the did:jwk.
    client_id = presentation_record.client_id
    if not client_id:
        async with profile.session() as session:
            client_id = (await retrieve_or_create_did_jwk(session)).did

    response_uri = oid4vp_response_uri(profile, presentation_record.presentation_id)

    return nonce, client_id, response_uri


def _query_accepts_doctype(cred: CredentialQuery, doc_type: Optional[str]) -> bool:
    """Whether a DCQL credential query accepts an mdoc of this doctype.

    Mirrors the DCQL evaluator's doctype check: ``meta.doctype_value``, else
    ``meta.doctype_values``; a query with neither accepts any doctype.
    """
    if cred.meta and cred.meta.doctype_value:
        return doc_type == cred.meta.doctype_value
    if cred.meta and cred.meta.doctype_values:
        return doc_type in cred.meta.doctype_values
    return True


async def _holder_binding_required(
    profile: Profile,
    presentation_record: OID4VPPresentation,
    doc_type: Optional[str],
) -> bool:
    """Whether an mdoc presentation must prove holder binding (device auth).

    For mdoc, the device signature over the SessionTranscript is the only proof
    that the holder's device key presented the credential for this request
    (nonce and verifier). Without it a captured DeviceResponse can be replayed.

    DCQL: OpenID4VP 1.0 Section 6.1 ``require_cryptographic_holder_binding``,
    default true. Binding is waived only when every ``mso_mdoc`` credential
    query that accepts this doctype sets it to false. The DCQL evaluator then
    checks the doctype against the query being answered, so a presentation
    cannot borrow the waiver of a query for another doctype.

    Presentation Exchange has no equivalent opt-out, so binding is required.
    """
    if not presentation_record.dcql_query_id:
        return True

    async with profile.session() as session:
        query = await DCQLQuery.retrieve_by_id(session, presentation_record.dcql_query_id)

    candidates = [
        cred
        for cred in query.credentials or []
        if cred.format == "mso_mdoc" and _query_accepts_doctype(cred, doc_type)
    ]
    if not candidates:
        return True
    return any(
        cred.require_cryptographic_holder_binding is not False for cred in candidates
    )


def _verify_single_presentation(
    response_bytes: bytes,
    nonce: str,
    client_id: str,
    response_uri: str,
    trust_anchor_registry: List[str],
) -> Any:
    """Verify a single OID4VP presentation.

    Args:
        response_bytes: The presentation bytes
        nonce: The nonce
        client_id: The client ID
        response_uri: The response URI
        trust_anchor_registry: JSON-serialized PemTrustAnchor strings, each of the form
            '{"certificate_pem": "...", "purpose": "Iaca"}'

    Returns:
        Verified payload dict if successful, None if failed
    """
    LOGGER.debug(
        "Calling verify_oid4vp_response with: "
        "nonce=%s client_id=%s response_uri=%s "
        "response_bytes_len=%d",
        nonce,
        client_id,
        response_uri,
        len(response_bytes),
    )

    # Try spec-compliant format (2024) first
    verified_data = isomdl_uniffi.verify_oid4vp_response(
        response_bytes,
        nonce,
        client_id,
        response_uri,
        trust_anchor_registry,
        True,
    )

    # If device auth failed but issuer is valid, try legacy format
    if (
        verified_data.device_authentication != isomdl_uniffi.AuthenticationStatus.VALID
        and verified_data.issuer_authentication
        == isomdl_uniffi.AuthenticationStatus.VALID
    ):
        if hasattr(isomdl_uniffi, "verify_oid4vp_response_legacy"):
            LOGGER.info(
                "Device auth failed with spec-compliant format, trying legacy 2023 format"
            )
            verified_data = isomdl_uniffi.verify_oid4vp_response_legacy(
                response_bytes,
                nonce,
                client_id,
                response_uri,
                trust_anchor_registry,
                True,
            )
        else:
            LOGGER.warning(
                "Device auth failed and legacy format not available in isomdl_uniffi"
            )

    return verified_data


class MsoMdocPresVerifier(PresVerifier):
    """Verifier for mso_mdoc presentations (OID4VP)."""

    def __init__(self, trust_anchors: Optional[List[str]] = None):
        """Initialize the presentation verifier.

        Args:
            trust_anchors: PEM-encoded trust anchor certificates.
        """
        self.trust_anchors = trust_anchors or []

    def _parse_jsonpath(self, path: str) -> List[str]:
        """Parse JSONPath to extract segments."""
        # Handle $['namespace']['element'] format
        if "['" in path:
            return [
                p.strip("]['\"")
                for p in path.split("['")
                if p.strip("]['\"") and p != "$"
            ]

        # Handle $.namespace.element format
        clean = path.replace("$", "")
        if clean.startswith("."):
            clean = clean[1:]
        return clean.split(".")

    async def verify_presentation(
        self,
        profile: Profile,
        presentation: Any,
        presentation_record: OID4VPPresentation,
    ) -> VerifyResult:
        """Verify an mso_mdoc presentation.

        Args:
            profile: The profile for context
            presentation: The presentation data (bytes)
            presentation_record: The presentation record containing request info

        Returns:
            VerifyResult: The verification result
        """
        try:
            # 1. Prepare Trust Anchors
            trust_anchors = (
                flatten_trust_anchors(self.trust_anchors) if self.trust_anchors else []
            )
            LOGGER.debug(
                "Trust anchors loaded: %d cert(s)",
                len(trust_anchors),
            )
            for i, pem in enumerate(trust_anchors):
                pem_stripped = pem.strip() if pem else ""
                LOGGER.debug(
                    "Trust anchor %d: len=%d",
                    i,
                    len(pem_stripped),
                )
                # Validate that the PEM is parseable by Python before
                # passing to Rust
                try:
                    _x509.load_pem_x509_certificate(pem_stripped.encode())
                except Exception as pem_err:
                    LOGGER.error(
                        "Trust anchor %d: PEM validation FAILED: %s",
                        i,
                        pem_err,
                    )

            if trust_anchors:
                LOGGER.debug(
                    "Trust anchors after chain-splitting: %d individual cert(s)",
                    len(trust_anchors),
                )

            # Fail-closed guard: refuse to verify without at least one trust
            # anchor.  An empty list causes Rust to accept any self-signed
            # issuer certificate, bypassing chain validation entirely.
            if not trust_anchors:
                return VerifyResult(
                    verified=False,
                    payload={
                        "error": "No trust anchors configured; presentation "
                        "verification requires at least one trust anchor."
                    },
                )

            # verify_oid4vp_response expects JSON-serialized PemTrustAnchor per anchor:
            # {"certificate_pem": "...", "purpose": "Iaca"}
            # Rust parses each string via serde_json::from_str::<PemTrustAnchor>().
            trust_anchor_registry = (
                [
                    json.dumps({"certificate_pem": pem, "purpose": "Iaca"})
                    for pem in trust_anchors
                ]
                if trust_anchors
                else []
            )
            if trust_anchor_registry:
                LOGGER.debug(
                    "trust_anchor_registry[0] first100: %r",
                    trust_anchor_registry[0][:100],
                )

            # 2. Get verification parameters
            nonce, client_id, response_uri = await _get_oid4vp_verification_params(
                profile, presentation_record
            )

            # 3. Normalize presentation input
            presentations_to_verify, is_list_input = _normalize_presentation_input(
                presentation
            )

            verified_payloads = []

            for pres_item in presentations_to_verify:
                LOGGER.debug(
                    "vp_token type=%s len=%s",
                    type(pres_item).__name__,
                    len(pres_item) if hasattr(pres_item, "__len__") else "N/A",
                )

                response_bytes = _decode_presentation_bytes(pres_item)

                verified_data = _verify_single_presentation(
                    response_bytes,
                    nonce,
                    client_id,
                    response_uri,
                    trust_anchor_registry,
                )

                # Issuer authentication proves the data is genuine. Only device
                # authentication (the device key's signature over the
                # SessionTranscript) binds the presentation to the holder and to
                # this request's nonce and verifier. deviceSigned is mandatory in
                # the ISO/IEC 18013-5 Document CDDL and in isomdl's Document, which
                # isomdl-uniffi fills with a placeholder that fails verification
                # when a wallet omits it.
                issuer_ok = (
                    verified_data.issuer_authentication
                    == isomdl_uniffi.AuthenticationStatus.VALID
                )
                device_ok = (
                    verified_data.device_authentication
                    == isomdl_uniffi.AuthenticationStatus.VALID
                )

                if issuer_ok and not device_ok:
                    if await _holder_binding_required(
                        profile, presentation_record, verified_data.doc_type
                    ):
                        LOGGER.warning(
                            "mDoc presentation rejected: device authentication "
                            "failed (Device=%s, Errors=%s). The query requires "
                            "holder binding.",
                            verified_data.device_authentication,
                            verified_data.errors,
                        )
                        return VerifyResult(
                            verified=False,
                            payload={
                                "error": "Device authentication failed: the "
                                "presentation is not bound to the holder's device "
                                "key for this request (holder binding required)",
                                "docType": verified_data.doc_type,
                                "issuer_auth": str(verified_data.issuer_authentication),
                                "device_auth": str(verified_data.device_authentication),
                            },
                        )
                    LOGGER.info(
                        "Accepting issuer-only mDoc presentation: the DCQL query "
                        "sets require_cryptographic_holder_binding to false "
                        "(Device=%s)",
                        verified_data.device_authentication,
                    )

                if issuer_ok:
                    try:
                        claims = extract_verified_claims(verified_data.verified_response)
                    except Exception as e:
                        LOGGER.warning("Failed to extract claims: %s", e)
                        claims = {}

                    # Check IETF Token Status List revocation if embedded in claims
                    revocation_error = await check_status_list_claim(claims)
                    if revocation_error:
                        LOGGER.warning(
                            "mDoc presentation rejected — credential revoked: %s",
                            revocation_error,
                        )
                        return VerifyResult(
                            verified=False,
                            payload={
                                "error": revocation_error,
                                "docType": verified_data.doc_type,
                            },
                        )

                    payload = {
                        "status": "verified",
                        "docType": verified_data.doc_type,
                        "issuer_auth": str(verified_data.issuer_authentication),
                        "device_auth": str(verified_data.device_authentication),
                    }
                    payload.update(claims)
                    verified_payloads.append(PreverifiedMdocClaims(claims=payload))
                else:
                    LOGGER.error(
                        "Verification failed: Issuer=%s, Device=%s, Errors=%s",
                        verified_data.issuer_authentication,
                        verified_data.device_authentication,
                        verified_data.errors,
                    )
                    try:
                        claims = extract_verified_claims(verified_data.verified_response)
                    except Exception:
                        claims = {}

                    return VerifyResult(
                        verified=False,
                        payload={
                            "error": verified_data.errors,
                            "issuer_auth": str(verified_data.issuer_authentication),
                            "device_auth": str(verified_data.device_authentication),
                            "claims": claims,
                        },
                    )

            # Return list if input was list, otherwise single item
            payload = verified_payloads
            if not is_list_input and len(verified_payloads) == 1:
                payload = verified_payloads[0]

            return VerifyResult(verified=True, payload=payload)

        except Exception as e:
            LOGGER.exception("Error verifying mdoc presentation")
            return VerifyResult(verified=False, payload={"error": str(e)})
