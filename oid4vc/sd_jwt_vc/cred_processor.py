"""Issue an SD-JWT credential."""

import base64
import binascii
import json
import logging
import re
import time
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.jwt import JWTVerifyResult
from acapy_agent.wallet.util import bytes_to_b64
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from jsonpointer import EndOfList, JsonPointer, JsonPointerException
from pydid import DIDUrl
from sd_jwt.issuer import SDJWTIssuer, SDObj
from sd_jwt.verifier import KB_DIGEST_KEY, SDJWTVerifier

from oid4vc.cred_processor import (
    CredProcessorError,
    CredVerifier,
    Issuer,
    PresVerifier,
    VerifyResult,
)
from oid4vc.config import Config
from oid4vc.jwt import jwt_sign, jwt_verify, key_from_x5c, key_material_for_kid
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult
from oid4vc.status_handler import StatusHandler

LOGGER = logging.getLogger(__name__)

# mso_mdoc TrustAnchorRecord purpose for CAs trusted to issue SD-JWT VC x5c chains
SD_JWT_ISSUER_TRUST_PURPOSE = "sd_jwt_issuer"
X5C_MAX_PATH_LENGTH = 10

# Certain claims, if present, are never to be included in the selective disclosures list.

# For flat claims, it's a simple matter of preventing the basic JSON pointer:
FLAT_CLAIMS_NEVER_SD = ("/iss", "/exp", "/vct", "/nbf")

# For claims that are objects, we need to be sure that neither the full claim, nor any
# sub-element of the object, is included in the selective disclosure, while still allowing
# claims with similar names to be selectively disclosable

# e.g., this regex will match `/status` or `/status/foo`, but not `/statuses`,
# in case `statuses` is a valid item to include in disclosures
OBJ_CLAIMS_NEVER_SD = re.compile(r"(?:/cnf|/status)(?:/.+)*")


class SDJWTError(BaseException):
    """SD-JWT Error."""


def validate_x5c_cert_chain(x5c: Any) -> List[x509.Certificate]:
    """Validate an x5c chain: std base64 DER certificates, leaf first.

    Each certificate must be signed by the next one and the leaf must hold a
    key type supported for signing. Returns the parsed certificates; raises
    ValueError otherwise.
    """
    if not (isinstance(x5c, list) and x5c and all(isinstance(cert, str) for cert in x5c)):
        raise ValueError(
            "x5c_cert_chain must be a non-empty list of base64 DER certificates"
        )
    try:
        certs = [
            x509.load_der_x509_certificate(base64.b64decode(cert, validate=True))
            for cert in x5c
        ]
    except (binascii.Error, ValueError) as err:
        raise ValueError(f"x5c_cert_chain has an invalid certificate: {err}") from err
    for cert, issuer in zip(certs, certs[1:]):
        try:
            cert.verify_directly_issued_by(issuer)
        except (InvalidSignature, TypeError, ValueError) as err:
            raise ValueError(
                "x5c_cert_chain must be ordered leaf first, each certificate "
                "issued by the next"
            ) from err
    key_from_x5c(x5c)
    return certs


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def _extension(cert: x509.Certificate, ext_type):
    try:
        return cert.extensions.get_extension_for_class(ext_type).value
    except x509.ExtensionNotFound:
        return None


def verify_x5c_trust(
    x5c: Any, trust_anchor_pems: List[str], now: Optional[datetime] = None
):
    """Check that an x5c chain leads to a trust anchor.

    The first certificate of each trust anchor PEM is trusted; any further
    certificates in it are intermediates that may complete the chain. Every
    certificate on the path must be within its validity period, issuers must
    be CAs (respecting pathLenConstraint and keyCertSign) and the leaf must
    allow digitalSignature. Raises ValueError otherwise.
    """
    chain = validate_x5c_cert_chain(x5c)
    anchors: List[x509.Certificate] = []
    intermediates: List[x509.Certificate] = []
    for pem in trust_anchor_pems:
        try:
            certs = x509.load_pem_x509_certificates(pem.encode())
        except ValueError:
            LOGGER.warning("Skipping unparseable SD-JWT issuer trust anchor")
            continue
        anchors.append(certs[0])
        intermediates.extend(certs[1:])
    if not anchors:
        raise ValueError(
            f"no '{SD_JWT_ISSUER_TRUST_PURPOSE}' trust anchors are configured"
        )

    path = [chain[0]]
    remaining = chain[1:]
    for _ in range(X5C_MAX_PATH_LENGTH):
        cert = path[-1]
        if cert in anchors:
            break
        anchor = next((a for a in anchors if _issued_by(cert, a)), None)
        if anchor is not None:
            path.append(anchor)
            break
        issuer = (
            remaining.pop(0)
            if remaining
            else next(
                (c for c in intermediates if c not in path and _issued_by(cert, c)),
                None,
            )
        )
        if issuer is None:
            raise ValueError("certificate chain does not lead to a trust anchor")
        path.append(issuer)
    else:
        raise ValueError("certificate chain is too long")

    now = now or datetime.now(timezone.utc)
    for cert in path:
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise ValueError(
                f"certificate '{cert.subject.rfc4514_string()}' is expired or "
                "not yet valid"
            )
    key_usage = _extension(path[0], x509.KeyUsage)
    if key_usage is not None and not key_usage.digital_signature:
        raise ValueError("leaf certificate does not allow digitalSignature")
    for depth, cert in enumerate(path[1:]):
        constraints = _extension(cert, x509.BasicConstraints)
        key_usage = _extension(cert, x509.KeyUsage)
        if (
            constraints is None
            or not constraints.ca
            or (constraints.path_length is not None and depth > constraints.path_length)
            or (key_usage is not None and not key_usage.key_cert_sign)
        ):
            raise ValueError(
                f"certificate '{cert.subject.rfc4514_string()}' is not a valid "
                "issuing CA for this chain"
            )


async def sd_jwt_issuer_trust_anchors(profile: Profile) -> List[str]:
    """Return the PEMs of the profile's SD-JWT VC issuer trust anchors.

    These are mso_mdoc TrustAnchorRecords with purpose 'sd_jwt_issuer',
    managed through /mso-mdoc/trust-anchors.
    """
    try:
        from mso_mdoc.trust_anchor import TrustAnchorRecord  # noqa: PLC0415
    except ImportError:
        LOGGER.warning("mso_mdoc is unavailable, so no SD-JWT issuer trust anchors")
        return []
    async with profile.session() as session:
        records = await TrustAnchorRecord.query(
            session, tag_filter={"purpose": SD_JWT_ISSUER_TRUST_PURPOSE}
        )
    return [record.certificate_pem for record in records if record.certificate_pem]


async def _check_x5c_signing_key(
    profile: Profile, x5c: List[str], verification_method: str
):
    """Ensure the x5c leaf certificate holds the credential signing key."""
    try:
        signing_key = await key_material_for_kid(profile, verification_method)
        leaf_key = key_from_x5c(x5c)
    except Exception as err:
        raise CredProcessorError(
            f"Could not compare x5c_cert_chain with {verification_method}: {err}"
        ) from err
    if signing_key.get_jwk_thumbprint() != leaf_key.get_jwk_thumbprint():
        raise CredProcessorError(
            "x5c_cert_chain leaf certificate does not hold the signing key "
            f"{verification_method}"
        )


def credential_issuer_url(context: AdminRequestContext) -> str:
    """Return this (tenant's) Credential Issuer Identifier URL."""
    config = Config.from_settings(context.settings)
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    return f"{config.endpoint}{subpath}"


@dataclass
class ClaimMetadata:
    """Claim metadata."""

    path: List[str] = None
    display: Optional[dict] = None
    mandatory: Optional[bool] = False
    value_type: Optional[str] = None  # Deprecated since v1.0


class SdJwtCredIssueProcessor(Issuer, CredVerifier, PresVerifier):
    """Credential processor class for sd_jwt_vc format."""

    def credential_metadata(self, supported_cred: dict) -> dict:
        """Shape issuer metadata for sd_jwt_vc format.

        Lifts ``vct`` from ``format_data`` to the top level (required by
        OID4VCI spec for SD-JWT VC) and converts the stored claims dict to
        the spec-compliant array form per OID4VCI 1.0 spec §E.2.2.
        """
        format_data = supported_cred.pop("format_data", None) or {}
        supported_cred.pop("vc_additional_data", None)  # sd_list is internal

        vct = format_data.get("vct")

        cred_metadata = supported_cred.get("credential_metadata") or {}
        claims = cred_metadata.get("claims")
        if isinstance(claims, dict):
            claims_arr = []
            for claim_name, claim_meta in claims.items():
                entry: dict = {"path": [claim_name]}
                if isinstance(claim_meta, dict):
                    if "display" in claim_meta:
                        entry["display"] = claim_meta["display"]
                    if "mandatory" in claim_meta:
                        entry["mandatory"] = claim_meta["mandatory"]
                claims_arr.append(entry)
            cred_metadata["claims"] = claims_arr
            supported_cred["credential_metadata"] = cred_metadata

        if vct:
            return {"vct": vct, **supported_cred}
        return supported_cred

    async def issue(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ) -> Any:
        """Return a signed credential in SD-JWT format."""
        assert supported.vc_additional_data

        sd_list = supported.vc_additional_data.get("sd_list") or []
        assert isinstance(sd_list, list)

        # Allow missing vct in body if format_data has vct
        body_vct = body.get("vct")
        supported_vct = supported.format_data.get("vct")
        if body_vct is not None and body_vct != supported_vct:
            raise CredProcessorError("Requested vct does not match offer.")

        vct = body_vct or supported_vct
        if not vct:
            raise CredProcessorError("No vct available in body or format_data.")

        current_time = int(time.time())
        claims = deepcopy(ex_record.credential_subject)

        if pop.holder_kid and pop.holder_kid.startswith("did:"):
            claims["sub"] = DIDUrl(pop.holder_kid).did
            claims["cnf"] = {"kid": pop.holder_kid}
        elif pop.holder_jwk:
            # FIXME: Credo explicitly requires a `kid` in `cnf`,
            # so we're making credo happy here
            pop.holder_jwk["use"] = "sig"
            did = "did:jwk:" + bytes_to_b64(
                json.dumps(pop.holder_jwk).encode(), urlsafe=True, pad=False
            )

            claims["cnf"] = {"kid": did + "#0", "jwk": pop.holder_jwk}
        elif pop.holder_x5c:
            # x5c-bound credential: cnf.x5c holds the holder's certificate chain
            # (leaf first).  Per SD-JWT VC §4.2.2 the leaf cert identifies the
            # holder key used for key-binding JWT verification.
            claims["cnf"] = {"x5c": pop.holder_x5c}
        else:
            raise ValueError("Unsupported pop holder value")

        # If an x5c cert chain is configured in vc_additional_data, use x5c
        # as the key-identification header (RFC 7517 §4.7); x5c and kid are
        # mutually exclusive. The issuer is then identified by an HTTPS URL
        # (the Credential Issuer Identifier) rather than the signing DID.
        x5c_chain = (supported.vc_additional_data or {}).get("x5c_cert_chain")
        if x5c_chain:
            await _check_x5c_signing_key(
                context.profile, x5c_chain, ex_record.verification_method
            )
            issuer = credential_issuer_url(context)
        else:
            issuer = ex_record.issuer_id
        headers = {
            "typ": supported.format,  # "vc+sd-jwt" or "dc+sd-jwt" per credential config
            **(
                {"x5c": x5c_chain}
                if x5c_chain
                else {"kid": ex_record.verification_method}
            ),
        }

        # exp can be provided in credential_subject or vc_additional_data;
        # default to 1 year from issuance if not set
        exp_seconds = (
            claims.pop("exp", None)
            or supported.vc_additional_data.get("exp_seconds")
            or (365 * 24 * 3600)
        )
        claims = {
            **claims,
            "vct": vct,
            "iss": issuer,
            "iat": current_time,
            "exp": current_time + int(exp_seconds),
        }

        status_handler = context.inject_or(StatusHandler)
        if status_handler and (
            credential_status := await status_handler.assign_status_entries(
                context, supported.supported_cred_id, ex_record.exchange_id
            )
        ):
            claims["status"] = credential_status
            LOGGER.info("credential with status: %s", claims)

        profile = context.profile
        did = ex_record.issuer_id
        ver_method = ex_record.verification_method
        try:
            cred = await sd_jwt_sign(sd_list, claims, headers, profile, did, ver_method)
            LOGGER.info("SD JWT VC CREDENTIAL: %s", cred)
            return cred
        except SDJWTError as error:
            raise CredProcessorError("Could not sign SD-JWT VC") from error

    def validate_credential_subject(self, supported: SupportedCredential, subject: dict):
        """Validate the credential subject."""
        vc_additional = supported.vc_additional_data
        assert vc_additional
        # assert supported.format_data
        claims_metadata = supported.credential_metadata.get("claims")
        sd_list = vc_additional.get("sd_list") or []

        # TODO this will only enforce mandatory fields that are selectively disclosable
        # We should validate that disclosed claims that are mandatory are also present
        missing = []
        for sd in sd_list:
            # iat is the only claim that can be disclosable that is not set in the subject
            if sd == "/iat":
                continue
            pointer = JsonPointer(sd)

            # Skip if no claims metadata defined
            if claims_metadata is None:
                continue

            metadata = pointer.resolve(claims_metadata, None)
            if metadata:
                metadata = ClaimMetadata(**metadata)
            else:
                metadata = ClaimMetadata()

            claim = pointer.resolve(subject, Unset)
            if claim is Unset and metadata.mandatory:
                missing.append(pointer.path)

            # TODO type checking against value_type

        if missing:
            raise CredProcessorError(
                "Invalid credential subject; selectively disclosable claim is"
                f" mandatory but missing: {missing}"
            )

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate a supported SD JWT VC Credential."""

        credential_metadata = supported.credential_metadata or supported.format_data or {}
        if not credential_metadata:
            raise ValueError("SD-JWT VC needs credential_metadata")

        vc_additional_data = supported.vc_additional_data or {}
        if not vc_additional_data:
            raise ValueError("SD-JWT VC needs vc_additional_data")

        if not (vc_additional_data.get("vct") or supported.format_data.get("vct")):
            raise ValueError("SD-JWT VC needs 'vct'")

        if (x5c_cert_chain := vc_additional_data.get("x5c_cert_chain")) is not None:
            validate_x5c_cert_chain(x5c_cert_chain)

        sd_list = vc_additional_data.get("sd_list") or []

        bad_claims = []
        for sd in sd_list:
            if (
                sd in FLAT_CLAIMS_NEVER_SD
                or OBJ_CLAIMS_NEVER_SD.fullmatch(sd)
                or sd == ""
                or sd[-1] == "/"
            ):
                bad_claims.append(sd)

        if bad_claims:
            raise SDJWTError(
                "The following claims cannot be "
                f"included in the selective disclosures: {bad_claims} "
                "\nThese values are protected and cannot be selectively disclosable: "
                f"{', '.join(FLAT_CLAIMS_NEVER_SD)}, /cnf, /status "
                "\nOr, you provided an empty string, or a string that ends with a `/` "
                "which are invalid for this purpose."
            )

        bad_pointer = []
        for sd in sd_list:
            try:
                JsonPointer(sd)
            except JsonPointerException:
                bad_pointer.append(sd)

        if bad_pointer:
            raise ValueError(f"Invalid JSON pointer(s): {bad_pointer}")

    async def verify_presentation(
        self,
        profile: Profile,
        presentation: Any,
        presentation_record: OID4VPPresentation,
    ) -> VerifyResult:
        """Verify signature over credential or presentation."""
        context: AdminRequestContext = profile.context
        config = Config.from_settings(context.settings)

        # Use the client_id (did:jwk) saved on the presentation record as the
        # expected KB-JWT audience.  The JAR sets client_id = jwk.did so Credo
        # puts that DID – not the HTTP endpoint URL – in the KB-JWT 'aud' claim.
        expected_aud = getattr(presentation_record, "client_id", None) or config.endpoint

        result = await sd_jwt_verify(
            profile, presentation, expected_aud, presentation_record.nonce
        )
        # TODO: This is a little hacky
        return VerifyResult(result.verified, presentation)

    async def verify_credential(
        self,
        profile: Profile,
        credential: Any,
    ) -> VerifyResult:
        """Verify signature over credential."""
        # TODO: Can we optimize this? since we end up doing this twice in a row

        result = await sd_jwt_verify(profile, credential)
        return VerifyResult(result.verified, result.payload)


class SDJWTIssuerACAPy(SDJWTIssuer):
    """SDJWTIssuer class for ACA-Py implementation."""

    def __init__(
        self,
        user_claims: dict,
        issuer_key,
        holder_key,
        profile: Profile,
        headers: dict,
        did: Optional[str] = None,
        verification_method: Optional[str] = None,
        add_decoy_claims: bool = False,
        serialization_format: str = "compact",
    ):
        """Initialize an SDJWTIssuerACAPy instance."""
        self._user_claims = user_claims
        self._issuer_key = issuer_key
        self._holder_key = holder_key

        self.profile = profile
        self.headers = headers
        self.did = did
        self.verification_method = verification_method

        self._add_decoy_claims = add_decoy_claims
        self._serialization_format = serialization_format
        self.ii_disclosures = []

    async def _create_signed_jws(self):
        self.serialized_sd_jwt = await jwt_sign(
            self.profile,
            self.headers,
            self.sd_jwt_payload,
            self.did,
            self.verification_method,
        )

    async def issue(self) -> str:
        """Issue an sd-jwt."""
        self._check_for_sd_claim(self._user_claims)
        self._assemble_sd_jwt_payload()
        await self._create_signed_jws()
        self._create_combined()
        return self.sd_jwt_issuance


Unset = object()


async def sd_jwt_sign(
    sd_list: List[str],
    claims: Dict[str, Any],
    headers: Dict[str, Any],
    profile: Profile,
    did: Optional[str] = None,
    verification_method: Optional[str] = None,
):
    """Compose and sign an sd-jwt."""

    for sd in sd_list:
        sd_pointer = JsonPointer(sd)
        sd_claim = sd_pointer.resolve(claims, Unset)

        if sd_claim is Unset:
            raise SDJWTError(f"Claim for {sd_pointer.path} not found in payload.")

        sub, key = sd_pointer.to_last(claims)

        if isinstance(sub, EndOfList):
            raise SDJWTError("Invalid JSON Pointer; EndOfList referenced")

        if isinstance(sub, dict):
            sub[SDObj(key)] = sd_claim
            sub.pop(key)

        if isinstance(sub, list):
            sd_pointer.set(claims, SDObj(sd_claim))

    return await SDJWTIssuerACAPy(
        user_claims=claims,
        issuer_key=None,
        holder_key=None,
        profile=profile,
        headers=headers,
        did=did,
        verification_method=verification_method,
    ).issue()


class SDJWTVerifyResult(JWTVerifyResult):
    """Result from verifying SD-JWT."""

    class Meta:
        """SDJWTVerifyResult metadata."""

        schema_class = "SDJWTVerifyResultSchema"

    def __init__(
        self,
        headers,
        payload,
        valid,
        kid,
        disclosures,
    ):
        """Initialize an SDJWTVerifyResult instance."""
        super().__init__(
            headers,
            payload,
            valid,
            kid,
        )
        self.disclosures = disclosures


class SDJWTVerifierACAPy(SDJWTVerifier):
    """SDJWTVerifier class for ACA-Py implementation."""

    def __init__(
        self,
        profile: Profile,
        sd_jwt_presentation: str,
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
        serialization_format: str = "compact",
    ):
        """Initialize an SDJWTVerifierACAPy instance."""
        self.profile = profile
        self.sd_jwt_presentation = sd_jwt_presentation

        if serialization_format not in ("compact", "json"):
            raise ValueError(f"Unknown serialization format: {serialization_format}")
        self._serialization_format = serialization_format

        self.expected_aud = expected_aud
        self.expected_nonce = expected_nonce

    async def _verify_sd_jwt(self):
        verified = await jwt_verify(
            self.profile,
            self._unverified_input_sd_jwt,
        )
        if verified.verified is False:
            raise CredProcessorError("Invalid signature")

        if "x5c" in verified.headers:
            try:
                verify_x5c_trust(
                    verified.headers["x5c"],
                    await sd_jwt_issuer_trust_anchors(self.profile),
                )
            except ValueError as err:
                raise CredProcessorError(f"Untrusted issuer x5c chain: {err}") from err

        self._sd_jwt_payload = verified.payload
        self._holder_public_key_payload = self._sd_jwt_payload.get("cnf", None)

    async def verify(self):
        """Verify an sd-jwt."""
        self._parse_sd_jwt(self.sd_jwt_presentation)
        self._create_hash_mappings(self._input_disclosures)
        await self._verify_sd_jwt()

        if self.expected_aud or self.expected_nonce:
            if not (self.expected_aud and self.expected_nonce):
                raise ValueError(
                    "Either both expected_aud and expected_nonce must be provided "
                    "or both must be None"
                )
            await self._verify_key_binding_jwt(
                self.expected_aud,
                self.expected_nonce,
            )

        return self

    async def _verify_key_binding_jwt(
        self,
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
    ):
        # Verify the key binding JWT using the holder public key
        if not self._holder_public_key_payload:
            raise ValueError("No holder public key in SD-JWT")
        verified_kb_jwt = await jwt_verify(
            self.profile,
            self._unverified_input_key_binding_jwt,
            cnf=self._holder_public_key_payload,
        )

        if verified_kb_jwt.headers["typ"] != self.KB_JWT_TYP_HEADER:
            raise ValueError("Invalid header typ")
        if verified_kb_jwt.payload["aud"] != expected_aud:
            raise ValueError("Invalid audience")
        if verified_kb_jwt.payload["nonce"] != expected_nonce:
            raise ValueError("Invalid nonce")

        if self._serialization_format == "compact":
            string_to_hash = self._combine(
                self._unverified_input_sd_jwt, *self._input_disclosures, ""
            )
            expected_sd_jwt_presentation_hash = self._b64hash(
                string_to_hash.encode("ascii")
            )

            if (
                verified_kb_jwt.payload[KB_DIGEST_KEY]
                != expected_sd_jwt_presentation_hash
            ):
                raise ValueError("Invalid digest in KB-JWT")


async def sd_jwt_verify(
    profile: Profile,
    sd_jwt_presentation: str,
    expected_aud: Optional[str] = None,
    expected_nonce: Optional[str] = None,
) -> VerifyResult:
    """Verify sd-jwt using SDJWTVerifierACAPy.verify()."""
    sd_jwt_verifier = SDJWTVerifierACAPy(
        profile, sd_jwt_presentation, expected_aud, expected_nonce
    )
    try:
        payload = (await sd_jwt_verifier.verify()).get_verified_payload()
        return VerifyResult(True, payload)
    except Exception as err:
        LOGGER.warning("SD-JWT verification failed: %s", err)
        return VerifyResult(False, None)
