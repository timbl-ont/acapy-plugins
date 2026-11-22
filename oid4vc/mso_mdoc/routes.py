"""mso_mdoc extra routes.

Format-specific routes for creating and updating mso_mdoc SupportedCredential
records.  Follows the same pattern as sd_jwt_vc/routes.py.

Protocol Compliance:
- OpenID4VCI 1.0 § E.1.1: mso_mdoc Credential Format
- ISO/IEC 18013-5:2021: Mobile driving licence (mDL) application
"""

import logging
from typing import Any, Dict

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.askar.profile import AskarProfileSession
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    request_schema,
    response_schema,
)
from marshmallow import RAISE, ValidationError, fields, validate, validates_schema

from oid4vc.cred_processor import CredProcessorError, CredProcessors
from oid4vc.models.supported_cred import (
    SupportedCredential,
    SupportedCredentialSchema,
    validate_proof_types_supported,
)
from oid4vc.routes import SupportedCredentialMatchSchema, supported_cred_is_unique
from . import trust_anchor_routes
from .document_signer import KEY_TYPES, DocumentSignerError, check_document_signer
from .mdoc.issuer import DEFAULT_VALID_UNTIL_SECONDS

LOGGER = logging.getLogger(__name__)

SIGNING_KEY_ID_REMOVED = (
    "signing_key_id was removed; use document_signer "
    '{"key_type": "pem", "signing_key_id": "..."} for a /mso-mdoc/signing-keys key, '
    'or {"key_type": "wallet", "multikey": "..."} for a wallet key'
)
STATUS_LIST_FIELDS_REMOVED = (
    "status_list_def_id and status_list_base_uri were removed; create a status list "
    "definition with list_type 'ietf' and this credential configuration's "
    "supported_cred_id (POST /status-list/defs), as for the other formats"
)
REMOVED_FIELDS = {
    "signing_key_id": SIGNING_KEY_ID_REMOVED,
    "status_list_def_id": STATUS_LIST_FIELDS_REMOVED,
    "status_list_base_uri": STATUS_LIST_FIELDS_REMOVED,
}


def _reject_removed_fields(body: Dict[str, Any]) -> None:
    """Answer a request that sends a removed field with what replaced it."""
    for field_name, message in REMOVED_FIELDS.items():
        if field_name in body:
            raise web.HTTPBadRequest(reason=message)


class DocumentSignerSchema(OpenAPISchema):
    """Where the document signer (DS) key and certificate come from."""

    key_type = fields.Str(
        required=True,
        validate=validate.OneOf(KEY_TYPES),
        metadata={
            "description": (
                "'wallet': a P-256 wallet key, certificate from the x509_certs "
                "plugin (purpose mdoc_ds). 'pem': a legacy /mso-mdoc/signing-keys key."
            ),
            "example": "wallet",
        },
    )
    multikey = fields.Str(
        required=False,
        metadata={
            "description": "Multikey of the P-256 wallet key, for key_type 'wallet'.",
            "example": "zDnaeZv4cPZ9zVfMvxWdjnXc1hFXY9LYM894FyZpVsGHnx3oG",
        },
    )
    signing_key_id = fields.Str(
        required=False,
        metadata={"description": "MdocSigningKeyRecord id, for key_type 'pem'."},
    )

    @validates_schema
    def check_key_reference(self, data, **kwargs):
        """Require the key reference that matches key_type."""
        if data.get("key_type") == "wallet" and not data.get("multikey"):
            raise ValidationError("multikey is required for key_type 'wallet'")
        if data.get("key_type") == "pem" and not data.get("signing_key_id"):
            raise ValidationError("signing_key_id is required for key_type 'pem'")


class ValidityInfoSchema(OpenAPISchema):
    """MSO validityInfo, as seconds after signing."""

    valid_from = fields.Int(
        required=False,
        validate=validate.Range(min=0),
        metadata={"description": "Seconds after signing; default 0.", "example": 0},
    )
    valid_until = fields.Int(
        required=False,
        validate=validate.Range(min=1),
        metadata={
            "description": "Seconds after signing; default 2592000 (30 days).",
            "example": DEFAULT_VALID_UNTIL_SECONDS,
        },
    )
    expected_update = fields.Int(
        required=False,
        validate=validate.Range(min=0),
        metadata={"description": "Seconds after signing; optional.", "example": 604800},
    )

    @validates_schema
    def check_range(self, data, **kwargs):
        """Require valid_until to be later than valid_from."""
        if data.get("valid_until", DEFAULT_VALID_UNTIL_SECONDS) <= data.get(
            "valid_from", 0
        ):
            raise ValidationError("valid_until must be greater than valid_from")


def _load_signer_fields(body: Dict[str, Any]) -> None:
    """Validate document_signer and validity_info in a raw request body in place."""
    _reject_removed_fields(body)
    try:
        if body.get("document_signer") is not None:
            body["document_signer"] = DocumentSignerSchema().load(
                body["document_signer"], unknown=RAISE
            )
        if body.get("validity_info") is not None:
            body["validity_info"] = ValidityInfoSchema().load(
                body["validity_info"], unknown=RAISE
            )
    except ValidationError as err:
        raise web.HTTPBadRequest(reason=str(err.messages)) from err


class MdocSupportedCredCreateRequestSchema(OpenAPISchema):
    """Schema for creating an mso_mdoc SupportedCredential."""

    format = fields.Str(required=True, metadata={"example": "mso_mdoc"})
    identifier = fields.Str(
        data_key="id",
        required=True,
        metadata={"example": "org.iso.18013.5.1.mDL"},
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), metadata={"example": ["cose_key"]}
    )
    credential_signing_alg_values_supported = fields.List(
        fields.Str(), metadata={"example": ["-7", "-8"]}
    )
    proof_types_supported = fields.Dict(
        required=False,
        validate=validate_proof_types_supported,
        metadata={"example": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}},
    )
    doctype = fields.Str(
        required=True,
        metadata={
            "description": "ISO 18013-5 document type identifier.",
            "example": "org.iso.18013.5.1.mDL",
        },
    )
    claims = fields.Dict(
        keys=fields.Str,
        required=False,
        metadata={
            "description": (
                "Namespace-keyed claims: {namespace: {claim_name: descriptor}}"
            ),
        },
    )
    credential_metadata = fields.Dict(
        required=False,
        metadata={
            "description": "Metadata about the credential, such as claims and display.",
            "example": {
                "claims": [
                    {
                        "path": ["org.iso.18013.5.1", "given_name"],
                        "display": [{"name": "Given Name", "locale": "en-US"}],
                    },
                    {
                        "path": ["org.iso.18013.5.1", "family_name"],
                        "display": [{"name": "Surname", "locale": "en-US"}],
                    },
                    {"path": ["org.iso.18013.5.1", "birth_date"], "mandatory": True},
                    {"path": ["org.iso.18013.5.1.aamva", "organ_donor"]},
                ],
                "display": [
                    {
                        "name": "Mobile Driving License",
                        "locale": "en-US",
                        "logo": {
                            "uri": "https://state.example.org/public/mdl.png",
                            "alt_text": "state mobile driving license",
                        },
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
        },
    )
    trust_anchors = fields.List(
        fields.Str,
        required=False,
        metadata={
            "description": "PEM-encoded X.509 root CA certificates for verification.",
        },
    )
    document_signer = fields.Nested(
        DocumentSignerSchema(),
        required=True,
        metadata={
            "description": "Document signer key and certificate source.",
            "example": {"key_type": "wallet", "multikey": "zDnae..."},
        },
    )
    validity_info = fields.Nested(
        ValidityInfoSchema(),
        required=False,
        metadata={"description": "MSO validity range, as seconds after signing."},
    )


class MdocSupportedCredUpdateRequestSchema(OpenAPISchema):
    """Schema for partial updates to an mso_mdoc SupportedCredential.

    All fields are optional; only supplied fields are changed.
    """

    format = fields.Str(required=False, metadata={"example": "mso_mdoc"})
    identifier = fields.Str(
        data_key="id",
        required=False,
        metadata={"example": "org.iso.18013.5.1.mDL"},
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), required=False, metadata={"example": ["cose_key"]}
    )
    credential_signing_alg_values_supported = fields.List(
        fields.Str(), required=False, metadata={"example": ["-7", "-8"]}
    )
    proof_types_supported = fields.Dict(
        required=False, validate=validate_proof_types_supported
    )
    doctype = fields.Str(
        required=False,
        metadata={
            "description": "ISO 18013-5 document type identifier.",
            "example": "org.iso.18013.5.1.mDL",
        },
    )
    claims = fields.Dict(keys=fields.Str, required=False)
    credential_metadata = fields.Dict(required=False)
    trust_anchors = fields.List(
        fields.Str,
        required=False,
        metadata={
            "description": "PEM-encoded X.509 root CA certificates for verification.",
        },
    )
    document_signer = fields.Nested(
        DocumentSignerSchema(),
        required=False,
        metadata={"description": "Document signer key and certificate source."},
    )
    validity_info = fields.Nested(
        ValidityInfoSchema(),
        required=False,
        metadata={"description": "MSO validity range, as seconds after signing."},
    )


@docs(
    tags=["oid4vci"],
    summary="Register a configuration for a supported MSO mDoc credential",
)
@request_schema(MdocSupportedCredCreateRequestSchema())
@response_schema(SupportedCredentialSchema())
@tenant_authentication
async def supported_credential_create_mdoc(request: web.Request):
    """Request handler for creating a credential supported record."""
    context = request["context"]
    assert isinstance(context, AdminRequestContext)
    profile = context.profile

    body: Dict[str, Any] = await request.json()
    _reject_removed_fields(body)
    try:
        body: Dict[str, Any] = MdocSupportedCredCreateRequestSchema().load(
            body, unknown=RAISE
        )
    except ValidationError as err:
        raise web.HTTPBadRequest(reason=str(err.messages)) from err

    if not await supported_cred_is_unique(body["identifier"], profile):
        raise web.HTTPBadRequest(
            reason=f"Record with identifier {body['identifier']} already exists."
        )

    LOGGER.debug(
        "Creating mdoc supported credential from request payload: %s",
        body,
    )

    format_data = {}
    format_data["doctype"] = body.pop("doctype")
    format_data["claims"] = body.pop("claims", None)

    vc_additional_data = {}
    vc_additional_data["trust_anchors"] = body.pop("trust_anchors", None)
    vc_additional_data["document_signer"] = body.pop("document_signer")
    vc_additional_data["validity_info"] = body.pop("validity_info", None)

    record = SupportedCredential(
        **body,
        format_data=format_data,
        vc_additional_data=vc_additional_data,
    )

    registered_processors = context.inject(CredProcessors)
    if record.format not in registered_processors.issuers:
        raise web.HTTPBadRequest(
            reason=f"Format {record.format} is not supported by"
            " currently registered processors"
        )

    processor = registered_processors.issuer_for_format(record.format)
    try:
        processor.validate_supported_credential(record)
    except (ValueError, CredProcessorError) as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    async with profile.session() as session:
        try:
            warnings = await check_document_signer(
                session, vc_additional_data["document_signer"]
            )
        except DocumentSignerError as err:
            raise web.HTTPBadRequest(reason=str(err)) from err
        for warning in warnings:
            LOGGER.warning("Supported credential %s: %s", record.identifier, warning)
        await record.save(session, reason="Save credential supported record.")

    return web.json_response(record.serialize())


async def mdoc_supported_cred_update_helper(
    record: SupportedCredential,
    body: Dict[str, Any],
    session: AskarProfileSession,
) -> SupportedCredential:
    """Helper for updating an mso_mdoc SupportedCredential record.

    Only fields present in *body* are updated; omitted fields retain their
    current values from *record*.
    """
    existing_format_data = record.format_data or {}
    existing_vc_data = record.vc_additional_data or {}

    # Identifier / format — fall back to existing values when not supplied
    if "id" in body:
        record.identifier = body.pop("id")
    else:
        body.pop("id", None)
    if "format" in body:
        record.format = body.pop("format")
    else:
        body.pop("format", None)

    # format_data — merge with existing
    format_data = dict(existing_format_data)
    if "doctype" in body:
        format_data["doctype"] = body.pop("doctype")
    else:
        body.pop("doctype", None)
    if "claims" in body:
        format_data["claims"] = body.pop("claims")
    else:
        body.pop("claims", None)

    # vc_additional_data — merge with existing
    vc_additional_data = dict(existing_vc_data)
    if "trust_anchors" in body:
        vc_additional_data["trust_anchors"] = body.pop("trust_anchors")
    else:
        body.pop("trust_anchors", None)
    for key in ("document_signer", "validity_info"):
        if key in body:
            vc_additional_data[key] = body.pop(key)
    vc_additional_data.pop("signing_key_id", None)
    vc_additional_data.pop("status_list_def_id", None)
    vc_additional_data.pop("status_list_base_uri", None)

    if "cryptographic_binding_methods_supported" in body:
        record.cryptographic_binding_methods_supported = body[
            "cryptographic_binding_methods_supported"
        ]
    if "credential_signing_alg_values_supported" in body:
        record.credential_signing_alg_values_supported = body[
            "credential_signing_alg_values_supported"
        ]
    if "proof_types_supported" in body:
        record.proof_types_supported = body["proof_types_supported"]
    if "credential_metadata" in body:
        record.credential_metadata = body["credential_metadata"]

    record.format_data = format_data
    record.vc_additional_data = vc_additional_data

    warnings = await check_document_signer(
        session, vc_additional_data.get("document_signer")
    )
    for warning in warnings:
        LOGGER.warning("Supported credential %s: %s", record.identifier, warning)

    await record.save(session)
    return record


@docs(
    tags=["oid4vci"],
    summary="Update a Supported Credential. "
    "Expected to be a complete replacement of a MSO mDoc Supported Credential record, "
    "i.e., optional values that aren't supplied will be `None`, rather than retaining "
    "their original value.",
)
@match_info_schema(SupportedCredentialMatchSchema())
@request_schema(MdocSupportedCredUpdateRequestSchema())
@response_schema(SupportedCredentialSchema())
@tenant_authentication
async def update_supported_credential_mdoc(request: web.Request):
    """Update an mso_mdoc SupportedCredential record."""

    context: AdminRequestContext = request["context"]
    supported_cred_id = request.match_info["supported_cred_id"]
    body: Dict[str, Any] = await request.json()
    _load_signer_fields(body)

    LOGGER.debug(
        "Updating mdoc supported credential %s with request payload: %s",
        supported_cred_id,
        body,
    )

    try:
        async with context.session() as session:
            record = await SupportedCredential.retrieve_by_id(session, supported_cred_id)

            assert isinstance(session, AskarProfileSession)
            record = await mdoc_supported_cred_update_helper(record, body, session)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except DocumentSignerError as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    registered_processors = context.inject(CredProcessors)
    if record.format not in registered_processors.issuers:
        raise web.HTTPBadRequest(
            reason=f"Format {record.format} is not supported by"
            " currently registered processors"
        )

    processor = registered_processors.issuer_for_format(record.format)
    try:
        processor.validate_supported_credential(record)
    except (ValueError, CredProcessorError) as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    return web.json_response(record.serialize())


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post(
                "/oid4vci/credential-supported/create/mso-mdoc",
                supported_credential_create_mdoc,
            ),
            web.put(
                "/oid4vci/credential-supported/records/mso-mdoc/{supported_cred_id}",
                update_supported_credential_mdoc,
            ),
        ]
    )
    await trust_anchor_routes.register(app)
