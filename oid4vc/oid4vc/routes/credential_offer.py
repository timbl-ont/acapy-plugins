"""Credential offer routes for OID4VCI admin API."""

import json
from urllib.parse import quote

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from aiohttp import web
from aiohttp_apispec import (
    docs,
    querystring_schema,
    response_schema,
)
from marshmallow import fields

from .helpers import _parse_cred_offer
from ..config import Config


class CredOfferQuerySchema(OpenAPISchema):
    """Schema for GetCredential."""

    user_pin_required = fields.Bool(required=False)
    exchange_id = fields.Str(required=False)


class CredOfferGrantSchema(OpenAPISchema):
    """Schema for GetCredential."""

    pre_authorized_code = fields.Str(required=True)
    user_pin_required = fields.Bool(required=False)


class CredOfferSchema(OpenAPISchema):
    """Credential Offer Schema."""

    credential_issuer = fields.Str(
        required=True,
        metadata={
            "description": "The URL of the credential issuer.",
            "example": "https://example.com",
        },
    )
    credential_configuration_ids = fields.List(
        fields.Str(
            required=True,
            metadata={
                "description": "The credential type identifier.",
                "example": "UniversityDegreeCredential",
            },
        )
    )
    grants = fields.Nested(CredOfferGrantSchema(), required=True)


class CredOfferResponseSchemaVal(OpenAPISchema):
    """Credential Offer Schema."""

    credential_offer = fields.Str(
        required=True,
        metadata={
            "description": "The URL of the credential value for display by QR code.",
            "example": "openid-credential-offer://...",
        },
    )
    offer = fields.Nested(CredOfferSchema(), required=True)


class CredOfferResponseSchemaRef(OpenAPISchema):
    """Credential Offer Schema."""

    credential_offer_uri = fields.Str(
        required=True,
        metadata={
            "description": "A URL which references the credential for display.",
            "example": "openid-credential-offer://...",
        },
    )
    offer = fields.Nested(CredOfferSchema(), required=True)


@docs(tags=["oid4vci"], summary="Get a credential offer by value")
@querystring_schema(CredOfferQuerySchema())
@response_schema(CredOfferResponseSchemaVal(), 200)
@tenant_authentication
async def get_cred_offer(request: web.BaseRequest):
    """Endpoint to retrieve an OpenID4VCI compliant offer by value.

    For example, can be used in QR-Code presented to a compliant wallet.
    """
    context: AdminRequestContext = request["context"]
    exchange_id = request.query["exchange_id"]

    offer = await _parse_cred_offer(context, exchange_id)
    offer_uri = quote(json.dumps(offer))
    offer_response = {
        "offer": offer,
        "credential_offer": f"openid-credential-offer://?credential_offer={offer_uri}",
    }
    return web.json_response(offer_response)


@docs(tags=["oid4vci"], summary="Get a credential offer by reference")
@querystring_schema(CredOfferQuerySchema())
@response_schema(CredOfferResponseSchemaRef(), 200)
@tenant_authentication
async def get_cred_offer_by_ref(request: web.BaseRequest):
    """Endpoint to retrieve an OpenID4VCI compliant offer by reference.

    credential_offer_uri can be dereferenced at the /oid4vc/dereference-credential-offer
    (see public_routes.dereference_cred_offer)

    For example, can be used in QR-Code presented to a compliant wallet.
    """
    context: AdminRequestContext = request["context"]
    exchange_id = request.query["exchange_id"]
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )

    offer = await _parse_cred_offer(context, exchange_id)

    config = Config.from_settings(context.settings)
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    ref_uri = (
        f"{config.endpoint}{subpath}/oid4vci/dereference-credential-offer"
        f"?exchange_id={exchange_id}"
    )
    offer_response = {
        "offer": offer,
        "credential_offer_uri": f"openid-credential-offer://?credential_offer={quote(ref_uri)}",
    }
    return web.json_response(offer_response)


DC_API_ISSUANCE_PROTOCOL = "openid4vci-v1"


class DcApiCredOfferResponseSchema(OpenAPISchema):
    """Credential offer for the W3C Digital Credentials API."""

    protocol = fields.Str(
        required=True,
        metadata={
            "description": "Issuance protocol identifier, for requests[].protocol.",
            "example": DC_API_ISSUANCE_PROTOCOL,
        },
    )
    data = fields.Dict(
        required=True,
        metadata={
            "description": (
                "Credential Offer to pass as requests[].data to "
                "navigator.credentials.create(), with the Credential Issuer "
                "Metadata (and, when ACA-Py is its own authorization server, the "
                "Authorization Server Metadata) embedded by value."
            )
        },
    )


@docs(
    tags=["oid4vci"],
    summary="Get a credential offer for the W3C Digital Credentials API (experimental)",
)
@querystring_schema(CredOfferQuerySchema())
@response_schema(DcApiCredOfferResponseSchema(), 200)
@tenant_authentication
async def get_dc_api_cred_offer(request: web.BaseRequest):
    """Credential offer for navigator.credentials.create() (DC-API issuance).

    Experimental: OpenID4VCI does not yet define its use with the W3C Digital
    Credentials API (OpenID4VCI issue #410). This follows the shape browsers
    accept for protocol ``openid4vci-v1``: the Credential Offer by value with
    ``credential_issuer_metadata`` and, when ACA-Py is its own authorization
    server, ``authorization_server_metadata`` embedded, so the wallet does not
    need to fetch them. The wallet then completes issuance through the usual
    token and credential endpoints. See ``docs/dc-api-issuance.md``.
    """
    # Imported here: public_routes imports this package while it loads.
    from ..public_routes.metadata import dc_api_offer_metadata  # noqa: PLC0415

    context: AdminRequestContext = request["context"]
    exchange_id = request.query["exchange_id"]

    offer = await _parse_cred_offer(context, exchange_id)
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )
    async with context.session() as session:
        metadata = await dc_api_offer_metadata(context, session, wallet_id)

    return web.json_response(
        {"protocol": DC_API_ISSUANCE_PROTOCOL, "data": {**offer, **metadata}}
    )
