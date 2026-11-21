"""OID4VP request routes for admin API."""

import json
import re
import time
import uuid
from secrets import token_urlsafe
from typing import List
from urllib.parse import quote, urlsplit

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    querystring_schema,
    request_schema,
    response_schema,
)
from marshmallow import fields

from ..config import Config
from ..dc_api import SUPPORTED_ENC, create_response_key
from ..did_utils import retrieve_or_create_did_jwk
from ..jwt import jwt_sign
from ..models.dcql_query import DCQLQuery
from ..models.presentation import (
    OID4VPPresentation,
    OID4VPPresentationSchema,
)
from ..models.request import (
    OID4VPRequest,
    OID4VPRequestSchema,
)


class CreateOID4VPReqResponseSchema(OpenAPISchema):
    """Response schema for creating an OID4VP Request."""

    request_uri = fields.Str(
        required=True,
        metadata={
            "description": "URI for the holder to resolve the request",
        },
    )

    request = fields.Nested(
        OID4VPRequestSchema,
        required=True,
        metadata={"descripton": "The created request"},
    )

    presentation = fields.Nested(
        OID4VPPresentationSchema,
        required=True,
        metadata={"descripton": "The created presentation"},
    )


class CreateOID4VPReqRequestSchema(OpenAPISchema):
    """Request schema for creating an OID4VP Request."""

    pres_def_id = fields.Str(
        required=False,
        metadata={
            "description": "Identifier used to identify presentation definition",
        },
    )

    dcql_query_id = fields.Str(
        required=False,
        metadata={
            "description": "Identifier used to identify DCQL query",
        },
    )

    vp_formats = fields.Dict(
        required=True,
        metadata={
            "description": "Expected presentation formats from the holder",
        },
    )


@docs(
    tags=["oid4vp"],
    summary="Create an OID4VP Request.",
)
@request_schema(CreateOID4VPReqRequestSchema)
@response_schema(CreateOID4VPReqResponseSchema)
async def create_oid4vp_request(request: web.Request):
    """Create an OID4VP Request."""

    context: AdminRequestContext = request["context"]
    body = await request.json()

    async with context.session() as session:
        # Get the DID:JWK that will be used as fallback client_id
        jwk = await retrieve_or_create_did_jwk(session)

        # Use x509 identity (x509_san_dns) when registered; otherwise did:jwk.
        storage = session.inject(BaseStorage)
        try:
            x509_record = await storage.get_record(
                X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
            )
            x509_id = json.loads(x509_record.value)
        except StorageNotFoundError:
            x509_id = None

        # OID4VP Final (ID3+): client_id for x509_san_dns scheme uses
        # URI prefix format: "x509_san_dns:{dns_name}".
        # This must match the client_id in the JAR payload.
        if x509_id:
            effective_client_id = f"x509_san_dns:{x509_id['client_id']}"
        else:
            effective_client_id = jwk.did

        if pres_def_id := body.get("pres_def_id"):
            req_record = OID4VPRequest(
                pres_def_id=pres_def_id, vp_formats=body["vp_formats"]
            )
            await req_record.save(session=session)

            pres_record = OID4VPPresentation(
                pres_def_id=pres_def_id,
                state=OID4VPPresentation.REQUEST_CREATED,
                request_id=req_record.request_id,
                client_id=effective_client_id,
            )
            await pres_record.save(session=session)

        elif dcql_query_id := body.get("dcql_query_id"):
            req_record = OID4VPRequest(
                dcql_query_id=dcql_query_id, vp_formats=body["vp_formats"]
            )
            await req_record.save(session=session)

            pres_record = OID4VPPresentation(
                dcql_query_id=dcql_query_id,
                state=OID4VPPresentation.REQUEST_CREATED,
                request_id=req_record.request_id,
                client_id=effective_client_id,
            )
            await pres_record.save(session=session)
        else:
            raise web.HTTPBadRequest(
                reason="One of pres_def_id or dcql_query_id must be provided"
            )

    config = Config.from_settings(context.settings)
    # wallet.id is present on sub-wallet profiles in all multitenant modes;
    # do not gate on multitenant.enabled (absent from sub-wallet settings in
    # single-wallet-askar mode), just read it directly.
    wallet_id = context.profile.settings.get("wallet.id")
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    # Use OID4VP_ENDPOINT when available (may differ from OID4VCI endpoint,
    # e.g.served via a separate TLS-terminating proxy for conformance tests).
    oid4vp_base = config.oid4vp_endpoint or config.endpoint
    request_uri = quote(f"{oid4vp_base}{subpath}/oid4vp/request/{req_record._id}")
    # In OID4VP Final spec, client_id_scheme was removed from authorization
    # request query parameters (it was removed in ID3 / draft-28).  The scheme
    # is communicated inside the signed JAR instead.  Do NOT include
    # client_id_scheme as a query parameter.
    full_uri = (
        f"openid://?client_id={quote(effective_client_id)}&request_uri={request_uri}"
    )

    return web.json_response(
        {
            "request_uri": full_uri,
            "request": req_record.serialize(),
            "presentation": pres_record.serialize(),
        }
    )


def _normalize_origin(origin: str) -> str:
    """Validate a web origin and return its serialization (no trailing slash)."""
    parts = urlsplit(origin) if isinstance(origin, str) else None
    if (
        parts is None
        or parts.scheme not in ("https", "http")
        or not parts.netloc
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise web.HTTPBadRequest(
            reason=f"expected_origins entries must be web origins, got {origin!r}"
        )
    return f"{parts.scheme}://{parts.netloc}"


class CreateOID4VPDcApiReqRequestSchema(OpenAPISchema):
    """Request schema for creating an OID4VP DC-API request."""

    dcql_query_id = fields.Str(
        required=True,
        metadata={
            "description": (
                "Identifier of the DCQL query. OpenID4VP 1.0 defines DCQL as the "
                "only query language, so Presentation Exchange is not accepted."
            )
        },
    )

    vp_formats = fields.Dict(
        required=True,
        metadata={
            "description": (
                "Formats the Verifier supports, sent to the wallet as "
                "client_metadata.vp_formats_supported. Keys and values follow "
                "OpenID4VP 1.0 Appendix B (e.g. mso_mdoc, dc+sd-jwt)."
            )
        },
    )

    expected_origins = fields.List(
        fields.Str(),
        required=True,
        metadata={
            "description": (
                "Web origins the request is delivered from via the W3C Digital "
                'Credentials API (e.g. "https://verifier.example"). For signed '
                "requests they are bound into the request object (OpenID4VP 1.0 "
                "Appendix A.2). For all requests the first origin defines the "
                "expected response audience 'origin:<origin>' (Appendix A.4)."
            )
        },
    )

    signed = fields.Bool(
        required=False,
        load_default=False,
        metadata={
            "description": (
                "Sign the request as a JAR (protocol openid4vp-v1-signed) using "
                "the registered X.509 identity (POST /oid4vp/x509-identity)."
            )
        },
    )


class CreateOID4VPDcApiReqResponseSchema(OpenAPISchema):
    """Response schema for creating an OID4VP DC-API request."""

    presentation_id = fields.Str(required=True)
    protocol = fields.Str(
        required=True,
        metadata={
            "description": (
                "W3C Digital Credentials API protocol identifier to pass as "
                "requests[].protocol: 'openid4vp-v1-signed' or "
                "'openid4vp-v1-unsigned'."
            )
        },
    )
    request = fields.Dict(
        required=True,
        metadata={
            "description": (
                "Object to pass as requests[].data to navigator.credentials.get(). "
                'For signed requests this is {"request": <JWS compact>}; for '
                "unsigned requests it carries the OpenID4VP parameters directly "
                "(response_mode 'dc_api.jwt', client_id omitted)."
            )
        },
    )
    nonce = fields.Str(required=True)
    client_id = fields.Str(
        required=False,
        metadata={
            "description": (
                "Verifier client_id, returned for signed requests only. Unsigned "
                "DC-API requests omit client_id (OpenID4VP 1.0 Appendix A.2)."
            )
        },
    )
    response_uri = fields.Str(
        required=True,
        metadata={
            "description": (
                "Controller submission URL: the verifier front-end POSTs the "
                "browser-returned Authorization Response here. This is NOT sent to "
                "the wallet and is not the OpenID4VP 'response_uri' parameter "
                "(undefined for the DC-API)."
            )
        },
    )
    vp_formats = fields.Dict(required=True)


@docs(
    tags=["oid4vp"],
    summary="Create an OID4VP request for the W3C Digital Credentials API.",
)
@request_schema(CreateOID4VPDcApiReqRequestSchema)
@response_schema(CreateOID4VPDcApiReqResponseSchema)
async def create_oid4vp_dc_api_request(request: web.Request):
    """Create an OID4VP request for navigator.credentials.get() (DC-API).

    Returns an OpenID4VP 1.0 Appendix A request for inline delivery through the
    W3C Digital Credentials API, using a DCQL query and Response Mode
    ``dc_api.jwt``. There is no ``request_uri`` round-trip and no OpenID4VP
    ``response_uri``: the wallet returns the encrypted Authorization Response to
    the page through the ``navigator.credentials.get()`` promise, and the verifier
    front-end forwards it to the controller submission URL (``response_uri`` in
    the response below).

    Each request gets an ephemeral P-256 key, advertised in
    ``client_metadata.jwks``; the wallet encrypts its response to it with ECDH-ES
    (OpenID4VP 1.0 Section 8.3). Unencrypted ``dc_api`` responses are not
    accepted.

    ``signed=true`` produces a signed request (protocol ``openid4vp-v1-signed``):
    a JAR carrying the X.509 identity (Client Identifier Prefix ``x509_san_dns``)
    and ``expected_origins``. Otherwise an unsigned request (protocol
    ``openid4vp-v1-unsigned``) is returned with ``client_id`` omitted. In an
    unsigned request the encryption key is not integrity-protected, so a script
    on the verifier page could substitute it; prefer signed requests.

    The response audience is ``origin:<origin>`` for both variants (Appendix A.4)
    and is stored as the presentation's ``client_id`` for audience checks.

    ISO mdoc requests fail closed: the mdoc DC-API session transcript
    (``OpenID4VPDCAPIHandover``) is not implemented, so device authentication
    (holder binding) cannot be verified. A DCQL credential query for
    ``mso_mdoc`` is rejected unless it sets
    ``require_cryptographic_holder_binding`` to ``false``, explicitly accepting
    issuer authentication only. See ``docs/dc-api.md``.
    """
    context: AdminRequestContext = request["context"]
    body = await request.json()

    signed = bool(body.get("signed", False))
    vp_formats = body.get("vp_formats")
    dcql_query_id = body.get("dcql_query_id")

    if body.get("pres_def_id"):
        raise web.HTTPBadRequest(
            reason="DC-API requests use DCQL (OpenID4VP 1.0); Presentation "
            "Exchange (pres_def_id) is not supported."
        )
    if not dcql_query_id:
        raise web.HTTPBadRequest(reason="dcql_query_id is required")
    if not isinstance(vp_formats, dict) or not vp_formats:
        raise web.HTTPBadRequest(reason="vp_formats is required")
    expected_origins = [
        _normalize_origin(origin) for origin in body.get("expected_origins") or []
    ]
    if not expected_origins:
        raise web.HTTPBadRequest(reason="expected_origins is required")

    # Audience of the response for OpenID4VP over the DC-API, signed or not
    # (Appendix A.4): the Origin prefixed with "origin:".
    response_audience = f"origin:{expected_origins[0]}"

    async with context.session() as session:
        try:
            dcql_query_record = await DCQLQuery.retrieve_by_id(session, dcql_query_id)
        except StorageNotFoundError as err:
            raise web.HTTPNotFound(
                reason=f"DCQL query {dcql_query_id} not found"
            ) from err

        # Fail closed for mdoc: holder binding is the DCQL default (Section 6.1)
        # but cannot be verified here without the DC-API session transcript.
        for cred in dcql_query_record.credentials:
            if (
                cred.format == "mso_mdoc"
                and cred.require_cryptographic_holder_binding is not False
            ):
                raise web.HTTPBadRequest(
                    reason=(
                        f"Credential query '{cred.credential_query_id}' requests "
                        "mso_mdoc with holder binding, which cannot be verified "
                        "over the DC-API (OpenID4VPDCAPIHandover is not "
                        "implemented). Set require_cryptographic_holder_binding "
                        "to false to accept issuer authentication only."
                    )
                )

        x509_id = None
        if signed:
            storage = session.inject(BaseStorage)
            try:
                x509_record = await storage.get_record(
                    X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
                )
                x509_id = json.loads(x509_record.value)
            except StorageNotFoundError as err:
                raise web.HTTPBadRequest(
                    reason="Signed DC-API requests require a registered X.509 "
                    "identity (POST /oid4vp/x509-identity)."
                ) from err

        nonce = token_urlsafe(16)
        req_record = OID4VPRequest(dcql_query_id=dcql_query_id, vp_formats=vp_formats)
        await req_record.save(session=session)

        pres_record = OID4VPPresentation(
            dcql_query_id=dcql_query_id,
            state=OID4VPPresentation.REQUEST_RETRIEVED,
            request_id=req_record.request_id,
            client_id=response_audience,
            nonce=nonce,
        )
        await pres_record.save(session=session)

        encryption_jwk = await create_response_key(session, pres_record.presentation_id)

    config = Config.from_settings(context.settings)
    wallet_id = context.profile.settings.get("wallet.id")
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    oid4vp_base = config.oid4vp_endpoint or config.endpoint
    response_uri = f"{oid4vp_base}{subpath}/oid4vp/response/{pres_record.presentation_id}"

    # OpenID4VP 1.0 Appendix A.2 parameters. Response Mode is ``dc_api.jwt``
    # (encrypted, Section 8.3); ``response_uri`` and ``state`` are not defined
    # for the DC-API and are therefore omitted.
    oid4vp_params = {
        "response_type": "vp_token",
        "response_mode": "dc_api.jwt",
        "nonce": nonce,
        "client_metadata": {
            "vp_formats_supported": vp_formats,
            "jwks": {"keys": [encryption_jwk]},
            "encrypted_response_enc_values_supported": list(SUPPORTED_ENC),
        },
        "dcql_query": dcql_query_record.record_value,
    }

    response = {
        "presentation_id": pres_record.presentation_id,
        "nonce": nonce,
        "response_uri": response_uri,
        "vp_formats": vp_formats,
    }

    if signed:
        # JAR (RFC 9101) for protocol openid4vp-v1-signed. The x5c chain
        # authenticates the verifier (x509_san_dns) and expected_origins binds the
        # request to the origins allowed to deliver it (A.2). aud is the static
        # discovery value (Section 5.8).
        client_id = f"x509_san_dns:{x509_id['client_id']}"
        now = int(time.time())
        jar_payload = {
            "iss": client_id,
            "aud": "https://self-issued.me/v2",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
            "client_id": client_id,
            "expected_origins": expected_origins,
            **oid4vp_params,
        }
        request_jwt = await jwt_sign(
            profile=context.profile,
            headers={
                "x5c": x509_id["cert_chain"],
                "typ": "oauth-authz-req+jwt",
                "alg": "ES256",
            },
            payload=jar_payload,
            verification_method=x509_id["verification_method"],
        )
        response["protocol"] = "openid4vp-v1-signed"
        response["client_id"] = client_id
        # OpenID4VP 1.0 A.3.2.1: the compact JWS is the value of the "request"
        # member inside the DC-API data object.
        response["request"] = {"request": request_jwt}
    else:
        # OpenID4VP 1.0 A.3.1: unsigned requests send the parameters directly in
        # the DC-API data object, with client_id omitted.
        response["protocol"] = "openid4vp-v1-unsigned"
        response["request"] = oid4vp_params

    return web.json_response(response)


class OID4VPRequestQuerySchema(OpenAPISchema):
    """Parameters and validators for presentations list query."""

    request_id = fields.UUID(
        required=False,
        metadata={"description": "Filter by request identifier."},
    )
    pres_def_id = fields.Str(
        required=False,
        metadata={"description": "Filter by presentation definition identifier."},
    )
    dcql_query_id = fields.Str(
        required=False,
        metadata={"description": "Filter by DCQL query identifier."},
    )


class OID4VPRequestListSchema(OpenAPISchema):
    """Result schema for an presentations query."""

    results = fields.Nested(
        OID4VPPresentationSchema(),
        many=True,
        metadata={"description": "Presentation Requests"},
    )


@docs(
    tags=["oid4vp"],
    summary="Fetch all OID4VP Requests.",
)
@querystring_schema(OID4VPRequestQuerySchema())
@response_schema(OID4VPRequestListSchema())
async def list_oid4vp_requests(request: web.Request):
    """Request handler for searching requests."""

    context: AdminRequestContext = request["context"]

    try:
        async with context.profile.session() as session:
            if request_id := request.query.get("request_id"):
                record = await OID4VPRequest.retrieve_by_id(session, request_id)
                results = [record.serialize()]
            else:
                filter_ = {
                    attr: value
                    for attr in ("pres_def_id", "dcql_query_id")
                    if (value := request.query.get(attr))
                }
                records = await OID4VPRequest.query(session=session, tag_filter=filter_)
                results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response({"results": results})


# ---------------------------------------------------------------------------
# X.509 identity admin endpoints
#
# These endpoints manage a single "X.509 identity" record that lets ACA-Py act
# as an OID4VP verifier with client_id_scheme=x509_san_dns.  The record stores
# the DER certificate chain (base64, leaf-first) together with the
# verification method referencing the matching signing key and the DNS name
# used as client_id.
# ---------------------------------------------------------------------------

X509_IDENTITY_RECORD_TYPE = "OID4VP.x509_identity"
X509_IDENTITY_RECORD_ID = "OID4VP.x509_identity"


class RegisterX509IdentitySchema(OpenAPISchema):
    """Request body for registering an X.509 identity."""

    cert_chain_pem = fields.Str(
        required=True,
        metadata={
            "description": (
                "PEM-encoded certificate chain (leaf first, concatenated).  "
                "Each certificate will be stored as a base64-encoded DER value "
                "in the x5c array."
            )
        },
    )
    verification_method = fields.Str(
        required=True,
        metadata={
            "description": (
                'Verification method identifier (e.g. "did:jwk:...#0") that '
                "references the key matching the leaf certificate."
            )
        },
    )
    client_id = fields.Str(
        required=True,
        metadata={
            "description": (
                "DNS name used as client_id in OID4VP requests "
                "(must match the dNSName SAN in the leaf certificate)."
            )
        },
    )


@docs(tags=["oid4vp"], summary="Register X.509 identity for OID4VP requests")
@request_schema(RegisterX509IdentitySchema())
async def register_x509_identity(request: web.Request):
    """Store an X.509 certificate chain for x509_san_dns OID4VP requests."""
    context: AdminRequestContext = request["context"]
    body = await request.json()

    pem: str = body["cert_chain_pem"]
    verification_method: str = body["verification_method"]
    client_id: str = body["client_id"]

    # Parse PEM → list of base64 DER strings (whitespace stripped)
    b64_certs: List[str] = [
        re.sub(r"\s+", "", cert)
        for cert in re.findall(
            r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
            pem,
            re.DOTALL,
        )
    ]
    if not b64_certs:
        raise web.HTTPBadRequest(reason="No certificates found in cert_chain_pem")

    value = json.dumps(
        {
            "cert_chain": b64_certs,
            "verification_method": verification_method,
            "client_id": client_id,
        }
    )

    async with context.session() as session:
        storage = session.inject(BaseStorage)
        # replace any existing record
        try:
            existing = await storage.get_record(
                X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
            )
            await storage.update_record(existing, value, {})
        except StorageNotFoundError:
            record = StorageRecord(
                type=X509_IDENTITY_RECORD_TYPE,
                value=value,
                id=X509_IDENTITY_RECORD_ID,
            )
            await storage.add_record(record)

    return web.json_response(
        {
            "cert_chain": b64_certs,
            "verification_method": verification_method,
            "client_id": client_id,
        }
    )


@docs(tags=["oid4vp"], summary="Retrieve registered X.509 identity")
async def get_x509_identity(request: web.Request):
    """Return the stored X.509 identity record."""
    context: AdminRequestContext = request["context"]

    async with context.session() as session:
        storage = session.inject(BaseStorage)
        try:
            record = await storage.get_record(
                X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
            )
            return web.json_response(json.loads(record.value))
        except StorageNotFoundError:
            raise web.HTTPNotFound(reason="No X.509 identity registered")


@docs(tags=["oid4vp"], summary="Delete registered X.509 identity")
async def delete_x509_identity(request: web.Request):
    """Remove the stored X.509 identity record."""
    context: AdminRequestContext = request["context"]

    async with context.session() as session:
        storage = session.inject(BaseStorage)
        try:
            record = await storage.get_record(
                X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
            )
            await storage.delete_record(record)
        except StorageNotFoundError:
            raise web.HTTPNotFound(reason="No X.509 identity registered")

    return web.json_response({"deleted": True})
