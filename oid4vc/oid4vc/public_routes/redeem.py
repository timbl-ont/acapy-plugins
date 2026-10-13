"""Back-channel pre-authorized code redemption for external authorization servers.

An external authorization server that serves the wallet-facing pre-authorized
code token request (Keycloak with the OID4VCI extension) calls this endpoint to
redeem a plugin-issued code. The plugin keeps ownership of the code, the
``tx_code`` and the exchange state; the AS handles client authentication
(wallet attestation) and DPoP, and issues the access token.
"""

import logging

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.storage.error import StorageError
from aiohttp import web

from ..auth_providers import BackChannelAuthError, resolve_auth_provider
from ..models.supported_cred import SupportedCredential
from ..pre_auth import PreAuthCodeError, redeem_pre_auth_code

LOGGER = logging.getLogger(__name__)

# Suggested lifetime (seconds) of the access token the AS issues for a
# redeemed code. Only needs to cover the nonce + credential requests.
REDEEMED_TOKEN_LIFETIME = 300


def _error(error: str, description: str, status: int = 400) -> web.Response:
    return web.json_response(
        {"error": error, "error_description": description},
        status=status,
        headers={"Cache-Control": "no-store"},
    )


async def redeem_pre_auth_code_route(request: web.Request) -> web.Response:
    """Redeem a pre-authorized code on behalf of the authorization server.

    Request: ``{"pre_authorized_code": str, "tx_code": str?, "client_id": str?}``
    Response: ``{"refresh_id", "credential_configuration_ids", "expires_in"}``
    """
    context: AdminRequestContext = request["context"]
    async with context.profile.session() as session:
        provider, ctx = await resolve_auth_provider(session, context.profile)
    if not provider.supports_redeem:
        raise web.HTTPNotFound()

    try:
        await provider.authenticate_back_channel(ctx, request)
    except BackChannelAuthError as err:
        LOGGER.warning("Rejected pre-auth redeem request: %s", err)
        return _error("invalid_client", "back-channel authentication failed", 401)

    try:
        body = await request.json()
    except ValueError:
        return _error("invalid_request", "request body must be JSON")
    if not isinstance(body, dict):
        return _error("invalid_request", "request body must be a JSON object")

    code = body.get("pre_authorized_code") or body.get("pre-authorized_code")
    tx_code = body.get("tx_code")
    try:
        record = await redeem_pre_auth_code(
            context.profile,
            code if isinstance(code, str) else None,
            tx_code if isinstance(tx_code, str) else None,
        )
    except PreAuthCodeError as err:
        return _error(err.error, err.description)

    try:
        async with context.profile.session() as session:
            supported = await SupportedCredential.retrieve_by_id(
                session, record.supported_cred_id
            )
    except (StorageError, BaseModelError):
        LOGGER.error("Supported credential for exchange %s missing", record.exchange_id)
        return _error("server_error", "credential configuration not found", 500)

    LOGGER.info(
        "Pre-authorized code for exchange %s redeemed by client %s",
        record.exchange_id,
        body.get("client_id"),
    )
    return web.json_response(
        {
            "refresh_id": record.refresh_id,
            "credential_configuration_ids": [supported.identifier],
            "expires_in": REDEEMED_TOKEN_LIFETIME,
        },
        headers={"Cache-Control": "no-store"},
    )
