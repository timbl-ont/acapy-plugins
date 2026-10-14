"""Back-channel pre-authorized code redemption (admin API).

An external authorization server that serves the wallet-facing pre-authorized
code token request (Keycloak with the OID4VCI extension) calls this endpoint to
redeem a plugin-issued code. The plugin keeps ownership of the code, the
``tx_code`` and the exchange; the authorization server handles wallet
authentication and DPoP, and issues the access token.

This is a trusted backend function, so it lives on the admin port, not the
public OID4VCI port. It deliberately does not use ACA-Py admin credentials (API
key / tenant token): the authorization server is an OAuth client of the
plugin and authenticates with the method configured for it in the tenant's
authorization server entry (``private_key_jwt`` by default; see
``auth_providers/client_auth.py``), carried in the form body. That keeps
tenant tokens away from the authorization server and limits it to redeeming
codes for the tenant it is configured for.

Routes:

- ``POST /oid4vci/pre-auth/redeem``: the agent's (base) wallet
- ``POST /oid4vci/tenant/{wallet_id}/pre-auth/redeem``: a tenant (multitenant)
"""

import logging

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.multitenant.base import BaseMultitenantManager
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.models.wallet_record import WalletRecord
from aiohttp import web
from aiohttp_apispec import docs

from ..auth_providers import (
    AuthServerConfigError,
    BackChannelAuthError,
    resolve_auth_provider,
)
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


async def _target_profile(context: AdminRequestContext, wallet_id: str | None) -> Profile:
    """Profile whose codes are being redeemed: the base wallet or a tenant."""
    if wallet_id is None:
        return context.profile

    manager = context.profile.inject_or(BaseMultitenantManager)
    if not manager:
        raise web.HTTPNotFound()
    try:
        async with context.profile.session() as session:
            wallet = await WalletRecord.retrieve_by_id(session, wallet_id)
    except (StorageNotFoundError, BaseModelError):
        raise web.HTTPNotFound() from None
    if wallet.requires_external_key:
        raise web.HTTPNotFound()  # unmanaged wallets need a key we don't have
    return await manager.get_wallet_profile(context.profile.context, wallet)


@docs(
    tags=["oid4vci"],
    summary="Redeem a pre-authorized code (authorization server back channel)",
    description=(
        "Called by an external authorization server (e.g. Keycloak) to redeem a "
        "plugin-issued pre-authorized code. Form parameters: pre_authorized_code, "
        "tx_code, wallet_client_id, and client credentials (client_assertion_type + "
        "client_assertion, or client_id + client_secret). Authenticated by the "
        "authorization server's configured client authentication, not by admin "
        "credentials."
    ),
)
async def redeem_pre_auth_code_route(request: web.Request) -> web.Response:
    """Redeem a pre-authorized code on behalf of the authorization server."""
    context: AdminRequestContext = request["context"]
    profile = await _target_profile(context, request.match_info.get("wallet_id"))

    try:
        async with profile.session() as session:
            provider, ctx = await resolve_auth_provider(session, profile)
    except AuthServerConfigError as err:
        LOGGER.warning("Pre-auth redeem: %s", err)
        raise web.HTTPNotFound() from err
    if not provider.supports_redeem:
        raise web.HTTPNotFound()

    form = await request.post()
    params = {k: v for k, v in form.items() if isinstance(v, str)}
    try:
        await provider.authenticate_back_channel(
            ctx, params, str(request.url.with_query(None))
        )
    except BackChannelAuthError as err:
        LOGGER.warning("Rejected pre-auth redeem request: %s", err)
        return _error("invalid_client", "client authentication failed", 401)

    code = params.get("pre_authorized_code") or params.get("pre-authorized_code")
    try:
        record = await redeem_pre_auth_code(profile, code, params.get("tx_code"))
    except PreAuthCodeError as err:
        return _error(err.error, err.description)

    try:
        async with profile.session() as session:
            supported = await SupportedCredential.retrieve_by_id(
                session, record.supported_cred_id
            )
    except (StorageError, BaseModelError):
        LOGGER.error("Supported credential for exchange %s missing", record.exchange_id)
        return _error("server_error", "credential configuration not found", 500)

    LOGGER.info(
        "Pre-authorized code for exchange %s redeemed (wallet client %s)",
        record.exchange_id,
        params.get("wallet_client_id"),
    )
    return web.json_response(
        {
            "refresh_id": record.refresh_id,
            "credential_configuration_ids": [supported.identifier],
            "expires_in": REDEEMED_TOKEN_LIFETIME,
        },
        headers={"Cache-Control": "no-store"},
    )
