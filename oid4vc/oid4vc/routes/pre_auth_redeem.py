"""Back-channel pre-authorized code redemption (admin API).

An external authorization server that serves the wallet-facing pre-authorized
code token request (Keycloak with the OID4VCI extension) calls this endpoint to
redeem a plugin-issued code. The plugin keeps ownership of the code, the
``tx_code`` and the exchange; the authorization server handles wallet
authentication and DPoP, and issues the access token.

This is a trusted backend function, so it lives on the admin port, not the
public OID4VCI port: ``POST /oid4vci/pre-auth/redeem``.

It deliberately does not use ACA-Py admin credentials (API key / tenant
token): the authorization server is an OAuth client of the plugin and
authenticates with the method configured for it in the tenant's authorization
server entry (``private_key_jwt`` by default; see
``auth_providers/client_auth.py``), carried in the form body.

The tenant is carried in that authentication: the caller names the credential
issuer it acts for (``credential_issuer``, a claim of its signed client
assertion, or a form parameter with ``client_secret_post``). The plugin maps it
to the base wallet or a tenant, then verifies the credentials against *that*
tenant's configuration and checks the verified claim matches. A caller cannot
act for a tenant whose configuration doesn't trust it, and no tenant can
redirect another tenant's authorization server to itself.
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
from ..auth_providers.client_auth import CREDENTIAL_ISSUER_CLAIM
from ..config import Config
from ..jose_util import JoseError, decode_jws
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


class _UnknownTenant(Exception):
    """The credential issuer named by the caller is not served here."""


def _claimed_credential_issuer(params: dict[str, str]) -> str | None:
    """The credential issuer the caller says it acts for (not yet verified)."""
    from_param = params.get(CREDENTIAL_ISSUER_CLAIM)
    assertion = params.get("client_assertion")
    if not assertion:
        return from_param
    try:
        _, payload, _, _ = decode_jws(assertion)
    except JoseError:
        return None
    from_assertion = payload.get(CREDENTIAL_ISSUER_CLAIM)
    if not isinstance(from_assertion, str):
        return None
    if from_param is not None and from_param != from_assertion:
        return None
    return from_assertion


async def _target_profile(
    context: AdminRequestContext, credential_issuer: str
) -> Profile:
    """Map a credential issuer identifier to the base wallet or a tenant profile.

    ``{endpoint}`` is the base wallet; ``{endpoint}/tenant/{wallet_id}`` a tenant.
    """
    root = context.root_profile or context.profile
    endpoint = Config.from_settings(root.settings).endpoint.rstrip("/")
    if credential_issuer.rstrip("/") == endpoint:
        return root

    prefix = f"{endpoint}/tenant/"
    wallet_id = (
        credential_issuer[len(prefix) :] if credential_issuer.startswith(prefix) else ""
    )
    manager = root.inject_or(BaseMultitenantManager)
    if not wallet_id or "/" in wallet_id or not manager:
        raise _UnknownTenant(credential_issuer)
    try:
        async with root.session() as session:
            wallet = await WalletRecord.retrieve_by_id(session, wallet_id)
    except (StorageNotFoundError, BaseModelError):
        raise _UnknownTenant(credential_issuer) from None
    if wallet.requires_external_key:
        raise _UnknownTenant(credential_issuer)  # unmanaged: no key to open it
    return await manager.get_wallet_profile(root.context, wallet)


@docs(
    tags=["oid4vci"],
    summary="Redeem a pre-authorized code (authorization server back channel)",
    description=(
        "Called by an external authorization server (e.g. Keycloak) to redeem a "
        "plugin-issued pre-authorized code. Form parameters: pre_authorized_code, "
        "tx_code, wallet_client_id, and client credentials (client_assertion_type + "
        "client_assertion, or client_id + client_secret + credential_issuer). "
        "Authenticated by the authorization server's configured client "
        "authentication, not by admin credentials; the tenant is the one whose "
        "credential issuer the authenticated caller names."
    ),
)
async def redeem_pre_auth_code_route(request: web.Request) -> web.Response:
    """Redeem a pre-authorized code on behalf of the authorization server."""
    context: AdminRequestContext = request["context"]
    form = await request.post()
    params = {k: v for k, v in form.items() if isinstance(v, str)}
    unauthenticated = _error("invalid_client", "client authentication failed", 401)

    credential_issuer = _claimed_credential_issuer(params)
    if not credential_issuer:
        LOGGER.warning("Rejected pre-auth redeem request: no credential_issuer")
        return unauthenticated
    try:
        profile = await _target_profile(context, credential_issuer)
        async with profile.session() as session:
            provider, ctx = await resolve_auth_provider(session, profile)
    except (_UnknownTenant, AuthServerConfigError) as err:
        LOGGER.warning(
            "Rejected pre-auth redeem request for %s: %s", credential_issuer, err
        )
        return unauthenticated
    if not provider.supports_redeem:
        LOGGER.warning(
            "Pre-auth redeem for %s: provider does not redeem", credential_issuer
        )
        return unauthenticated

    try:
        # Verifies the credentials against this tenant's configuration,
        # including that the verified credential_issuer is this tenant's.
        await provider.authenticate_back_channel(
            ctx, params, str(request.url.with_query(None))
        )
    except BackChannelAuthError as err:
        LOGGER.warning("Rejected pre-auth redeem request: %s", err)
        return unauthenticated

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
