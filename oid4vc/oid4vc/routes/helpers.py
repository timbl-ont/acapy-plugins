"""Helper functions for OID4VC routes."""

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.storage.error import StorageError
from aiohttp import web

from ..auth_providers import (
    AuthContext,
    AuthServerConfigError,
    AuthServerRegistry,
    default_registry,
    provider_type,
)
from ..config import Config
from ..models.exchange import OID4VCIExchangeRecord
from ..models.supported_cred import SupportedCredential
from ..utils import get_first_auth_server


async def _create_pre_auth_code(
    profile: Profile,
    config: Config,
    auth_server: dict | None,
    subject_id: str,
    credential_configuration_id: str | None = None,
    user_pin: str | None = None,
) -> str:
    """Create a pre-authorized code via the configured authorization server provider."""
    registry = profile.inject_or(AuthServerRegistry) or default_registry()
    provider = registry.get(provider_type(auth_server))
    return await provider.create_pre_authorized_code(
        AuthContext(profile, config, dict(auth_server or {})),
        subject_id=subject_id,
        credential_configuration_id=credential_configuration_id,
        user_pin=user_pin,
    )


async def _parse_cred_offer(context: AdminRequestContext, exchange_id: str) -> dict:
    """Helper function for cred_offer request parsing.

    Used in get_cred_offer and public_routes.dereference_cred_offer endpoints.
    """
    config = Config.from_settings(context.settings)
    try:
        async with context.session() as session:
            record = await OID4VCIExchangeRecord.retrieve_by_id(session, exchange_id)
            supported = await SupportedCredential.retrieve_by_id(
                session, record.supported_cred_id
            )
            auth_server = await get_first_auth_server(session, context.profile)
            if auth_server is None:
                auth_server = config.auth_server
            record.code = await _create_pre_auth_code(
                context.profile,
                config,
                auth_server,
                record.refresh_id,
                supported.identifier,
                record.pin,
            )
            # A new code starts a fresh single-use / tx_code attempt budget.
            record.pin_attempts = 0
            record.code_redeemed_at = None
            record.state = OID4VCIExchangeRecord.STATE_OFFER_CREATED
            await record.save(session, reason="Credential offer created")
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except AuthServerConfigError as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    user_pin_required: bool = record.pin is not None
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    pre_auth_grant: dict = {
        "pre-authorized_code": record.code,
    }
    if user_pin_required:
        # OID4VCI 1.0 final: tx_code replaces user_pin_required in the offer.
        # Indicate that a transaction code is required without revealing the value.
        pre_auth_grant["tx_code"] = {"input_mode": "text"}
    return {
        "credential_issuer": f"{config.endpoint}{subpath}",
        "credential_configuration_ids": [supported.identifier],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": pre_auth_grant,
        },
    }
