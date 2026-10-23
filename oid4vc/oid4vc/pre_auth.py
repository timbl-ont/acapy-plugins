"""Pre-authorized code redemption, shared by every authorization server mode.

The plugin owns the pre-authorized code and its ``tx_code``. The built-in
``/token`` endpoint redeems codes directly; an external authorization server
that supports it (Keycloak with the OID4VCI extension) redeems them through
the back-channel redeem endpoint. Either way the same checks apply:

- the code is single use;
- ``tx_code`` is compared in constant time;
- after ``max_tx_code_attempts`` failures the code is locked, so a ``tx_code``
  cannot be brute-forced online (OID4VCI 1.0 §13.6.2). An exchange gets one
  code; fetching its offer again returns the same code, so a locked code
  needs a new exchange.
"""

import hmac
import logging

from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.util import datetime_now, datetime_to_str
from acapy_agent.storage.error import StorageError

from .config import Config
from .models.exchange import OID4VCIExchangeRecord

LOGGER = logging.getLogger(__name__)


class PreAuthCodeError(Exception):
    """Pre-authorized code redemption failed (OAuth error code + description)."""

    def __init__(self, error: str, description: str):
        """Initialize the error."""
        super().__init__(description)
        self.error = error
        self.description = description


def _tx_code_matches(supplied: str, expected: str) -> bool:
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


async def redeem_pre_auth_code(
    profile: Profile, code: str | None, tx_code: str | None
) -> OID4VCIExchangeRecord:
    """Validate and atomically redeem a pre-authorized code.

    Returns the exchange record on success; raises ``PreAuthCodeError``.
    """
    if not code or not isinstance(code, str):
        raise PreAuthCodeError(
            "invalid_request", "pre-authorized_code is missing or invalid"
        )
    max_attempts = Config.from_settings(profile.settings).max_tx_code_attempts

    async with profile.transaction() as txn:
        try:
            record = await OID4VCIExchangeRecord.retrieve_by_code(
                txn, code, for_update=True
            )
        except (StorageError, BaseModelError) as err:
            # StorageNotFoundError / StorageDuplicateError are StorageErrors.
            raise PreAuthCodeError(
                "invalid_grant", "pre-authorized code is invalid"
            ) from err

        if record.state not in (
            OID4VCIExchangeRecord.STATE_CREATED,
            OID4VCIExchangeRecord.STATE_OFFER_CREATED,
        ):
            raise PreAuthCodeError(
                "invalid_grant", "pre-authorized code is no longer valid"
            )

        if record.code_redeemed_at is not None or record.token is not None:
            raise PreAuthCodeError(
                "invalid_grant", "pre-authorized code has already been used"
            )

        if record.pin is not None:
            if (record.pin_attempts or 0) >= max_attempts:
                raise PreAuthCodeError(
                    "invalid_grant",
                    "pre-authorized code locked after failed tx_code attempts",
                )
            if not tx_code:
                raise PreAuthCodeError("invalid_request", "tx_code is required")
            if not _tx_code_matches(str(tx_code), record.pin):
                record.pin_attempts = (record.pin_attempts or 0) + 1
                await record.save(txn, reason="Failed tx_code attempt")
                await txn.commit()
                LOGGER.info(
                    "Failed tx_code attempt %d/%d for exchange %s",
                    record.pin_attempts,
                    max_attempts,
                    record.exchange_id,
                )
                raise PreAuthCodeError("invalid_grant", "tx_code is invalid")

        record.code_redeemed_at = datetime_to_str(datetime_now())
        await record.save(txn, reason="Pre-authorized code redeemed")
        await txn.commit()

    return record
