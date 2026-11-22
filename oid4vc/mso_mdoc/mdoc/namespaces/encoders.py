"""Encoders that turn JSON element values into CBOR-ready values.

Each encoder takes the value from a credential subject and returns what
``cbor2.dumps`` must write for it: a ``CBORTag`` for ``full-date`` (tag 1004)
and ``tdate`` (tag 0), ``bytes`` for a ``bstr``, and plain ``str``, ``int``,
``bool``, ``list`` or ``dict`` otherwise.

An encoder raises ``EncodingError`` for a value it cannot encode. The message
says what was expected and never includes the value, because element values
such as portraits and dates of birth must not reach logs or API errors.
"""

import base64
import binascii
import re
from datetime import UTC, date, datetime
from typing import Any, Callable, Mapping

from cbor2 import CBORTag

FULL_DATE_TAG = 1004
TDATE_TAG = 0

Encoder = Callable[[Any], Any]


class EncodingError(ValueError):
    """An element value that cannot be encoded.

    The message describes the expected form and never contains the value.
    """


_FULL_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ALPHA2 = re.compile(r"^[A-Z]{2}$")
_COUNTRY_CODE = re.compile(r"^[A-Z]{2,3}$")
_SUBDIVISION = re.compile(r"^[A-Z]{2}-[A-Z0-9]{1,3}$")
_UN_SIGN = re.compile(r"^[A-Z]{1,3}$")
_APPROXIMATE_MASK = re.compile(r"^[01]{8}$")
_DATA_URI_PREFIX = re.compile(r"^data:[^,]*;base64,", re.IGNORECASE)


def tstr(max_length: int | None = None) -> Encoder:
    """Text string, optionally at most ``max_length`` characters."""

    def encode(value: Any) -> str:
        if not isinstance(value, str):
            raise EncodingError("expected a text string")
        if max_length is not None and len(value) > max_length:
            raise EncodingError(f"text is longer than {max_length} characters")
        return value

    return encode


tstr150 = tstr(150)


def latin1(value: Any) -> str:
    """Text of at most 150 characters from ISO/IEC 8859-1 (Latin-1)."""
    text = tstr150(value)
    if any(ord(char) > 0xFF for char in text):
        raise EncodingError("text contains characters outside Latin-1")
    return text


def _pattern(regex: re.Pattern, expected: str) -> Encoder:
    def encode(value: Any) -> str:
        if not isinstance(value, str) or not regex.match(value):
            raise EncodingError(f"expected {expected}")
        return value

    return encode


alpha2 = _pattern(_ALPHA2, "an ISO 3166-1 alpha-2 country code")
country_code = _pattern(_COUNTRY_CODE, "an ISO 3166-1 alpha-2 or alpha-3 country code")
subdivision = _pattern(_SUBDIVISION, "an ISO 3166-2 subdivision code such as US-IA")
un_distinguishing_sign = _pattern(_UN_SIGN, "a UN distinguishing sign of 1 to 3 letters")


def _parse_full_date(value: Any) -> str:
    if not isinstance(value, str) or not _FULL_DATE.match(value):
        raise EncodingError("expected a full-date (YYYY-MM-DD)")
    try:
        date.fromisoformat(value)
    except ValueError:
        raise EncodingError("expected a valid calendar date (YYYY-MM-DD)") from None
    return value


def full_date(value: Any) -> CBORTag:
    """``full-date``: ``YYYY-MM-DD``, written as tag 1004 (RFC 8943)."""
    return CBORTag(FULL_DATE_TAG, _parse_full_date(value))


def tdate(value: Any) -> CBORTag:
    """``tdate``: an RFC 3339 date-time, written as tag 0.

    The value is normalised to UTC without fractional seconds, the form
    ISO/IEC 18013-5 uses (``YYYY-MM-DDTHH:MM:SSZ``).
    """
    if not isinstance(value, str) or "T" not in value.upper():
        raise EncodingError("expected an RFC 3339 date-time")
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        raise EncodingError("expected an RFC 3339 date-time") from None
    if moment.tzinfo is None:
        raise EncodingError("expected an RFC 3339 date-time with a time zone")
    moment = moment.astimezone(UTC).replace(microsecond=0)
    return CBORTag(TDATE_TAG, moment.strftime("%Y-%m-%dT%H:%M:%SZ"))


def tdate_or_full_date(value: Any) -> CBORTag:
    """A ``tdate`` for a date-time, or a ``full-date`` for a plain date."""
    if isinstance(value, str) and "T" in value.upper():
        return tdate(value)
    return full_date(value)


def bstr(value: Any) -> bytes:
    """Byte string from bytes, a list of byte values, or base64 / base64url text.

    Base64 text may be padded or not, and may carry a ``data:...;base64,``
    prefix, which is removed.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, list):
        if not all(isinstance(b, int) and not isinstance(b, bool) for b in value):
            raise EncodingError("expected a list of byte values")
        try:
            return bytes(value)
        except ValueError:
            raise EncodingError("expected byte values from 0 to 255") from None
    if isinstance(value, str):
        text = _DATA_URI_PREFIX.sub("", value.strip())
        padded = text + "=" * (-len(text) % 4)
        altchars = b"-_" if ("-" in text or "_" in text) else None
        try:
            return base64.b64decode(padded, altchars=altchars, validate=True)
        except (binascii.Error, ValueError):
            raise EncodingError("expected base64 or base64url text") from None
    raise EncodingError("expected base64 text or a list of byte values")


def integer(value: Any) -> int:
    """Integer (a JSON boolean is not accepted)."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise EncodingError("expected an integer")
    return value


def uint(value: Any) -> int:
    """Unsigned integer."""
    number = integer(value)
    if number < 0:
        raise EncodingError("expected an unsigned integer")
    return number


def boolean(value: Any) -> bool:
    """Boolean."""
    if not isinstance(value, bool):
        raise EncodingError("expected a boolean")
    return value


def one_of(*allowed: Any) -> Encoder:
    """One of a fixed set of values (strings or integers, matched by type)."""

    def encode(value: Any) -> Any:
        if isinstance(value, bool) or not any(
            type(value) is type(option) and value == option for option in allowed
        ):
            raise EncodingError(
                "expected one of " + ", ".join(repr(option) for option in allowed)
            )
        return value

    return encode


iso5218_sex = one_of(0, 1, 2, 9)


def json_value(value: Any) -> Any:
    """Any JSON value, written with the natural JSON-to-CBOR mapping and no tags."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [json_value(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise EncodingError("expected an object with text keys")
        return {key: json_value(item) for key, item in value.items()}
    raise EncodingError("expected a JSON value")


def struct(
    fields: Mapping[str, Encoder],
    required: tuple[str, ...] = (),
    name: str = "object",
) -> Encoder:
    """Map with known keys, written in the order ``fields`` lists them.

    Keys missing from the input are left out; keys in ``required`` must be
    present, and unknown keys are refused.
    """

    def encode(value: Any) -> dict:
        if not isinstance(value, dict):
            raise EncodingError(f"expected {name}")
        unknown = sorted(set(value) - set(fields))
        if unknown:
            raise EncodingError(f"{name} has unknown keys: {', '.join(unknown)}")
        missing = [key for key in required if key not in value]
        if missing:
            raise EncodingError(f"{name} is missing: {', '.join(missing)}")
        encoded = {}
        for key, field in fields.items():
            if key in value:
                try:
                    encoded[key] = field(value[key])
                except EncodingError as err:
                    raise EncodingError(f"{name} '{key}': {err}") from None
        return encoded

    return encode


def array_of(item: Encoder, non_empty: bool = False, name: str = "array") -> Encoder:
    """Array whose every item is encoded with ``item``."""

    def encode(value: Any) -> list:
        if not isinstance(value, list):
            raise EncodingError(f"expected {name}")
        if non_empty and not value:
            raise EncodingError(f"{name} must not be empty")
        encoded = []
        for index, element in enumerate(value):
            try:
                encoded.append(item(element))
            except EncodingError as err:
                raise EncodingError(f"{name} item {index}: {err}") from None
        return encoded

    return encode


def photoid_birth_date(value: Any) -> dict:
    """ISO/IEC TS 23220-2 ``birth_date``, always written as the map form.

    ``{"birth_date": full-date, ? "approximate_mask": tstr}``. A plain
    ``YYYY-MM-DD`` input becomes the map without a mask. The mask is exactly
    eight ``0``/``1`` characters (YYYYMMDD, ``1`` = masked).
    """
    if isinstance(value, str):
        return {"birth_date": full_date(value)}
    encoded = struct(
        {"birth_date": full_date, "approximate_mask": _approximate_mask},
        required=("birth_date",),
        name="birth_date",
    )(value)
    return encoded


def _approximate_mask(value: Any) -> str:
    if not isinstance(value, str) or not _APPROXIMATE_MASK.match(value):
        raise EncodingError("expected 8 characters of 0 and 1 (YYYYMMDD)")
    return value
