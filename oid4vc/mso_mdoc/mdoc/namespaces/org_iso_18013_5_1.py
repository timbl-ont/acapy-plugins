"""The ``org.iso.18013.5.1`` namespace of the ISO/IEC 18013-5 mDL.

Mirrors ``OrgIso1801351`` in spruceid/isomdl
(``src/definitions/namespaces/org_iso_18013_5_1/``). Country codes and the UN
distinguishing sign are checked by shape only; isomdl also checks them against
its code lists.
"""

import re
from typing import Any, Mapping

from . import encoders as enc
from .schema import Element, Namespace

NAMESPACE = "org.iso.18013.5.1"

VEHICLE_CATEGORY_CODES = (
    "A", "B", "C", "D", "BE", "CE", "DE", "AM", "A1", "A2", "B1", "C1", "D1", "C1E",
    "D1E",
)  # fmt: skip

EYE_COLOURS = (
    "black", "blue", "brown", "dichromatic", "grey", "green", "hazel", "maroon", "pink",
    "unknown",
)  # fmt: skip

HAIR_COLOURS = (
    "bald", "black", "blond", "brown", "grey", "red", "auburn", "sandy", "white",
    "unknown",
)  # fmt: skip

_code = enc.struct(
    {"code": enc.tstr(), "sign": enc.tstr(), "value": enc.tstr()},
    required=("code",),
    name="code",
)

driving_privilege = enc.struct(
    {
        "vehicle_category_code": enc.one_of(*VEHICLE_CATEGORY_CODES),
        "issue_date": enc.full_date,
        "expiry_date": enc.full_date,
        "codes": enc.array_of(_code, non_empty=True, name="codes"),
    },
    required=("vehicle_category_code",),
    name="driving privilege",
)

driving_privileges = enc.array_of(driving_privilege, name="driving_privileges")


def _check(values: Mapping[str, Any]) -> None:
    jurisdiction = values.get("issuing_jurisdiction")
    country = values.get("issuing_country")
    if jurisdiction is not None and country is not None:
        if not str(jurisdiction).startswith(str(country)):
            raise enc.EncodingError(
                "issuing_jurisdiction must start with issuing_country"
            )


SCHEMA = Namespace(
    id=NAMESPACE,
    elements={
        "family_name": Element(enc.latin1, mandatory=True),
        "given_name": Element(enc.latin1, mandatory=True),
        "birth_date": Element(enc.full_date, mandatory=True),
        "issue_date": Element(enc.tdate_or_full_date, mandatory=True),
        "expiry_date": Element(enc.tdate_or_full_date, mandatory=True),
        "issuing_country": Element(enc.alpha2, mandatory=True),
        "issuing_authority": Element(enc.latin1, mandatory=True),
        "document_number": Element(enc.latin1, mandatory=True),
        "portrait": Element(enc.bstr, mandatory=True),
        "driving_privileges": Element(driving_privileges, mandatory=True),
        "un_distinguishing_sign": Element(enc.un_distinguishing_sign, mandatory=True),
        "administrative_number": Element(enc.latin1),
        "sex": Element(enc.iso5218_sex),
        "height": Element(enc.uint),
        "weight": Element(enc.uint),
        "eye_colour": Element(enc.one_of(*EYE_COLOURS)),
        "hair_colour": Element(enc.one_of(*HAIR_COLOURS)),
        "birth_place": Element(enc.latin1),
        "resident_address": Element(enc.latin1),
        "portrait_capture_date": Element(enc.tdate),
        "age_in_years": Element(enc.uint),
        "age_birth_year": Element(enc.uint),
        "issuing_jurisdiction": Element(enc.subdivision),
        "nationality": Element(enc.alpha2),
        "resident_city": Element(enc.latin1),
        "resident_state": Element(enc.latin1),
        "resident_postal_code": Element(enc.latin1),
        "resident_country": Element(enc.alpha2),
        "family_name_national_character": Element(enc.tstr()),
        "given_name_national_character": Element(enc.tstr()),
        "signature_usual_mark": Element(enc.bstr),
    },
    patterns=(
        (re.compile(r"age_over_\d{2}"), Element(enc.boolean)),
        (re.compile(r"biometric_template_.+"), Element(enc.bstr)),
    ),
    check=_check,
    # An mDL with no driving privileges granted still carries the element.
    defaults={"driving_privileges": []},
)
