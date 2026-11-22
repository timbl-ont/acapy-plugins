"""The ``org.iso.18013.5.1.aamva`` namespace of the AAMVA mDL Implementation Guidelines.

Mirrors ``OrgIso1801351Aamva`` in spruceid/isomdl
(``src/definitions/namespaces/org_iso_18013_5_1_aamva/``, guidelines version 1.2).
Element identifiers are case-sensitive, and two contain a dot.
"""

import re

from . import encoders as enc
from .schema import Element, Namespace

NAMESPACE = "org.iso.18013.5.1.aamva"

NAME_SUFFIXES = (
    "JR", "SR", "1ST", "I", "2ND", "II", "3RD", "III", "4TH", "IV", "5TH", "V", "6TH",
    "VI", "7TH", "VII", "8TH", "VIII", "9TH", "IX",
)  # fmt: skip

RACE_ETHNICITY = ("AI", "AP", "BK", "H", "O", "U", "W")

_COUNTY_CODE = re.compile(r"^\d{3}$")

name_truncation = enc.one_of("T", "N", "U")
name_suffix = enc.one_of(*NAME_SUFFIXES)
aamva_sex = enc.one_of(1, 2, 9)
present = enc.one_of(1)


def county_code(value):
    """Three-digit county code."""
    if not isinstance(value, str) or not _COUNTY_CODE.match(value):
        raise enc.EncodingError("expected a county code of three digits")
    return value


_vehicle_class = enc.struct(
    {
        "domestic_vehicle_class_code": enc.tstr(),
        "domestic_vehicle_class_description": enc.tstr(),
        "issue_date": enc.full_date,
        "expiry_date": enc.full_date,
    },
    required=("domestic_vehicle_class_code", "domestic_vehicle_class_description"),
    name="domestic_vehicle_class",
)

_restriction = enc.struct(
    {
        "domestic_vehicle_restriction_code": enc.tstr(),
        "domestic_vehicle_restriction_description": enc.tstr(),
    },
    required=("domestic_vehicle_restriction_description",),
    name="domestic vehicle restriction",
)

_endorsement = enc.struct(
    {
        "domestic_vehicle_endorsement_code": enc.tstr(),
        "domestic_vehicle_endorsement_description": enc.tstr(),
    },
    required=("domestic_vehicle_endorsement_description",),
    name="domestic vehicle endorsement",
)

domestic_driving_privilege = enc.struct(
    {
        "domestic_vehicle_class": _vehicle_class,
        "domestic_vehicle_restrictions": enc.array_of(
            _restriction, non_empty=True, name="domestic_vehicle_restrictions"
        ),
        "domestic_vehicle_endorsements": enc.array_of(
            _endorsement, non_empty=True, name="domestic_vehicle_endorsements"
        ),
    },
    name="domestic driving privilege",
)

domestic_driving_privileges = enc.array_of(
    domestic_driving_privilege, name="domestic_driving_privileges"
)

SCHEMA = Namespace(
    id=NAMESPACE,
    elements={
        "domestic_driving_privileges": Element(
            domestic_driving_privileges, mandatory=True
        ),
        "family_name_truncation": Element(name_truncation, mandatory=True),
        "given_name_truncation": Element(name_truncation, mandatory=True),
        "sex": Element(aamva_sex, mandatory=True),
        "DHS_compliance": Element(enc.one_of("F", "N"), mandatory=True),
        "name_suffix": Element(name_suffix),
        "aka_suffix": Element(name_suffix),
        "organ_donor": Element(present),
        "veteran": Element(present),
        "CDL_indicator": Element(present),
        "DHS_temporary_lawful_status": Element(present),
        "aka_family_name.v2": Element(enc.latin1),
        "aka_given_name.v2": Element(enc.latin1),
        "weight_range": Element(enc.one_of(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)),
        "race_ethnicity": Element(enc.one_of(*RACE_ETHNICITY)),
        "EDL_credential": Element(enc.one_of(1, 2)),
        "resident_county": Element(county_code),
        "hazmat_endorsement_expiration_date": Element(enc.full_date),
        "DHS_compliance_text": Element(enc.tstr()),
    },
)
