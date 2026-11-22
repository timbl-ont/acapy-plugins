"""The ``org.iso.23220.1`` namespace, as the ISO/IEC TS 23220-4 Annex C photo ID uses it.

Mirrors ``OrgIso232201`` on timbl-ont/isomdl ``feat/photoid-23220-4``
(``src/definitions/namespaces/org_iso_23220_1/``): ISO/IEC TS 23220-2:2026 for
encoding and 23220-4:2026 Annex C Table C.1 for presence. Annex C C.2.1 caps
every text element at 150 characters.
"""

import re

from . import encoders as enc
from .schema import Element, Namespace

NAMESPACE = "org.iso.23220.1"

SCHEMA = Namespace(
    id=NAMESPACE,
    elements={
        "family_name": Element(enc.tstr150, mandatory=True),
        "given_name": Element(enc.tstr150, mandatory=True),
        "birth_date": Element(enc.photoid_birth_date, mandatory=True),
        "portrait": Element(enc.bstr, mandatory=True),
        "issue_date": Element(enc.full_date, mandatory=True),
        "expiry_date": Element(enc.full_date, mandatory=True),
        "issuing_authority": Element(enc.tstr150, mandatory=True),
        "issuing_country": Element(enc.country_code, mandatory=True),
        "age_over_18": Element(enc.boolean, mandatory=True),
        "age_in_years": Element(enc.uint),
        "age_birth_year": Element(enc.uint),
        "portrait_capture_date": Element(enc.tdate),
        "birthplace": Element(enc.tstr150),
        "name_at_birth": Element(enc.tstr150),
        "resident_address": Element(enc.tstr150),
        "resident_city": Element(enc.tstr150),
        "resident_postal_code": Element(enc.tstr150),
        "resident_country": Element(enc.alpha2),
        "resident_city_latin1": Element(enc.latin1),
        "sex": Element(enc.iso5218_sex),
        "nationality": Element(enc.country_code),
        "document_number": Element(enc.tstr150),
        "issuing_subdivision": Element(enc.subdivision),
        "family_name_latin1": Element(enc.latin1),
        "given_name_latin1": Element(enc.latin1),
    },
    patterns=((re.compile(r"age_over_\d{2}"), Element(enc.boolean)),),
)
