"""Issuance profiles: the doctypes this plugin knows and the namespaces each requires."""

from dataclasses import dataclass
from typing import Mapping, Optional

from . import org_iso_18013_5_1, org_iso_18013_5_1_aamva, org_iso_23220_1
from . import org_iso_23220_photoid_1
from .schema import Namespace

MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
PHOTO_ID_DOCTYPE = "org.iso.23220.photoid.1"


@dataclass(frozen=True)
class Profile:
    """A doctype, the namespaces it must carry, and its standard optional ones."""

    name: str
    doctype: str
    required: tuple[str, ...]
    known: tuple[str, ...] = ()


MDL = Profile(
    name="ISO/IEC 18013-5 mDL",
    doctype=MDL_DOCTYPE,
    required=(org_iso_18013_5_1.NAMESPACE,),
    known=(org_iso_18013_5_1_aamva.NAMESPACE,),
)

MDL_AAMVA = Profile(
    name="AAMVA mDL",
    doctype=MDL_DOCTYPE,
    required=(org_iso_18013_5_1.NAMESPACE, org_iso_18013_5_1_aamva.NAMESPACE),
)

PHOTO_ID = Profile(
    name="ISO/IEC TS 23220-4 photo ID",
    doctype=PHOTO_ID_DOCTYPE,
    required=(org_iso_23220_1.NAMESPACE,),
    known=(org_iso_23220_photoid_1.NAMESPACE,),
)

NAMESPACE_SCHEMAS: dict[str, Namespace] = {
    schema.id: schema
    for schema in (
        org_iso_18013_5_1.SCHEMA,
        org_iso_18013_5_1_aamva.SCHEMA,
        org_iso_23220_1.SCHEMA,
        org_iso_23220_photoid_1.SCHEMA,
    )
}


def select_profile(doctype: str, declared: Mapping[str, object]) -> Optional[Profile]:
    """The profile for ``doctype``, or None for a doctype without one.

    An mDL whose credential configuration declares the AAMVA namespace uses the
    AAMVA profile, which requires that namespace.
    """
    if doctype == PHOTO_ID_DOCTYPE:
        return PHOTO_ID
    if doctype == MDL_DOCTYPE:
        if org_iso_18013_5_1_aamva.NAMESPACE in declared:
            return MDL_AAMVA
        return MDL
    return None
