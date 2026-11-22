"""The ``org.iso.23220.photoid.1`` namespace of the ISO/IEC TS 23220-4 Annex C photo ID.

Mirrors ``OrgIso23220Photoid1`` on timbl-ont/isomdl ``feat/photoid-23220-4``
(``src/definitions/namespaces/org_iso_23220_photoid_1/``), Annex C Table C.2.
Every element is optional. ``travel_document_type`` and ``travel_document_mrz``
are conditional on ``dg1`` in ``org.iso.23220.datagroups.1``, which is not
modelled here.
"""

from . import encoders as enc
from .schema import Element, Namespace

NAMESPACE = "org.iso.23220.photoid.1"

SCHEMA = Namespace(
    id=NAMESPACE,
    elements={
        "person_id": Element(enc.tstr150),
        "birth_country": Element(enc.alpha2),
        "birth_state": Element(enc.tstr150),
        "birth_city": Element(enc.tstr150),
        "administrative_number": Element(enc.tstr150),
        "resident_street": Element(enc.tstr150),
        "resident_house_number": Element(enc.tstr150),
        "travel_document_type": Element(enc.tstr150),
        "travel_document_number": Element(enc.tstr150),
        "resident_state": Element(enc.latin1),
        "travel_document_mrz": Element(enc.tstr150),
        "family_name_viz": Element(enc.tstr150),
        "given_name_viz": Element(enc.tstr150),
        "enrolment_portrait_image": Element(enc.bstr),
    },
)
