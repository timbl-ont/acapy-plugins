"""Encode a credential subject as mdoc namespaces of CBOR-encoded element values.

``encode_document`` turns the credential subject of an exchange into
``{namespace: {element identifier: CBOR bytes}}``, the input of
``PreparedMdoc.new_from_cbor``. The subject is keyed by namespace::

    {
        "org.iso.23220.1": {"family_name": "Smith", ...},
        "org.iso.23220.photoid.1": {"person_id": "1234567890"},
        "ca.on.photoid.1": {"health_number": "1234-567-890"},
    }

Namespaces with a schema (``org.iso.18013.5.1``, ``org.iso.18013.5.1.aamva``,
``org.iso.23220.1``, ``org.iso.23220.photoid.1``) are validated and encoded by
it. Any other namespace is issuer-defined: it must be declared in the credential
configuration's claims, which also give each element's ``value_type``.
"""

import logging
from typing import Any, Mapping, Optional

import cbor2

from . import encoders as enc
from .encoders import EncodingError
from .org_iso_18013_5_1 import NAMESPACE as MDL_NAMESPACE
from .org_iso_18013_5_1_aamva import NAMESPACE as AAMVA_NAMESPACE
from .profiles import (
    MDL,
    MDL_AAMVA,
    MDL_DOCTYPE,
    NAMESPACE_SCHEMAS,
    PHOTO_ID,
    PHOTO_ID_DOCTYPE,
    Profile,
    select_profile,
)
from .schema import DocumentEncodingError

LOGGER = logging.getLogger(__name__)

__all__ = [
    "DocumentEncodingError",
    "MDL",
    "MDL_AAMVA",
    "MDL_DOCTYPE",
    "NAMESPACE_SCHEMAS",
    "PHOTO_ID",
    "PHOTO_ID_DOCTYPE",
    "Profile",
    "VALUE_TYPES",
    "declared_claims",
    "encode_document",
    "normalize_subject",
    "select_profile",
    "validate_claims_config",
]

# Encoders for the ``value_type`` of an issuer-defined element.
VALUE_TYPES = {
    "tstr": enc.tstr(),
    "bstr": enc.bstr,
    "full-date": enc.full_date,
    "tdate": enc.tdate,
    "uint": enc.uint,
    "int": enc.integer,
    "bool": enc.boolean,
    "json": enc.json_value,
}


def declared_claims(
    format_claims: Any, metadata_claims: Any = None
) -> dict[str, dict[str, dict]]:
    """The claims a credential configuration declares: namespace → element → descriptor.

    ``format_claims`` is ``format_data.claims``: keyed by namespace, or a list of
    OID4VCI claim descriptions. ``metadata_claims`` is ``credential_metadata.claims``,
    a list of claim descriptions whose ``path`` is ``[namespace, element]``. A
    descriptor that is not an object counts as an empty one.
    """
    declared: dict[str, dict[str, dict]] = {}

    def add(namespace: Any, element: Any, descriptor: Any) -> None:
        if isinstance(namespace, str) and isinstance(element, str):
            entry = descriptor if isinstance(descriptor, dict) else {}
            declared.setdefault(namespace, {}).setdefault(element, {}).update(entry)

    def add_list(claims: list) -> None:
        for claim in claims:
            path = claim.get("path") if isinstance(claim, dict) else None
            if isinstance(path, list) and len(path) == 2:
                add(path[0], path[1], {k: v for k, v in claim.items() if k != "path"})

    if isinstance(metadata_claims, list):
        add_list(metadata_claims)
    if isinstance(format_claims, dict):
        for namespace, elements in format_claims.items():
            if isinstance(elements, dict):
                for element, descriptor in elements.items():
                    add(namespace, element, descriptor)
    elif isinstance(format_claims, list):
        add_list(format_claims)
    return declared


def normalize_subject(doctype: str, subject: Any) -> dict[str, dict]:
    """The credential subject keyed by namespace.

    A flat mDL subject (element identifiers at the top level, as older
    configurations send) is accepted and mapped to ``org.iso.18013.5.1``, with a
    nested ``org.iso.18013.5.1.aamva`` key kept as its own namespace. Any other
    doctype requires a subject keyed by namespace.
    """
    if not isinstance(subject, dict) or not subject:
        raise DocumentEncodingError(
            "credential subject must be a non-empty object keyed by namespace"
        )

    if doctype == MDL_DOCTYPE and MDL_NAMESPACE not in subject:
        wrapped = subject.get(MDL_DOCTYPE)
        flat = wrapped if isinstance(wrapped, dict) else subject
        LOGGER.warning(
            "Flat mDL credential subject is deprecated; key it by namespace (%s)",
            MDL_NAMESPACE,
        )
        namespaces = {
            MDL_NAMESPACE: {
                k: v for k, v in flat.items() if k not in (AAMVA_NAMESPACE, MDL_DOCTYPE)
            }
        }
        aamva = flat.get(AAMVA_NAMESPACE, subject.get(AAMVA_NAMESPACE))
        if aamva is not None:
            namespaces[AAMVA_NAMESPACE] = aamva
        return namespaces

    for namespace, elements in subject.items():
        if not isinstance(elements, dict):
            raise DocumentEncodingError(
                "credential subject must be keyed by namespace; "
                f"'{namespace}' does not hold an object of elements"
            )
    return dict(subject)


def _encode_issuer_namespace(
    namespace: str, values: Mapping[str, Any], declared: Mapping[str, dict]
) -> dict[str, Any]:
    elements = declared.get(namespace)
    if elements is None:
        raise DocumentEncodingError(
            f"namespace '{namespace}' has no schema and is not declared in the "
            "credential configuration's claims"
        )
    encoded = {}
    for element, value in values.items():
        descriptor = elements.get(element)
        if descriptor is None:
            raise DocumentEncodingError(
                f"element '{element}' in namespace '{namespace}' is not declared in "
                "the credential configuration's claims"
            )
        value_type = descriptor.get("value_type", "json")
        encoder = VALUE_TYPES.get(value_type)
        if encoder is None:
            raise DocumentEncodingError(
                f"element '{element}' in namespace '{namespace}' has unknown "
                f"value_type '{value_type}'"
            )
        try:
            encoded[element] = encoder(value)
        except EncodingError as err:
            raise DocumentEncodingError(
                f"element '{element}' in namespace '{namespace}': {err}"
            ) from None
    return encoded


def encode_document(
    doctype: str,
    subject: Any,
    declared: Optional[Mapping[str, dict]] = None,
) -> dict[str, dict[str, bytes]]:
    """Encode ``subject`` as ``{namespace: {element: CBOR bytes}}`` for ``doctype``.

    ``declared`` is the result of ``declared_claims`` for the credential
    configuration. Raises ``DocumentEncodingError``, whose message names the
    namespace and element but never the value.
    """
    declared = declared or {}
    profile = select_profile(doctype, declared)
    namespaces = normalize_subject(doctype, subject)

    encoded: dict[str, dict[str, bytes]] = {}
    for namespace, values in namespaces.items():
        if not values:
            raise DocumentEncodingError(f"namespace '{namespace}' has no elements")
        schema = NAMESPACE_SCHEMAS.get(namespace)
        if schema is not None:
            items = schema.encode(values)
        else:
            items = _encode_issuer_namespace(namespace, values, declared)
        encoded[namespace] = {element: cbor2.dumps(v) for element, v in items.items()}

    if profile is not None:
        missing = [ns for ns in profile.required if ns not in encoded]
        if missing:
            raise DocumentEncodingError(
                f"{profile.name} credential subject is missing namespace(s): "
                + ", ".join(missing)
            )

    for namespace, elements in declared.items():
        for element, descriptor in elements.items():
            if descriptor.get("mandatory") is True and element not in encoded.get(
                namespace, {}
            ):
                raise DocumentEncodingError(
                    f"element '{element}' in namespace '{namespace}' is mandatory in "
                    "the credential configuration but missing from the subject"
                )
    return encoded


def validate_claims_config(format_claims: Any) -> None:
    """Check ``format_data.claims`` of a credential configuration.

    Every ``value_type`` must be a known name and may only appear in an
    issuer-defined namespace, and a namespace with a schema may only declare
    elements the schema knows. Raises ``DocumentEncodingError``.
    """
    for namespace, elements in declared_claims(format_claims).items():
        schema = NAMESPACE_SCHEMAS.get(namespace)
        for element, descriptor in elements.items():
            value_type = descriptor.get("value_type")
            if schema is not None:
                if schema.element(element) is None:
                    raise DocumentEncodingError(
                        f"claims declare unknown element '{element}' in namespace "
                        f"'{namespace}'"
                    )
                if value_type is not None:
                    raise DocumentEncodingError(
                        f"value_type for '{element}' in namespace '{namespace}': "
                        "value_type applies only to issuer-defined namespaces"
                    )
            elif value_type is not None and value_type not in VALUE_TYPES:
                raise DocumentEncodingError(
                    f"unknown value_type '{value_type}' for '{element}' in namespace "
                    f"'{namespace}'; expected one of {', '.join(VALUE_TYPES)}"
                )
