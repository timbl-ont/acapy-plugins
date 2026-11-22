"""Namespace schemas: the data elements of one mdoc namespace and how to encode them."""

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from .encoders import Encoder, EncodingError


class DocumentEncodingError(ValueError):
    """A credential subject that cannot be encoded as mdoc namespaces.

    The message names the namespace and element, never the value.
    """


@dataclass(frozen=True)
class Element:
    """One data element: its encoder and whether the namespace requires it."""

    encode: Encoder
    mandatory: bool = False


@dataclass(frozen=True)
class Namespace:
    """The data elements of a namespace, by element identifier.

    ``patterns`` cover families of identifiers such as ``age_over_NN``; an
    identifier matches ``elements`` first, then the first matching pattern.
    ``check`` runs on the input after every element has been encoded, for
    rules that involve more than one element. It raises ``EncodingError``.
    ``defaults`` supplies values for elements the input leaves out.
    """

    id: str
    elements: Mapping[str, Element]
    patterns: tuple[tuple[re.Pattern, Element], ...] = field(default_factory=tuple)
    check: Optional[Callable[[Mapping[str, Any]], None]] = None
    defaults: Mapping[str, Any] = field(default_factory=dict)

    def element(self, identifier: str) -> Optional[Element]:
        """The element definition for ``identifier``, or None if unknown."""
        if identifier in self.elements:
            return self.elements[identifier]
        for pattern, element in self.patterns:
            if pattern.fullmatch(identifier):
                return element
        return None

    def encode(self, values: Mapping[str, Any]) -> dict[str, Any]:
        """Encode every element of ``values``; return CBOR-ready values by identifier.

        Raises ``DocumentEncodingError`` for an unknown element, a missing
        mandatory element, or a value its encoder refuses.
        """
        values = {**self.defaults, **values}
        encoded: dict[str, Any] = {}
        for identifier, value in values.items():
            element = self.element(identifier)
            if element is None:
                raise DocumentEncodingError(
                    f"unknown element '{identifier}' in namespace '{self.id}'"
                )
            try:
                encoded[identifier] = element.encode(value)
            except EncodingError as err:
                raise DocumentEncodingError(
                    f"element '{identifier}' in namespace '{self.id}': {err}"
                ) from None

        missing = [
            identifier
            for identifier, element in self.elements.items()
            if element.mandatory and identifier not in values
        ]
        if missing:
            raise DocumentEncodingError(
                f"namespace '{self.id}' is missing mandatory element(s): "
                + ", ".join(missing)
            )

        if self.check:
            try:
                self.check(values)
            except EncodingError as err:
                raise DocumentEncodingError(f"namespace '{self.id}': {err}") from None
        return encoded
