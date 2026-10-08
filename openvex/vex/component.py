"""Product and subcomponent data structures.

The ``Component`` type is the shared abstract structure used to identify a
product or one of its subcomponents. A ``Product`` is a ``Component`` that
additionally carries a list of ``subcomponents``.
"""

from dataclasses import dataclass, field
from typing import Optional

from openvex.vex.constants import HASH_NAMES, IDENTIFIER_TYPES
from openvex.vex.errors import ValidationError


@dataclass
class Component:
    """A software component identified by an IRI, identifiers and hashes."""

    id: Optional[str] = None
    identifiers: dict = field(default_factory=dict)
    hashes: dict = field(default_factory=dict)

    def validate(self):
        """Validate identifier and hash labels against the spec catalogs."""
        for key in self.identifiers:
            if key not in IDENTIFIER_TYPES:
                raise ValidationError(
                    f"unknown identifier type {key!r}; expected one of "
                    f"{sorted(IDENTIFIER_TYPES)}"
                )
        for key in self.hashes:
            if key not in HASH_NAMES:
                raise ValidationError(
                    f"unknown hash algorithm {key!r}; expected one of "
                    f"{sorted(HASH_NAMES)}"
                )

    def to_dict(self):
        """Serialise to a JSON compatible dict, omitting empty fields."""
        data = {}
        if self.id is not None:
            data["@id"] = self.id
        if self.identifiers:
            data["identifiers"] = dict(self.identifiers)
        if self.hashes:
            data["hashes"] = dict(self.hashes)
        return data

    @classmethod
    def from_dict(cls, data):
        """Build a Component from a JSON compatible dict."""
        return cls(
            id=data.get("@id"),
            identifiers=dict(data.get("identifiers", {})),
            hashes=dict(data.get("hashes", {})),
        )


@dataclass
class Product(Component):
    """A product: a Component that may contain subcomponents."""

    subcomponents: list = field(default_factory=list)

    def validate(self):
        """Validate the product and all of its subcomponents."""
        super().validate()
        for subcomponent in self.subcomponents:
            subcomponent.validate()

    def to_dict(self):
        """Serialise to a JSON compatible dict, omitting empty fields."""
        data = super().to_dict()
        if self.subcomponents:
            data["subcomponents"] = [
                sub.to_dict() for sub in self.subcomponents
            ]
        return data

    @classmethod
    def from_dict(cls, data):
        """Build a Product from a JSON compatible dict."""
        base = Component.from_dict(data)
        subcomponents = [
            Component.from_dict(sub) for sub in data.get("subcomponents", [])
        ]
        return cls(
            id=base.id,
            identifiers=base.identifiers,
            hashes=base.hashes,
            subcomponents=subcomponents,
        )
