"""VEX statement data structure.

A statement is an assertion by the document author about the impact a
vulnerability has on one or more products. It carries a status, the
vulnerability, the affected products, and a set of optional enrichment
fields (justification, impact statement, action statement, ...).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from openvex.vex.component import Product
from openvex.vex.constants import (
    JUSTIFICATIONS,
    STATUS_LABELS,
    Status,
)
from openvex.vex.errors import ValidationError
from openvex.vex.utils import format_timestamp, parse_timestamp
from openvex.vex.vulnerability import Vulnerability


@dataclass
class Statement:
    """A single VEX statement."""

    vulnerability: Vulnerability
    status: str
    products: list = field(default_factory=list)
    id: Optional[str] = None
    version: Optional[int] = None
    timestamp: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    supplier: Optional[str] = None
    status_notes: Optional[str] = None
    justification: Optional[str] = None
    impact_statement: Optional[str] = None
    action_statement: Optional[str] = None
    action_statement_timestamp: Optional[datetime] = None

    def validate(self):
        """Validate the statement against the OpenVEX spec."""
        if self.status not in STATUS_LABELS:
            raise ValidationError(
                f"invalid status {self.status!r}; expected one of "
                f"{sorted(STATUS_LABELS)}"
            )
        self.vulnerability.validate()
        for product in self.products:
            product.validate()
        if self.status == Status.NOT_AFFECTED:
            if not self.justification and not self.impact_statement:
                raise ValidationError(
                    "a 'not_affected' statement MUST include a "
                    "justification or an impact_statement"
                )
            if self.justification and self.justification not in JUSTIFICATIONS:
                raise ValidationError(
                    f"invalid justification {self.justification!r}; "
                    f"expected one of {sorted(JUSTIFICATIONS)}"
                )

    def to_dict(self):
        """Serialise to a JSON compatible dict, omitting empty fields."""
        data = {
            "vulnerability": self.vulnerability.to_dict(),
            "status": self.status,
        }
        if self.id is not None:
            data["@id"] = self.id
        if self.version is not None:
            data["version"] = self.version
        if self.timestamp is not None:
            data["timestamp"] = format_timestamp(self.timestamp)
        if self.last_updated is not None:
            data["last_updated"] = format_timestamp(self.last_updated)
        if self.products:
            data["products"] = [product.to_dict() for product in self.products]
        if self.supplier is not None:
            data["supplier"] = self.supplier
        if self.status_notes is not None:
            data["status_notes"] = self.status_notes
        if self.justification is not None:
            data["justification"] = self.justification
        if self.impact_statement is not None:
            data["impact_statement"] = self.impact_statement
        if self.action_statement is not None:
            data["action_statement"] = self.action_statement
        if self.action_statement_timestamp is not None:
            data["action_statement_timestamp"] = format_timestamp(
                self.action_statement_timestamp
            )
        return data

    @classmethod
    def from_dict(cls, data):
        """Build a Statement from a JSON compatible dict."""
        vulnerability = Vulnerability.from_dict(data.get("vulnerability", {}))
        return cls(
            vulnerability=vulnerability,
            status=data.get("status", ""),
            products=[Product.from_dict(p) for p in data.get("products", [])],
            id=data.get("@id"),
            version=data.get("version"),
            timestamp=parse_timestamp(data.get("timestamp")),
            last_updated=parse_timestamp(data.get("last_updated")),
            supplier=data.get("supplier"),
            status_notes=data.get("status_notes"),
            justification=data.get("justification"),
            impact_statement=data.get("impact_statement"),
            action_statement=data.get("action_statement"),
            action_statement_timestamp=parse_timestamp(
                data.get("action_statement_timestamp")
            ),
        )
