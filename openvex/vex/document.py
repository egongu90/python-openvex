"""OpenVEX document data structure.

A document groups one or more statements together and carries the document
level metadata (author, identifier, timestamp, version, ...). Documents are
serialised as JSON-LD structures.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from openvex.vex.constants import DEFAULT_CONTEXT_URL, SPEC_VERSION
from openvex.vex.errors import ValidationError
from openvex.vex.statement import Statement
from openvex.vex.utils import format_timestamp, parse_timestamp


@dataclass
class VexDocument:
    """An OpenVEX document grouping one or more VEX statements."""

    author: str
    id: str
    version: int
    statements: list = field(default_factory=list)
    context: str = DEFAULT_CONTEXT_URL
    role: Optional[str] = None
    timestamp: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    tooling: Optional[str] = None

    @property
    def spec_version(self):
        """The OpenVEX specification version this document targets."""
        return SPEC_VERSION

    def validate(self):
        """Validate the document and all of its statements."""
        if not self.author:
            raise ValidationError("document 'author' is required")
        if not self.id:
            raise ValidationError("document '@id' is required")
        if self.timestamp is None:
            raise ValidationError("document 'timestamp' is required")
        if self.version < 0:
            raise ValidationError("document 'version' must be non-negative")
        for statement in self.statements:
            statement.validate()

    def effective_timestamp(self, statement):
        """Resolve a statement's effective timestamp.

        Implements the OpenVEX inheritance flow: a statement timestamp
        overrides the document timestamp. When the statement does not define
        one, the document timestamp cascades down.
        """
        if statement.timestamp is not None:
            return statement.timestamp
        return self.timestamp

    def to_dict(self):
        """Serialise to a JSON compatible dict, omitting empty fields."""
        data = {
            "@context": self.context,
            "@id": self.id,
            "author": self.author,
            "timestamp": format_timestamp(self.timestamp),
            "version": self.version,
            "statements": [
                statement.to_dict() for statement in self.statements
            ],
        }
        if self.role is not None:
            data["role"] = self.role
        if self.last_updated is not None:
            data["last_updated"] = format_timestamp(self.last_updated)
        if self.tooling is not None:
            data["tooling"] = self.tooling
        return data

    def to_json(self, indent=2):
        """Validate and serialise the document to a JSON string."""
        self.validate()
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data):
        """Build a VexDocument from a JSON compatible dict."""
        return cls(
            author=data.get("author", ""),
            id=data.get("@id", ""),
            version=data.get("version", 0),
            statements=[
                Statement.from_dict(statement)
                for statement in data.get("statements", [])
            ],
            context=data.get("@context", DEFAULT_CONTEXT_URL),
            role=data.get("role"),
            timestamp=parse_timestamp(data.get("timestamp")),
            last_updated=parse_timestamp(data.get("last_updated")),
            tooling=data.get("tooling"),
        )

    @classmethod
    def from_json(cls, raw):
        """Build a VexDocument from a JSON string."""
        return cls.from_dict(json.loads(raw))


# Backwards compatible alias for the original class name.
Vex = VexDocument
