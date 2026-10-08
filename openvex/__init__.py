"""OpenVEX: a lightweight, embeddable VEX implementation.

This package provides a Python data model for OpenVEX documents, statements,
products and vulnerabilities, with validation against the OpenVEX
specification v0.2.0 and JSON (JSON-LD) serialisation / deserialisation.
"""

from openvex.vex import (  # noqa: F401
    Component,
    Justification,
    OpenVexError,
    Product,
    Statement,
    Status,
    ValidationError,
    Vex,
    VexDocument,
    Vulnerability,
    format_timestamp,
    parse_timestamp,
)

__version__ = "0.1.0"

__all__ = [
    "Component",
    "Product",
    "Vulnerability",
    "Statement",
    "VexDocument",
    "Vex",
    "OpenVexError",
    "ValidationError",
    "Status",
    "Justification",
    "parse_timestamp",
    "format_timestamp",
    "__version__",
]
