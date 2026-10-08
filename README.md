# python-openvex

A lightweight, embeddable [OpenVEX](https://openvex.dev) (VEX) implementation in Python.

OpenVEX is a machine-readable format for expressing the impact that a vulnerability has on a product. This library provides a typed data model for OpenVEX **documents**, **statements**, **products** and **vulnerabilities**, with validation against the [OpenVEX specification v0.2.0](https://openvex.dev/spec/v0.2.0) and JSON (JSON-LD) serialisation / deserialisation.

[![CI](https://github.com/egongu90/python-openvex/actions/workflows/ci.yml/badge.svg)](https://github.com/egongu90/python-openvex/actions/workflows/ci.yml)
[![Release](https://github.com/egongu90/python-openvex/actions/workflows/release.yml/badge.svg)](https://github.com/egongu90/python-openvex/actions/workflows/release.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

## Features

- Typed data model for the full OpenVEX v0.2.0 structure: document → statement → product/component → vulnerability.
- Spec validation: status labels, status justifications, IANA hash names, software identifier types, and the `not_affected` justification / impact-statement rule.
- JSON (JSON-LD) serialisation and deserialisation (`to_json` / `from_json`, `to_dict` / `from_dict`).
- RFC 3339 / ISO 8601 timestamp handling (normalises the trailing `Z` designator; naive datetimes are assumed UTC).
- Statement timestamp inheritance via `effective_timestamp`.
- **Zero runtime dependencies** — the library uses only the Python standard library.

## Installation

Requires **Python 3.10+**.

```bash
pip install openvex
```

Or from source:

```bash
git clone https://github.com/egongu90/python-openvex
cd python-openvex
pip install -e .
```

## Quick start

The example below builds the log4j / Spring Boot document from the specification, validates it, and serialises it to JSON:

```python
from datetime import datetime, timezone

from openvex import (
    Justification,
    Product,
    Statement,
    Status,
    VexDocument,
    Vulnerability,
)

vulnerability = Vulnerability(
    name="CVE-2021-44228",
    id="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    description="Remote code injection in Log4j",
    aliases=["GHSA-jfh8-c2jp-5v3q"],
)

product = Product(
    id="pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3",
    identifiers={"purl": "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3"},
    hashes={"sha-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
)

statement = Statement(
    vulnerability=vulnerability,
    status=Status.NOT_AFFECTED,
    products=[product],
    justification=Justification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    impact_statement=(
        "Spring Boot users are only affected by this vulnerability if they "
        "have switched the default logging system to Log4J2."
    ),
)

document = VexDocument(
    author="Spring Builds <spring-builds@users.noreply.github.com>",
    id=(
        "https://openvex.dev/docs/public/"
        "vex-2e67563e128250cbcb3e98930df948dd053e43271d70dc50cfa22d57e03fe96f"
    ),
    role="Project Release Bot",
    timestamp=datetime(2023, 1, 16, 19, 7, 16, tzinfo=timezone.utc),
    version=1,
    statements=[statement],
)

print(document.to_json())  # validates, then serialises
parsed = VexDocument.from_json(document.to_json())  # round-trip
```

A runnable version of this (plus a document-version inheritance demo) lives in [`test.py`](test.py):

```bash
python test.py
```

## API reference

All public symbols are exported from the top-level `openvex` package.

### `VexDocument` (alias `Vex`)

A document groups one or more statements and carries the document-level metadata.

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `author` | `str` | yes | Document author. |
| `id` | `str` | yes | Document `@id` (IRI). |
| `version` | `int` | yes | Must be non-negative. |
| `statements` | `list[Statement]` | no | Defaults to `[]`. |
| `context` | `str` | no | Defaults to `https://openvex.dev/ns/v0.2.0`. |
| `role` | `str` | no | |
| `timestamp` | `datetime` | yes | |
| `last_updated` | `datetime` | no | |
| `tooling` | `str` | no | |

Methods:

- `validate()` — validates the document and every statement.
- `to_dict()` / `to_json(indent=2)` — serialise (empty fields omitted; `to_json` validates first).
- `from_dict(data)` / `from_json(raw)` — deserialise.
- `effective_timestamp(statement)` — resolves a statement's effective timestamp (a statement timestamp overrides the document timestamp).
- `spec_version` — property, the spec version targeted (`0.2.0`).

### `Statement`

An assertion about the impact a vulnerability has on one or more products.

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `vulnerability` | `Vulnerability` | yes | |
| `status` | `str` | yes | One of `Status`. |
| `products` | `list[Product]` | no | Defaults to `[]`. |
| `id` | `str` | no | Statement `@id`. |
| `version` | `int` | no | |
| `timestamp` | `datetime` | no | Overrides the document timestamp when set. |
| `last_updated` | `datetime` | no | |
| `supplier` | `str` | no | |
| `status_notes` | `str` | no | |
| `justification` | `str` | no | One of `Justification`; required for `not_affected` unless an `impact_statement` is set. |
| `impact_statement` | `str` | no | |
| `action_statement` | `str` | no | |
| `action_statement_timestamp` | `datetime` | no | |

Methods: `validate()`, `to_dict()`, `from_dict(data)`.

### `Product` / `Component`

`Product` is a `Component` that may carry `subcomponents`.

| Field | Type | Notes |
| --- | --- | --- |
| `id` | `str` | `@id` (IRI). |
| `identifiers` | `dict` | Keys must be in `IDENTIFIER_TYPES` (`purl`, `cpe22`, `cpe23`). |
| `hashes` | `dict` | Keys must be in `HASH_NAMES` (IANA names, e.g. `sha-256`). |
| `subcomponents` | `list[Component]` | `Product` only. |

Methods: `validate()`, `to_dict()`, `from_dict(data)`.

### `Vulnerability`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `name` | `str` | yes | Main identifier (e.g. a CVE). |
| `id` | `str` | no | `@id` (IRI). |
| `description` | `str` | no | |
| `aliases` | `list[str]` | no | |

Methods: `validate()`, `to_dict()`, `from_dict(data)`.

### Label constants

- `Status` — `NOT_AFFECTED`, `AFFECTED`, `FIXED`, `UNDER_INVESTIGATION`.
- `Justification` — `COMPONENT_NOT_PRESENT`, `VULNERABLE_CODE_NOT_PRESENT`, `VULNERABLE_CODE_NOT_IN_EXECUTE_PATH`, `VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY`, `INLINE_MITIGATIONS_ALREADY_EXIST`.
- `STATUS_LABELS`, `JUSTIFICATIONS`, `HASH_NAMES`, `IDENTIFIER_TYPES` — frozensets of the valid values.
- `SPEC_VERSION`, `DEFAULT_CONTEXT_URL`, `PUBLIC_NAMESPACE`.

### Errors

- `OpenVexError` — base class (a `ValueError`).
- `ValidationError` — raised when a structure fails spec validation.

### Timestamp helpers

- `parse_timestamp(value)` — parses an ISO 8601 / RFC 3339 string (or `datetime`) into a timezone-aware `datetime`; a trailing `Z` is normalised to `+00:00` and naive values are assumed UTC.
- `format_timestamp(value)` — formats a `datetime` as an ISO 8601 string.

## Validation rules

- A document requires `author`, `id` and `timestamp`, and a non-negative `version`.
- A statement `status` must be one of the `Status` labels.
- A `not_affected` statement **must** include a `justification` or an `impact_statement`; a `justification`, if present, must be one of the `Justification` labels.
- Component `identifiers` keys must be in `IDENTIFIER_TYPES` and `hashes` keys must be in `HASH_NAMES`.
- A `vulnerability` requires a `name`.

## Development

```bash
# set up
python -m venv .venv && source .venv/bin/activate
pip install -r test-requirements.txt   # dev/test tooling (not needed at runtime)
pip install -e .

# tests
python -m pytest

# lint + static security
python -m flake8 openvex test.py tests
python -m bandit -c bandit.yaml -r .
```

Pre-commit hooks (flake8, isort, black, bandit) are configured in [`.pre-commit-config.yaml`](.pre-commit-config.yaml):

```bash
pip install pre-commit
pre-commit install
```

## Security

- **No runtime dependencies** — the library imports only the standard library, minimising its supply-chain surface.
- **CI** ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the test suite (Python 3.10–3.13), flake8, bandit, and a **gitleaks** secret scan on every push / pull request.
- **Release** ([`.github/workflows/release.yml`](.github/workflows/release.yml)) builds the package only on version tags, with SHA-pinned actions, an isolated PEP 517 build, least-privilege permissions, and a **SLSA L2 provenance attestation**.

## License

[Apache License 2.0](LICENSE).
