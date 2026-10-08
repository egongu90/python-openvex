"""Unit tests for the OpenVEX implementation."""

from datetime import datetime, timedelta, timezone

import pytest

from openvex import (
    Component,
    Justification,
    OpenVexError,
    Product,
    Statement,
    Status,
    ValidationError,
    VexDocument,
    Vulnerability,
    format_timestamp,
    parse_timestamp,
)

UTC = timezone.utc
TS = datetime(2023, 1, 16, 19, 7, 16, tzinfo=UTC)


def make_vulnerability(name="CVE-2021-44228"):
    return Vulnerability(name=name)


def make_product(purl="pkg:maven/example/app@1.0.0"):
    return Product(
        id=purl,
        identifiers={"purl": purl},
        hashes={"sha-256": "a1b2c3d4e5f6"},
    )


def make_statement(status=Status.FIXED, **kwargs):
    if "products" not in kwargs:
        kwargs["products"] = [make_product()]
    return Statement(
        vulnerability=make_vulnerability(),
        status=status,
        **kwargs,
    )


def make_document(**kwargs):
    defaults = {
        "author": "Test Author",
        "id": "https://openvex.dev/docs/example/vex-123",
        "version": 1,
        "timestamp": TS,
        "statements": [make_statement()],
    }
    defaults.update(kwargs)
    return VexDocument(**defaults)


class TestStatusValidation:
    def test_valid_statuses(self):
        for status in (
            Status.AFFECTED,
            Status.FIXED,
            Status.UNDER_INVESTIGATION,
        ):
            make_statement(status=status).validate()
        # not_affected needs a justification or impact statement
        make_statement(
            status=Status.NOT_AFFECTED,
            justification=Justification.COMPONENT_NOT_PRESENT,
        ).validate()

    def test_invalid_status(self):
        with pytest.raises(ValidationError):
            make_statement(status="not_a_real_status").validate()

    def test_not_affected_requires_justification_or_impact(self):
        statement = make_statement(status=Status.NOT_AFFECTED)
        with pytest.raises(ValidationError):
            statement.validate()

    def test_not_affected_with_justification(self):
        statement = make_statement(
            status=Status.NOT_AFFECTED,
            justification=Justification.COMPONENT_NOT_PRESENT,
        )
        statement.validate()

    def test_not_affected_with_impact_statement(self):
        statement = make_statement(
            status=Status.NOT_AFFECTED,
            impact_statement="the vulnerable code is not reachable",
        )
        statement.validate()

    def test_invalid_justification(self):
        statement = make_statement(
            status=Status.NOT_AFFECTED,
            justification="made_up_justification",
        )
        with pytest.raises(ValidationError):
            statement.validate()


class TestVulnerabilityValidation:
    def test_missing_name(self):
        with pytest.raises(ValidationError):
            make_vulnerability(name="").validate()

    def test_valid(self):
        make_vulnerability().validate()


class TestComponentValidation:
    def test_invalid_hash_algorithm(self):
        component = Component(hashes={"sha-999": "deadbeef"})
        with pytest.raises(ValidationError):
            component.validate()

    def test_invalid_identifier_type(self):
        component = Component(identifiers={"swid": "some-value"})
        with pytest.raises(ValidationError):
            component.validate()

    def test_valid_labels(self):
        component = Component(
            identifiers={
                "purl": "pkg:maven/example/app@1.0.0",
                "cpe23": "cpe:2.3:a:x",
            },
            hashes={"sha-256": "abc", "blake2b-512": "def"},
        )
        component.validate()

    def test_subcomponent_validation(self):
        bad_sub = Component(hashes={"nope": "x"})
        product = Product(subcomponents=[bad_sub])
        with pytest.raises(ValidationError):
            product.validate()


class TestDocumentValidation:
    def test_missing_author(self):
        with pytest.raises(ValidationError):
            make_document(author="").validate()

    def test_missing_id(self):
        with pytest.raises(ValidationError):
            make_document(id="").validate()

    def test_missing_timestamp(self):
        with pytest.raises(ValidationError):
            make_document(timestamp=None).validate()

    def test_negative_version(self):
        with pytest.raises(ValidationError):
            make_document(version=-1).validate()

    def test_valid_document(self):
        make_document().validate()


class TestSerialization:
    def test_to_dict_minimal(self):
        document = make_document()
        data = document.to_dict()
        assert data["@context"] == "https://openvex.dev/ns/v0.2.0"
        assert data["@id"] == "https://openvex.dev/docs/example/vex-123"
        assert data["author"] == "Test Author"
        assert data["version"] == 1
        assert data["statements"][0]["status"] == Status.FIXED

    def test_empty_optional_fields_omitted(self):
        document = make_document()
        data = document.to_dict()
        assert "role" not in data
        assert "last_updated" not in data
        assert "tooling" not in data
        statement = data["statements"][0]
        assert "justification" not in statement
        assert "impact_statement" not in statement
        assert "supplier" not in statement

    def test_optional_fields_present(self):
        document = make_document(
            role="Document Creator",
            last_updated=TS + timedelta(hours=1),
            tooling="openvex-python",
        )
        data = document.to_dict()
        assert data["role"] == "Document Creator"
        assert data["tooling"] == "openvex-python"
        assert data["last_updated"] is not None

    def test_subcomponents_serialised(self):
        product = Product(
            id="pkg:maven/example/app@1.0.0",
            subcomponents=[
                Component(
                    id="pkg:maven/log4j/log4j-core@2.4",
                    identifiers={"purl": "pkg:maven/log4j/log4j-core@2.4"},
                )
            ],
        )
        statement = make_statement(products=[product])
        data = statement.to_dict()
        assert data["products"][0]["subcomponents"][0]["@id"] == (
            "pkg:maven/log4j/log4j-core@2.4"
        )

    def test_to_json_is_valid_json(self):
        import json

        document = make_document()
        raw = document.to_json()
        parsed = json.loads(raw)
        assert parsed["@id"] == document.id


class TestDeserialization:
    def test_round_trip(self):
        document = make_document(
            role="Document Creator",
            tooling="openvex-python",
        )
        document.statements[0].justification = (
            Justification.COMPONENT_NOT_PRESENT
        )
        document.statements[0].status = Status.NOT_AFFECTED
        parsed = VexDocument.from_json(document.to_json())
        assert parsed.to_dict() == document.to_dict()

    def test_from_dict(self):
        raw = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://openvex.dev/docs/example/vex-9",
            "author": "A",
            "timestamp": "2023-01-08T18:02:03-06:00",
            "version": 1,
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2023-12345"},
                    "products": [{"@id": "pkg:apk/wolfi/git@2.39.0-r1"}],
                    "status": "fixed",
                }
            ],
        }
        document = VexDocument.from_dict(raw)
        assert document.statements[0].vulnerability.name == "CVE-2023-12345"
        assert document.statements[0].products[0].id == (
            "pkg:apk/wolfi/git@2.39.0-r1"
        )
        assert document.timestamp.tzinfo is not None

    def test_alias_vex(self):
        assert VexDocument is not None
        from openvex import Vex

        assert Vex is VexDocument


class TestTimestamps:
    def test_parse_zulu(self):
        parsed = parse_timestamp("2023-01-16T19:07:16Z")
        assert parsed == datetime(2023, 1, 16, 19, 7, 16, tzinfo=UTC)

    def test_parse_offset(self):
        parsed = parse_timestamp("2023-01-08T18:02:03-06:00")
        assert parsed.utcoffset() == timedelta(hours=-6)

    def test_parse_naive_assumed_utc(self):
        parsed = parse_timestamp("2023-01-08T18:02:03")
        assert parsed.tzinfo is not None

    def test_parse_none(self):
        assert parse_timestamp(None) is None

    def test_parse_invalid(self):
        with pytest.raises(ValidationError):
            parse_timestamp("not-a-date")

    def test_format_timestamp(self):
        assert format_timestamp(None) is None
        assert format_timestamp(TS) == "2023-01-16T19:07:16+00:00"

    def test_inheritance_flow(self):
        document = make_document()
        document.statements[0].timestamp = None
        document.statements.append(make_statement())
        document.statements[1].timestamp = TS - timedelta(days=1)
        # First statement inherits the document timestamp.
        assert document.effective_timestamp(document.statements[0]) == TS
        # Second statement overrides with its own timestamp.
        assert document.effective_timestamp(document.statements[1]) == (
            TS - timedelta(days=1)
        )


class TestErrorHierarchy:
    def test_validation_error_is_openvex_error(self):
        assert issubclass(ValidationError, OpenVexError)
        assert issubclass(OpenVexError, ValueError)
