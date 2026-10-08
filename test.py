"""Runnable demonstration of the OpenVEX implementation.

Builds the log4j / Spring Boot example from the OpenVEX specification,
validates it, serialises it to JSON, and round-trips it back through the
parser. Run it directly with ``python test.py``.
"""

from datetime import datetime, timedelta, timezone

from openvex import (
    Justification,
    Product,
    Statement,
    Status,
    VexDocument,
    Vulnerability,
)

BASE_TIME = datetime(2023, 1, 16, 19, 7, 16, 853479, tzinfo=timezone.utc)


def build_log4j_document():
    """Build the log4j / Spring Boot example from the spec."""
    vulnerability = Vulnerability(
        name="CVE-2021-44228",
        id="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        description="Remote code injection in Log4j",
        aliases=["GHSA-jfh8-c2jp-5v3q"],
    )

    product = Product(
        id="pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3",
        identifiers={
            "purl": "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3",
        },
        hashes={
            "sha-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # noqa: E501
        },
    )

    statement = Statement(
        vulnerability=vulnerability,
        status=Status.NOT_AFFECTED,
        products=[product],
        justification=Justification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        impact_statement=(
            "Spring Boot users are only affected by this vulnerability if "
            "they have switched the default logging system to Log4J2. The "
            "log4j-to-slf4j and log4j-api jars that we include in "
            "spring-boot-starter-logging cannot be exploited on their own."
        ),
    )

    return VexDocument(
        author="Spring Builds <spring-builds@users.noreply.github.com>",
        id="https://openvex.dev/docs/public/"
        "vex-2e67563e128250cbcb3e98930df948dd053e43271d70dc50cfa22d57e03fe96f",
        role="Project Release Bot",
        timestamp=BASE_TIME,
        version=1,
        statements=[statement],
    )


def build_evolved_document():
    """Demonstrate the inheritance flow across document versions.

    The first statement keeps its own (older) timestamp; the second
    statement omits a timestamp so it inherits the new document timestamp.
    """
    older = BASE_TIME - timedelta(days=1)
    vulnerability = Vulnerability(name="CVE-2023-12345")
    product = Product(
        id="pkg:apk/wolfi/git@2.39.0-r1?arch=armv7",
        identifiers={"purl": "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7"},
    )

    first = Statement(
        vulnerability=vulnerability,
        status=Status.UNDER_INVESTIGATION,
        products=[product],
        timestamp=older,
    )
    second = Statement(
        vulnerability=vulnerability,
        status=Status.FIXED,
        products=[product],
    )

    return VexDocument(
        author="Wolfi J Inkinson",
        role="Document Creator",
        id="https://openvex.dev/docs/example/vex-9fb3463de1b57",
        timestamp=BASE_TIME,
        version=2,
        statements=[first, second],
    )


def main():
    document = build_log4j_document()
    print("=== Log4j / Spring Boot example ===")
    print(document.to_json())

    # Round-trip through the parser.
    parsed = VexDocument.from_json(document.to_json())
    parsed.validate()
    assert parsed.to_dict() == document.to_dict(), "round-trip mismatch"

    evolved = build_evolved_document()
    print("\n=== Evolved document (inheritance flow) ===")
    print(evolved.to_json())
    for statement in evolved.statements:
        effective = evolved.effective_timestamp(statement)
        print(f"  {statement.status:>20} -> {effective.isoformat()}")


if __name__ == "__main__":
    main()
