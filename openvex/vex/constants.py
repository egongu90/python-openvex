"""Constants and label catalogs for the OpenVEX specification.

These values are derived from the OpenVEX specification v0.2.0 and the
VEX Working Group documents (status labels, status justifications, the
IANA hash function textual names, and the software identifier types).
"""

SPEC_VERSION = "0.2.0"

CONTEXT_URL_TEMPLATE = "https://openvex.dev/ns/v{version}"
DEFAULT_CONTEXT_URL = "https://openvex.dev/ns/v0.2.0"

PUBLIC_NAMESPACE = "https://openvex.dev/docs"
RESERVED_NAMESPACES = ("public", "example")


class Status:
    """VEX status labels."""

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


STATUS_LABELS = frozenset(
    {
        Status.NOT_AFFECTED,
        Status.AFFECTED,
        Status.FIXED,
        Status.UNDER_INVESTIGATION,
    }
)


class Justification:
    """Machine readable status justification labels."""

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


JUSTIFICATIONS = frozenset(
    {
        Justification.COMPONENT_NOT_PRESENT,
        Justification.VULNERABLE_CODE_NOT_PRESENT,
        Justification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        Justification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
        Justification.INLINE_MITIGATIONS_ALREADY_EXIST,
    }
)


HASH_NAMES = frozenset(
    {
        "md5",
        "sha1",
        "sha-256",
        "sha-384",
        "sha-512",
        "sha3-224",
        "sha3-256",
        "sha3-384",
        "sha3-512",
        "blake2s-256",
        "blake2b-256",
        "blake2b-512",
    }
)


IDENTIFIER_TYPES = frozenset({"purl", "cpe22", "cpe23"})
