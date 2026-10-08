"""Helpers for handling OpenVEX timestamps.

OpenVEX timestamps follow RFC 3339 / ISO 8601 and SHOULD carry a UTC
offset. This module normalises the common representations (including the
trailing ``Z`` designator) into timezone aware :class:`datetime` objects.
"""

from datetime import datetime, timezone

from openvex.vex.errors import ValidationError


def parse_timestamp(value):
    """Parse an ISO 8601 / RFC 3339 timestamp into a datetime.

    ``None`` is passed through as ``None``. A trailing ``Z`` (Zulu / UTC)
    is normalised to a ``+00:00`` offset. Naive datetimes are assumed to be
    UTC so that the returned value is always timezone aware.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return _ensure_aware(value)
    if not isinstance(value, str):
        raise ValidationError(
            "timestamp must be an ISO 8601 string or datetime, got "
            f"{type(value).__name__}"
        )
    text = value.strip()
    if not text:
        raise ValidationError("timestamp must not be empty")
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError(f"invalid timestamp {value!r}: {exc}") from exc
    return _ensure_aware(parsed)


def format_timestamp(value):
    """Format a datetime (or None) as an ISO 8601 string."""
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise ValidationError(
            "cannot format a non-datetime timestamp: "
            f"{type(value).__name__}"
        )
    return _ensure_aware(value).isoformat()


def _ensure_aware(value):
    """Return a timezone aware datetime, assuming UTC when naive."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
