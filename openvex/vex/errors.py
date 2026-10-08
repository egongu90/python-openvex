"""Exception types for the OpenVEX implementation."""


class OpenVexError(ValueError):
    """Base class for all OpenVEX errors."""


class ValidationError(OpenVexError):
    """Raised when an OpenVEX structure fails spec validation."""
