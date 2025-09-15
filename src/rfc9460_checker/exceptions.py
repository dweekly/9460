"""Custom exceptions for RFC 9460 checker."""


class RFC9460Error(Exception):
    """Base exception for RFC 9460 checker."""

    pass


class DNSQueryError(RFC9460Error):
    """Raised when DNS query fails."""

    pass


class DataValidationError(RFC9460Error):
    """Raised when data validation fails."""

    pass


class ConfigurationError(RFC9460Error):
    """Raised when configuration is invalid."""

    pass
