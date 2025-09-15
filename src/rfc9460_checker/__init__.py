"""RFC 9460 DNS record checking functionality."""

from .dns_client import RFC9460Checker
from .parser import parse_https_record, parse_svcb_record
from .validator import (
    validate_dataset,
    validate_dns_response,
    validate_domain,
    validate_scan_result,
)

__all__ = [
    "RFC9460Checker",
    "parse_https_record",
    "parse_svcb_record",
    "validate_domain",
    "validate_dns_response",
    "validate_scan_result",
    "validate_dataset",
]
