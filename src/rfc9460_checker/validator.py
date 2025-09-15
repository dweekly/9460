"""Validators for domain names and DNS responses."""

import ipaddress
from typing import Any, Dict, List, Optional

from ..utils.tld_validator import validate_domain_tld


def validate_domain(domain: str, check_tld: bool = True) -> bool:
    """Validate a domain name.

    Args:
        domain: The domain name to validate.
        check_tld: Whether to validate TLD against IANA list.

    Returns:
        True if valid, False otherwise.
    """
    if not domain or len(domain) > 253:
        return False

    # Remove trailing dot if present
    if domain.endswith("."):
        domain = domain[:-1]

    # Check each label
    labels = domain.split(".")
    if not labels:
        return False

    # For real domain validation, need at least domain.tld
    # But allow single labels if not checking TLD (for testing/internal use)
    if check_tld and len(labels) < 2:
        return False

    for label in labels:
        if not validate_label(label):
            return False

    # Optionally validate against IANA TLD list
    if check_tld and not validate_domain_tld(domain):
        return False

    return True


def validate_label(label: str) -> bool:
    """Validate a single domain label.

    Args:
        label: The domain label to validate.

    Returns:
        True if valid, False otherwise.
    """
    if not label or len(label) > 63:
        return False

    # Label must start with alphanumeric
    if not label[0].isalnum():
        return False

    # Label must end with alphanumeric
    if not label[-1].isalnum():
        return False

    # Label can contain alphanumeric and hyphens
    for char in label:
        if not (char.isalnum() or char == "-"):
            return False

    return True


def validate_dns_response(response: Dict[str, Any]) -> bool:
    """Validate a DNS response dictionary.

    Args:
        response: The DNS response to validate.

    Returns:
        True if valid, False otherwise.
    """
    required_fields = ["domain", "subdomain", "full_domain", "has_https_record"]

    for field in required_fields:
        if field not in response:
            return False

    # If has_https_record is True, check for additional fields
    if response.get("has_https_record"):
        https_fields = ["https_priority", "https_target"]
        for field in https_fields:
            if field not in response or response[field] is None:
                return False

    return True


def validate_alpn_protocol(protocol: str) -> bool:
    """Validate an ALPN protocol identifier.

    Args:
        protocol: The ALPN protocol identifier.

    Returns:
        True if valid, False otherwise.
    """
    # Common valid ALPN protocols
    valid_protocols = {
        "http/0.9",
        "http/1.0",
        "http/1.1",
        "spdy/1",
        "spdy/2",
        "spdy/3",
        "spdy/3.1",
        "h2",
        "h2c",
        "h3",
        "h3-29",
        "h3-Q050",
        "h3-T051",
        "hq",
        "hq-29",
        "doq",
        "doq-i00",
    }

    return protocol in valid_protocols or protocol.startswith("h3-")


def validate_ipv4_hint(ip_str: str) -> bool:
    """Validate an IPv4 hint address.

    Args:
        ip_str: The IPv4 address string.

    Returns:
        True if valid, False otherwise.
    """
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_ipv6_hint(ip_str: str) -> bool:
    """Validate an IPv6 hint address.

    Args:
        ip_str: The IPv6 address string.

    Returns:
        True if valid, False otherwise.
    """
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_port(port: Optional[int]) -> bool:
    """Validate a port number.

    Args:
        port: The port number.

    Returns:
        True if valid or None, False otherwise.
    """
    if port is None:
        return True
    return isinstance(port, int) and 1 <= port <= 65535


def validate_priority(priority: Optional[int]) -> bool:
    """Validate an HTTPS/SVCB priority value.

    Args:
        priority: The priority value.

    Returns:
        True if valid, False otherwise.
    """
    if priority is None:
        return False
    return isinstance(priority, int) and 0 <= priority <= 65535


def validate_scan_result(result: Dict[str, Any]) -> List[str]:
    """Validate a complete scan result and return list of issues.

    Args:
        result: The scan result dictionary.

    Returns:
        List of validation issues (empty if valid).
    """
    issues = []

    # Check required fields
    required_fields = [
        "domain",
        "subdomain",
        "full_domain",
        "has_https_record",
    ]

    for field in required_fields:
        if field not in result:
            issues.append(f"Missing required field: {field}")

    # Validate domain fields
    if "domain" in result and not validate_domain(result["domain"]):
        issues.append(f"Invalid domain: {result['domain']}")

    if "full_domain" in result and not validate_domain(result["full_domain"]):
        issues.append(f"Invalid full_domain: {result['full_domain']}")

    # Validate subdomain value
    if "subdomain" in result and result["subdomain"] not in ["root", "www"]:
        issues.append(f"Invalid subdomain value: {result['subdomain']}")

    # If has HTTPS record, validate additional fields
    if result.get("has_https_record"):
        if "https_priority" in result:
            if not validate_priority(result["https_priority"]):
                issues.append(f"Invalid HTTPS priority: {result['https_priority']}")

        if "https_target" in result:
            target = result["https_target"]
            if target and not validate_domain(str(target).rstrip(".")):
                issues.append(f"Invalid HTTPS target: {target}")

        # Validate ALPN protocols
        if "alpn_protocols" in result and result["alpn_protocols"]:
            protocols = result["alpn_protocols"].split(",")
            for protocol in protocols:
                if not validate_alpn_protocol(protocol.strip()):
                    issues.append(f"Invalid ALPN protocol: {protocol}")

        # Validate port
        if "port" in result and not validate_port(result["port"]):
            issues.append(f"Invalid port: {result['port']}")

        # Validate IP hints
        if "ipv4hint" in result and result["ipv4hint"]:
            if not validate_ipv4_hint(result["ipv4hint"]):
                issues.append(f"Invalid IPv4 hint: {result['ipv4hint']}")

        if "ipv6hint" in result and result["ipv6hint"]:
            if not validate_ipv6_hint(result["ipv6hint"]):
                issues.append(f"Invalid IPv6 hint: {result['ipv6hint']}")

    # Validate boolean fields
    boolean_fields = ["has_https_record", "has_http3", "ech_config"]
    for field in boolean_fields:
        if field in result and not isinstance(result[field], bool):
            issues.append(f"Field {field} should be boolean, got {type(result[field]).__name__}")

    return issues


def validate_dataset(data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate an entire dataset and return quality report.

    Args:
        data: List of scan results.

    Returns:
        Dictionary with validation statistics and issues.
    """
    total_records = len(data)
    invalid_records = []
    all_issues = []
    issue_counts: Dict[str, int] = {}

    for i, record in enumerate(data):
        issues = validate_scan_result(record)
        if issues:
            invalid_records.append(i)
            all_issues.extend(issues)
            for issue in issues:
                # Extract issue type
                issue_type = issue.split(":")[0]
                issue_counts[issue_type] = issue_counts.get(issue_type, 0) + 1

    return {
        "total_records": total_records,
        "valid_records": total_records - len(invalid_records),
        "invalid_records": len(invalid_records),
        "validity_rate": (
            (total_records - len(invalid_records)) / total_records * 100 if total_records > 0 else 0
        ),
        "invalid_record_indices": invalid_records[:10],  # First 10 invalid
        "issue_counts": issue_counts,
        "sample_issues": all_issues[:10],  # First 10 issues
    }
