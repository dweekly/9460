"""Validation for domain names and RFC 9460 HTTPS/SVCB records."""

import ipaddress
from collections.abc import Iterable
from typing import Any, cast

import dns.name

from ..utils.tld_validator import validate_domain_tld
from .models import (
    CLIENT_SUPPORTED_PARAM_KEYS,
    ValidationIssue,
    param_name_key,
)


def validate_domain(domain: str, check_tld: bool = True) -> bool:
    """Validate a hostname, optionally including its public top-level domain."""
    if not domain or len(domain) > 253:
        return False

    if domain.endswith("."):
        domain = domain[:-1]

    labels = domain.split(".")
    if not labels or (check_tld and len(labels) < 2):
        return False
    if check_tld and len(labels[-1]) < 2:
        return False

    if any(not validate_label(label) for label in labels):
        return False

    return not check_tld or validate_domain_tld(domain)


def validate_label(label: str) -> bool:
    """Validate one hostname label."""
    if not label or len(label) > 63:
        return False
    if not label[0].isalnum() or not label[-1].isalnum():
        return False
    return all(char.isalnum() or char == "-" for char in label)


def validate_dns_name(name: str, allow_root: bool = False) -> bool:
    """Validate a DNS name without requiring it to have a public TLD.

    SVCB targets are DNS names rather than necessarily public hostnames, so the
    checker must not apply the top-site input validation rules to them.
    """
    if not isinstance(name, str) or not name:
        return False
    if name == ".":
        return allow_root
    try:
        parsed = dns.name.from_text(name)
    except dns.exception.DNSException, UnicodeError, ValueError:
        return False
    wire = parsed.to_wire()
    return wire is not None and len(wire) <= 255


def _issue(
    code: str,
    severity: str,
    message: str,
    key: int | None = None,
) -> ValidationIssue:
    issue: ValidationIssue = {
        "code": code,
        "severity": severity,  # type: ignore[typeddict-item]
        "message": message,
    }
    if key is not None:
        issue["key"] = key
    return issue


def _keys_from_record(record: dict[str, Any]) -> set[int]:
    keys: set[int] = set()
    details = record.get("param_details", [])
    if isinstance(details, list):
        for detail in details:
            if isinstance(detail, dict) and isinstance(detail.get("key"), int):
                keys.add(detail["key"])

    params = record.get("params", {})
    if isinstance(params, dict):
        for name in params:
            if isinstance(name, str):
                key = param_name_key(name)
                if key is not None:
                    keys.add(key)
    return keys


def _mandatory_keys(value: Any) -> list[int] | None:
    if not isinstance(value, (list, tuple)) or not value:
        return None
    keys: list[int] = []
    for item in value:
        if isinstance(item, int):
            key = item
        elif isinstance(item, str):
            parsed = param_name_key(item)
            if parsed is None:
                return None
            key = parsed
        else:
            return None
        if not 0 <= key <= 65535:
            return None
        keys.append(key)
    return keys


def _has_nonempty_value(value: Any) -> bool:
    if isinstance(value, dict):
        return "value" in value and _has_nonempty_value(value["value"])
    if isinstance(value, (bytes, str, list, tuple)):
        return len(value) > 0
    return value is not None and value is not False


def validate_svcb_record(
    record: dict[str, Any],
    *,
    record_type: str = "HTTPS",
    owner_name: str | None = None,
    supported_param_keys: Iterable[int] | None = None,
) -> dict[str, Any]:
    """Classify one parsed SVCB-compatible record.

    ``valid_but_incompatible`` means the record is well-formed but names a
    mandatory key outside the supplied implementation capability set.  Unknown
    optional keys remain valid and are preserved by the parser.
    """
    issues: list[ValidationIssue] = []
    incompatible = False
    supported = set(
        CLIENT_SUPPORTED_PARAM_KEYS if supported_param_keys is None else supported_param_keys
    )
    incompatible_keys: set[int] = set()
    priority = record.get("priority")
    target = record.get("target")
    params = record.get("params", {})
    param_keys = _keys_from_record(record)

    wire = record.get("wire")
    wire_param_keys: set[int] = set()
    if isinstance(wire, dict):
        wire_issues = wire.get("issues", [])
        if isinstance(wire_issues, list):
            issues.extend(
                cast(
                    ValidationIssue,
                    issue,
                )
                for issue in wire_issues
                if isinstance(issue, dict)
                and isinstance(issue.get("code"), str)
                and issue.get("severity") in {"error", "warning", "incompatible"}
            )
        wire_params = wire.get("params", [])
        if isinstance(wire_params, list):
            wire_param_keys.update(
                param["key"]
                for param in wire_params
                if isinstance(param, dict) and isinstance(param.get("key"), int)
            )

    if not validate_priority(priority):
        issues.append(_issue("invalid_priority", "error", f"Invalid SvcPriority: {priority}"))
    expected_mode = "alias" if priority == 0 else "service"
    if record.get("mode") not in (None, expected_mode):
        issues.append(
            _issue(
                "mode_priority_mismatch",
                "error",
                f"Mode {record.get('mode')} does not match SvcPriority {priority}",
            )
        )

    if not isinstance(target, str) or not validate_dns_name(target, allow_root=True):
        issues.append(_issue("invalid_target", "error", f"Invalid TargetName: {target}"))

    if expected_mode == "alias":
        if owner_name and isinstance(target, str):
            owner = owner_name.rstrip(".").lower()
            alias_target = target.rstrip(".").lower()
            if target != "." and owner == alias_target:
                issues.append(
                    _issue(
                        "alias_loop",
                        "warning",
                        "AliasMode TargetName points back to its owner; resolution will loop",
                    )
                )
        if param_keys and not any(issue.get("code") == "alias_params_ignored" for issue in issues):
            issues.append(
                _issue(
                    "alias_params_ignored",
                    "warning",
                    "SvcParams on an AliasMode record are ignored",
                )
            )
    elif isinstance(params, dict):
        details = record.get("param_details", [])
        if isinstance(details, list):
            for detail in details:
                if isinstance(detail, dict) and detail.get("parse_error"):
                    issues.append(
                        _issue(
                            "malformed_param",
                            "error",
                            str(detail["parse_error"]),
                            detail.get("key") if isinstance(detail.get("key"), int) else None,
                        )
                    )
        mandatory = params.get("mandatory")
        if "mandatory" in params:
            mandatory_keys = _mandatory_keys(mandatory)
            if mandatory_keys is None:
                issues.append(
                    _issue(
                        "invalid_mandatory",
                        "error",
                        "mandatory must contain one or more valid, unique SvcParamKeys",
                        0,
                    )
                )
            else:
                if len(mandatory_keys) != len(set(mandatory_keys)):
                    issues.append(
                        _issue(
                            "duplicate_mandatory_key",
                            "error",
                            "mandatory contains the same SvcParamKey more than once",
                            0,
                        )
                    )
                if 0 in mandatory_keys:
                    issues.append(
                        _issue(
                            "mandatory_lists_itself",
                            "error",
                            "mandatory must not include itself",
                            0,
                        )
                    )
                for key in mandatory_keys:
                    if key not in param_keys:
                        issues.append(
                            _issue(
                                "missing_mandatory_param",
                                "error",
                                f"mandatory key {key} is not present in this record",
                                key,
                            )
                        )
                    elif key not in supported:
                        incompatible = True
                        incompatible_keys.add(key)
                        issues.append(
                            _issue(
                                "unsupported_mandatory_param",
                                "incompatible",
                                f"mandatory key {key} is not supported by this checker",
                                key,
                            )
                        )

        if record_type.upper() == "HTTPS":
            for key in sorted({2, 3}.intersection(param_keys)):
                if key not in supported and key not in incompatible_keys:
                    incompatible = True
                    incompatible_keys.add(key)
                    issues.append(
                        _issue(
                            "unsupported_automatically_mandatory_param",
                            "incompatible",
                            f"HTTPS key {key} is automatically mandatory but unsupported",
                            key,
                        )
                    )

        if "alpn" in params:
            alpns = params["alpn"]
            if not isinstance(alpns, list) or not alpns:
                issues.append(
                    _issue("invalid_alpn", "error", "alpn must contain at least one ALPN ID", 1)
                )
            else:
                for alpn in alpns:
                    if 1 in wire_param_keys:
                        # The independent decoder validates the original
                        # length-prefixed opaque bytes; the display string may
                        # be a longer base64 representation.
                        continue
                    if not validate_alpn_id(alpn):
                        issues.append(
                            _issue(
                                "invalid_alpn",
                                "error",
                                f"Invalid ALPN protocol identifier: {alpn}",
                                1,
                            )
                        )

        if "no-default-alpn" in params:
            if params["no-default-alpn"] is not True:
                issues.append(
                    _issue(
                        "invalid_no_default_alpn",
                        "error",
                        "no-default-alpn must have an empty value",
                        2,
                    )
                )
            if "alpn" not in params:
                issues.append(
                    _issue(
                        "no_default_alpn_without_alpn",
                        "error",
                        "no-default-alpn requires alpn in the same record",
                        2,
                    )
                )

        if "port" in params and (params["port"] is None or not validate_port(params["port"])):
            issues.append(_issue("invalid_port", "error", f"Invalid port: {params['port']}", 3))

        if "ech" in params and not _has_nonempty_value(params["ech"]):
            issues.append(_issue("empty_ech", "error", "ech must not be empty", 5))

        for name, validator, key in (
            ("ipv4hint", validate_ipv4_hint, 4),
            ("ipv6hint", validate_ipv6_hint, 6),
        ):
            if name not in params:
                continue
            hints = params[name]
            if not isinstance(hints, list) or not hints:
                issues.append(_issue(f"invalid_{name}", "error", f"{name} must not be empty", key))
            elif any(not isinstance(hint, str) or not validator(hint) for hint in hints):
                issues.append(
                    _issue(
                        f"invalid_{name}",
                        "error",
                        f"{name} contains an address of the wrong family",
                        key,
                    )
                )

    has_error = any(issue["severity"] == "error" for issue in issues)
    if has_error:
        status = "invalid"
    elif incompatible:
        status = "valid_but_incompatible"
    else:
        status = "valid"

    return {
        "status": status,
        "issues": issues,
        "compatible": status == "valid",
        "usable": status == "valid",
        "record_type": record_type.upper(),
    }


def validate_svcb_rrset(
    records: list[dict[str, Any]],
    *,
    record_type: str = "HTTPS",
    owner_name: str | None = None,
    supported_param_keys: Iterable[int] | None = None,
) -> dict[str, Any]:
    """Validate a complete RRset and annotate its records in place."""
    rrset_issues: list[ValidationIssue] = []
    aliases: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []

    for record in records:
        result = validate_svcb_record(
            record,
            record_type=record_type,
            owner_name=owner_name,
            supported_param_keys=supported_param_keys,
        )
        record["validity"] = result["status"]
        record["validation_issues"] = result["issues"]
        record["compatible"] = result["compatible"]
        record["usable"] = result["usable"]
        record["ignored"] = False
        if record.get("mode") == "alias":
            aliases.append(record)
        else:
            services.append(record)

    if aliases and services:
        rrset_issues.append(
            _issue(
                "mixed_modes",
                "warning",
                "RRset contains AliasMode and ServiceMode; ServiceMode records are ignored",
            )
        )
        for record in services:
            record["ignored"] = True
            record["usable"] = False

    if len(aliases) > 1:
        rrset_issues.append(
            _issue(
                "multiple_alias_records",
                "warning",
                "RRset contains more than one AliasMode record",
            )
        )

    active_records = aliases if aliases else services
    record_issues = [
        issue
        for record in active_records
        for issue in record.get("validation_issues", [])
        if isinstance(issue, dict)
    ]
    inactive_wire_issues = [
        issue
        for record in records
        if all(record is not active for active in active_records)
        for issue in (
            record.get("wire", {}).get("issues", []) if isinstance(record.get("wire"), dict) else []
        )
        if isinstance(issue, dict) and issue.get("severity") == "error"
    ]
    all_issues = rrset_issues + record_issues + inactive_wire_issues
    wire_malformed = any(
        isinstance(issue, dict) and issue.get("severity") == "error"
        for record in records
        for issue in (
            record.get("wire", {}).get("issues", []) if isinstance(record.get("wire"), dict) else []
        )
    )
    if wire_malformed or any(record.get("validity") == "invalid" for record in active_records):
        status = "invalid"
        for record in records:
            record["usable"] = False
    elif not any(record.get("usable") for record in active_records) and any(
        record.get("validity") == "valid_but_incompatible" for record in active_records
    ):
        status = "valid_but_incompatible"
    else:
        status = "valid"

    return {
        "status": status,
        "issues": all_issues,
        "record_count": len(records),
        "usable_record_count": sum(bool(record.get("usable")) for record in records),
        "alias_mode": bool(aliases),
        "service_mode": bool(services),
    }


def validate_dns_response(response: dict[str, Any]) -> bool:
    """Return whether a checker response has the expected structural fields."""
    required_fields = ["domain", "subdomain", "full_domain", "has_https_record"]
    if any(field not in response for field in required_fields):
        return False

    if response.get("schema_version") == 2:
        v2_fields = ["record_type", "query_status", "records", "validation_status"]
        if any(field not in response for field in v2_fields):
            return False
        if not isinstance(response["records"], list):
            return False

    if response.get("has_https_record"):
        if response.get("records"):
            return True
        return (
            response.get("https_priority") is not None and response.get("https_target") is not None
        )
    return True


def validate_alpn_id(protocol: Any) -> bool:
    """Validate the RFC 9460 wire-size rule for an ALPN identifier."""
    if not isinstance(protocol, str):
        return False
    try:
        size = len(protocol.encode("utf-8"))
    except UnicodeError:
        return False
    return 1 <= size <= 255


def validate_alpn_protocol(protocol: str) -> bool:
    """Validate a commonly deployed ALPN protocol (legacy helper API)."""
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
    """Return whether a hint is an IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError, ValueError:
        return False


def validate_ipv6_hint(ip_str: str) -> bool:
    """Return whether a hint is an IPv6 address."""
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except ipaddress.AddressValueError, ValueError:
        return False


def validate_port(port: int | None) -> bool:
    """Validate the RFC's inclusive 0-65535 SvcParam port range."""
    if port is None:
        return True
    return isinstance(port, int) and not isinstance(port, bool) and 0 <= port <= 65535


def validate_priority(priority: int | None) -> bool:
    """Validate a SvcPriority value."""
    return isinstance(priority, int) and not isinstance(priority, bool) and 0 <= priority <= 65535


def validate_scan_result(result: dict[str, Any]) -> list[str]:
    """Validate one complete observation and return human-readable issues."""
    issues: list[str] = []
    for field in ["domain", "subdomain", "full_domain", "has_https_record"]:
        if field not in result:
            issues.append(f"Missing required field: {field}")

    record_type = str(result.get("record_type", "HTTPS")).upper()
    name_validator = validate_dns_name if record_type == "SVCB" else validate_domain
    if "domain" in result and not name_validator(result["domain"]):
        issues.append(f"Invalid domain: {result['domain']}")
    if "full_domain" in result and not name_validator(result["full_domain"]):
        issues.append(f"Invalid full_domain: {result['full_domain']}")
    if (
        record_type == "HTTPS"
        and "subdomain" in result
        and result["subdomain"] not in ["root", "www"]
    ):
        issues.append(f"Invalid subdomain value: {result['subdomain']}")

    records = result.get("records")
    if isinstance(records, list) and records:
        rrset = validate_svcb_rrset(
            records,
            record_type=record_type,
            owner_name=result.get("owner_name") or result.get("full_domain"),
        )
        for issue in rrset["issues"]:
            if issue["severity"] == "error":
                issues.append(f"RFC 9460 {issue['code']}: {issue['message']}")
    elif result.get("has_https_record"):
        if "https_priority" in result and not validate_priority(result["https_priority"]):
            issues.append(f"Invalid HTTPS priority: {result['https_priority']}")
        if "https_target" in result:
            target = result["https_target"]
            if target and not validate_dns_name(str(target), allow_root=True):
                issues.append(f"Invalid HTTPS target: {target}")
        if result.get("alpn_protocols"):
            for protocol in result["alpn_protocols"].split(","):
                if not validate_alpn_id(protocol.strip()):
                    issues.append(f"Invalid ALPN protocol: {protocol}")
        if "port" in result and not validate_port(result["port"]):
            issues.append(f"Invalid port: {result['port']}")
        for field, validator, label in (
            ("ipv4hint", validate_ipv4_hint, "IPv4"),
            ("ipv6hint", validate_ipv6_hint, "IPv6"),
        ):
            if result.get(field):
                for hint in str(result[field]).split(","):
                    if not validator(hint.strip()):
                        issues.append(f"Invalid {label} hint: {hint}")

    for field in ["has_https_record", "has_svcb_record", "has_http3", "ech_config"]:
        if field in result and not isinstance(result[field], bool):
            issues.append(f"Field {field} should be boolean, got {type(result[field]).__name__}")
    return issues


def validate_dataset(data: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate a dataset and return a compact quality report."""
    total_records = len(data)
    invalid_records: list[int] = []
    all_issues: list[str] = []
    issue_counts: dict[str, int] = {}

    for index, record in enumerate(data):
        issues = validate_scan_result(record)
        if issues:
            invalid_records.append(index)
            all_issues.extend(issues)
            for issue in issues:
                issue_type = issue.split(":")[0]
                issue_counts[issue_type] = issue_counts.get(issue_type, 0) + 1

    valid_records = total_records - len(invalid_records)
    return {
        "total_records": total_records,
        "valid_records": valid_records,
        "invalid_records": len(invalid_records),
        "validity_rate": valid_records / total_records * 100 if total_records else 0,
        "invalid_record_indices": invalid_records[:10],
        "issue_counts": issue_counts,
        "sample_issues": all_issues[:10],
    }
