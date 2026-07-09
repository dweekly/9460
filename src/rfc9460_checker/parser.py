"""JSON-safe parsing for complete HTTPS and SVCB RRsets."""

import base64
import ipaddress
import logging
from collections.abc import Iterable, Mapping
from typing import Any

from .models import (
    CLIENT_SUPPORTED_PARAM_KEYS,
    DECODED_PARAM_KEYS,
    PARAM_KEY_NAMES,
    PARSER_LIMITATIONS,
    SCHEMA_VERSION,
    SVCPARAM_REGISTRY,
    SVCPARAM_REGISTRY_METADATA,
    VALIDATOR_RULESET_VERSION,
    param_key_name,
)
from .validator import validate_svcb_rrset

logger = logging.getLogger(__name__)


def parse_https_record(answers: Any, owner_name: str | None = None) -> dict[str, Any]:
    """Parse every HTTPS record and expose legacy summary fields as a view."""
    return _parse_rrset(answers, "HTTPS", owner_name=owner_name)


def parse_svcb_record(answers: Any, owner_name: str | None = None) -> dict[str, Any]:
    """Parse every SVCB record and expose legacy summary fields as a view."""
    return _parse_rrset(answers, "SVCB", owner_name=owner_name)


def parse_svcb_records(
    answers: Any,
    record_type: str = "HTTPS",
    owner_name: str | None = None,
) -> list[dict[str, Any]]:
    """Return the complete decoded RDATA list for an SVCB-compatible RRset."""
    if answers is None:
        return []
    try:
        rdatas = list(answers)
    except TypeError:
        return []

    records: list[dict[str, Any]] = []
    for rdata in rdatas:
        records.append(_parse_rdata(rdata))

    # DNS RRsets are unordered.  A stable representation makes snapshots and
    # change detection deterministic without implying selection among equal
    # priorities.
    records.sort(
        key=lambda record: (
            record.get("priority", 65536),
            str(record.get("target", "")),
            str(record.get("raw", "")),
        )
    )
    validate_svcb_rrset(records, record_type=record_type, owner_name=owner_name)
    return records


def _parse_rrset(
    answers: Any,
    record_type: str,
    *,
    owner_name: str | None = None,
) -> dict[str, Any]:
    metadata = _answer_metadata(answers)
    query_name = owner_name or metadata["query_name"]
    rrset_owner_name = metadata["rrset_owner_name"] or query_name
    records = parse_svcb_records(answers, record_type, rrset_owner_name)
    if not records:
        return {}

    validation = validate_svcb_rrset(
        records,
        record_type=record_type,
        owner_name=rrset_owner_name,
    )
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "probe_type": "dns",
        "record_type": record_type,
        "query_name": query_name,
        "rrset_owner_name": rrset_owner_name,
        # Compatibility alias: the owner of the returned RRset, not the QNAME.
        "owner_name": rrset_owner_name,
        "record_count": len(records),
        "records": records,
        "ttl": metadata["ttl"],
        "resolver": metadata["resolver"],
        "resolver_port": metadata["resolver_port"],
        "canonical_name": metadata["canonical_name"],
        "svcparam_registry": dict(SVCPARAM_REGISTRY_METADATA),
        "validator_ruleset_version": VALIDATOR_RULESET_VERSION,
        "parser_limitations": list(PARSER_LIMITATIONS),
        "validation_status": validation["status"],
        "validation_issues": validation["issues"],
        "rrset_validation": validation,
    }
    result.update(_legacy_projection(records, record_type))
    return result


def _parse_rdata(rdata: Any) -> dict[str, Any]:
    priority = getattr(rdata, "priority", None)
    target_value = getattr(rdata, "target", None)
    target = str(target_value) if target_value is not None else ""
    record: dict[str, Any] = {
        "priority": priority,
        "target": target,
        "mode": "alias" if priority == 0 else "service",
        "params": {},
        "param_details": [],
        "raw": _rdata_text(rdata),
    }

    params = getattr(rdata, "params", None)
    if not isinstance(params, Mapping):
        return record

    sortable: list[tuple[int, Any, Any]] = []
    for original_key, value in params.items():
        try:
            numeric_key = int(original_key)
        except TypeError, ValueError:
            numeric_key = -1
        sortable.append((numeric_key, original_key, value))

    for numeric_key, original_key, value in sorted(sortable, key=lambda item: item[0]):
        name = param_key_name(numeric_key) if numeric_key >= 0 else str(original_key)
        detail: dict[str, Any] = {
            "key": numeric_key,
            "name": name,
            "known": numeric_key in PARAM_KEY_NAMES,
            "registered": numeric_key in PARAM_KEY_NAMES,
            "decoded": numeric_key in DECODED_PARAM_KEYS,
            "client_supported": numeric_key in CLIENT_SUPPORTED_PARAM_KEYS,
            "registry_reference": SVCPARAM_REGISTRY.get(numeric_key, {}).get("reference"),
            "raw": _raw_param_value(value),
        }
        try:
            decoded = _decode_param(numeric_key, value)
        except (TypeError, ValueError, UnicodeError) as error:
            decoded = _raw_param_value(value)
            detail["parse_error"] = f"Could not decode {name}: {error}"
        detail["value"] = decoded
        record["params"][name] = decoded
        record["param_details"].append(detail)
    return record


def _decode_param(key: int, value: Any) -> Any:
    if key == 0:
        return _parse_mandatory(value)
    if key == 1:
        return _parse_alpn(value)
    if key == 2:
        return _parse_no_default_alpn(value)
    if key == 3:
        return _parse_port(value)
    if key == 4:
        return _parse_ip_hint(value, version=4)
    if key == 5:
        return _parse_binary_param(value, "ech")
    if key == 6:
        return _parse_ip_hint(value, version=6)
    return _parse_binary_param(value, "value")


def _parse_mandatory(param_value: Any) -> list[str]:
    keys = getattr(param_value, "keys", None)
    if not isinstance(keys, (list, tuple)):
        if isinstance(param_value, (list, tuple)):
            keys = param_value
        elif isinstance(param_value, bytes):
            if not param_value or len(param_value) % 2:
                raise ValueError("mandatory wire value must contain one or more 16-bit keys")
            keys = [
                int.from_bytes(param_value[index : index + 2], "big")
                for index in range(0, len(param_value), 2)
            ]
        elif isinstance(param_value, str):
            keys = [item.strip() for item in param_value.split(",") if item.strip()]
        else:
            raise TypeError("unsupported mandatory value")

    result: list[str] = []
    for key in keys:
        if isinstance(key, str) and not key.isdigit():
            result.append(key.lower().replace("_", "-"))
        else:
            result.append(param_key_name(int(key)))
    return result


def _parse_alpn(param_value: Any) -> list[str]:
    """Decode dnspython ALPN values and simple fixture/wire representations."""
    ids = getattr(param_value, "ids", None)
    if isinstance(ids, (list, tuple)):
        return [_decode_alpn_id(value) for value in ids]
    if isinstance(param_value, (list, tuple)):
        return [_decode_alpn_id(value) for value in param_value]
    if isinstance(param_value, bytes):
        wire_values = _parse_length_prefixed_values(param_value)
        if wire_values is not None:
            return [_decode_alpn_id(value) for value in wire_values]
        try:
            text = param_value.decode("ascii")
        except UnicodeDecodeError:
            return []
        return [item for item in text.split(",") if item]
    logger.warning("Unknown ALPN format: %s", type(param_value))
    return []


def _decode_alpn_id(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("ascii")
        except UnicodeDecodeError:
            return "base64:" + base64.b64encode(value).decode("ascii")
    return str(value)


def _parse_length_prefixed_values(value: bytes) -> list[bytes] | None:
    if not value:
        return None
    result: list[bytes] = []
    offset = 0
    while offset < len(value):
        size = value[offset]
        offset += 1
        if size == 0 or offset + size > len(value):
            return None
        result.append(value[offset : offset + size])
        offset += size
    return result if offset == len(value) else None


def _parse_no_default_alpn(param_value: Any) -> bool:
    # dnspython represents this empty-value parameter as None.
    if param_value is None or param_value is True or param_value == b"" or param_value == "":
        return True
    return False


def _parse_port(param_value: Any) -> int | None:
    """Decode a port, returning None for malformed compatibility fixtures."""
    port = getattr(param_value, "port", None)
    if isinstance(port, int) and not isinstance(port, bool):
        return port
    if isinstance(param_value, int) and not isinstance(param_value, bool):
        return param_value
    if isinstance(param_value, bytes) and len(param_value) == 2:
        return int.from_bytes(param_value, "big")
    try:
        return int(str(param_value))
    except ValueError, TypeError:
        logger.warning("Could not parse port: %s", param_value)
        return None


def _parse_ip_hint(param_value: Any, version: int | None = None) -> list[str]:
    """Decode an IPv4 or IPv6 address-hint list."""
    addresses = getattr(param_value, "addresses", None)
    if isinstance(addresses, (list, tuple)):
        return [str(address) for address in addresses]
    if isinstance(param_value, (list, tuple)):
        return [str(address) for address in param_value]
    if isinstance(param_value, bytes):
        family = version or (4 if len(param_value) % 4 == 0 else 6)
        width = 4 if family == 4 else 16
        if not param_value or len(param_value) % width:
            raise ValueError(f"invalid IPv{family} hint wire length")
        return [
            str(ipaddress.ip_address(param_value[index : index + width]))
            for index in range(0, len(param_value), width)
        ]
    if param_value:
        return [str(param_value)]
    return []


def _parse_binary_param(param_value: Any, attribute: str) -> Any:
    value = getattr(param_value, attribute, None)
    if not isinstance(value, bytes):
        value = param_value
    if isinstance(value, bytes):
        return {
            "encoding": "base64",
            "value": base64.b64encode(value).decode("ascii"),
        }
    if value is None:
        return {"encoding": "base64", "value": ""}
    if isinstance(value, (str, int, float, bool, list, dict)):
        return value
    return str(value)


def _raw_param_value(param_value: Any) -> Any:
    if param_value is None:
        return ""
    to_text = getattr(param_value, "to_text", None)
    if callable(to_text):
        try:
            text = to_text()
            if isinstance(text, str):
                return text
        except AttributeError, TypeError, ValueError:
            pass
    for attribute in ("value", "ech"):
        value = getattr(param_value, attribute, None)
        if isinstance(value, bytes):
            return {
                "encoding": "base64",
                "value": base64.b64encode(value).decode("ascii"),
            }
    if isinstance(param_value, bytes):
        return {
            "encoding": "base64",
            "value": base64.b64encode(param_value).decode("ascii"),
        }
    if isinstance(param_value, (str, int, float, bool, list, dict)):
        return param_value
    return str(param_value)


def _rdata_text(rdata: Any) -> str:
    to_text = getattr(rdata, "to_text", None)
    if callable(to_text):
        try:
            value = to_text()
            if isinstance(value, str):
                return value
        except AttributeError, TypeError, ValueError:
            pass
    return str(rdata)


def _answer_metadata(answers: Any) -> dict[str, Any]:
    ttl = _integer_attribute(answers, "ttl")
    rrset = getattr(answers, "rrset", None)
    if ttl is None:
        ttl = _integer_attribute(rrset, "ttl")
    return {
        "ttl": ttl,
        "resolver": _text_attribute(answers, "nameserver"),
        "resolver_port": _integer_attribute(answers, "port"),
        "query_name": _text_attribute(answers, "qname"),
        "rrset_owner_name": _text_attribute(rrset, "name") or _text_attribute(answers, "name"),
        "canonical_name": _text_attribute(answers, "canonical_name"),
    }


def _integer_attribute(value: Any, attribute: str) -> int | None:
    candidate = getattr(value, attribute, None)
    if isinstance(candidate, int) and not isinstance(candidate, bool):
        return candidate
    return None


def _text_attribute(value: Any, attribute: str) -> str | None:
    candidate = getattr(value, attribute, None)
    if candidate is None or candidate.__class__.__module__.startswith("unittest.mock"):
        return None
    text = str(candidate)
    return text if text else None


def _legacy_projection(records: list[dict[str, Any]], record_type: str) -> dict[str, Any]:
    """Derive the v1 scalar fields without discarding the v2 RRset."""
    selected = min(records, key=_priority_sort_value)
    usable_services = [
        record
        for record in records
        if record.get("mode") == "service" and record.get("usable") and not record.get("ignored")
    ]
    protocols = _unique(
        protocol
        for record in usable_services
        for protocol in record.get("params", {}).get("alpn", [])
        if isinstance(protocol, str)
    )
    ipv4_hints = _unique(
        hint
        for record in usable_services
        for hint in record.get("params", {}).get("ipv4hint", [])
        if isinstance(hint, str)
    )
    ipv6_hints = _unique(
        hint
        for record in usable_services
        for hint in record.get("params", {}).get("ipv6hint", [])
        if isinstance(hint, str)
    )
    primary_service = min(
        usable_services,
        key=_priority_sort_value,
        default=None,
    )
    projection: dict[str, Any] = {}
    prefix = "https" if record_type == "HTTPS" else "svcb"
    projection[f"{prefix}_priority"] = selected.get("priority")
    projection[f"{prefix}_target"] = selected.get("target")

    if record_type == "SVCB":
        projection["svcb_params"] = {
            detail["key"]: detail.get("raw")
            for detail in selected.get("param_details", [])
            if isinstance(detail, dict) and isinstance(detail.get("key"), int)
        }

    projection.update(
        {
            "alpn_protocols": ",".join(protocols) if protocols else None,
            "has_http3": "h3" in protocols,
            "port": (
                primary_service.get("params", {}).get("port")
                if primary_service is not None
                else None
            ),
            "ipv4hint": ",".join(ipv4_hints) if ipv4_hints else None,
            "ipv6hint": ",".join(ipv6_hints) if ipv6_hints else None,
            "ech_config": any("ech" in record.get("params", {}) for record in usable_services),
        }
    )
    return projection


def _unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _priority_sort_value(record: dict[str, Any]) -> int:
    priority = record.get("priority")
    return priority if isinstance(priority, int) and not isinstance(priority, bool) else 65536
