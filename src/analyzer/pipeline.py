"""Canonical snapshot and GitHub Pages data pipeline.

The pipeline upgrades flat scanner rows to a deterministic schema-v2 snapshot,
retains legacy aggregate history without inventing unavailable detail, and
emits the three JSON documents consumed by the public dashboard.
"""

import argparse
import base64
import binascii
import gzip
import hashlib
import json
import math
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any, cast

import pandas as pd

from .metrics import (
    analyze_alpn_protocols,
    calculate_error_statistics,
    calculate_metrics,
    calculate_priority_distribution,
    identify_feature_leaders,
)

SCHEMA_VERSION = 2
MEBIBYTE = 1024 * 1024
DEFAULT_MAX_CANONICAL_SNAPSHOT_BYTES = 8 * MEBIBYTE
DEFAULT_MAX_PAGES_JSON_BYTES = 16 * MEBIBYTE
PAGES_DATA_FILENAMES = ("latest.json", "history.json", "changes.json")
ABSENCE_ERRORS = {"noanswer", "no answer", "no https record", "no svcb record"}
PROVENANCE_KEYS = (
    "package_version",
    "script_version",
    "python_version",
    "dnspython_version",
    "validator_ruleset",
    "wire_decoder",
    "registry_snapshot",
)
ROW_PROVENANCE_ALIASES = {
    "validator_ruleset": ("validator_ruleset_version",),
    "wire_decoder": ("wire_decoder_version",),
    "registry_snapshot": ("svcparam_registry",),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _iso_datetime(value: Any, default: str | None = None) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return default or _utc_now()
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if not text:
            return default or _utc_now()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            # Accept timestamps embedded in the project's historical filenames.
            try:
                parsed = datetime.strptime(text, "%Y-%m-%d_%H-%M-%S")
            except ValueError as error:
                raise ValueError(f"invalid scan timestamp: {value!r}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _json_safe(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, float) and math.isnan(value):
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return f"base64:{base64.b64encode(value).decode('ascii')}"
    if isinstance(value, datetime):
        return _iso_datetime(value)
    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(item)
            for key, item in sorted(value.items(), key=lambda x: str(x[0]))
        }
    if isinstance(value, set):
        return sorted((_json_safe(item) for item in value), key=_canonical_text)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "item"):
        return _json_safe(value.item())
    if hasattr(value, "tolist"):
        return _json_safe(value.tolist())
    return str(value)


def _wire_blob(value: bytes) -> dict[str, Any]:
    return {
        "encoding": "base64",
        "value": base64.b64encode(value).decode("ascii"),
        "length": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
    }


def _normalize_wire_value(value: Any) -> Any:
    """Canonicalize and verify binary evidence without reserializing DNS data."""
    if isinstance(value, bytes):
        return _wire_blob(value)
    if isinstance(value, Mapping):
        if value.get("encoding") == "base64" and isinstance(value.get("value"), str):
            try:
                decoded = base64.b64decode(value["value"], validate=True)
            except (binascii.Error, ValueError) as error:
                raise ValueError("wire evidence contains invalid base64") from error
            if "length" in value and _integer(value.get("length"), -1) != len(decoded):
                raise ValueError("wire evidence length does not match decoded bytes")
            digest = hashlib.sha256(decoded).hexdigest()
            supplied_digest = value.get("sha256")
            if supplied_digest is not None and str(supplied_digest).lower() != digest:
                raise ValueError("wire evidence SHA-256 does not match decoded bytes")
            normalized = {
                str(key): _normalize_wire_value(item)
                for key, item in value.items()
                if key not in {"encoding", "value", "length", "sha256"}
            }
            normalized.update(_wire_blob(decoded))
            return normalized
        return {str(key): _normalize_wire_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [_normalize_wire_value(item) for item in value]
    return _json_safe(value)


def _wire_rdata_hashes(capture: Any) -> set[str]:
    if not isinstance(capture, Mapping):
        return set()
    responses = capture.get("responses")
    if not isinstance(responses, Sequence) or isinstance(responses, (str, bytes)):
        return set()
    used_responses = [
        response
        for response in responses
        if isinstance(response, Mapping) and response.get("used_for_observation") is True
    ]
    selected_responses = used_responses or list(responses)
    hashes: set[str] = set()
    for response in selected_responses:
        if not isinstance(response, Mapping):
            continue
        rdata = response.get("rdata")
        if not isinstance(rdata, Sequence) or isinstance(rdata, (str, bytes)):
            continue
        for item in rdata:
            if not isinstance(item, Mapping) or not isinstance(item.get("bytes"), Mapping):
                continue
            digest = item["bytes"].get("sha256")
            if isinstance(digest, str):
                hashes.add(digest.lower())
    return hashes


def _validate_rdata_links(
    records: Any,
    captured_hashes: set[str],
    *,
    context: str,
) -> None:
    """Require every semantic RDATA digest to link to retained wire evidence."""
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        return
    for record in records:
        if not isinstance(record, Mapping):
            continue
        digest = record.get("rdata_sha256")
        if digest is None:
            continue
        normalized_digest = str(digest).lower()
        if len(normalized_digest) != 64 or any(
            character not in "0123456789abcdef" for character in normalized_digest
        ):
            raise ValueError(f"{context} rdata_sha256 is not a SHA-256 hex digest")
        if normalized_digest not in captured_hashes:
            raise ValueError(f"{context} rdata_sha256 does not link to captured RDATA")
        if isinstance(record, dict):
            record["rdata_sha256"] = normalized_digest


def _canonical_text(value: Any) -> str:
    return json.dumps(_json_safe(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _write_json(path: Path, value: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_json_safe(value), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def _value_list(value: Any) -> list[str]:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [str(part).strip() for part in value if str(part).strip()]
    return [str(value).strip()]


def _boolean(value: Any) -> bool:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return False
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "none", "null"}
    return bool(value)


def _integer(value: Any, default: int = 0) -> int:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return default
    try:
        return int(value)
    except TypeError, ValueError:
        return default


def _record_mode(record: Mapping[str, Any]) -> str:
    mode = str(record.get("mode") or "").lower()
    if mode:
        return mode
    try:
        return "alias" if int(float(str(record.get("priority")))) == 0 else "service"
    except TypeError, ValueError:
        return "service"


def _record_sort_key(record: Mapping[str, Any]) -> tuple[int, str, str]:
    try:
        priority = int(float(str(record.get("priority"))))
    except TypeError, ValueError:
        priority = 65536
    return (priority, str(record.get("target") or ""), _canonical_text(record))


def _normalize_record(record: Mapping[str, Any]) -> dict[str, Any]:
    extensions_value = record.get("extensions")
    existing_extensions: dict[str, Any] = {}
    if isinstance(extensions_value, Mapping):
        nested_extensions = extensions_value.get("extensions")
        if isinstance(nested_extensions, Mapping):
            existing_extensions.update(dict(nested_extensions))
        existing_extensions.update(
            {key: value for key, value in extensions_value.items() if key != "extensions"}
        )
    wire_value = record.get("wire")
    if not isinstance(wire_value, Mapping):
        wire_value = existing_extensions.pop("wire", None)
    else:
        existing_extensions.pop("wire", None)
    rdata_sha256 = record.get("rdata_sha256")
    if not isinstance(rdata_sha256, str):
        promoted_hash = existing_extensions.pop("rdata_sha256", None)
        rdata_sha256 = promoted_hash if isinstance(promoted_hash, str) else None
    else:
        existing_extensions.pop("rdata_sha256", None)
    known = {
        "priority",
        "target",
        "mode",
        "params",
        "service_params",
        "param_details",
        "raw",
        "presentation",
        "ttl",
        "validation",
        "validity",
        "validation_issues",
        "usable",
        "ignored",
        "rdata_sha256",
        "wire",
        "extensions",
    }
    target = record.get("target") if "target" in record else "."
    normalized: dict[str, Any] = {
        "priority": _json_safe(record.get("priority")),
        "target": str(target) if target is not None else None,
        "mode": _record_mode(record),
        "params": _json_safe(record.get("params") or record.get("service_params") or {}),
        "param_details": _json_safe(record.get("param_details") or []),
        "raw": _json_safe(record.get("raw")),
        "presentation": _json_safe(record.get("presentation") or record.get("raw")),
        "ttl": _json_safe(record.get("ttl")),
        "validity": _json_safe(record.get("validity")),
        "validation_issues": _json_safe(record.get("validation_issues") or []),
        "usable": _json_safe(record.get("usable")),
        "ignored": _json_safe(record.get("ignored")),
    }
    if isinstance(rdata_sha256, str):
        normalized["rdata_sha256"] = rdata_sha256
    if isinstance(record.get("validation"), Mapping):
        normalized["validation"] = _json_safe(record["validation"])
    if isinstance(wire_value, Mapping):
        normalized["wire"] = _normalize_wire_value(wire_value)
    extensions = dict(existing_extensions)
    extensions.update({key: value for key, value in record.items() if key not in known})
    if extensions:
        normalized["extensions"] = _json_safe(extensions)
    return normalized


def _legacy_record(row: Mapping[str, Any], rrtype: str, present: bool) -> list[dict[str, Any]]:
    if not present:
        return []
    prefix = "https" if rrtype == "HTTPS" else "svcb"
    priority = row.get(f"{prefix}_priority")
    target = row.get(f"{prefix}_target")
    params: dict[str, Any] = {}
    if rrtype == "HTTPS":
        alpn = _value_list(row.get("alpn_protocols"))
        if alpn:
            params["alpn"] = alpn
        if row.get("port") is not None and not (
            isinstance(row.get("port"), float) and math.isnan(row["port"])
        ):
            params["port"] = _json_safe(row.get("port"))
        ipv4 = _value_list(row.get("ipv4hint"))
        ipv6 = _value_list(row.get("ipv6hint"))
        if ipv4:
            params["ipv4hint"] = ipv4
        if ipv6:
            params["ipv6hint"] = ipv6
        if _boolean(row.get("ech_config")):
            params["ech"] = True
    elif isinstance(row.get("svcb_params"), Mapping):
        params = dict(row["svcb_params"])
    return [
        _normalize_record(
            {
                "priority": priority,
                "target": target or ".",
                "mode": "alias" if priority == 0 else "service",
                "params": params,
                "raw": row.get("raw") or row.get("raw_record"),
                "ttl": row.get("ttl"),
                # Legacy flat rows predate record-level validation. Treat their
                # selected ServiceMode projection as usable for compatibility.
                "usable": True,
                "ignored": False,
            }
        )
    ]


def _presence(row: Mapping[str, Any], rrtype: str) -> bool:
    if "present" in row:
        return _boolean(row.get("present"))
    status = str(row.get("status") or row.get("query_status") or "").lower()
    if status:
        return status in {"present", "valid", "invalid", "valid_but_incompatible"}
    if "has_record" in row:
        return _boolean(row.get("has_record"))
    return _boolean(row.get("has_svcb_record" if rrtype == "SVCB" else "has_https_record"))


def _status(row: Mapping[str, Any], present: bool) -> str:
    explicit = row.get("status") or row.get("query_status")
    if explicit:
        status = str(explicit).lower()
        return "absent" if status in {"no_answer", "noanswer"} else status
    if present:
        return "present"
    error = str(row.get("error") or row.get("query_error") or "").strip()
    lowered = error.lower()
    if lowered == "nxdomain":
        return "nxdomain"
    if lowered == "timeout":
        return "timeout"
    if lowered in ABSENCE_ERRORS or not lowered:
        return "absent"
    return "error"


def _normalize_validation(row: Mapping[str, Any], present: bool) -> dict[str, Any]:
    value = row.get("validation")
    if isinstance(value, Mapping):
        status = str(value.get("status") or ("unknown" if present else "not_applicable"))
        issues_value = value.get("issues") or []
    else:
        status = str(row.get("validation_status") or ("unknown" if present else "not_applicable"))
        issues_value = row.get("validation_issues") or row.get("issues") or []
    if isinstance(issues_value, str):
        issues = [issues_value]
    elif isinstance(issues_value, Iterable):
        issues = [_json_safe(issue) for issue in issues_value]
    else:
        issues = [_json_safe(issues_value)]
    unique_issues = {_canonical_text(issue): issue for issue in issues}
    return {
        "status": status.lower(),
        "issues": [unique_issues[key] for key in sorted(unique_issues)],
    }


def _valid_ech(value: Any) -> bool:
    """Return whether a decoded ECH parameter contains valid, non-empty bytes."""
    if isinstance(value, bytes):
        return bool(value)
    if isinstance(value, Mapping):
        if value.get("encoding") != "base64" or not isinstance(value.get("value"), str):
            return False
        try:
            return bool(base64.b64decode(value["value"], validate=True))
        except binascii.Error, ValueError:
            return False
    if isinstance(value, str) and value.startswith("base64:"):
        try:
            return bool(base64.b64decode(value.removeprefix("base64:"), validate=True))
        except binascii.Error, ValueError:
            return False
    return False


def _eligible_feature_records(
    records: Sequence[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    """Keep only effective, usable, non-ignored ServiceMode records."""
    return [
        record
        for record in records
        if _record_mode(record) == "service"
        and record.get("usable") is True
        and not _boolean(record.get("ignored"))
    ]


def _normalize_features(
    row: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    probe_type: str,
    *,
    native_records: bool,
) -> dict[str, Any]:
    existing = row.get("features")
    if probe_type != "dns":
        return _json_safe(existing) if isinstance(existing, Mapping) else {}
    feature_map = dict(existing) if isinstance(existing, Mapping) else {}
    eligible = _eligible_feature_records(records)
    alpn: set[str] = set()
    ports: list[Any] = []
    ipv4: list[str] = []
    ipv6: list[str] = []
    ech = False
    no_default_alpn = False
    if not native_records:
        alpn.update(_value_list(row.get("alpn_protocols") or feature_map.get("alpn")))
        ech = _boolean(
            row.get("ech_config")
            or feature_map.get("ech_advertised")
            or feature_map.get("ech_deployment")
        )
        no_default_alpn = _boolean(row.get("no_default_alpn") or feature_map.get("no_default_alpn"))
        ipv4.extend(_value_list(row.get("ipv4hint")))
        ipv6.extend(_value_list(row.get("ipv6hint")))
    for record in eligible:
        params = record.get("params")
        if not isinstance(params, Mapping):
            continue
        alpn.update(_value_list(params.get("alpn")))
        if params.get("port") is not None:
            ports.append(params["port"])
        ipv4.extend(_value_list(params.get("ipv4hint") or params.get("ipv4_hints")))
        ipv6.extend(_value_list(params.get("ipv6hint") or params.get("ipv6_hints")))
        ech = ech or _valid_ech(params.get("ech"))
        no_default_alpn = (
            no_default_alpn
            or "no-default-alpn" in params
            or _boolean(params.get("no_default_alpn"))
        )
    h3 = "h3" in alpn
    if not native_records:
        h3 = h3 or _boolean(
            row.get("has_http3")
            or feature_map.get("h3_advertised")
            or feature_map.get("http3_support")
        )
    row_port = row.get("port")
    custom_row_port = False
    if (
        not native_records
        and row_port is not None
        and not (isinstance(row_port, float) and math.isnan(row_port))
    ):
        try:
            custom_row_port = int(row_port) != 443
        except TypeError, ValueError:
            custom_row_port = True
    custom_ports = []
    for port in ports:
        try:
            if int(port) != 443:
                custom_ports.append(port)
        except TypeError, ValueError:
            custom_ports.append(port)
    return {
        "alpn": sorted(alpn),
        "h3_advertised": h3,
        "ech_advertised": ech,
        "ports": _json_safe(ports),
        "custom_port": bool(custom_ports)
        or custom_row_port
        or (not native_records and _boolean(feature_map.get("custom_port"))),
        "ipv4_hints": sorted(set(ipv4)),
        "ipv6_hints": sorted(set(ipv6)),
        "no_default_alpn": no_default_alpn,
    }


def normalize_observation(row: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize one old or new scanner result into a schema-v2 observation."""
    probe_type = str(row.get("probe_type") or "dns").lower()
    rrtype_value = row.get("rrtype") or row.get("record_type")
    rrtype = (
        str(rrtype_value or "HTTPS").upper()
        if probe_type == "dns"
        else (str(rrtype_value).upper() if rrtype_value else None)
    )
    domain = str(row.get("domain") or "").rstrip(".")
    extensions_value = row.get("extensions")
    existing_extensions = dict(extensions_value) if isinstance(extensions_value, Mapping) else {}
    query_name_value = row.get("query_name") or existing_extensions.get("query_name")
    query_name = str(
        query_name_value
        or row.get("full_domain")
        or row.get("name")
        or row.get("owner_name")
        or domain
    ).rstrip(".")
    name = str(
        query_name_value
        or row.get("name")
        or row.get("full_domain")
        or row.get("owner_name")
        or domain
    ).rstrip(".")
    rrset_owner_name = (
        row.get("rrset_owner_name")
        if "rrset_owner_name" in row
        else existing_extensions.get("rrset_owner_name")
    )
    variant = str(row.get("variant") or row.get("subdomain") or "").lower()
    if not variant:
        variant = "www" if domain and name == f"www.{domain}" else "root"
    present = _presence(row, rrtype or "")
    records_value = row.get("records")
    native_records = isinstance(records_value, Sequence) and not isinstance(
        records_value, (str, bytes)
    )
    if isinstance(records_value, Sequence) and not isinstance(records_value, (str, bytes)):
        records = [
            _normalize_record(record) for record in records_value if isinstance(record, Mapping)
        ]
    else:
        records = _legacy_record(row, rrtype or "", present) if probe_type == "dns" else []
    records.sort(key=_record_sort_key)
    effective_value = row.get("effective_records")
    if isinstance(effective_value, Sequence) and not isinstance(effective_value, (str, bytes)):
        native_records = True
        effective_records = [
            _normalize_record(record) for record in effective_value if isinstance(record, Mapping)
        ]
        effective_records.sort(key=_record_sort_key)
    else:
        effective_records = None

    status = _status(row, present)
    raw_error = row.get("error") or row.get("query_error")
    error = None if status in {"absent", "nxdomain"} else raw_error
    resolver = row.get("resolver") or row.get("actual_resolver")
    configured_resolvers = sorted(set(_value_list(row.get("configured_resolvers"))))
    provenance_value = row.get("provenance")
    provenance = dict(provenance_value) if isinstance(provenance_value, Mapping) else {}
    if resolver and "resolver" not in provenance:
        provenance["resolver"] = resolver
    if row.get("resolver_port") is not None:
        provenance.setdefault("resolver_port", row.get("resolver_port"))
    if row.get("canonical_name") is not None:
        provenance.setdefault("canonical_name", row.get("canonical_name"))

    known = {
        "probe_type",
        "domain",
        "name",
        "query_name",
        "owner_name",
        "rrset_owner_name",
        "full_domain",
        "variant",
        "subdomain",
        "rrtype",
        "record_type",
        "status",
        "query_status",
        "present",
        "records",
        "record_count",
        "effective_records",
        "effective_validation_status",
        "rrset_validation",
        "alias_chain",
        "alias_resolution_status",
        "alias_resolution_error",
        "resolved_rrsets",
        "wire_capture",
        "wire_validation",
        "wire_decoder_version",
        "validation",
        "validation_status",
        "validation_issues",
        "issues",
        "features",
        "resolver",
        "actual_resolver",
        "resolver_port",
        "configured_resolvers",
        "canonical_name",
        "provenance",
        "error",
        "query_error",
        "has_https_record",
        "has_svcb_record",
        "has_record",
        "https_priority",
        "https_target",
        "svcb_priority",
        "svcb_target",
        "svcb_params",
        "alpn_protocols",
        "has_http3",
        "ech_config",
        "port",
        "ipv4hint",
        "ipv6hint",
        "no_default_alpn",
        "raw",
        "raw_record",
        "ttl",
        "timestamp",
        "script_version",
        "dns_servers",
        "schema_version",
        "extensions",
    }
    promoted_wire_fields: dict[str, Any] = {}
    for field in ("wire_capture", "wire_validation", "wire_decoder_version"):
        if field in row:
            promoted_wire_fields[field] = row.get(field)
            existing_extensions.pop(field, None)
        elif field in existing_extensions:
            promoted_wire_fields[field] = existing_extensions.pop(field)
    extensions = {
        key: value
        for key, value in existing_extensions.items()
        if key not in {"query_name", "rrset_owner_name"}
    }
    extensions.update({key: value for key, value in row.items() if key not in known})
    normalized: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "probe_type": probe_type,
        "domain": domain,
        "name": name,
        "query_name": query_name,
        "owner_name": _json_safe(row.get("owner_name") or rrset_owner_name or name),
        "rrset_owner_name": _json_safe(rrset_owner_name),
        "variant": variant,
        "rrtype": rrtype,
        "status": status,
        "present": present,
        "records": records,
        "record_count": _integer(row.get("record_count"), len(records)),
        "validation": _normalize_validation(row, present),
        "features": _normalize_features(
            row,
            effective_records if effective_records is not None else records,
            probe_type,
            native_records=native_records,
        ),
        "resolver": _json_safe(resolver),
        "resolver_port": _json_safe(row.get("resolver_port")),
        "configured_resolvers": configured_resolvers,
        "canonical_name": _json_safe(row.get("canonical_name")),
        "ttl": _json_safe(row.get("ttl")),
        "provenance": _json_safe(provenance),
        "error": _json_safe(error),
    }
    if effective_records is not None:
        normalized["effective_records"] = effective_records
    for field in (
        "effective_validation_status",
        "rrset_validation",
        "alias_chain",
        "alias_resolution_status",
        "alias_resolution_error",
        "resolved_rrsets",
    ):
        if field in row:
            normalized[field] = (
                _normalize_wire_value(row.get(field))
                if field == "resolved_rrsets"
                else _json_safe(row.get(field))
            )
    normalized.update(
        {
            field: (_normalize_wire_value(value) if field == "wire_capture" else _json_safe(value))
            for field, value in promoted_wire_fields.items()
        }
    )
    captured_rdata_hashes = _wire_rdata_hashes(normalized.get("wire_capture"))
    _validate_rdata_links(
        normalized["records"],
        captured_rdata_hashes,
        context="record",
    )
    resolved_rdata_hashes: set[str] = set()
    resolved_rrsets = normalized.get("resolved_rrsets")
    if isinstance(resolved_rrsets, Sequence) and not isinstance(resolved_rrsets, (str, bytes)):
        for rrset in resolved_rrsets:
            if not isinstance(rrset, Mapping):
                continue
            rrset_hashes = _wire_rdata_hashes(rrset.get("wire_capture"))
            resolved_rdata_hashes.update(rrset_hashes)
            _validate_rdata_links(
                rrset.get("records"),
                rrset_hashes,
                context="resolved RRset record",
            )
    if "effective_records" in normalized:
        _validate_rdata_links(
            normalized["effective_records"],
            captured_rdata_hashes | resolved_rdata_hashes,
            context="effective record",
        )
    if extensions:
        normalized["extensions"] = _json_safe(extensions)
    return normalized


def _observation_key(observation: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(observation.get("probe_type") or ""),
        str(observation.get("domain") or ""),
        str(observation.get("name") or ""),
        str(observation.get("variant") or ""),
        str(observation.get("rrtype") or ""),
    )


def _observation_sort_key(
    observation: Mapping[str, Any],
) -> tuple[str, str, str, str, str, str, str]:
    """Sort deterministically without making resolver part of record identity."""
    return (
        *_observation_key(observation),
        str(observation.get("resolver") or ""),
        _canonical_text(observation),
    )


def load_cohort(path: Path | None = None) -> dict[str, Any]:
    """Load and fingerprint the tracked target cohort."""
    if path is None:
        source_name = "bundled top_websites.json"
        source_text = (
            resources.files("src.data").joinpath("top_websites.json").read_text(encoding="utf-8")
        )
    else:
        source_name = str(path)
        source_text = path.read_text(encoding="utf-8")
    value = json.loads(source_text)
    if not isinstance(value, Mapping):
        raise ValueError(f"cohort file must contain a JSON object: {source_name}")
    domains = [str(domain).rstrip(".") for domain in value.get("websites", [])]
    digest = hashlib.sha256("\n".join(domains).encode("utf-8")).hexdigest()[:16]
    return {
        "id": str(value.get("id") or f"sha256:{digest}"),
        "source": value.get("source"),
        "updated_at": value.get("updated_at") or value.get("last_updated"),
        "count": len(domains),
        "domains": domains,
    }


def _cohort_from_rows(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    domains = sorted({str(row.get("domain")).rstrip(".") for row in rows if row.get("domain")})
    digest = hashlib.sha256("\n".join(domains).encode("utf-8")).hexdigest()[:16]
    return {
        "id": f"sha256:{digest}",
        "source": "scan input",
        "updated_at": None,
        "count": len(domains),
        "domains": domains,
    }


def _extract_resolvers(
    rows: Sequence[Mapping[str, Any]], supplied: Sequence[str] | None
) -> list[str]:
    values: list[str] = _value_list(supplied)
    for row in rows:
        actual = row.get("resolver") or row.get("actual_resolver")
        if actual:
            values.append(str(actual))
    return sorted(set(values))


def _extract_configured_resolvers(
    rows: Sequence[Mapping[str, Any]], supplied: Sequence[str] | None
) -> list[str]:
    values: list[str] = _value_list(supplied)
    for row in rows:
        values.extend(_value_list(row.get("dns_servers")))
        values.extend(_value_list(row.get("configured_resolvers")))
    return sorted(set(values))


def _merge_scan_provenance(
    target: dict[str, Any], container: Any, *, include_all: bool = False
) -> None:
    if not isinstance(container, Mapping):
        return
    software = container.get("software")
    if isinstance(software, Mapping):
        version = software.get("version")
        if version is not None:
            target.setdefault("package_version", version)
            target.setdefault("script_version", version)
        if software.get("python") is not None:
            target.setdefault("python_version", software["python"])
        if software.get("dnspython") is not None:
            target.setdefault("dnspython_version", software["dnspython"])
        if software.get("commit") is not None:
            target.setdefault("source_commit", software["commit"])
        target.setdefault("software", dict(software))
    if container.get("validator_ruleset_version") is not None:
        target.setdefault("validator_ruleset", container["validator_ruleset_version"])
    if container.get("wire_decoder_version") is not None:
        target.setdefault("wire_decoder", container["wire_decoder_version"])
    if container.get("svcparam_registry") is not None:
        target.setdefault("registry_snapshot", container["svcparam_registry"])
    nested = container.get("provenance")
    if isinstance(nested, Mapping):
        target.update(dict(nested))
    if include_all:
        target.update({key: value for key, value in container.items() if key != "provenance"})
    else:
        target.update({key: container[key] for key in PROVENANCE_KEYS if key in container})


def _row_provenance_value(row: Mapping[str, Any], key: str) -> Any:
    """Read one canonical provenance value from a standalone observation row."""
    for field in (key, *ROW_PROVENANCE_ALIASES.get(key, ())):
        value = row.get(field)
        if value is not None:
            return value
    nested = row.get("provenance")
    if isinstance(nested, Mapping):
        return nested.get(key)
    return None


def build_snapshot(
    data: Any,
    *,
    scan_started_at: Any | None = None,
    scan_completed_at: Any | None = None,
    resolvers: Sequence[str] | None = None,
    cohort: Mapping[str, Any] | None = None,
    scan_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a canonical schema-v2 snapshot from old or new observations."""
    source_scan_metadata: dict[str, Any] = {}
    source_scan_provenance: dict[str, Any] = {}
    source_configured_resolvers: Sequence[str] | None = None
    if isinstance(data, pd.DataFrame):
        rows = [dict(row) for row in data.to_dict(orient="records")]
    elif isinstance(data, Mapping):
        value = data.get("observations")
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            raise ValueError("snapshot input object must contain an observations array")
        rows = [dict(row) for row in value if isinstance(row, Mapping)]
        source_scan = data.get("scan")
        if isinstance(source_scan, Mapping):
            _merge_scan_provenance(source_scan_provenance, source_scan)
            _merge_scan_provenance(
                source_scan_provenance, source_scan.get("provenance"), include_all=True
            )
            _merge_scan_provenance(source_scan_provenance, source_scan.get("metadata"))
            _merge_scan_provenance(source_scan_provenance, source_scan.get("extensions"))
            scan_started_at = (
                scan_started_at or source_scan.get("started_at") or source_scan.get("timestamp")
            )
            scan_completed_at = scan_completed_at or source_scan.get("completed_at")
            resolvers = (
                resolvers or source_scan.get("observed_resolvers") or source_scan.get("resolvers")
            )
            configured_value = source_scan.get("configured_resolvers")
            if isinstance(configured_value, Sequence) and not isinstance(
                configured_value, (str, bytes)
            ):
                source_configured_resolvers = configured_value
            source_scan_metadata = {
                key: value
                for key, value in source_scan.items()
                if key
                not in {
                    "id",
                    "started_at",
                    "timestamp",
                    "completed_at",
                    "resolvers",
                    "observed_resolvers",
                    "configured_resolvers",
                    "observation_count",
                    "provenance",
                    "extensions",
                }
            }
            if isinstance(source_scan.get("extensions"), Mapping):
                source_scan_metadata.update(dict(source_scan["extensions"]))
        if cohort is None and isinstance(data.get("cohort"), Mapping):
            cohort = data["cohort"]
    elif isinstance(data, Iterable) and not isinstance(data, (str, bytes)):
        rows = [dict(row) for row in data if isinstance(row, Mapping)]
    else:
        raise TypeError("snapshot data must be a DataFrame, snapshot, or iterable of mappings")

    input_timestamps = [str(row["timestamp"]) for row in rows if row.get("timestamp")]
    started_at = _iso_datetime(
        scan_started_at or (min(input_timestamps) if input_timestamps else None)
    )
    completed_at = _iso_datetime(
        scan_completed_at or (max(input_timestamps) if input_timestamps else started_at), started_at
    )
    observations = [normalize_observation(row) for row in rows]
    observations.sort(key=_observation_sort_key)
    cohort_value = _json_safe(dict(cohort)) if cohort is not None else _cohort_from_rows(rows)
    if "count" not in cohort_value:
        cohort_value["count"] = len(cohort_value.get("domains", []))

    metadata = source_scan_metadata
    metadata.update(dict(scan_metadata or {}))
    metadata.setdefault("input_rows", len(rows))
    _merge_scan_provenance(source_scan_provenance, scan_metadata)
    for key in PROVENANCE_KEYS:
        if key in source_scan_provenance:
            continue
        values = {
            _canonical_text(value): _json_safe(value)
            for row in rows
            if (value := _row_provenance_value(row, key)) is not None
        }
        if len(values) == 1:
            source_scan_provenance[key] = next(iter(values.values()))
        elif values:
            source_scan_provenance[key] = [values[item] for item in sorted(values)]
    observed_resolvers = _extract_resolvers(rows, resolvers)
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "scan": {
            "id": started_at,
            "started_at": started_at,
            "completed_at": completed_at,
            # ``resolvers`` is retained for one schema-v2 compatibility cycle;
            # it is an alias of actual answer provenance, never configuration.
            "resolvers": observed_resolvers,
            "observed_resolvers": observed_resolvers,
            "configured_resolvers": _extract_configured_resolvers(
                rows, source_configured_resolvers
            ),
            "observation_count": len(observations),
            "provenance": _json_safe(source_scan_provenance),
            "extensions": _json_safe(metadata),
        },
        "cohort": cohort_value,
        "observations": observations,
        "metrics": calculate_metrics(observations),
        "distributions": {
            "alpn_protocols": analyze_alpn_protocols(observations),
            "priorities": calculate_priority_distribution(observations),
        },
        "feature_leaders": identify_feature_leaders(observations),
        "error_statistics": calculate_error_statistics(observations),
    }
    return cast(dict[str, Any], _json_safe(snapshot))


def _snapshot_filename(snapshot: Mapping[str, Any]) -> str:
    scan = snapshot.get("scan")
    if not isinstance(scan, Mapping):
        raise ValueError("snapshot has no scan metadata")
    started = _iso_datetime(scan.get("started_at"))
    stamp = started.replace("T", "_").replace(":", "-").replace("Z", "")
    return f"rfc9460_scan_{stamp}.json.gz"


def write_snapshot(snapshot: Mapping[str, Any], scan_dir: Path) -> Path:
    """Write a reproducible gzip-compressed canonical snapshot."""
    if snapshot.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"only schema version {SCHEMA_VERSION} snapshots can be written")
    scan_dir.mkdir(parents=True, exist_ok=True)
    path = scan_dir / _snapshot_filename(snapshot)
    payload = (
        json.dumps(_json_safe(snapshot), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            compressed.write(payload)
    return path


def load_snapshot(path: Path) -> dict[str, Any]:
    """Load a compressed or plain JSON snapshot."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as source:
            value = json.load(source)
    else:
        with path.open(encoding="utf-8") as source:
            value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"snapshot must contain an object: {path}")
    return value


def _legacy_metrics(value: Mapping[str, Any]) -> dict[str, Any]:
    metrics_value = value.get("metrics")
    old: Mapping[str, Any] = metrics_value if isinstance(metrics_value, Mapping) else {}
    adoption_value = old.get("adoption")
    adoption: Mapping[str, Any] = adoption_value if isinstance(adoption_value, Mapping) else {}
    features_value = old.get("features")
    features: Mapping[str, Any] = features_value if isinstance(features_value, Mapping) else {}
    domains = int(old.get("unique_domains") or 0)
    total_rows = int(old.get("total_domains_checked") or 0)
    https_names = domains * 2 if domains else total_rows // 2
    svcb_names = max(total_rows - https_names, 0) if total_rows else https_names
    https_count_value = adoption.get("https_count")
    https_count = (
        int(https_count_value)
        if https_count_value is not None
        else round(float(adoption.get("overall_adoption") or 0) * https_names / 100)
    )
    svcb_count_value = adoption.get("svcb_count")
    svcb_count = (
        int(svcb_count_value)
        if svcb_count_value is not None
        else round(float(adoption.get("svcb_adoption") or 0) * svcb_names / 100)
    )

    def metric(count: int, denominator: int, percentage: Any | None = None) -> dict[str, Any]:
        calculated = round(count / denominator * 100, 2) if denominator else 0.0
        return {
            "count": count,
            "denominator": denominator,
            "percentage": float(percentage) if percentage is not None else calculated,
        }

    root_count = round(float(adoption.get("root_adoption") or 0) * domains / 100)
    www_count = round(float(adoption.get("www_adoption") or 0) * domains / 100)
    normalized_features: dict[str, Any] = {}
    for name, legacy_name in (
        ("h3_advertised", "http3_support"),
        ("ech_advertised", "ech_deployment"),
        ("custom_port", "custom_port"),
        ("ipv4_hints", "ipv4_hints"),
        ("ipv6_hints", "ipv6_hints"),
        ("alpn_advertised", "alpn_advertised"),
        ("no_default_alpn", "no_default_alpn"),
    ):
        source_value = features.get(legacy_name)
        source: Mapping[str, Any] = source_value if isinstance(source_value, Mapping) else {}
        normalized_features[name] = metric(
            int(source.get("count") or 0), https_count, source.get("percentage")
        )
    unknown = metric(https_count + svcb_count, https_count + svcb_count)
    zero = metric(0, https_count + svcb_count)
    validity = {
        "overall": {
            "present": https_count + svcb_count,
            "valid": zero,
            "invalid": zero,
            "valid_but_incompatible": zero,
            "unknown": unknown,
        }
    }
    for rrtype, count in (("https", https_count), ("svcb", svcb_count)):
        validity[rrtype] = {
            "present": count,
            "valid": metric(0, count),
            "invalid": metric(0, count),
            "valid_but_incompatible": metric(0, count),
            "unknown": metric(count, count),
        }
    return {
        "denominators": {
            "domains": domains,
            "observations": total_rows,
            "queried_names": https_names,
            "https_names": https_names,
            "svcb_names": svcb_names,
            "https_observations": https_names,
            "svcb_observations": svcb_names,
            "root_https_names": domains,
            "www_https_names": domains,
            "https_present_rrsets": https_count,
            "svcb_present_rrsets": svcb_count,
            "usable_https_rrsets": https_count,
            "usable_svcb_rrsets": svcb_count,
        },
        "adoption": {
            "https": metric(https_count, https_names, adoption.get("overall_adoption")),
            "root_https": metric(root_count, domains, adoption.get("root_adoption")),
            "www_https": metric(www_count, domains, adoption.get("www_adoption")),
            "svcb": metric(svcb_count, svcb_names, adoption.get("svcb_adoption")),
            "overall_adoption": float(adoption.get("overall_adoption") or 0),
            "root_adoption": float(adoption.get("root_adoption") or 0),
            "www_adoption": float(adoption.get("www_adoption") or 0),
            "svcb_adoption": float(adoption.get("svcb_adoption") or 0),
            "https_count": https_count,
            "svcb_count": svcb_count,
        },
        "validity": validity,
        "features": normalized_features,
        "compatibility": {
            "legacy_source_feature_names": {
                "http3_support": "h3_advertised",
                "ech_deployment": "ech_advertised",
            }
        },
    }


def import_legacy_history(legacy_dir: Path) -> list[dict[str, Any]]:
    """Import only aggregate facts available in schema-v1 analysis files."""
    entries: list[dict[str, Any]] = []
    for path in sorted(legacy_dir.glob("rfc9460_analysis_*.json")):
        try:
            value = load_snapshot(path)
        except OSError, ValueError, json.JSONDecodeError:
            continue
        if value.get("schema_version") == SCHEMA_VERSION:
            continue
        metadata = value.get("metadata")
        if not isinstance(metadata, Mapping) or not isinstance(value.get("metrics"), Mapping):
            continue
        scan_date = _iso_datetime(metadata.get("scan_date"))
        entries.append(
            {
                "schema_version": 1,
                "scan_id": f"legacy:{scan_date}",
                "scan_date": scan_date,
                "cohort": {
                    "id": None,
                    "source": None,
                    "updated_at": None,
                    "count": int(value["metrics"].get("unique_domains") or 0),
                },
                "metrics": _legacy_metrics(value),
                "details_available": False,
                "source_file": path.name,
            }
        )
    return entries


def _snapshot_paths(scan_dir: Path) -> list[Path]:
    return sorted(scan_dir.glob("rfc9460_scan_*.json.gz"))


def _detailed_snapshots(scan_dir: Path) -> list[dict[str, Any]]:
    snapshots: list[dict[str, Any]] = []
    for path in _snapshot_paths(scan_dir):
        try:
            snapshot = load_snapshot(path)
        except OSError, ValueError, json.JSONDecodeError:
            continue
        if snapshot.get("schema_version") == SCHEMA_VERSION and isinstance(
            snapshot.get("scan"), Mapping
        ):
            snapshots.append(snapshot)
    snapshots.sort(key=lambda item: str(item["scan"].get("started_at") or ""))
    return snapshots


def _history_entry(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    scan = cast(Mapping[str, Any], snapshot["scan"])
    cohort_value = snapshot.get("cohort")
    cohort: Mapping[str, Any] = cohort_value if isinstance(cohort_value, Mapping) else {}
    return {
        "schema_version": SCHEMA_VERSION,
        "scan_id": scan["id"],
        "scan_date": scan["completed_at"],
        "cohort": {
            "id": cohort.get("id"),
            "source": cohort.get("source"),
            "updated_at": cohort.get("updated_at"),
            "count": cohort.get("count"),
        },
        "metrics": snapshot["metrics"],
        "details_available": True,
    }


def build_history(
    snapshots: Sequence[Mapping[str, Any]], legacy_dir: Path | None = None
) -> list[dict[str, Any]]:
    """Combine legacy aggregates and schema-v2 history in chronological order."""
    entries = import_legacy_history(legacy_dir) if legacy_dir else []
    entries.extend(_history_entry(snapshot) for snapshot in snapshots)
    deduplicated = {str(entry["scan_id"]): entry for entry in entries}
    return sorted(deduplicated.values(), key=lambda entry: (entry["scan_date"], entry["scan_id"]))


def _identity(observation: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "probe_type": observation.get("probe_type"),
        "domain": observation.get("domain"),
        "name": observation.get("name"),
        "variant": observation.get("variant"),
        "rrtype": observation.get("rrtype"),
    }


def _material_alias_chain(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [
        {key: item.get(key) for key in ("depth", "owner_name", "target_name") if key in item}
        for item in value
        if isinstance(item, Mapping)
    ]


def _material_resolved_rrsets(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    fields = (
        "owner_name",
        "record_type",
        "validation_status",
        "validation_issues",
        "records",
    )
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        material = {key: item.get(key) for key in fields if key in item}
        if "validation_issues" in material:
            material["validation_issues"] = _material_issues(material["validation_issues"])
        if "records" in material:
            material["records"] = _material_records(material["records"])
        result.append(material)
    return result


def _material_records(value: Any) -> list[dict[str, Any]]:
    """Drop packet-location evidence while retaining semantic record identity."""
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        record = {key: item[key] for key in item if key != "wire"}
        if "validation_issues" in record:
            record["validation_issues"] = _material_issues(record["validation_issues"])
        if isinstance(record.get("validation"), Mapping):
            record["validation"] = _material_validation(record["validation"])
        extensions = record.get("extensions")
        if isinstance(extensions, Mapping) and "wire" in extensions:
            cleaned = {key: extensions[key] for key in extensions if key != "wire"}
            if cleaned:
                record["extensions"] = cleaned
            else:
                record.pop("extensions")
        result.append(record)
    return result


def _material_issues(value: Any) -> list[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    result: list[Any] = []
    for issue in value:
        if isinstance(issue, Mapping):
            result.append(
                {key: issue.get(key) for key in ("code", "severity", "key") if key in issue}
            )
        else:
            result.append(issue)
    return sorted(result, key=_canonical_text)


def _material_validation(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    result = {key: value[key] for key in value if key != "issues"}
    if "issues" in value:
        result["issues"] = _material_issues(value["issues"])
    return result


def _state(observation: Mapping[str, Any]) -> dict[str, Any]:
    effective_records = (
        observation.get("effective_records")
        if "effective_records" in observation
        else observation.get("records")
    )
    return {
        "status": observation.get("status"),
        "present": observation.get("present"),
        "records": _material_records(observation.get("records")),
        "validation": _material_validation(observation.get("validation")),
        "features": observation.get("features") or {},
        "effective_records": _material_records(effective_records),
        "effective_validation_status": observation.get("effective_validation_status"),
        "alias_resolution_status": observation.get("alias_resolution_status"),
        "alias_chain": _material_alias_chain(observation.get("alias_chain")),
        "resolved_rrsets": _material_resolved_rrsets(observation.get("resolved_rrsets")),
    }


def _has_wire_decoder_provenance(snapshot: Mapping[str, Any]) -> bool:
    """Return whether a detailed snapshot identifies its wire decoder."""
    scan = snapshot.get("scan")
    if not isinstance(scan, Mapping):
        return False
    provenance = scan.get("provenance")
    if not isinstance(provenance, Mapping):
        return False
    value = provenance.get("wire_decoder")
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return bool(value)
    return value is not None


def _registry_snapshot_provenance(snapshot: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Return structured SvcParam registry provenance when a scan carries it."""
    scan = snapshot.get("scan")
    if not isinstance(scan, Mapping):
        return None
    provenance = scan.get("provenance")
    if not isinstance(provenance, Mapping):
        return None
    registry = provenance.get("registry_snapshot")
    return registry if isinstance(registry, Mapping) else None


def _registry_snapshot_changed(previous: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    """Detect a registry interpretation boundary without penalizing added hash metadata."""
    before = _registry_snapshot_provenance(previous)
    after = _registry_snapshot_provenance(current)
    if before is None or after is None:
        return False

    before_version = before.get("version", before.get("iana_last_updated"))
    after_version = after.get("version", after.get("iana_last_updated"))
    if before_version is not None and after_version is not None:
        if _canonical_text(before_version) != _canonical_text(after_version):
            return True

        before_hash = before.get("content_sha256", before.get("payload_sha256"))
        after_hash = after.get("content_sha256", after.get("payload_sha256"))
        if before_hash is not None and after_hash is not None:
            return _canonical_text(before_hash) != _canonical_text(after_hash)
        # Adding a content hash to the same dated/versioned registry improves
        # provenance without changing the interpretation boundary.
        return False

    return _canonical_text(before) != _canonical_text(after)


def compare_snapshots(
    previous: Mapping[str, Any] | None, current: Mapping[str, Any]
) -> dict[str, Any]:
    """Describe gained, lost, and materially changed observations."""
    current_scan_value = current.get("scan")
    current_scan: Mapping[str, Any] = (
        current_scan_value if isinstance(current_scan_value, Mapping) else {}
    )
    previous_scan_value = previous.get("scan") if previous else None
    previous_scan: Mapping[str, Any] = (
        previous_scan_value if isinstance(previous_scan_value, Mapping) else {}
    )
    generated_at = current_scan.get("completed_at") or _utc_now()
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "comparable": previous is not None,
        "from_scan": previous_scan.get("id"),
        "to_scan": current_scan.get("id"),
        "summary": {"gained": 0, "lost": 0, "changed": 0},
        "gained": [],
        "lost": [],
        "changed": [],
    }
    if previous is None:
        result["reason_code"] = "no_detailed_predecessor"
        result["reason"] = (
            "This is the first detailed schema-v2 scan, so no comparable per-name "
            "predecessor exists."
        )
        return result

    if not _has_wire_decoder_provenance(previous) and _has_wire_decoder_provenance(current):
        result["comparable"] = False
        result["reason_code"] = "wire_decoder_baseline"
        result["reason"] = (
            "The previous detailed scan lacks wire-decoder provenance. This scan establishes "
            "the raw-wire evidence baseline, so per-name deployment changes are not comparable; "
            "comparison resumes with the next wire-enabled scan."
        )
        return result

    if _registry_snapshot_changed(previous, current):
        result["comparable"] = False
        result["reason_code"] = "registry_snapshot_baseline"
        result["reason"] = (
            "The SvcParam registry snapshot changed. This scan establishes a new interpretation "
            "baseline so registry metadata cannot masquerade as a DNS deployment change; "
            "comparison resumes between scans using the same registry snapshot."
        )
        return result

    before = {
        _observation_key(item): item
        for item in previous.get("observations", [])
        if isinstance(item, Mapping)
    }
    after = {
        _observation_key(item): item
        for item in current.get("observations", [])
        if isinstance(item, Mapping)
    }
    for key in sorted(set(before) | set(after)):
        old = before.get(key)
        new = after.get(key)
        old_present = bool(old and old.get("present"))
        new_present = bool(new and new.get("present"))
        if new_present and not old_present and new is not None:
            result["gained"].append({**_identity(new), "after": _state(new)})
        elif old_present and not new_present and old is not None:
            result["lost"].append({**_identity(old), "before": _state(old)})
        elif old_present and new_present and old is not None and new is not None:
            old_state = _state(old)
            new_state = _state(new)
            fields = [field for field in old_state if old_state[field] != new_state[field]]
            if fields:
                result["changed"].append(
                    {
                        **_identity(new),
                        "fields": fields,
                        "before": old_state,
                        "after": new_state,
                    }
                )
    result["summary"] = {name: len(result[name]) for name in ("gained", "lost", "changed")}
    return result


def generate_pages_data(
    snapshot: Mapping[str, Any],
    *,
    scan_dir: Path,
    pages_dir: Path,
    legacy_dir: Path | None = None,
) -> dict[str, Path]:
    """Generate deterministic latest, history, and changes dashboard data."""
    snapshots = _detailed_snapshots(scan_dir)
    current_id = snapshot["scan"]["id"]
    if not any(item["scan"]["id"] == current_id for item in snapshots):
        snapshots.append(dict(snapshot))
        snapshots.sort(key=lambda item: item["scan"]["started_at"])
    current_index = next(
        index for index, item in enumerate(snapshots) if item["scan"]["id"] == current_id
    )
    previous = snapshots[current_index - 1] if current_index else None
    generated_at = snapshot["scan"]["completed_at"]
    history = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "entries": build_history(snapshots, legacy_dir),
    }
    changes = compare_snapshots(previous, snapshot)
    return {
        "latest": _write_json(pages_dir / "latest.json", snapshot),
        "history": _write_json(pages_dir / "history.json", history),
        "changes": _write_json(pages_dir / "changes.json", changes),
    }


def _load_input(path: Path) -> Any:
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path)
    return load_snapshot(path)


def run_pipeline(
    input_path: Path,
    *,
    scan_dir: Path,
    pages_dir: Path,
    legacy_dir: Path | None = None,
    cohort_path: Path | None = None,
    scan_started_at: str | None = None,
) -> dict[str, Path]:
    """Build and persist a canonical snapshot and all Pages data."""
    data = _load_input(input_path)
    cohort = load_cohort(cohort_path)
    snapshot = build_snapshot(data, scan_started_at=scan_started_at, cohort=cohort)
    snapshot_path = write_snapshot(snapshot, scan_dir)
    paths = generate_pages_data(
        snapshot, scan_dir=scan_dir, pages_dir=pages_dir, legacy_dir=legacy_dir
    )
    return {"snapshot": snapshot_path, **paths}


def verify_pages_data(
    latest_path: Path,
    *,
    scan_dir: Path,
    max_age_hours: float | None = None,
) -> dict[str, Any]:
    """Verify that all generated data describes the newest canonical scan."""
    pages_dir = latest_path.parent
    history_path = pages_dir / "history.json"
    changes_path = pages_dir / "changes.json"
    missing = [path for path in (latest_path, history_path, changes_path) if not path.is_file()]
    if missing:
        raise ValueError(
            "missing generated Pages data: " + ", ".join(str(path) for path in missing)
        )
    latest = load_snapshot(latest_path)
    history = load_snapshot(history_path)
    changes = load_snapshot(changes_path)
    snapshots = _detailed_snapshots(scan_dir)
    if not snapshots:
        raise ValueError(f"no schema-v2 snapshots found in {scan_dir}")
    newest = snapshots[-1]
    scan_id = latest.get("scan", {}).get("id")
    if latest != newest:
        raise ValueError("latest.json does not exactly match the newest canonical snapshot")
    v2_entries = [
        entry
        for entry in history.get("entries", [])
        if isinstance(entry, Mapping) and entry.get("schema_version") == SCHEMA_VERSION
    ]
    if not v2_entries or v2_entries[-1].get("scan_id") != scan_id:
        raise ValueError("history.json does not end with the latest schema-v2 scan")
    if changes.get("to_scan") != scan_id:
        raise ValueError("changes.json does not target the latest scan")
    completed_at = latest.get("scan", {}).get("completed_at")
    if history.get("generated_at") != completed_at or changes.get("generated_at") != completed_at:
        raise ValueError("generated data timestamps do not match the latest completed scan")
    if max_age_hours is not None:
        completed = datetime.fromisoformat(str(completed_at).replace("Z", "+00:00"))
        age_hours = (datetime.now(timezone.utc) - completed).total_seconds() / 3600
        if age_hours > max_age_hours:
            raise ValueError(
                f"latest scan is {age_hours:.1f} hours old (limit: {max_age_hours:.1f} hours)"
            )
    return {"scan_id": scan_id, "completed_at": completed_at, "files": 3}


def _checked_artifact_size(path: Path, *, limit: int, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"missing {label}: {path}")
    size = path.stat().st_size
    if size > limit:
        raise ValueError(
            f"{label} {path} is {size} bytes ({size / MEBIBYTE:.2f} MiB), "
            f"exceeding the {limit}-byte ({limit / MEBIBYTE:.2f} MiB) limit; "
            "inspect the generated payload before raising the configured limit"
        )
    return {"path": str(path), "bytes": size, "limit_bytes": limit}


def verify_generated_artifact_sizes(
    *,
    scan_dir: Path,
    pages_dir: Path,
    max_snapshot_bytes: int = DEFAULT_MAX_CANONICAL_SNAPSHOT_BYTES,
    max_pages_json_bytes: int = DEFAULT_MAX_PAGES_JSON_BYTES,
) -> dict[str, Any]:
    """Fail closed when newly generated tracked artifacts exceed safe size limits."""
    if max_snapshot_bytes <= 0:
        raise ValueError("max_snapshot_bytes must be greater than zero")
    if max_pages_json_bytes <= 0:
        raise ValueError("max_pages_json_bytes must be greater than zero")

    snapshots = _snapshot_paths(scan_dir)
    if not snapshots:
        raise ValueError(f"no canonical snapshots found in {scan_dir}")
    snapshot = _checked_artifact_size(
        snapshots[-1],
        limit=max_snapshot_bytes,
        label="newest canonical snapshot",
    )

    required_pages = [pages_dir / filename for filename in PAGES_DATA_FILENAMES]
    missing = [path for path in required_pages if not path.is_file()]
    if missing:
        raise ValueError(
            "missing generated Pages data: " + ", ".join(str(path) for path in missing)
        )
    # Include future public JSON views automatically instead of silently leaving
    # them outside the pre-commit safeguard.
    page_paths = sorted(set(required_pages).union(pages_dir.glob("*.json")))
    pages = [
        _checked_artifact_size(
            path,
            limit=max_pages_json_bytes,
            label="public Pages JSON",
        )
        for path in page_paths
    ]
    return {
        "snapshot": snapshot,
        "pages": pages,
        "limits": {
            "snapshot_bytes": max_snapshot_bytes,
            "pages_json_bytes": max_pages_json_bytes,
        },
    }


def _positive_byte_limit(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer number of bytes") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and verify RFC 9460 tracker data")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build a canonical snapshot and Pages JSON")
    build.add_argument("--input", type=Path, required=True)
    build.add_argument("--scan-dir", type=Path, default=Path("data/scans"))
    build.add_argument("--pages-dir", type=Path, default=Path("docs/data"))
    build.add_argument("--legacy-dir", type=Path, default=Path("results"))
    build.add_argument(
        "--cohort",
        type=Path,
        help="cohort JSON file (defaults to the bundled tracked cohort)",
    )
    build.add_argument("--scan-time", help="override the scan start time")

    verify = commands.add_parser("verify", help="verify freshness and generated-data consistency")
    verify.add_argument("--latest", type=Path, default=Path("docs/data/latest.json"))
    verify.add_argument("--scan-dir", type=Path, default=Path("data/scans"))
    verify.add_argument("--max-age-hours", type=float, default=48.0)

    sizes = commands.add_parser(
        "check-sizes",
        help="enforce pre-commit size limits for generated tracked data",
    )
    sizes.add_argument("--scan-dir", type=Path, default=Path("data/scans"))
    sizes.add_argument("--pages-dir", type=Path, default=Path("docs/data"))
    sizes.add_argument(
        "--max-snapshot-bytes",
        type=_positive_byte_limit,
        default=DEFAULT_MAX_CANONICAL_SNAPSHOT_BYTES,
    )
    sizes.add_argument(
        "--max-pages-json-bytes",
        type=_positive_byte_limit,
        default=DEFAULT_MAX_PAGES_JSON_BYTES,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run a canonical-data build or verification command."""
    args = _parser().parse_args(argv)
    if args.command == "build":
        paths = run_pipeline(
            args.input,
            scan_dir=args.scan_dir,
            pages_dir=args.pages_dir,
            legacy_dir=args.legacy_dir,
            cohort_path=args.cohort,
            scan_started_at=args.scan_time,
        )
        print(json.dumps({name: str(path) for name, path in paths.items()}, sort_keys=True))
        return 0
    if args.command == "verify":
        result = verify_pages_data(
            args.latest, scan_dir=args.scan_dir, max_age_hours=args.max_age_hours
        )
    else:
        result = verify_generated_artifact_sizes(
            scan_dir=args.scan_dir,
            pages_dir=args.pages_dir,
            max_snapshot_bytes=args.max_snapshot_bytes,
            max_pages_json_bytes=args.max_pages_json_bytes,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
