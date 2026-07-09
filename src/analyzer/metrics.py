"""Adoption, validity, and feature metrics for RFC 9460 observations.

The metric layer accepts both the original flat CSV rows and schema-v2
observations.  RFC 9460 does not require a site to publish HTTPS or SVCB
records, so this module deliberately reports adoption and validity instead of
assigning a synthetic "compliance score".
"""

import base64
import binascii
import logging
import math
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

Observation = Mapping[str, Any]
MetricInput = Any


def _rows(data: MetricInput) -> list[Observation]:
    """Return mapping rows from a DataFrame or iterable of mappings."""
    if isinstance(data, pd.DataFrame):
        return [dict(row) for row in data.to_dict(orient="records")]
    if data is None:
        return []
    if isinstance(data, Mapping):
        observations = data.get("observations")
        if isinstance(observations, Sequence) and not isinstance(observations, (str, bytes)):
            return [row for row in observations if isinstance(row, Mapping)]
        return [data]
    if isinstance(data, Iterable) and not isinstance(data, (str, bytes)):
        return [row for row in data if isinstance(row, Mapping)]
    raise TypeError("metrics input must be a DataFrame, snapshot, or iterable of mappings")


def _missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, float):
        return math.isnan(value)
    try:
        result = pd.isna(value)
        return bool(result) if isinstance(result, (bool, int)) else False
    except TypeError, ValueError:
        return False


def _truthy(value: Any) -> bool:
    if _missing(value):
        return False
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "none", "null"}
    try:
        return bool(value)
    except TypeError, ValueError:
        return False


def _rrtype(row: Observation) -> str:
    return str(row.get("rrtype") or row.get("record_type") or "HTTPS").upper()


def _dns_rows(data: MetricInput) -> list[Observation]:
    """Return DNS observations, excluding future TLS/HTTP probe extensions."""
    return [row for row in _rows(data) if str(row.get("probe_type") or "dns").lower() == "dns"]


def _name(row: Observation) -> str:
    explicit = row.get("name") or row.get("full_domain")
    if explicit:
        return str(explicit).rstrip(".")
    domain = str(row.get("domain") or "").rstrip(".")
    variant = str(row.get("variant") or row.get("subdomain") or "").lower()
    return f"www.{domain}" if domain and variant == "www" else domain


def _variant(row: Observation) -> str:
    variant = row.get("variant") or row.get("subdomain")
    if variant:
        return str(variant).lower()
    domain = str(row.get("domain") or "").rstrip(".")
    return "www" if domain and _name(row) == f"www.{domain}" else "root"


def _present(row: Observation) -> bool:
    if "present" in row and not _missing(row.get("present")):
        return _truthy(row.get("present"))
    status = str(row.get("status") or "").lower()
    if status:
        return status in {"present", "valid", "invalid", "valid_but_incompatible"}
    key = "has_svcb_record" if _rrtype(row) == "SVCB" else "has_https_record"
    return _truthy(row.get(key))


def _validation_status(row: Observation) -> str:
    validation = row.get("validation")
    if isinstance(validation, Mapping):
        status = validation.get("status")
    else:
        status = row.get("validation_status")
    if status:
        return str(status).lower()
    return "unknown" if _present(row) else "not_applicable"


def _records(row: Observation) -> list[Observation]:
    value = row.get("records")
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [record for record in value if isinstance(record, Mapping)]
    return []


def _effective_records(row: Observation) -> list[Observation]:
    value = row.get("effective_records")
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [record for record in value if isinstance(record, Mapping)]
    return _records(row)


def _has_native_records(row: Observation) -> bool:
    """Return whether the row uses the schema-v2 record representation."""
    return "records" in row or "effective_records" in row or row.get("schema_version") == 2


def _record_mode(record: Observation) -> str:
    mode = str(record.get("mode") or "").lower()
    if mode:
        return mode
    priority = record.get("priority")
    if _missing(priority):
        return "service"
    try:
        return "alias" if int(float(str(priority))) == 0 else "service"
    except TypeError, ValueError:
        return "service"


def _usable(row: Observation) -> bool:
    if not _present(row):
        return False
    if _validation_status(row) in {"invalid", "valid_but_incompatible"}:
        return False
    if _has_native_records(row):
        return bool(_eligible_records(row))
    # Legacy flat rows do not contain record-level validity annotations.
    return True


def _eligible_records(row: Observation) -> list[Observation]:
    """Return effective ServiceMode records explicitly marked usable."""
    return [
        record
        for record in _effective_records(row)
        if _record_mode(record) == "service"
        and record.get("usable") is True
        and not _truthy(record.get("ignored"))
    ]


def _params(record: Observation) -> Observation:
    value = record.get("params") or record.get("service_params") or {}
    return value if isinstance(value, Mapping) else {}


def _as_values(value: Any) -> list[str]:
    if _missing(value):
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [str(part).strip() for part in value if not _missing(part) and str(part).strip()]
    return [str(value).strip()]


def _protocols(row: Observation) -> set[str]:
    protocols: set[str] = set()
    if not _has_native_records(row):
        protocols.update(_as_values(row.get("alpn_protocols") or row.get("alpn")))
        features = row.get("features")
        if isinstance(features, Mapping):
            protocols.update(_as_values(features.get("alpn") or features.get("alpn_protocols")))
    for record in _eligible_records(row):
        protocols.update(_as_values(_params(record).get("alpn")))
    return protocols


def _has_parameter(row: Observation, names: Sequence[str], flat_names: Sequence[str]) -> bool:
    if not _has_native_records(row):
        features = row.get("features")
        if isinstance(features, Mapping):
            for name in names:
                if name in features and _truthy(features.get(name)):
                    return True
        for name in flat_names:
            if name in row and _truthy(row.get(name)):
                return True
    for record in _eligible_records(row):
        params = _params(record)
        if any(name in params and _truthy(params.get(name)) for name in names):
            return True
    return False


def _valid_ech(value: Any) -> bool:
    """Return whether an ECH parameter contains non-empty, valid bytes."""
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


def _has_ech(row: Observation) -> bool:
    if not _has_native_records(row):
        features = row.get("features")
        feature_value = (
            features.get("ech_advertised") or features.get("ech_deployment")
            if isinstance(features, Mapping)
            else None
        )
        return _truthy(row.get("ech_config")) or _truthy(feature_value)
    return any(_valid_ech(_params(record).get("ech")) for record in _eligible_records(row))


def _has_custom_port(row: Observation) -> bool:
    """Return whether an HTTPS ServiceMode record advertises a non-443 port."""

    def is_custom(value: Any) -> bool:
        if _missing(value):
            return False
        try:
            return int(value) != 443
        except TypeError, ValueError:
            return True

    if not _has_native_records(row):
        features = row.get("features")
        if isinstance(features, Mapping):
            ports = features.get("ports")
            if any(is_custom(value) for value in _as_values(ports)):
                return True
            if "custom_port" in features and _truthy(features.get("custom_port")):
                return True
        if is_custom(row.get("port")):
            return True
    for record in _eligible_records(row):
        if is_custom(_params(record).get("port")):
            return True
    return False


def _features(row: Observation) -> dict[str, bool]:
    protocols = _protocols(row)
    return {
        "h3_advertised": "h3" in protocols
        or (
            not _has_native_records(row)
            and _has_parameter(row, ("h3_advertised", "http3_support"), ("has_http3",))
        ),
        "ech_advertised": _has_ech(row),
        "custom_port": _has_custom_port(row),
        "ipv4_hints": _has_parameter(row, ("ipv4hint", "ipv4_hints"), ("ipv4hint",)),
        "ipv6_hints": _has_parameter(row, ("ipv6hint", "ipv6_hints"), ("ipv6hint",)),
        "alpn_advertised": bool(protocols),
        "no_default_alpn": _has_parameter(
            row, ("no-default-alpn", "no_default_alpn"), ("no_default_alpn",)
        ),
    }


def _ratio(count: int, total: int) -> float:
    return round(count / total * 100, 2) if total else 0.0


def _metric(count: int, total: int) -> dict[str, Any]:
    return {"count": count, "denominator": total, "percentage": _ratio(count, total)}


def calculate_adoption_rate(data: MetricInput) -> dict[str, Any]:
    """Calculate record adoption with RRtype-specific denominators.

    The legacy flat percentage keys remain available for one release.  New
    callers should use the nested ``https``, ``root_https``, ``www_https``, and
    ``svcb`` metrics, each of which includes its denominator.
    """
    rows = _dns_rows(data)
    https_rows = [row for row in rows if _rrtype(row) == "HTTPS"]
    svcb_rows = [row for row in rows if _rrtype(row) == "SVCB"]
    root_rows = [row for row in https_rows if _variant(row) == "root"]
    www_rows = [row for row in https_rows if _variant(row) == "www"]

    https_count = sum(_present(row) for row in https_rows)
    svcb_count = sum(_present(row) for row in svcb_rows)
    root_count = sum(_present(row) for row in root_rows)
    www_count = sum(_present(row) for row in www_rows)

    return {
        "https": _metric(https_count, len(https_rows)),
        "root_https": _metric(root_count, len(root_rows)),
        "www_https": _metric(www_count, len(www_rows)),
        "svcb": _metric(svcb_count, len(svcb_rows)),
        # One-release compatibility fields.
        "overall_adoption": _ratio(https_count, len(https_rows)),
        "root_adoption": _ratio(root_count, len(root_rows)),
        "www_adoption": _ratio(www_count, len(www_rows)),
        "svcb_adoption": _ratio(svcb_count, len(svcb_rows)),
        "https_count": https_count,
        "svcb_count": svcb_count,
    }


def calculate_validity_metrics(data: MetricInput) -> dict[str, Any]:
    """Summarize validity classifications for present RRsets."""
    rows = [row for row in _dns_rows(data) if _present(row)]

    def summarize(selected: list[Observation]) -> dict[str, Any]:
        counts = Counter(_validation_status(row) for row in selected)
        total = len(selected)
        result: dict[str, Any] = {"present": total}
        for status in ("valid", "invalid", "valid_but_incompatible", "unknown"):
            result[status] = _metric(counts[status], total)
        return result

    return {
        "overall": summarize(rows),
        "https": summarize([row for row in rows if _rrtype(row) == "HTTPS"]),
        "svcb": summarize([row for row in rows if _rrtype(row) == "SVCB"]),
    }


def calculate_feature_distribution(
    data: MetricInput, *, include_compatibility_aliases: bool = True
) -> dict[str, Any]:
    """Calculate optional feature adoption among usable HTTPS RRsets.

    Direct callers receive the deprecated ``http3_support`` and
    ``ech_deployment`` aliases for one release. Canonical schema-v2 metrics set
    ``include_compatibility_aliases=False`` and expose only the precise names.
    """
    eligible = [row for row in _dns_rows(data) if _rrtype(row) == "HTTPS" and _usable(row)]
    counts: Counter[str] = Counter()
    for row in eligible:
        counts.update(name for name, present in _features(row).items() if present)
    result: dict[str, Any] = {
        name: _metric(counts[name], len(eligible))
        for name in (
            "h3_advertised",
            "ech_advertised",
            "custom_port",
            "ipv4_hints",
            "ipv6_hints",
            "alpn_advertised",
            "no_default_alpn",
        )
    }
    if include_compatibility_aliases:
        result["http3_support"] = result["h3_advertised"]
        result["ech_deployment"] = result["ech_advertised"]
        result["_deprecated_aliases"] = {
            "http3_support": "h3_advertised",
            "ech_deployment": "ech_advertised",
        }
    return result


def calculate_metrics(data: MetricInput) -> dict[str, Any]:
    """Return the schema-v2 adoption, validity, and feature metrics."""
    rows = _dns_rows(data)
    https_rows = [row for row in rows if _rrtype(row) == "HTTPS"]
    svcb_rows = [row for row in rows if _rrtype(row) == "SVCB"]
    names = {_name(row) for row in rows if _name(row)}
    domains = {str(row.get("domain")) for row in rows if row.get("domain")}
    denominators = {
        "domains": len(domains),
        "observations": len(rows),
        "queried_names": len(names),
        "https_names": len({_name(row) for row in https_rows if _name(row)}),
        "svcb_names": len({_name(row) for row in svcb_rows if _name(row)}),
        "https_observations": len(https_rows),
        "svcb_observations": len(svcb_rows),
        "root_https_names": len([row for row in https_rows if _variant(row) == "root"]),
        "www_https_names": len([row for row in https_rows if _variant(row) == "www"]),
        "https_present_rrsets": sum(_present(row) for row in https_rows),
        "svcb_present_rrsets": sum(_present(row) for row in svcb_rows),
        "usable_https_rrsets": sum(_usable(row) for row in https_rows),
        "usable_svcb_rrsets": sum(_usable(row) for row in svcb_rows),
    }
    return {
        "denominators": denominators,
        "adoption": calculate_adoption_rate(rows),
        "validity": calculate_validity_metrics(rows),
        "features": calculate_feature_distribution(rows, include_compatibility_aliases=False),
        "compatibility": {
            "deprecated_feature_aliases": {
                "http3_support": "h3_advertised",
                "ech_deployment": "ech_advertised",
            }
        },
    }


def calculate_compliance_metrics(data: MetricInput) -> dict[str, Any]:
    """Compatibility alias for :func:`calculate_metrics`.

    The returned object intentionally has no ``average_compliance_score``.
    """
    metrics = calculate_metrics(data)
    metrics["total_domains_checked"] = metrics["denominators"]["https_names"]
    metrics["unique_domains"] = metrics["denominators"]["domains"]
    return metrics


def analyze_alpn_protocols(data: MetricInput) -> dict[str, int]:
    """Count each ALPN identifier once per usable HTTPS RRset."""
    counts: Counter[str] = Counter()
    for row in _dns_rows(data):
        if _rrtype(row) == "HTTPS" and _usable(row):
            counts.update(_protocols(row))
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def calculate_priority_distribution(data: MetricInput) -> dict[int, int]:
    """Count priorities across every record in present HTTPS RRsets."""
    counts: Counter[int] = Counter()
    for row in _dns_rows(data):
        if _rrtype(row) != "HTTPS" or not _present(row):
            continue
        records = _records(row)
        if records:
            values = [record.get("priority") for record in records]
        else:
            values = [row.get("https_priority")]
        for value in values:
            if not _missing(value):
                try:
                    counts[int(float(str(value)))] += 1
                except TypeError, ValueError:
                    logger.debug("Ignoring non-integer priority %r", value)
    return dict(sorted(counts.items()))


def identify_feature_leaders(data: MetricInput, top_n: int = 10) -> list[dict[str, Any]]:
    """Rank domains by observed optional features, without a compliance score."""
    grouped: dict[str, list[Observation]] = {}
    for row in _dns_rows(data):
        if _rrtype(row) == "HTTPS" and _usable(row):
            grouped.setdefault(str(row.get("domain") or _name(row)), []).append(row)

    leaders: list[dict[str, Any]] = []
    for domain, domain_rows in grouped.items():
        feature_names = sorted(
            {name for row in domain_rows for name, present in _features(row).items() if present}
        )
        leaders.append(
            {
                "domain": domain,
                "https_rrsets": len(domain_rows),
                "feature_count": len(feature_names),
                "features": feature_names,
            }
        )
    leaders.sort(key=lambda item: (-item["feature_count"], -item["https_rrsets"], item["domain"]))
    return leaders[:top_n]


def identify_top_performers(data: MetricInput, top_n: int = 10) -> list[tuple[str, float]]:
    """Compatibility alias returning ``(domain, feature_count)`` tuples."""
    return [
        (leader["domain"], float(leader["feature_count"]))
        for leader in identify_feature_leaders(data, top_n)
    ]


def calculate_error_statistics(data: MetricInput) -> dict[str, int]:
    """Count query errors without treating ordinary absence as invalidity."""
    errors: Counter[str] = Counter()
    for row in _dns_rows(data):
        value = row.get("error") or row.get("query_error")
        status = str(row.get("status") or row.get("query_status") or "").lower()
        normalized = str(value or "").strip().lower()
        if status in {"absent", "no_answer", "noanswer", "nxdomain"}:
            continue
        if normalized in {
            "nxdomain",
            "noanswer",
            "no answer",
            "no https record",
            "no svcb record",
        }:
            continue
        if not _missing(value):
            errors[str(value)] += 1
    return dict(sorted(errors.items(), key=lambda item: (-item[1], item[0])))
