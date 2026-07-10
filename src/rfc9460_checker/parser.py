"""JSON-safe parsing for complete HTTPS and SVCB RRsets."""

import base64
import binascii
import hashlib
import ipaddress
import logging
from collections.abc import Iterable, Mapping
from typing import Any

import dns.exception
import dns.name

from .models import (
    CLIENT_SUPPORTED_PARAM_KEYS,
    DECODED_PARAM_KEYS,
    PARAM_KEY_NAMES,
    PARSER_LIMITATIONS,
    SCHEMA_VERSION,
    SVCPARAM_REGISTRY,
    SVCPARAM_REGISTRY_METADATA,
    VALIDATOR_RULESET_VERSION,
    WIRE_DECODER_VERSION,
    param_key_name,
)
from .validator import validate_svcb_rrset
from .wire import decode_dns_message
from .wire_capture import DNSWireCapture

logger = logging.getLogger(__name__)


def parse_https_record(answers: Any, owner_name: str | None = None) -> dict[str, Any]:
    """Parse every HTTPS record and expose legacy summary fields as a view."""
    return _parse_rrset(answers, "HTTPS", owner_name=owner_name)


def parse_svcb_record(answers: Any, owner_name: str | None = None) -> dict[str, Any]:
    """Parse every SVCB record and expose legacy summary fields as a view."""
    return _parse_rrset(answers, "SVCB", owner_name=owner_name)


def parse_captured_response(
    source: Any,
    record_type: str,
    owner_name: str,
) -> dict[str, Any]:
    """Recover a requested RRset and evidence from transport-level captures.

    This path is used when dnspython rejects a message before it can construct
    an ``Answer``.  A captured matching RRset is still an observed deployment;
    strict wire errors make it present-and-invalid rather than a query error.
    """
    context = _wire_context(source, record_type, owner_name, None)
    records = context.pop("_records")
    if not records:
        context.pop("_ttl", None)
        resolver = context.pop("_resolver", None)
        resolver_port = context.pop("_resolver_port", None)
        context.pop("_rrset_owner_name", None)
        if resolver is not None:
            context["resolver"] = resolver
        if resolver_port is not None:
            context["resolver_port"] = resolver_port
        return context
    metadata = {
        "ttl": context.pop("_ttl"),
        "resolver": context.pop("_resolver"),
        "resolver_port": context.pop("_resolver_port"),
        "query_name": owner_name,
        "rrset_owner_name": context.pop("_rrset_owner_name"),
        "canonical_name": None,
    }
    return _result_from_records(records, record_type, owner_name, metadata, context)


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
    context = _wire_context(answers, record_type, query_name, rrset_owner_name)
    wire_records = context.pop("_records")
    for internal_field in ("_ttl", "_resolver", "_resolver_port", "_rrset_owner_name"):
        context.pop(internal_field, None)
    try:
        rdata_values = list(answers)
    except TypeError:
        rdata_values = []
    parsed_records = parse_svcb_records(rdata_values, record_type, rrset_owner_name)
    if wire_records:
        records = wire_records
        _merge_presentations(records, rdata_values)
    else:
        records = parsed_records
    if not records:
        return {}

    return _result_from_records(records, record_type, query_name, metadata, context)


def _result_from_records(
    records: list[dict[str, Any]],
    record_type: str,
    query_name: str | None,
    metadata: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    """Build the public RRset shape from normalized and wire-derived records."""
    rrset_owner_name = metadata["rrset_owner_name"] or query_name

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
        "wire_decoder_version": WIRE_DECODER_VERSION,
        "parser_limitations": list(PARSER_LIMITATIONS),
        "validation_status": validation["status"],
        "validation_issues": validation["issues"],
        "rrset_validation": validation,
    }
    result.update(context)
    result.update(_legacy_projection(records, record_type))
    return result


def _wire_context(
    source: Any,
    record_type: str,
    query_name: str | None,
    preferred_owner: str | None,
) -> dict[str, Any]:
    """Decode captured responses and select the response used for this RRset."""
    captures_value = getattr(source, "_rfc9460_wire_captures", [])
    captures = (
        [capture for capture in captures_value if isinstance(capture, DNSWireCapture)]
        if isinstance(captures_value, list)
        else []
    )
    capture_metadata_value = getattr(source, "_rfc9460_wire_capture_metadata", None)
    capture_metadata = (
        {
            key: value
            for key, value in capture_metadata_value.items()
            if isinstance(key, str)
            and isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
        }
        if isinstance(capture_metadata_value, dict)
        else None
    )
    unavailable: dict[str, Any] = {
        "wire_decoder_version": WIRE_DECODER_VERSION,
        "wire_capture": {
            "format_version": 1,
            "responses": [],
            "capture_metadata": capture_metadata,
            "unavailable_reason": (
                "the DNS transport capture layer ran but retained no response"
                if capture_metadata is not None
                else "input did not pass through the DNS transport capture layer"
            ),
        },
        "wire_validation": {
            "format_version": 1,
            "ruleset_version": WIRE_DECODER_VERSION,
            "status": "not_collected",
            "issues": [],
            "responses": [],
        },
        "_records": [],
        "_ttl": None,
        "_resolver": None,
        "_resolver_port": None,
        "_rrset_owner_name": preferred_owner or query_name,
    }
    if not captures:
        return unavailable

    expected_type = 65 if record_type.upper() == "HTTPS" else 64
    decoded_responses = [decode_dns_message(capture.response_wire) for capture in captures]
    selected_wires = _accepted_response_wires(source, query_name)
    selected_wire_set = set(selected_wires)
    selected_index: int | None = None
    for selected_wire in selected_wires:
        for index in range(len(captures) - 1, -1, -1):
            if captures[index].response_wire == selected_wire:
                selected_index = index
                break
        if selected_index is not None:
            break

    query_matches = [
        _capture_matches_query(capture, decoded, expected_type, query_name)
        for capture, decoded in zip(captures, decoded_responses)
    ]
    candidates_by_response = []
    for index, decoded in enumerate(decoded_responses):
        candidates = _matching_wire_records(decoded, expected_type, query_name, preferred_owner)
        header = decoded.get("header")
        truncated = isinstance(header, dict) and header.get("truncated") is True
        noerror = isinstance(header, dict) and header.get("rcode") == 0
        if selected_index != index and (not query_matches[index] or truncated or not noerror):
            candidates = []
        candidates_by_response.append(candidates)
    if selected_index is None:
        selected_index = next(
            (index for index, records in enumerate(candidates_by_response) if records),
            next((index for index, matches in enumerate(query_matches) if matches), None),
        )
    chosen_index = selected_index if selected_index is not None else 0

    capture_responses: list[dict[str, Any]] = []
    validation_responses: list[dict[str, Any]] = []
    for index, (capture, decoded, candidates) in enumerate(
        zip(captures, decoded_responses, candidates_by_response)
    ):
        evidence = capture.evidence(sequence=index)
        used = index == selected_index
        response_issues = list(decoded.get("issues", []))
        header = decoded.get("header")
        if isinstance(header, dict) and header.get("truncated") is True:
            response_issues.append(
                {
                    "code": "truncated_dns_response",
                    "severity": "warning",
                    "message": "The UDP response set TC=1 and is not a complete answer",
                    "offset": 2,
                    "length": 2,
                }
            )
        for record in candidates:
            svcb = record.get("svcb", {})
            if isinstance(svcb, dict):
                response_issues.extend(svcb.get("issues", []))
        if any(
            isinstance(issue, dict) and issue.get("severity") == "error"
            for issue in response_issues
        ):
            response_status = "failed"
        elif candidates:
            response_status = "passed"
        else:
            response_status = "not_applicable"
        rdata = []
        for record in candidates:
            svcb = record.get("svcb", {})
            if not isinstance(svcb, dict):
                continue
            rdata.append(
                {
                    "section": record.get("section"),
                    "rr_index": record.get("section_index"),
                    "owner_name": record.get("owner"),
                    "rrtype": record.get("type"),
                    "rrclass": record.get("class"),
                    "ttl": record.get("ttl"),
                    "offset": record.get("rdata_offset"),
                    "bytes": svcb.get("bytes"),
                }
            )
        capture_responses.append(
            {
                "response_index": index,
                "query_name": query_name,
                "rrtype": expected_type,
                "resolver": evidence.get("resolver"),
                "resolver_port": evidence.get("resolver_port"),
                "transport": capture.transport,
                "accepted_by_dnspython": capture.response_wire in selected_wire_set,
                "matches_query": query_matches[index],
                "used_for_observation": used,
                "message": decoded.get("message"),
                "dns_header": decoded.get("header"),
                "rdata": rdata,
            }
        )
        validation_responses.append(
            {
                "response_index": index,
                "message_sha256": decoded.get("message", {}).get("sha256"),
                "status": response_status,
                "issues": response_issues,
            }
        )

    selected_records = candidates_by_response[chosen_index] if selected_index is not None else []
    normalized_records = [_record_from_wire(record, chosen_index) for record in selected_records]
    selected_packet_issues = decoded_responses[chosen_index].get("issues", [])
    if normalized_records and isinstance(selected_packet_issues, list):
        normalized_records[0]["wire"]["issues"] = [
            *selected_packet_issues,
            *normalized_records[0]["wire"].get("issues", []),
        ]
    normalized_records.sort(
        key=lambda record: (
            (record.get("priority") if isinstance(record.get("priority"), int) else 65536),
            str(record.get("target", "")),
            str(record.get("rdata_sha256", "")),
        )
    )
    selected_validation = validation_responses[chosen_index]
    selected_capture = capture_responses[chosen_index]
    selected_owner = (
        str(selected_records[0].get("owner")) if selected_records else preferred_owner or query_name
    )
    return {
        "wire_decoder_version": WIRE_DECODER_VERSION,
        "wire_capture": {
            "format_version": 1,
            "responses": capture_responses,
            "capture_metadata": capture_metadata,
            "unavailable_reason": (
                None if selected_index is not None else "captured packets did not match the query"
            ),
        },
        "wire_validation": {
            "format_version": 1,
            "ruleset_version": WIRE_DECODER_VERSION,
            "status": selected_validation["status"],
            "issues": selected_validation["issues"],
            "responses": validation_responses,
        },
        "_records": normalized_records,
        "_ttl": selected_records[0].get("ttl") if selected_records else None,
        "_resolver": selected_capture.get("resolver") if selected_index is not None else None,
        "_resolver_port": (
            selected_capture.get("resolver_port") if selected_index is not None else None
        ),
        "_rrset_owner_name": selected_owner,
    }


def _accepted_response_wires(source: Any, query_name: str | None) -> list[bytes]:
    """Extract parser-accepted message bytes without reserializing a response."""
    candidates: list[Any] = []
    response_value = getattr(source, "response", None)
    if callable(response_value):
        try:
            candidates.append(response_value())
        except AttributeError, KeyError, TypeError:
            pass
    elif response_value is not None:
        candidates.append(response_value)

    kwargs = getattr(source, "kwargs", None)
    responses = kwargs.get("responses") if isinstance(kwargs, dict) else None
    if isinstance(responses, Mapping):
        matching: list[Any] = []
        others: list[Any] = []
        for name, response in responses.items():
            if query_name is not None and _normalized_dns_name(str(name)) == _normalized_dns_name(
                query_name
            ):
                matching.append(response)
            else:
                others.append(response)
        candidates.extend(matching or others)

    wires: list[bytes] = []
    for candidate in candidates:
        wire = getattr(candidate, "wire", None)
        if isinstance(wire, bytes) and wire not in wires:
            wires.append(wire)
    return wires


def _matching_wire_records(
    decoded: dict[str, Any],
    expected_type: int,
    query_name: str | None,
    preferred_owner: str | None,
) -> list[dict[str, Any]]:
    records = [
        record
        for record in decoded.get("records", [])
        if isinstance(record, dict)
        and record.get("section") == "answer"
        and record.get("type") == expected_type
        and record.get("class") == 1
    ]
    if not records:
        return []
    desired = preferred_owner
    if desired is None and query_name is not None:
        desired = _wire_terminal_owner(decoded, query_name)
    if desired is None:
        return []
    return [
        record
        for record in records
        if _normalized_dns_name(str(record.get("owner", ""))) == _normalized_dns_name(desired)
    ]


def _wire_terminal_owner(decoded: dict[str, Any], query_name: str) -> str | None:
    """Follow an unambiguous answer-section CNAME/DNAME chain.

    The independent decoder exposes only aliases whose complete RDATA was
    bounded and consumed.  Ambiguous owners, loops, and invalid names fail
    closed instead of attributing an unrelated RRset to the query.
    """
    current = _dns_name(query_name)
    if current is None:
        return None
    aliases_value = decoded.get("aliases", [])
    aliases = [
        alias
        for alias in aliases_value
        if isinstance(alias, dict)
        and alias.get("section") == "answer"
        and alias.get("class") == 1
        and alias.get("type") in {5, 39}
    ]
    visited: set[str] = set()
    for _ in range(min(len(aliases) + 1, 128)):
        identity = current.canonicalize().to_text()
        if identity in visited:
            return None
        visited.add(identity)

        cname_targets = {
            target.canonicalize().to_text(): target
            for alias in aliases
            if alias.get("type") == 5
            and (owner := _dns_name(str(alias.get("owner", "")))) is not None
            and owner == current
            and (target := _dns_name(str(alias.get("target", "")))) is not None
        }
        if cname_targets:
            if len(cname_targets) != 1:
                return None
            current = next(iter(cname_targets.values()))
            continue

        dname_targets: list[tuple[int, str, dns.name.Name]] = []
        for alias in aliases:
            if alias.get("type") != 39:
                continue
            owner = _dns_name(str(alias.get("owner", "")))
            target = _dns_name(str(alias.get("target", "")))
            if (
                owner is None
                or target is None
                or current == owner
                or not current.is_subdomain(owner)
            ):
                continue
            try:
                synthesized = current.relativize(owner).concatenate(target)
            except dns.name.NameTooLong:
                return None
            dname_targets.append(
                (len(owner.labels), synthesized.canonicalize().to_text(), synthesized)
            )
        if dname_targets:
            closest = max(item[0] for item in dname_targets)
            synthesized_names = {
                identity: name
                for label_count, identity, name in dname_targets
                if label_count == closest
            }
            if len(synthesized_names) != 1:
                return None
            current = next(iter(synthesized_names.values()))
            continue
        return current.to_text()
    return None


def _capture_matches_query(
    capture: DNSWireCapture,
    response: dict[str, Any],
    expected_type: int,
    query_name: str | None,
) -> bool:
    """Verify the request/response transaction before pre-parser recovery."""
    if capture.query_wire is None or query_name is None:
        return False
    query = decode_dns_message(capture.query_wire)
    query_header = query.get("header")
    response_header = response.get("header")
    if not isinstance(query_header, dict) or not isinstance(response_header, dict):
        return False
    query_flags = query_header.get("flags")
    response_flags = response_header.get("flags")
    if not isinstance(query_flags, int) or not isinstance(response_flags, int):
        return False
    if query_flags & 0x8000 or not response_flags & 0x8000:
        return False
    if query_header.get("id") != response_header.get("id"):
        return False
    if (query_flags & 0x7800) != (response_flags & 0x7800):
        return False
    query_questions = query.get("questions")
    response_questions = response.get("questions")
    if not isinstance(query_questions, list) or not isinstance(response_questions, list):
        return False
    if len(query_questions) != 1 or len(response_questions) != 1:
        return False
    question = query_questions[0]
    echoed_question = response_questions[0]
    return (
        isinstance(question, dict)
        and isinstance(echoed_question, dict)
        and question.get("type") == expected_type
        and question.get("class") == 1
        and echoed_question.get("type") == question.get("type")
        and echoed_question.get("class") == question.get("class")
        and _normalized_dns_name(str(question.get("name", ""))) == _normalized_dns_name(query_name)
        and _normalized_dns_name(str(echoed_question.get("name", "")))
        == _normalized_dns_name(str(question.get("name", "")))
    )


def _record_from_wire(wire_record: dict[str, Any], response_index: int) -> dict[str, Any]:
    svcb_value = wire_record.get("svcb")
    svcb = svcb_value if isinstance(svcb_value, dict) else {}
    priority = svcb.get("priority")
    target = svcb.get("target")
    raw_blob_value = svcb.get("bytes")
    raw_blob: dict[str, Any] = raw_blob_value if isinstance(raw_blob_value, dict) else {}
    raw_bytes = _blob_bytes(raw_blob)
    record: dict[str, Any] = {
        "priority": priority,
        "target": target if isinstance(target, str) else "",
        "mode": "alias" if priority == 0 else "service",
        "params": {},
        "param_details": [],
        "raw": f"\\# {len(raw_bytes)} {raw_bytes.hex()}",
        "presentation": f"\\# {len(raw_bytes)} {raw_bytes.hex()}",
        "rdata_sha256": raw_blob.get("sha256"),
        "wire": {
            "response_index": response_index,
            "status": svcb.get("status"),
            "rdata_offset": wire_record.get("rdata_offset"),
            "rdata_length": wire_record.get("rdlength"),
            "issues": svcb.get("issues", []),
            "params": [],
        },
    }
    params_value = svcb.get("params")
    params = params_value if isinstance(params_value, list) else []
    for param in params:
        if not isinstance(param, dict) or not isinstance(param.get("key"), int):
            continue
        key = param["key"]
        blob_value = param.get("bytes")
        blob: dict[str, Any] = blob_value if isinstance(blob_value, dict) else {}
        value = _blob_bytes(blob)
        name = param_key_name(key)
        detail: dict[str, Any] = {
            "key": key,
            "name": name,
            "known": key in PARAM_KEY_NAMES,
            "registered": key in PARAM_KEY_NAMES,
            "decoded": key in DECODED_PARAM_KEYS,
            "client_supported": key in CLIENT_SUPPORTED_PARAM_KEYS,
            "registry_reference": SVCPARAM_REGISTRY.get(key, {}).get("reference"),
            "raw": blob,
        }
        try:
            decoded = _decode_param(key, value)
        except (TypeError, ValueError, UnicodeError) as error:
            decoded = blob
            if priority != 0:
                detail["parse_error"] = f"Could not decode {name}: {error}"
        detail["value"] = decoded
        record["params"][name] = decoded
        record["param_details"].append(detail)
        record["wire"]["params"].append(
            {
                "key": key,
                "header_offset": param.get("header_offset"),
                "value_offset": param.get("value_offset"),
                "declared_length": param.get("declared_length"),
                "value_length": blob.get("length"),
                "value_sha256": blob.get("sha256"),
            }
        )
    return record


def _blob_bytes(blob: dict[str, Any]) -> bytes:
    if blob.get("encoding") != "base64" or not isinstance(blob.get("value"), str):
        return b""
    try:
        return base64.b64decode(blob["value"], validate=True)
    except binascii.Error, ValueError:
        return b""


def _merge_presentations(wire_records: list[dict[str, Any]], rdata_values: list[Any]) -> None:
    candidates: dict[str, list[str]] = {}
    for rdata in rdata_values:
        to_wire = getattr(rdata, "to_wire", None)
        if not callable(to_wire):
            continue
        try:
            normalized_wire = to_wire()
        except AttributeError, TypeError, ValueError:
            continue
        if not isinstance(normalized_wire, bytes):
            continue
        digest = hashlib.sha256(normalized_wire).hexdigest()
        candidates.setdefault(digest, []).append(_rdata_text(rdata))
    for wire_record in wire_records:
        record_digest = wire_record.get("rdata_sha256")
        presentations = candidates.get(str(record_digest), [])
        if presentations:
            presentation = presentations.pop(0)
            wire_record["raw"] = presentation
            wire_record["presentation"] = presentation


def _normalized_dns_name(name: str) -> str:
    parsed = _dns_name(name)
    return parsed.canonicalize().to_text() if parsed is not None else name.rstrip(".").casefold()


def _dns_name(name: str) -> dns.name.Name | None:
    try:
        return dns.name.from_text(name)
    except dns.exception.DNSException, UnicodeError, ValueError:
        return None


def _parse_rdata(rdata: Any) -> dict[str, Any]:
    priority = getattr(rdata, "priority", None)
    target_value = getattr(rdata, "target", None)
    target = str(target_value) if target_value is not None else ""
    presentation = _rdata_text(rdata)
    record: dict[str, Any] = {
        "priority": priority,
        "target": target,
        "mode": "alias" if priority == 0 else "service",
        "params": {},
        "param_details": [],
        "raw": presentation,
        "presentation": presentation,
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
