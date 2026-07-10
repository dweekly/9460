"""Bounded, JSON-safe DNS and RFC 9460 wire decoding.

The decoder deliberately does not use dnspython's RDATA objects.  It operates
on the datagram or TCP message body captured at the socket boundary, before a
library can reject or normalize duplicate keys, parameter order, or names.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

SVCB_RDTYPES = {64: "SVCB", 65: "HTTPS"}
DNS_HEADER_LENGTH = 12
MAX_DNS_RECORDS = 4096
MAX_NAME_JUMPS = 128
ECH_CONFIG_VERSION = 0xFE0D


def wire_evidence(value: bytes) -> dict[str, Any]:
    """Return canonical base64, length, and SHA-256 evidence for bytes."""
    return {
        "encoding": "base64",
        "value": base64.b64encode(value).decode("ascii"),
        "length": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
    }


def _issue(
    code: str,
    message: str,
    *,
    offset: int,
    severity: str = "error",
    length: int | None = None,
    key: int | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "code": code,
        "severity": severity,
        "message": message,
        "offset": offset,
    }
    if length is not None:
        result["length"] = length
    if key is not None:
        result["key"] = key
    return result


def _name_text(labels: list[bytes]) -> str:
    if not labels:
        return "."
    rendered: list[str] = []
    for label in labels:
        text = ""
        for octet in label:
            if 0x21 <= octet <= 0x7E and octet not in {0x2E, 0x5C}:
                text += chr(octet)
            else:
                text += f"\\{octet:03d}"
        rendered.append(text)
    return ".".join(rendered) + "."


def _decode_name(
    message: bytes,
    offset: int,
    limit: int,
    *,
    allow_compression: bool,
    compression_code: str,
    max_jumps: int,
) -> tuple[str | None, int, list[dict[str, Any]]]:
    """Decode one DNS name and report bytes consumed at its original location."""
    issues: list[dict[str, Any]] = []
    labels: list[bytes] = []
    cursor = offset
    consumed = 0
    jumped = False
    jumps = 0
    visited: set[int] = set()
    expanded_length = 1  # Root terminator.

    while True:
        current_limit = len(message) if jumped else limit
        if cursor >= current_limit:
            issues.append(
                _issue(
                    "truncated_dns_name",
                    "DNS name ends before its root label",
                    offset=cursor,
                )
            )
            return None, consumed, issues
        label_length = message[cursor]

        if label_length == 0:
            if not jumped:
                consumed += 1
            return _name_text(labels), consumed, issues

        if label_length & 0xC0 == 0xC0:
            if cursor + 1 >= current_limit:
                issues.append(
                    _issue(
                        "truncated_compression_pointer",
                        "DNS compression pointer is missing its second octet",
                        offset=cursor,
                    )
                )
                return None, consumed, issues
            pointer = ((label_length & 0x3F) << 8) | message[cursor + 1]
            if not allow_compression:
                issues.append(
                    _issue(
                        compression_code,
                        "RFC 9460 TargetName must be uncompressed",
                        offset=cursor,
                        length=2,
                    )
                )
            if not jumped:
                consumed += 2
            if pointer >= len(message):
                issues.append(
                    _issue(
                        "compression_pointer_out_of_bounds",
                        f"DNS compression pointer {pointer} is outside the message",
                        offset=cursor,
                        length=2,
                    )
                )
                return None, consumed, issues
            if pointer in visited or jumps >= max_jumps:
                issues.append(
                    _issue(
                        "compression_pointer_loop",
                        "DNS compression pointer chain is cyclic or too deep",
                        offset=cursor,
                        length=2,
                    )
                )
                return None, consumed, issues
            visited.add(pointer)
            cursor = pointer
            jumped = True
            jumps += 1
            continue

        if label_length & 0xC0:
            issues.append(
                _issue(
                    "invalid_dns_label_type",
                    "DNS name uses a reserved label type",
                    offset=cursor,
                    length=1,
                )
            )
            return None, consumed, issues

        label_end = cursor + 1 + label_length
        if label_end > current_limit:
            issues.append(
                _issue(
                    "truncated_dns_label",
                    "DNS label extends beyond its containing field",
                    offset=cursor,
                    length=max(current_limit - cursor, 0),
                )
            )
            return None, consumed, issues
        expanded_length += label_length + 1
        if expanded_length > 255:
            issues.append(
                _issue(
                    "dns_name_too_long",
                    "Expanded DNS name exceeds 255 octets",
                    offset=offset,
                )
            )
            return None, consumed, issues
        labels.append(message[cursor + 1 : label_end])
        if not jumped:
            consumed += label_length + 1
        cursor = label_end


def _ech_config_contents_issues(contents: bytes, offset: int) -> list[dict[str, Any]]:
    """Validate the ECHConfigContents structure standardized for version 0xfe0d."""

    def invalid(message: str, field_offset: int, length: int | None = None) -> dict[str, Any]:
        return _issue(
            "invalid_ech_config_contents",
            message,
            offset=field_offset,
            length=length,
            key=5,
        )

    cursor = 0
    # config_id (uint8) and kem_id (uint16).
    if len(contents) < 3:
        return [
            invalid(
                "ECHConfigContents is missing config_id or kem_id",
                offset,
                len(contents),
            )
        ]
    cursor = 3

    # public_key<1..2^16-1>.
    if cursor + 2 > len(contents):
        return [invalid("ECHConfigContents is missing the public_key length", offset + cursor)]
    public_key_length = int.from_bytes(contents[cursor : cursor + 2], "big")
    public_key_length_offset = offset + cursor
    cursor += 2
    if public_key_length == 0:
        return [
            invalid(
                "ECHConfigContents public_key must contain at least one octet",
                public_key_length_offset,
                2,
            )
        ]
    if cursor + public_key_length > len(contents):
        return [
            invalid(
                "ECHConfigContents public_key exceeds the enclosing ECHConfig",
                public_key_length_offset,
                len(contents) - (cursor - 2),
            )
        ]
    cursor += public_key_length

    # HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>.
    if cursor + 2 > len(contents):
        return [invalid("ECHConfigContents is missing the cipher_suites length", offset + cursor)]
    cipher_suites_length = int.from_bytes(contents[cursor : cursor + 2], "big")
    cipher_suites_length_offset = offset + cursor
    cursor += 2
    if cipher_suites_length < 4 or cipher_suites_length > 65532:
        return [
            invalid(
                "ECHConfigContents cipher_suites must contain at least one four-octet suite",
                cipher_suites_length_offset,
                2,
            )
        ]
    if cipher_suites_length % 4:
        return [
            invalid(
                "ECHConfigContents cipher_suites length must be a multiple of four",
                cipher_suites_length_offset,
                2,
            )
        ]
    if cursor + cipher_suites_length > len(contents):
        return [
            invalid(
                "ECHConfigContents cipher_suites exceeds the enclosing ECHConfig",
                cipher_suites_length_offset,
                len(contents) - (cursor - 2),
            )
        ]
    cursor += cipher_suites_length

    # maximum_name_length (uint8) and public_name<1..255>.
    if cursor >= len(contents):
        return [invalid("ECHConfigContents is missing maximum_name_length", offset + cursor)]
    cursor += 1
    if cursor >= len(contents):
        return [invalid("ECHConfigContents is missing the public_name length", offset + cursor)]
    public_name_length = contents[cursor]
    public_name_length_offset = offset + cursor
    cursor += 1
    if public_name_length == 0:
        return [
            invalid(
                "ECHConfigContents public_name must contain at least one octet",
                public_name_length_offset,
                1,
            )
        ]
    if cursor + public_name_length > len(contents):
        return [
            invalid(
                "ECHConfigContents public_name exceeds the enclosing ECHConfig",
                public_name_length_offset,
                len(contents) - (cursor - 1),
            )
        ]
    cursor += public_name_length

    # Extension extensions<0..2^16-1>.
    if cursor + 2 > len(contents):
        return [invalid("ECHConfigContents is missing the extensions length", offset + cursor)]
    extensions_length = int.from_bytes(contents[cursor : cursor + 2], "big")
    extensions_length_offset = offset + cursor
    cursor += 2
    extensions_end = cursor + extensions_length
    if extensions_end != len(contents):
        wording = "exceeds" if extensions_end > len(contents) else "does not consume"
        return [
            invalid(
                f"ECHConfigContents extensions vector {wording} the enclosing ECHConfig",
                extensions_length_offset,
                len(contents) - (cursor - 2),
            )
        ]

    extension_types: set[int] = set()
    while cursor < extensions_end:
        if extensions_end - cursor < 4:
            return [
                invalid(
                    "ECH extension is missing its type or data length",
                    offset + cursor,
                    extensions_end - cursor,
                )
            ]
        extension_type = int.from_bytes(contents[cursor : cursor + 2], "big")
        extension_length = int.from_bytes(contents[cursor + 2 : cursor + 4], "big")
        extension_offset = offset + cursor
        cursor += 4
        if extension_type in extension_types:
            return [
                _issue(
                    "duplicate_ech_extension_type",
                    f"ECHConfigContents repeats extension type {extension_type}",
                    offset=extension_offset,
                    length=2,
                    key=5,
                )
            ]
        extension_types.add(extension_type)
        if cursor + extension_length > extensions_end:
            return [
                invalid(
                    "ECH extension data exceeds the extensions vector",
                    extension_offset,
                    extensions_end - (cursor - 4),
                )
            ]
        cursor += extension_length

    return []


def _ech_config_list_issues(value: bytes, offset: int) -> list[dict[str, Any]]:
    """Validate an RFC 9849 ECHConfigList, including known-version contents."""
    if len(value) < 2:
        return [
            _issue(
                "invalid_ech_config_list_length",
                "ECHConfigList is missing its two-octet vector length",
                offset=offset,
                length=len(value),
                key=5,
            )
        ]

    declared_length = int.from_bytes(value[:2], "big")
    if declared_length < 4 or declared_length != len(value) - 2:
        return [
            _issue(
                "invalid_ech_config_list_length",
                "ECHConfigList length must match its value and contain at least one ECHConfig",
                offset=offset,
                length=2,
                key=5,
            )
        ]

    cursor = 2
    end = len(value)
    while cursor < end:
        config_offset = cursor
        if end - cursor < 4:
            return [
                _issue(
                    "truncated_ech_config",
                    "ECHConfig is missing its version or contents length",
                    offset=offset + cursor,
                    length=end - cursor,
                    key=5,
                )
            ]
        version = int.from_bytes(value[cursor : cursor + 2], "big")
        contents_length = int.from_bytes(value[cursor + 2 : cursor + 4], "big")
        cursor += 4
        contents_end = cursor + contents_length
        if contents_end > end:
            return [
                _issue(
                    "truncated_ech_config",
                    "ECHConfig contents exceed the enclosing ECHConfigList",
                    offset=offset + config_offset,
                    length=end - config_offset,
                    key=5,
                )
            ]
        if version == ECH_CONFIG_VERSION:
            issues = _ech_config_contents_issues(value[cursor:contents_end], offset + cursor)
            if issues:
                return issues
        cursor = contents_end

    return []


def _param_format_issues(key: int, value: bytes, offset: int) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if key == 0:
        if not value or len(value) % 2:
            issues.append(
                _issue(
                    "invalid_mandatory_wire_length",
                    "mandatory must contain one or more 16-bit SvcParamKeys",
                    offset=offset,
                    length=len(value),
                    key=key,
                )
            )
        else:
            keys = [
                int.from_bytes(value[index : index + 2], "big") for index in range(0, len(value), 2)
            ]
            for previous, current in zip(keys, keys[1:]):
                if current == previous:
                    issues.append(
                        _issue(
                            "duplicate_mandatory_key",
                            f"mandatory repeats SvcParamKey {current}",
                            offset=offset,
                            length=len(value),
                            key=current,
                        )
                    )
                    break
                if current < previous:
                    issues.append(
                        _issue(
                            "misordered_mandatory_keys",
                            "mandatory keys are not in strictly increasing wire order",
                            offset=offset,
                            length=len(value),
                            key=current,
                        )
                    )
                    break
    elif key == 1:
        cursor = 0
        if not value:
            issues.append(
                _issue(
                    "empty_alpn",
                    "alpn must contain at least one length-prefixed ALPN ID",
                    offset=offset,
                    length=0,
                    key=key,
                )
            )
        while cursor < len(value):
            size = value[cursor]
            if size == 0:
                issues.append(
                    _issue(
                        "empty_alpn_id",
                        "ALPN IDs must contain at least one octet",
                        offset=offset + cursor,
                        length=1,
                        key=key,
                    )
                )
                break
            if cursor + 1 + size > len(value):
                issues.append(
                    _issue(
                        "truncated_alpn_id",
                        "Length-prefixed ALPN ID exceeds the SvcParamValue",
                        offset=offset + cursor,
                        length=len(value) - cursor,
                        key=key,
                    )
                )
                break
            cursor += size + 1
    elif key == 2 and value:
        issues.append(
            _issue(
                "nonempty_no_default_alpn",
                "no-default-alpn wire value must be empty",
                offset=offset,
                length=len(value),
                key=key,
            )
        )
    elif key == 3 and len(value) != 2:
        issues.append(
            _issue(
                "invalid_port_wire_length",
                "port wire value must be exactly two octets",
                offset=offset,
                length=len(value),
                key=key,
            )
        )
    elif key == 4 and (not value or len(value) % 4):
        issues.append(
            _issue(
                "invalid_ipv4hint_wire_length",
                "ipv4hint must contain one or more complete IPv4 addresses",
                offset=offset,
                length=len(value),
                key=key,
            )
        )
    elif key == 5:
        if not value:
            issues.append(
                _issue(
                    "empty_ech",
                    "ech wire value must not be empty",
                    offset=offset,
                    length=0,
                    key=key,
                )
            )
        else:
            issues.extend(_ech_config_list_issues(value, offset))
    elif key == 6 and (not value or len(value) % 16):
        issues.append(
            _issue(
                "invalid_ipv6hint_wire_length",
                "ipv6hint must contain one or more complete IPv6 addresses",
                offset=offset,
                length=len(value),
                key=key,
            )
        )
    return issues


def _decode_svcb_at(
    message: bytes,
    start: int,
    end: int,
    *,
    max_name_jumps: int,
) -> dict[str, Any]:
    raw = message[start:end]
    issues: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "rdata_offset": start,
        "bytes": wire_evidence(raw),
        "params": [],
    }
    if end - start < 2:
        issues.append(
            _issue(
                "truncated_svcpriority",
                "SVCB RDATA ends within the two-octet SvcPriority",
                offset=start,
                length=max(end - start, 0),
            )
        )
        result.update({"priority": None, "target": None, "mode": None})
        result["issues"] = issues
        result["status"] = "invalid"
        return result

    priority = int.from_bytes(message[start : start + 2], "big")
    result["priority"] = priority
    result["mode"] = "alias" if priority == 0 else "service"
    target, target_length, name_issues = _decode_name(
        message,
        start + 2,
        end,
        allow_compression=False,
        compression_code="compressed_target_name",
        max_jumps=max_name_jumps,
    )
    issues.extend(name_issues)
    result["target"] = target
    result["target_offset"] = start + 2
    result["target_length"] = target_length
    if target is None or target_length == 0:
        result["issues"] = issues
        result["status"] = "invalid"
        return result

    cursor = start + 2 + target_length
    previous_key: int | None = None
    params: list[dict[str, Any]] = []
    while cursor < end:
        remaining = end - cursor
        if remaining < 4:
            issues.append(
                _issue(
                    "truncated_svcparam_header",
                    "RDATA ends within an SvcParam key/length header",
                    offset=cursor,
                    length=remaining,
                )
            )
            break
        key = int.from_bytes(message[cursor : cursor + 2], "big")
        declared_length = int.from_bytes(message[cursor + 2 : cursor + 4], "big")
        value_offset = cursor + 4
        value_end = value_offset + declared_length
        if previous_key is not None and key <= previous_key:
            code = "duplicate_svcparam_key" if key == previous_key else "misordered_svcparam_key"
            wording = "duplicates" if key == previous_key else "follows a larger key"
            issues.append(
                _issue(
                    code,
                    f"SvcParamKey {key} {wording}; keys must be strictly increasing",
                    offset=cursor,
                    length=2,
                    key=key,
                )
            )
        previous_key = key
        available_end = min(value_end, end)
        value = message[value_offset:available_end]
        param = {
            "key": key,
            "header_offset": cursor,
            "value_offset": value_offset,
            "declared_length": declared_length,
            "bytes": wire_evidence(value),
        }
        params.append(param)
        if value_end > end:
            issues.append(
                _issue(
                    "truncated_svcparam_value",
                    f"SvcParamKey {key} declares {declared_length} value octets, "
                    f"but only {end - value_offset} remain",
                    offset=value_offset,
                    length=max(end - value_offset, 0),
                    key=key,
                )
            )
            break
        if priority != 0:
            issues.extend(_param_format_issues(key, value, value_offset))
        cursor = value_end

    result["params"] = params
    if priority == 0 and params:
        issues.append(
            _issue(
                "alias_params_ignored",
                "AliasMode SvcParams are present and must be ignored",
                offset=params[0]["header_offset"],
                severity="warning",
            )
        )
    result["issues"] = issues
    result["status"] = (
        "invalid" if any(issue.get("severity") == "error" for issue in issues) else "valid"
    )
    return result


def _shift_offsets(value: Any, amount: int) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.endswith("offset") and isinstance(child, int):
                value[key] = child + amount
            else:
                _shift_offsets(child, amount)
    elif isinstance(value, list):
        for child in value:
            _shift_offsets(child, amount)


def decode_svcb_rdata(
    rdata: bytes,
    *,
    rdata_offset: int = 0,
    max_name_jumps: int = MAX_NAME_JUMPS,
) -> dict[str, Any]:
    """Strictly decode one standalone SVCB-compatible RDATA value."""
    result = _decode_svcb_at(rdata, 0, len(rdata), max_name_jumps=max_name_jumps)
    if rdata_offset:
        _shift_offsets(result, rdata_offset)
    return result


def decode_dns_message(
    message: bytes,
    *,
    max_records: int = MAX_DNS_RECORDS,
    max_name_jumps: int = MAX_NAME_JUMPS,
) -> dict[str, Any]:
    """Walk a DNS message independently and decode all SVCB-compatible RRs.

    The function never raises for untrusted packet bytes.  Bounds and resource
    limits become machine-readable issues instead.
    """
    issues: list[dict[str, Any]] = []
    aliases: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "format_version": 1,
        "message": wire_evidence(message),
        "questions": [],
        "records": [],
        "aliases": aliases,
        "issues": issues,
    }
    if len(message) < DNS_HEADER_LENGTH:
        issues.append(
            _issue(
                "truncated_dns_header",
                "DNS message is shorter than its 12-octet header",
                offset=0,
                length=len(message),
            )
        )
        result["status"] = "invalid"
        return result

    identifier = int.from_bytes(message[0:2], "big")
    flags = int.from_bytes(message[2:4], "big")
    counts = [int.from_bytes(message[index : index + 2], "big") for index in range(4, 12, 2)]
    qdcount, ancount, nscount, arcount = counts
    result["header"] = {
        "id": identifier,
        "flags": flags,
        "rcode": flags & 0xF,
        "question_count": qdcount,
        "answer_count": ancount,
        "authority_count": nscount,
        "additional_count": arcount,
        "truncated": bool(flags & 0x0200),
    }
    total_records = ancount + nscount + arcount
    if qdcount + total_records > max_records:
        issues.append(
            _issue(
                "dns_record_limit_exceeded",
                f"DNS header declares more than the {max_records}-record decode limit",
                offset=4,
                length=8,
            )
        )
        result["status"] = "invalid"
        return result

    cursor = DNS_HEADER_LENGTH
    questions: list[dict[str, Any]] = []
    for question_index in range(qdcount):
        name, consumed, name_issues = _decode_name(
            message,
            cursor,
            len(message),
            allow_compression=True,
            compression_code="compressed_question_name",
            max_jumps=max_name_jumps,
        )
        issues.extend(name_issues)
        if name is None or consumed == 0 or cursor + consumed + 4 > len(message):
            if name is not None and cursor + consumed + 4 > len(message):
                issues.append(
                    _issue(
                        "truncated_dns_question",
                        "DNS question is missing QTYPE or QCLASS",
                        offset=cursor,
                        length=len(message) - cursor,
                    )
                )
            result["status"] = "invalid"
            return result
        qtype = int.from_bytes(message[cursor + consumed : cursor + consumed + 2], "big")
        qclass = int.from_bytes(message[cursor + consumed + 2 : cursor + consumed + 4], "big")
        questions.append(
            {
                "index": question_index,
                "name": name,
                "type": qtype,
                "class": qclass,
                "offset": cursor,
            }
        )
        cursor += consumed + 4
    result["questions"] = questions

    section_counts = (("answer", ancount), ("authority", nscount), ("additional", arcount))
    svcb_records: list[dict[str, Any]] = []
    opt_count = 0
    for section, count in section_counts:
        for record_index in range(count):
            owner, consumed, name_issues = _decode_name(
                message,
                cursor,
                len(message),
                allow_compression=True,
                compression_code="compressed_owner_name",
                max_jumps=max_name_jumps,
            )
            issues.extend(name_issues)
            if owner is None or consumed == 0:
                result["status"] = "invalid"
                return result
            header_offset = cursor + consumed
            if header_offset + 10 > len(message):
                issues.append(
                    _issue(
                        "truncated_resource_record_header",
                        "Resource record is missing TYPE, CLASS, TTL, or RDLENGTH",
                        offset=cursor,
                        length=len(message) - cursor,
                    )
                )
                result["status"] = "invalid"
                return result
            rdtype = int.from_bytes(message[header_offset : header_offset + 2], "big")
            rdclass = int.from_bytes(message[header_offset + 2 : header_offset + 4], "big")
            ttl = int.from_bytes(message[header_offset + 4 : header_offset + 8], "big")
            rdlength = int.from_bytes(message[header_offset + 8 : header_offset + 10], "big")
            rdata_offset = header_offset + 10
            rdata_end = rdata_offset + rdlength
            available_end = min(rdata_end, len(message))
            if rdtype == 41:
                opt_count += 1
                valid_opt_owner = owner == "."
                valid_opt_section = section == "additional"
                if opt_count == 1 and valid_opt_owner and valid_opt_section:
                    extended_rcode = (ttl >> 24) & 0xFF
                    result["header"]["extended_rcode"] = extended_rcode
                    result["header"]["rcode"] = (extended_rcode << 4) | (flags & 0xF)
                if opt_count > 1:
                    issues.append(
                        _issue(
                            "duplicate_opt_record",
                            "DNS message contains more than one OPT pseudo-record",
                            offset=cursor,
                        )
                    )
                if not valid_opt_owner:
                    issues.append(
                        _issue(
                            "invalid_opt_owner",
                            "OPT pseudo-record owner name must be the DNS root",
                            offset=cursor,
                        )
                    )
                if not valid_opt_section:
                    issues.append(
                        _issue(
                            "misplaced_opt_record",
                            "OPT pseudo-record must appear in the additional section",
                            offset=cursor,
                        )
                    )
            if rdtype in {5, 39} and rdclass == 1:
                alias_target, alias_length, alias_issues = _decode_name(
                    message,
                    rdata_offset,
                    available_end,
                    allow_compression=True,
                    compression_code="compressed_alias_target",
                    max_jumps=max_name_jumps,
                )
                issues.extend(alias_issues)
                if (
                    alias_target is not None
                    and rdata_end <= len(message)
                    and alias_length == rdlength
                ):
                    aliases.append(
                        {
                            "section": section,
                            "section_index": record_index,
                            "owner": owner,
                            "type": rdtype,
                            "type_name": "CNAME" if rdtype == 5 else "DNAME",
                            "class": rdclass,
                            "target": alias_target,
                            "rdata_offset": rdata_offset,
                            "rdlength": rdlength,
                        }
                    )
                elif alias_target is not None and rdata_end <= len(message):
                    issues.append(
                        _issue(
                            "trailing_alias_rdata",
                            "CNAME or DNAME RDATA has bytes after its target name",
                            offset=rdata_offset + alias_length,
                            length=rdlength - alias_length,
                        )
                    )
            if rdtype in SVCB_RDTYPES:
                decoded = _decode_svcb_at(
                    message,
                    rdata_offset,
                    available_end,
                    max_name_jumps=max_name_jumps,
                )
                record = {
                    "section": section,
                    "section_index": record_index,
                    "owner": owner,
                    "type": rdtype,
                    "type_name": SVCB_RDTYPES[rdtype],
                    "class": rdclass,
                    "ttl": ttl,
                    "rr_offset": cursor,
                    "rdata_offset": rdata_offset,
                    "rdlength": rdlength,
                    "svcb": decoded,
                }
                svcb_records.append(record)
            if rdata_end > len(message):
                issues.append(
                    _issue(
                        "rdata_overrun",
                        f"Resource record declares {rdlength} RDATA octets beyond the message",
                        offset=rdata_offset,
                        length=len(message) - rdata_offset,
                    )
                )
                result["records"] = svcb_records
                result["status"] = "invalid"
                return result
            cursor = rdata_end

    if cursor != len(message):
        issues.append(
            _issue(
                "trailing_dns_bytes",
                "DNS message has bytes after all header-declared sections",
                offset=cursor,
                length=len(message) - cursor,
            )
        )
    result["records"] = svcb_records
    result["status"] = (
        "invalid"
        if issues or any(record["svcb"].get("status") == "invalid" for record in svcb_records)
        else "valid"
    )
    return result
