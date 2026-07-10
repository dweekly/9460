"""Tests for the independent RFC 9460 DNS wire decoder."""

import base64
import hashlib

import dns.exception
import dns.message
import dns.name
import pytest

from src.rfc9460_checker.wire import (
    decode_dns_message,
    decode_svcb_rdata,
    wire_evidence,
)


def _name(name: str) -> bytes:
    if name == ".":
        return b"\x00"
    return (
        b"".join(
            bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")
        )
        + b"\x00"
    )


def _param(key: int, value: bytes) -> bytes:
    return key.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def _ech_config(version: int, contents: bytes) -> bytes:
    return version.to_bytes(2, "big") + len(contents).to_bytes(2, "big") + contents


def _ech_config_list(*configs: bytes) -> bytes:
    encoded = b"".join(configs)
    return len(encoded).to_bytes(2, "big") + encoded


def _ech_contents(
    *,
    public_key: bytes = b"\x01",
    cipher_suites: bytes = b"\x00\x01\x00\x01",
    public_name: bytes = b"public.example",
    extensions: bytes = b"",
) -> bytes:
    return (
        b"\x01"  # config_id
        + b"\x00\x20"  # kem_id
        + len(public_key).to_bytes(2, "big")
        + public_key
        + len(cipher_suites).to_bytes(2, "big")
        + cipher_suites
        + b"\x00"  # maximum_name_length
        + len(public_name).to_bytes(1, "big")
        + public_name
        + len(extensions).to_bytes(2, "big")
        + extensions
    )


def _ech_extension(extension_type: int, data: bytes) -> bytes:
    return extension_type.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def _response(rdata: bytes, *, rdtype: int = 65, rdlength: int | None = None) -> bytes:
    qname = _name("example.com.")
    header = (
        b"\x12\x34"  # ID
        b"\x81\x80"  # Standard NOERROR response.
        b"\x00\x01"  # QDCOUNT
        b"\x00\x01"  # ANCOUNT
        b"\x00\x00"  # NSCOUNT
        b"\x00\x00"  # ARCOUNT
    )
    question = qname + rdtype.to_bytes(2, "big") + b"\x00\x01"
    answer = (
        b"\xc0\x0c"
        + rdtype.to_bytes(2, "big")
        + b"\x00\x01"
        + b"\x00\x00\x01\x2c"
        + (len(rdata) if rdlength is None else rdlength).to_bytes(2, "big")
        + rdata
    )
    return header + question + answer


def _response_with_opt(rdata: bytes, options: bytes) -> bytes:
    message = bytearray(_response(rdata))
    message[10:12] = b"\x00\x01"
    message.extend(
        b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00" + len(options).to_bytes(2, "big") + options
    )
    return bytes(message)


def test_wire_evidence_is_canonical_and_self_describing() -> None:
    """Binary evidence has canonical base64, length, and SHA-256."""
    value = b"\x00\x01\xff"

    assert wire_evidence(value) == {
        "encoding": "base64",
        "value": base64.b64encode(value).decode("ascii"),
        "length": 3,
        "sha256": hashlib.sha256(value).hexdigest(),
    }


def test_decodes_rfc_style_rdata_and_preserves_ordered_params() -> None:
    """A valid RFC vector retains its network-order parameter sequence."""
    mandatory = b"\x00\x01\x00\x04"
    alpn = b"\x02h2\x05h3-19"
    rdata = b"\x00\x10" + _name("foo.example.org.")
    rdata += _param(0, mandatory) + _param(1, alpn) + _param(4, b"\xc0\x00\x02\x01")

    decoded = decode_svcb_rdata(rdata, rdata_offset=47)

    assert decoded["status"] == "valid"
    assert decoded["priority"] == 16
    assert decoded["target"] == "foo.example.org."
    assert [param["key"] for param in decoded["params"]] == [0, 1, 4]
    assert decoded["bytes"]["value"] == base64.b64encode(rdata).decode("ascii")
    assert decoded["rdata_offset"] == 47


@pytest.mark.parametrize(
    ("params", "code"),
    [
        (_param(1, b"\x02h2") + _param(1, b"\x02h3"), "duplicate_svcparam_key"),
        (_param(4, b"\xc0\x00\x02\x01") + _param(1, b"\x02h2"), "misordered_svcparam_key"),
        (b"\x00\x01\x00", "truncated_svcparam_header"),
        (b"\x00\x01\x00\x04\x02h", "truncated_svcparam_value"),
    ],
)
def test_rejects_duplicate_misordered_and_truncated_params(params: bytes, code: str) -> None:
    """Outer SvcParam framing and strict key order are independently checked."""
    decoded = decode_svcb_rdata(b"\x00\x01\x00" + params)

    assert decoded["status"] == "invalid"
    assert code in {issue["code"] for issue in decoded["issues"]}


@pytest.mark.parametrize(
    ("key", "value", "code"),
    [
        (0, b"", "invalid_mandatory_wire_length"),
        (0, b"\x00\x04\x00\x01", "misordered_mandatory_keys"),
        (1, b"", "empty_alpn"),
        (1, b"\x03h2", "truncated_alpn_id"),
        (2, b"x", "nonempty_no_default_alpn"),
        (3, b"\x01", "invalid_port_wire_length"),
        (4, b"", "invalid_ipv4hint_wire_length"),
        (5, b"", "empty_ech"),
        (6, b"\x00" * 15, "invalid_ipv6hint_wire_length"),
    ],
)
def test_validates_initial_svcparam_wire_formats(key: int, value: bytes, code: str) -> None:
    """RFC-defined keys receive their key-specific wire-format checks."""
    decoded = decode_svcb_rdata(b"\x00\x01\x00" + _param(key, value))

    assert decoded["status"] == "invalid"
    assert code in {issue["code"] for issue in decoded["issues"]}


def test_accepts_framed_unknown_and_structurally_valid_known_ech_configs() -> None:
    """Unknown ECH versions use generic framing while 0xfe0d gets strict decoding."""
    ech = _ech_config_list(
        _ech_config(0x1234, b""),
        _ech_config(0xFE0D, _ech_contents()),
    )

    decoded = decode_svcb_rdata(b"\x00\x01\x00" + _param(5, ech))

    assert decoded["status"] == "valid"
    assert decoded["issues"] == []


def test_accepts_rfc_9848_ech_config_list_example() -> None:
    """The published RFC 9848 ECHConfigList example passes strict decoding."""
    ech = base64.b64decode(
        "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrW"
        "PgAEAAEAAWQVZWNoLXNpdGVzLmV4YW1wbGUubmV0AAA="
    )

    decoded = decode_svcb_rdata(b"\x00\x01\x00" + _param(5, ech))

    assert decoded["status"] == "valid"
    assert decoded["issues"] == []


@pytest.mark.parametrize(
    ("ech", "code"),
    [
        (b"\x00", "invalid_ech_config_list_length"),
        (b"\x00\x03abc", "invalid_ech_config_list_length"),
        (b"\x00\x05" + _ech_config(0x1234, b""), "invalid_ech_config_list_length"),
        (b"\x00\x05\x12\x34\x00\x02x", "truncated_ech_config"),
    ],
)
def test_rejects_malformed_ech_config_list_framing(ech: bytes, code: str) -> None:
    """The redundant ECHConfigList and per-config lengths must agree exactly."""
    decoded = decode_svcb_rdata(b"\x00\x01\x00" + _param(5, ech))

    assert decoded["status"] == "invalid"
    assert code in {issue["code"] for issue in decoded["issues"]}


@pytest.mark.parametrize(
    ("contents", "code"),
    [
        (_ech_contents(public_key=b""), "invalid_ech_config_contents"),
        (_ech_contents(cipher_suites=b""), "invalid_ech_config_contents"),
        (_ech_contents(cipher_suites=b"\x00" * 5), "invalid_ech_config_contents"),
        (_ech_contents(public_name=b""), "invalid_ech_config_contents"),
        (
            _ech_contents(extensions=_ech_extension(7, b"a") + _ech_extension(7, b"b")),
            "duplicate_ech_extension_type",
        ),
    ],
)
def test_rejects_malformed_known_ech_config_contents(contents: bytes, code: str) -> None:
    """Version 0xfe0d vectors and extensions are structurally bounded and unique."""
    ech = _ech_config_list(_ech_config(0xFE0D, contents))

    decoded = decode_svcb_rdata(b"\x00\x01\x00" + _param(5, ech))

    assert decoded["status"] == "invalid"
    assert code in {issue["code"] for issue in decoded["issues"]}


def test_alias_mode_params_are_valid_but_explicitly_ignored() -> None:
    """Parameters in AliasMode are warnings rather than malformed wire."""
    rdata = b"\x00\x00" + _name("service.example.") + _param(1, b"\x02h2")

    decoded = decode_svcb_rdata(rdata)

    assert decoded["status"] == "valid"
    assert decoded["mode"] == "alias"
    assert decoded["issues"][0]["code"] == "alias_params_ignored"
    assert decoded["issues"][0]["severity"] == "warning"

    ignored_bad_port = decode_svcb_rdata(
        b"\x00\x00" + _name("service.example.") + _param(3, b"\x01")
    )
    assert ignored_bad_port["status"] == "valid"
    assert {issue["code"] for issue in ignored_bad_port["issues"]} == {"alias_params_ignored"}

    ignored_bad_ech = decode_svcb_rdata(
        b"\x00\x00" + _name("service.example.") + _param(5, b"not-an-ech-config-list")
    )
    assert ignored_bad_ech["status"] == "valid"
    assert {issue["code"] for issue in ignored_bad_ech["issues"]} == {"alias_params_ignored"}


def test_packet_decoder_rejects_compressed_target_but_retains_rdata() -> None:
    """Compression of TargetName is rejected without losing the evidence."""
    # TargetName points at the question name. RFC 1035 compression is valid in
    # many RDATA names, but RFC 9460 explicitly forbids it for TargetName.
    rdata = b"\x00\x01\xc0\x0c" + _param(1, b"\x02h2")
    message = _response(rdata)

    decoded = decode_dns_message(message)
    wire_record = decoded["records"][0]

    assert decoded["status"] == "invalid"
    assert wire_record["owner"] == "example.com."
    assert wire_record["section"] == "answer"
    assert wire_record["svcb"]["target"] == "example.com."
    assert "compressed_target_name" in {issue["code"] for issue in wire_record["svcb"]["issues"]}


def test_packet_decoder_rejects_a_forward_compression_pointer() -> None:
    """A compression pointer cannot refer to a later name in the message."""
    # The question name at offset 12 points forward to the answer owner at
    # offset 18. dnspython rejects the same packet with BadPointer.
    message = bytes.fromhex(
        "123481800001000100000000c01200410001"
        "076578616d706c6503636f6d00"
        "00410001000000010003000100"
    )

    decoded = decode_dns_message(message)

    assert decoded["status"] == "invalid"
    assert "forward_compression_pointer" in {issue["code"] for issue in decoded["issues"]}
    with pytest.raises(dns.name.BadPointer):
        dns.message.from_wire(message)


def test_packet_decoder_rejects_a_compressed_dname_target() -> None:
    """RFC 6672 requires DNAME RDATA target names to be uncompressed."""
    message = bytes.fromhex(
        "123481800001000100000000"
        "03777777076578616d706c6503636f6d0000410001"
        "c01000270001000000010002c00c"
    )

    decoded = decode_dns_message(message)

    assert decoded["status"] == "invalid"
    assert decoded["aliases"] == []
    issue_codes = {issue["code"] for issue in decoded["issues"]}
    assert "compressed_dname_target" in issue_codes
    assert "trailing_alias_rdata" not in issue_codes
    assert dns.message.from_wire(message).answer


def test_packet_bounds_fail_closed_without_throwing() -> None:
    """Packet and RDATA overruns become findings rather than exceptions."""
    rdata = b"\x00\x01\x00" + _param(1, b"\x02h2")
    message = _response(rdata, rdlength=len(rdata) + 9)

    decoded = decode_dns_message(message)

    assert decoded["status"] == "invalid"
    assert decoded["issues"][0]["code"] == "rdata_overrun"
    assert decoded["records"][0]["svcb"]["bytes"]["value"] == base64.b64encode(rdata).decode(
        "ascii"
    )
    assert decode_dns_message(b"short")["issues"][0]["code"] == "truncated_dns_header"


def test_packet_decoder_combines_the_edns_extended_rcode() -> None:
    """An OPT extended RCODE contributes the high response-code bits."""
    rdata = b"\x00\x01\x00" + _param(1, b"\x02h2")
    message = bytearray(_response(rdata))
    message[10:12] = b"\x00\x01"
    message.extend(b"\x00\x00\x29\x04\xd0\x01\x00\x00\x00\x00\x00")

    decoded = decode_dns_message(bytes(message))

    assert decoded["header"]["extended_rcode"] == 1
    assert decoded["header"]["rcode"] == 16
    assert decoded["status"] == "valid"


@pytest.mark.parametrize("options", [b"", b"\xfd\xe9\x00\x03abc"])
def test_packet_decoder_accepts_valid_generic_edns_option_framing(options: bytes) -> None:
    """Empty OPT RDATA and an opaque, length-bounded option are both valid."""
    rdata = b"\x00\x01\x00" + _param(1, b"\x02h2")

    decoded = decode_dns_message(_response_with_opt(rdata, options))

    assert decoded["status"] == "valid"
    assert decoded["issues"] == []


@pytest.mark.parametrize(
    ("options", "code"),
    [
        (b"x", "truncated_edns_option_header"),
        (b"\xfd\xe9\x00\x03ab", "truncated_edns_option_value"),
    ],
)
def test_packet_decoder_rejects_malformed_edns_option_framing(
    options: bytes,
    code: str,
) -> None:
    """Every EDNS option header and declared value must fit OPT RDATA."""
    rdata = b"\x00\x01\x00" + _param(1, b"\x02h2")

    message = _response_with_opt(rdata, options)
    decoded = decode_dns_message(message)

    assert decoded["status"] == "invalid"
    assert code in {issue["code"] for issue in decoded["issues"]}
    with pytest.raises(dns.exception.FormError):
        dns.message.from_wire(message)


def test_packet_decoder_rejects_duplicate_opt_records() -> None:
    """Multiple OPT pseudo-records make the DNS envelope malformed."""
    rdata = b"\x00\x01\x00" + _param(1, b"\x02h2")
    message = bytearray(_response(rdata))
    message[10:12] = b"\x00\x02"
    opt = b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"
    message.extend(opt + opt)

    decoded = decode_dns_message(bytes(message))

    assert decoded["status"] == "invalid"
    assert "duplicate_opt_record" in {issue["code"] for issue in decoded["issues"]}


def test_packet_decoder_rejects_non_root_opt_owner() -> None:
    """A malformed OPT owner cannot supply the extended response code."""
    rdata = b"\x00\x01\x00" + _param(1, b"\x02h2")
    message = bytearray(_response(rdata))
    message[10:12] = b"\x00\x01"
    message.extend(_name("fake.example.") + b"\x00\x29\x04\xd0\x01\x00\x00\x00\x00\x00")

    decoded = decode_dns_message(bytes(message))

    assert decoded["status"] == "invalid"
    assert decoded["header"]["rcode"] == 0
    assert "extended_rcode" not in decoded["header"]
    assert "invalid_opt_owner" in {issue["code"] for issue in decoded["issues"]}


def test_decoder_observes_alias_params_even_when_dnspython_rejects_them() -> None:
    """Pre-parser bytes preserve an RFC-valid case dnspython rejects."""
    rdata = b"\x00\x00" + _name("service.example.") + _param(1, b"\x02h2")
    message = _response(rdata)

    with pytest.raises(dns.exception.FormError):
        dns.message.from_wire(message)

    decoded = decode_dns_message(message)
    assert decoded["status"] == "valid"
    assert decoded["records"][0]["svcb"]["issues"][0]["code"] == "alias_params_ignored"
