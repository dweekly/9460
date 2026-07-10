"""Integration between transport capture, strict wire decoding, and observations."""

from unittest.mock import AsyncMock, patch

import dns.exception
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from src.rfc9460_checker.dns_client import RFC9460Checker
from src.rfc9460_checker.parser import parse_captured_response, parse_https_record
from src.rfc9460_checker.wire_capture import CapturingBackend, DNSWireCapture

PEER = ("192.0.2.53", 53)


def _name(name: str) -> bytes:
    if name == ".":
        return b"\x00"
    labels = name.rstrip(".").split(".")
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"


def _param(key: int, value: bytes) -> bytes:
    return key.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def _response(rdata: bytes) -> bytes:
    return _response_rrset([rdata])


def _response_with_opt(rdata: bytes, options: bytes) -> bytes:
    message = bytearray(_response(rdata))
    message[10:12] = b"\x00\x01"
    message.extend(
        b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00" + len(options).to_bytes(2, "big") + options
    )
    return bytes(message)


def _response_rrset(rdatas: list[bytes], qname_text: str = "example.com.") -> bytes:
    qname = _name(qname_text)
    header_and_question = (
        b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + qname + b"\x00\x41\x00\x01"
    )
    header_and_question = (
        header_and_question[:6] + len(rdatas).to_bytes(2, "big") + header_and_question[8:]
    )
    answers = b"".join(
        b"\xc0\x0c\x00\x41\x00\x01\x00\x00\x01\x2c" + len(rdata).to_bytes(2, "big") + rdata
        for rdata in rdatas
    )
    return header_and_question + answers


def _query(qname_text: str = "example.com.") -> bytes:
    return (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + _name(qname_text)
        + b"\x00\x41\x00\x01"
    )


def _response_answers(
    qname_text: str,
    answers: list[tuple[str, int, bytes]],
) -> bytes:
    question = _name(qname_text) + b"\x00\x41\x00\x01"
    header = b"\x12\x34\x81\x80\x00\x01" + len(answers).to_bytes(2, "big") + b"\x00\x00\x00\x00"
    encoded_answers = b"".join(
        _name(owner)
        + rdtype.to_bytes(2, "big")
        + b"\x00\x01\x00\x00\x01\x2c"
        + len(rdata).to_bytes(2, "big")
        + rdata
        for owner, rdtype, rdata in answers
    )
    return header + question + encoded_answers


def _nxdomain_response() -> bytes:
    return (
        b"\x12\x34\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00"
        + _name("example.com.")
        + b"\x00\x41\x00\x01"
    )


def _noanswer_response(qname_text: str = "example.com.") -> bytes:
    return (
        b"\x12\x34\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
        + _name(qname_text)
        + b"\x00\x41\x00\x01"
    )


def _answer(message: bytes) -> dns.resolver.Answer:
    response = dns.message.from_wire(message)
    answer = dns.resolver.Answer(
        dns.name.from_text("example.com."),
        dns.rdatatype.HTTPS,
        dns.rdataclass.IN,
        response,
        PEER[0],
        PEER[1],
    )
    answer._rfc9460_wire_captures = [DNSWireCapture("udp", PEER, message)]
    return answer


def test_raw_duplicate_key_overrides_dnspython_normalization() -> None:
    """Strict wire evidence overrides a lossy accepted object model."""
    rdata = b"\x00\x01\x00" + _param(1, b"\x02h2") + _param(1, b"\x02h3")
    message = _response(rdata)
    answer = _answer(message)

    # dnspython silently retains only the final duplicate; the strict record
    # must retain both occurrences and reject the entire RRset.
    assert len(answer[0].params) == 1
    parsed = parse_https_record(answer, owner_name="example.com")

    assert parsed["validation_status"] == "invalid"
    assert parsed["wire_validation"]["status"] == "failed"
    assert [detail["value"] for detail in parsed["records"][0]["param_details"]] == [
        ["h2"],
        ["h3"],
    ]
    assert "duplicate_svcparam_key" in {issue["code"] for issue in parsed["validation_issues"]}
    response = parsed["wire_capture"]["responses"][0]
    assert response["used_for_observation"] is True
    assert response["accepted_by_dnspython"] is True
    assert response["message"]["length"] == len(message)


def test_normalized_presentation_is_joined_by_exact_rdata_hash() -> None:
    """Equal priority/target records never exchange presentation strings."""
    rdatas = [
        b"\x00\x01\x00" + _param(1, b"\x01b"),
        b"\x00\x01\x00" + _param(1, b"\x01d"),
    ]
    message = _response_rrset(rdatas)

    parsed = parse_https_record(_answer(message), owner_name="example.com")

    assert parsed["record_count"] == 2
    for record in parsed["records"]:
        alpn = record["params"]["alpn"][0]
        assert f'alpn="{alpn}"' in record["presentation"]


def test_recovers_alias_params_response_rejected_by_dnspython() -> None:
    """A rejected but captured RFC-valid AliasMode response is recovered."""
    rdata = b"\x00\x00" + _name("service.example.") + _param(1, b"\x02h2")
    message = _response(rdata)
    error = dns.exception.FormError("dnspython rejected AliasMode params")
    error._rfc9460_wire_captures = [DNSWireCapture("udp", PEER, message, query_wire=_query())]

    parsed = parse_captured_response(error, "HTTPS", "example.com")

    assert parsed["record_count"] == 1
    assert parsed["validation_status"] == "valid"
    assert parsed["records"][0]["mode"] == "alias"
    assert parsed["records"][0]["usable"] is True
    assert parsed["records"][0]["params"]["alpn"] == ["h2"]
    assert parsed["wire_validation"]["status"] == "passed"
    assert parsed["wire_capture"]["responses"][0]["accepted_by_dnspython"] is False


@pytest.mark.parametrize(
    ("key", "value"),
    [
        (0, b"x"),
        (4, b"\xc0"),
        (5, b"x"),
        (6, b"\x20"),
    ],
)
def test_alias_mode_suppresses_ignored_value_parse_errors(key: int, value: bytes) -> None:
    """Ignored AliasMode values cannot become normalization errors."""
    rdata = b"\x00\x00" + _name("service.example.") + _param(key, value)
    message = _response(rdata)
    error = dns.exception.FormError("ignored malformed AliasMode value")
    error._rfc9460_wire_captures = [DNSWireCapture("udp", PEER, message, query_wire=_query())]

    parsed = parse_captured_response(error, "HTTPS", "example.com")

    assert parsed["validation_status"] == "valid"
    assert {issue["code"] for issue in parsed["validation_issues"]} == {"alias_params_ignored"}
    assert all("parse_error" not in detail for detail in parsed["records"][0]["param_details"])


def test_recovery_follows_a_cname_to_the_requested_rrset() -> None:
    """A complete unambiguous CNAME chain identifies the terminal owner."""
    malformed_https = b"\x00\x01\x00" + _param(3, b"\x01")
    message = _response_answers(
        "www.example.com.",
        [
            ("www.example.com.", 5, _name("edge.example.net.")),
            ("edge.example.net.", 65, malformed_https),
        ],
    )
    error = dns.exception.FormError("rejected post-CNAME HTTPS RDATA")
    error._rfc9460_wire_captures = [
        DNSWireCapture("udp", PEER, message, query_wire=_query("www.example.com."))
    ]

    parsed = parse_captured_response(error, "HTTPS", "www.example.com")

    assert parsed["record_count"] == 1
    assert parsed["query_name"] == "www.example.com"
    assert parsed["rrset_owner_name"] == "edge.example.net."
    assert parsed["validation_status"] == "invalid"


def test_recovery_follows_a_valid_suffix_compressed_cname_target() -> None:
    """Ordinary backward CNAME compression remains usable for owner recovery."""
    # The question starts at offset 12, so the example.com suffix begins at
    # offset 16 after the three-octet "www" label.
    compressed_target = b"\x04edge\xc0\x10"
    valid_https = b"\x00\x01\x00" + _param(1, b"\x02h2")
    message = _response_answers(
        "www.example.com.",
        [
            ("www.example.com.", 5, compressed_target),
            ("edge.example.com.", 65, valid_https),
        ],
    )
    error = dns.exception.FormError("synthetic pre-parser recovery")
    error._rfc9460_wire_captures = [
        DNSWireCapture("udp", PEER, message, query_wire=_query("www.example.com."))
    ]

    parsed = parse_captured_response(error, "HTTPS", "www.example.com")

    assert parsed["record_count"] == 1
    assert parsed["rrset_owner_name"] == "edge.example.com."
    assert parsed["validation_status"] == "valid"


def test_forward_question_pointer_cannot_recover_a_valid_observation() -> None:
    """A parser-rejected forward pointer fails transaction-safe recovery closed."""
    message = bytes.fromhex(
        "123481800001000100000000c01200410001"
        "076578616d706c6503636f6d00"
        "00410001000000010003000100"
    )
    error = dns.exception.FormError("forward question pointer")
    error._rfc9460_wire_captures = [DNSWireCapture("udp", PEER, message, query_wire=_query())]

    parsed = parse_captured_response(error, "HTTPS", "example.com")

    assert "records" not in parsed
    assert parsed["wire_validation"]["status"] == "failed"
    assert "forward_compression_pointer" in {
        issue["code"] for issue in parsed["wire_validation"]["issues"]
    }


def test_malformed_opt_cannot_recover_a_valid_observation() -> None:
    """Malformed EDNS framing makes an otherwise valid HTTPS RRset invalid."""
    valid_https = b"\x00\x01\x00" + _param(1, b"\x02h2")
    message = _response_with_opt(valid_https, b"x")
    error = dns.exception.FormError("short EDNS option header")
    error._rfc9460_wire_captures = [DNSWireCapture("udp", PEER, message, query_wire=_query())]

    parsed = parse_captured_response(error, "HTTPS", "example.com")

    assert parsed["record_count"] == 1
    assert parsed["validation_status"] == "invalid"
    assert parsed["wire_validation"]["status"] == "failed"
    assert "truncated_edns_option_header" in {
        issue["code"] for issue in parsed["validation_issues"]
    }


def test_compressed_dname_cannot_steer_owner_recovery() -> None:
    """A forbidden compressed DNAME target is evidence, never an alias edge."""
    qname = "www.example.com."
    first_answer_offset = 12 + len(_name(qname)) + 4
    compressed_target = (0xC000 | first_answer_offset).to_bytes(2, "big")
    valid_https = b"\x00\x01\x00" + _param(1, b"\x02h2")
    message = _response_answers(
        qname,
        [
            ("target.net.", 1, b"\xc0\x00\x02\x01"),
            ("example.com.", 39, compressed_target),
            ("www.target.net.", 65, valid_https),
        ],
    )
    error = dns.exception.FormError("compressed DNAME target")
    error._rfc9460_wire_captures = [DNSWireCapture("udp", PEER, message, query_wire=_query(qname))]

    parsed = parse_captured_response(error, "HTTPS", "www.example.com")

    assert "records" not in parsed
    assert parsed["wire_validation"]["status"] == "failed"
    assert "compressed_dname_target" in {
        issue["code"] for issue in parsed["wire_validation"]["issues"]
    }


def test_recovery_applies_the_closest_dname_substitution() -> None:
    """DNAME replacement is label-aware and selects the closest ancestor."""
    malformed_https = b"\x00\x01\x00" + _param(3, b"\x01")
    message = _response_answers(
        "www.branch.example.com.",
        [
            ("example.com.", 39, _name("broad.example.net.")),
            ("branch.example.com.", 39, _name("service.example.net.")),
            ("www.service.example.net.", 65, malformed_https),
        ],
    )
    error = dns.exception.FormError("rejected post-DNAME HTTPS RDATA")
    error._rfc9460_wire_captures = [
        DNSWireCapture(
            "udp",
            PEER,
            message,
            query_wire=_query("www.branch.example.com."),
        )
    ]

    parsed = parse_captured_response(error, "HTTPS", "www.branch.example.com")

    assert parsed["record_count"] == 1
    assert parsed["rrset_owner_name"] == "www.service.example.net."
    assert parsed["validation_status"] == "invalid"


def test_recovery_rejects_conflicting_cname_targets() -> None:
    """Conflicting aliases fail closed instead of choosing an answer owner."""
    malformed_https = b"\x00\x01\x00" + _param(3, b"\x01")
    message = _response_answers(
        "www.example.com.",
        [
            ("www.example.com.", 5, _name("first.example.net.")),
            ("www.example.com.", 5, _name("second.example.net.")),
            ("first.example.net.", 65, malformed_https),
        ],
    )
    error = dns.exception.FormError("ambiguous CNAME response")
    error._rfc9460_wire_captures = [
        DNSWireCapture("udp", PEER, message, query_wire=_query("www.example.com."))
    ]

    parsed = parse_captured_response(error, "HTTPS", "www.example.com")

    assert "records" not in parsed


def test_recovery_canonicalizes_unicode_query_names() -> None:
    """A U-label input matches its A-label wire question and owner."""
    malformed_https = b"\x00\x01\x00" + _param(3, b"\x01")
    alabel = "xn--bcher-kva.de."
    message = _response_rrset([malformed_https], alabel)
    error = dns.exception.FormError("rejected IDN response")
    error._rfc9460_wire_captures = [DNSWireCapture("udp", PEER, message, query_wire=_query(alabel))]

    parsed = parse_captured_response(error, "HTTPS", "bücher.de")

    assert parsed["record_count"] == 1
    assert parsed["rrset_owner_name"] == alabel
    assert parsed["wire_capture"]["responses"][0]["matches_query"] is True


def test_recovery_rejects_a_stale_transaction_from_the_right_resolver() -> None:
    """Matching resolver address alone cannot authenticate a captured response."""
    rdata = b"\x00\x01\x00" + _param(1, b"\x02h2")
    message = _response(rdata)
    stale_query = b"\x99\x99" + _query()[2:]
    error = dns.exception.FormError("stale datagram")
    error._rfc9460_wire_captures = [DNSWireCapture("udp", PEER, message, query_wire=stale_query)]

    parsed = parse_captured_response(error, "HTTPS", "example.com")

    assert "records" not in parsed
    assert parsed["wire_capture"]["responses"][0]["matches_query"] is False
    assert parsed["wire_capture"]["responses"][0]["used_for_observation"] is False


def test_message_bounds_error_invalidates_an_otherwise_valid_rrset() -> None:
    """Used-message framing errors are part of aggregate RRset validity."""
    rdata = b"\x00\x01\x00" + _param(1, b"\x02h2")
    message = _response(rdata) + b"trailing"
    error = dns.exception.FormError("trailing DNS bytes")
    error._rfc9460_wire_captures = [DNSWireCapture("udp", PEER, message, query_wire=_query())]

    parsed = parse_captured_response(error, "HTTPS", "example.com")

    assert parsed["wire_validation"]["status"] == "failed"
    assert parsed["validation_status"] == "invalid"
    assert "trailing_dns_bytes" in {issue["code"] for issue in parsed["validation_issues"]}


def test_opaque_alpn_wire_length_is_not_revalidated_as_display_text() -> None:
    """A valid binary ALPN ID remains valid after base64 display rendering."""
    opaque_id = b"\xff" * 200
    rdata = b"\x00\x01\x00" + _param(1, bytes([len(opaque_id)]) + opaque_id)
    message = _response(rdata)
    error = dns.exception.FormError("opaque ALPN fixture")
    error._rfc9460_wire_captures = [DNSWireCapture("udp", PEER, message, query_wire=_query())]

    parsed = parse_captured_response(error, "HTTPS", "example.com")

    assert parsed["wire_validation"]["status"] == "passed"
    assert parsed["validation_status"] == "valid"
    assert parsed["records"][0]["params"]["alpn"][0].startswith("base64:")


def test_truncated_udp_packet_is_evidence_but_never_a_recovered_rrset() -> None:
    """TC=1 cannot supply a complete observation when TCP fallback fails."""
    rdata = b"\x00\x01\x00" + _param(1, b"\x02h2")
    message = bytearray(_response(rdata))
    message[2] |= 0x02
    error = dns.exception.Timeout("TCP fallback failed")
    error._rfc9460_wire_captures = [
        DNSWireCapture("udp", PEER, bytes(message), query_wire=_query())
    ]

    parsed = parse_captured_response(error, "HTTPS", "example.com")

    assert "records" not in parsed
    assert parsed["wire_validation"]["responses"][0]["issues"][0]["code"] == (
        "truncated_dns_response"
    )


@pytest.mark.parametrize("mutation", ["servfail", "unrelated_owner"])
def test_recovery_requires_noerror_and_the_requested_owner(mutation: str) -> None:
    """Matching IDs cannot turn error or unrelated answer data into adoption."""
    rdata = b"\x00\x01\x00" + _param(1, b"\x02h2")
    message = bytearray(_response(rdata))
    if mutation == "servfail":
        message[3] = (message[3] & 0xF0) | 2
    else:
        answer_offset = 12 + len(_name("example.com.")) + 4
        message[answer_offset : answer_offset + 2] = b"\xc0\x14"  # Owner is com.
    error = dns.exception.FormError(mutation)
    error._rfc9460_wire_captures = [
        DNSWireCapture("udp", PEER, bytes(message), query_wire=_query())
    ]

    parsed = parse_captured_response(error, "HTTPS", "example.com")

    assert "records" not in parsed
    assert parsed["wire_capture"]["responses"][0]["matches_query"] is True


def test_recovery_rejects_an_edns_extended_error_response() -> None:
    """A zero header nibble does not hide a nonzero EDNS extended RCODE."""
    rdata = b"\x00\x01\x00" + _param(1, b"\x02h2")
    message = bytearray(_response(rdata))
    message[10:12] = b"\x00\x01"
    message.extend(b"\x00\x00\x29\x04\xd0\x01\x00\x00\x00\x00\x00")
    error = dns.exception.FormError("BADVERS response")
    error._rfc9460_wire_captures = [
        DNSWireCapture("udp", PEER, bytes(message), query_wire=_query())
    ]

    parsed = parse_captured_response(error, "HTTPS", "example.com")

    assert "records" not in parsed
    assert parsed["wire_capture"]["responses"][0]["dns_header"]["rcode"] == 16


def test_noanswer_selects_the_response_accepted_by_dnspython() -> None:
    """A rejected retry cannot displace the final parser-accepted absence response."""
    malformed_rdata = b"\x00\x01\x00" + _param(3, b"\x01")
    rejected = _response(malformed_rdata)
    accepted = _noanswer_response()
    response = dns.message.from_wire(accepted)
    error = dns.resolver.NoAnswer(response=response)
    error._rfc9460_wire_captures = [
        DNSWireCapture("udp", PEER, rejected, query_wire=_query()),
        DNSWireCapture("udp", PEER, accepted, query_wire=_query()),
    ]

    parsed = parse_captured_response(error, "HTTPS", "example.com")

    assert "records" not in parsed
    captures = parsed["wire_capture"]["responses"]
    assert captures[0]["accepted_by_dnspython"] is False
    assert captures[0]["used_for_observation"] is False
    assert captures[1]["accepted_by_dnspython"] is True
    assert captures[1]["used_for_observation"] is True


def test_nxdomain_selects_the_response_from_the_exception_map() -> None:
    """Parametrized NXDOMAIN retains the exact response that established absence."""
    qname = dns.name.from_text("example.com.")
    accepted = _nxdomain_response()
    response = dns.message.from_wire(accepted)
    error = dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: response})
    error._rfc9460_wire_captures = [DNSWireCapture("udp", PEER, accepted, query_wire=_query())]

    parsed = parse_captured_response(error, "HTTPS", "example.com")

    assert "records" not in parsed
    capture = parsed["wire_capture"]["responses"][0]
    assert capture["accepted_by_dnspython"] is True
    assert capture["used_for_observation"] is True


def test_transaction_matching_treats_echoed_qname_case_as_insignificant() -> None:
    """DNS question-name case changes do not block safe wire recovery."""
    rdata = b"\x00\x01\x00" + _param(3, b"\x01")
    message = _response_rrset([rdata], "ExAmPlE.CoM.")
    error = dns.exception.FormError("case-varied QNAME")
    error._rfc9460_wire_captures = [DNSWireCapture("udp", PEER, message, query_wire=_query())]

    parsed = parse_captured_response(error, "HTTPS", "example.com")

    assert parsed["record_count"] == 1
    assert parsed["validation_status"] == "invalid"
    assert parsed["wire_capture"]["responses"][0]["matches_query"] is True


@pytest.mark.asyncio
async def test_checker_surfaces_capture_metadata_for_an_accepted_answer() -> None:
    """Capture retention counters survive the successful resolver Answer path."""
    checker = RFC9460Checker(dns_servers=[PEER[0]])
    message = _response(b"\x00\x01\x00" + _param(1, b"\x02h2"))

    async def answer_with_capture(owner: str, record_type: str, *, backend: object) -> object:
        assert isinstance(backend, CapturingBackend)
        backend._retain_capture(DNSWireCapture("udp", PEER, message, query_wire=_query()))
        return _answer(message)

    with patch.object(checker.resolver, "resolve", new_callable=AsyncMock) as resolve:
        resolve.side_effect = answer_with_capture
        result = await checker.query_https_record("example.com")

    assert result["query_status"] == "present"
    assert result["wire_capture"]["capture_metadata"]["retained_capture_count"] == 1
    assert result["wire_capture"]["capture_metadata"]["dropped_capture_count"] == 0


@pytest.mark.asyncio
async def test_checker_reports_rejected_malformed_rrset_as_present_invalid() -> None:
    """Rejected malformed wire remains an observed invalid deployment."""
    checker = RFC9460Checker(dns_servers=[PEER[0]])
    rdata = b"\x00\x01\x00" + _param(3, b"\x01")
    message = _response(rdata)

    async def reject_with_capture(owner: str, record_type: str, *, backend: object) -> object:
        assert owner == "example.com"
        assert record_type == "HTTPS"
        assert isinstance(backend, CapturingBackend)
        backend.max_captures = 2
        for _ in range(3):
            backend._retain_capture(DNSWireCapture("udp", PEER, message, query_wire=_query()))
        backend._note_filtered_datagram()
        raise dns.exception.FormError("invalid port RDATA")

    with patch.object(checker.resolver, "resolve", new_callable=AsyncMock) as resolve:
        resolve.side_effect = reject_with_capture
        result = await checker.query_https_record("example.com")

    assert result["query_status"] == "present"
    assert result["has_https_record"] is True
    assert result["query_error"] is None
    assert result["validation_status"] == "invalid"
    assert result["alias_resolution_status"] == "not_applicable"
    assert result["resolution_issues"][0]["code"] == "recovered_pre_parser_wire_response"
    assert result["wire_capture"]["responses"][0]["message"]["value"]
    assert result["wire_capture"]["capture_metadata"] == {
        "retained_capture_count": 2,
        "max_capture_count": 2,
        "dropped_capture_count": 1,
        "filtered_datagram_count": 1,
        "oversized_datagram_count": 0,
        "discarded_stream_buffer_count": 0,
    }


@pytest.mark.asyncio
async def test_checker_never_recovers_a_packet_from_an_unconfigured_peer() -> None:
    """Pre-parser recovery does not turn an unexpected datagram into an answer."""
    checker = RFC9460Checker(dns_servers=[PEER[0]])
    rdata = b"\x00\x01\x00" + _param(1, b"\x02h2")
    message = _response(rdata)

    async def reject_spoof(owner: str, record_type: str, *, backend: object) -> object:
        assert isinstance(backend, CapturingBackend)
        backend.captures.append(
            DNSWireCapture("udp", ("198.51.100.53", 53), message, query_wire=_query())
        )
        raise dns.exception.FormError("unexpected responder")

    with patch.object(checker.resolver, "resolve", new_callable=AsyncMock) as resolve:
        resolve.side_effect = reject_spoof
        result = await checker.query_https_record("example.com")

    assert result["query_status"] == "error"
    assert result["has_https_record"] is False
    assert result["wire_capture"]["responses"] == []
    assert result["wire_capture"]["capture_metadata"]["retained_capture_count"] == 0
    assert result["wire_capture"]["capture_metadata"]["filtered_datagram_count"] == 1


@pytest.mark.asyncio
async def test_negative_response_retains_exact_wire_and_resolver() -> None:
    """NXDOMAIN remains non-validity while retaining its supplying resolver."""
    checker = RFC9460Checker(dns_servers=[PEER[0]])

    async def nxdomain(owner: str, record_type: str, *, backend: object) -> object:
        backend.captures.append(  # type: ignore[attr-defined]
            DNSWireCapture("udp", PEER, _nxdomain_response(), query_wire=_query())
        )
        raise dns.resolver.NXDOMAIN

    with patch.object(checker.resolver, "resolve", new_callable=AsyncMock) as resolve:
        resolve.side_effect = nxdomain
        result = await checker.query_https_record("example.com")

    assert result["query_status"] == "nxdomain"
    assert result["validation_status"] == "not_applicable"
    assert result["resolver"] == PEER[0]
    assert result["resolver_port"] == PEER[1]
    assert result["wire_capture"]["responses"][0]["used_for_observation"] is True
