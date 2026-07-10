"""Unit tests for parser module."""

from unittest.mock import Mock

import dns.rdata
import dns.rdataclass
import dns.rdatatype

from src.rfc9460_checker.models import (
    CLIENT_SUPPORTED_PARAM_KEYS,
    DECODED_PARAM_KEYS,
    OPAQUE_REGISTERED_PARAM_KEYS,
    PARSER_LIMITATIONS,
    REGISTERED_PARAM_KEYS,
    SVCPARAM_REGISTRY_METADATA,
    VALIDATOR_RULESET_VERSION,
    param_key_name,
)
from src.rfc9460_checker.parser import (
    _parse_alpn,
    _parse_ip_hint,
    _parse_port,
    parse_https_record,
    parse_svcb_record,
)


def https_rdata(text: str):
    """Build a real dnspython HTTPS RDATA fixture from presentation text."""
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.HTTPS, text)


class TestParseHttpsRecord:
    """Test suite for HTTPS record parsing."""

    def test_parse_valid_https_record(self, mock_dns_response: Mock) -> None:
        """Test parsing of valid HTTPS record."""
        result = parse_https_record(mock_dns_response)

        assert result["https_priority"] == 1
        assert result["https_target"] == "example.com."
        assert result["alpn_protocols"] == "h3,h2"
        assert result["has_http3"] is True
        assert result["port"] == 443
        assert result["ipv4hint"] == "192.0.2.1"
        assert result["ipv6hint"] == "2001:db8::1"
        assert result["ech_config"] is True

    def test_parse_empty_answers(self) -> None:
        """Test parsing of empty answers."""
        result = parse_https_record([])
        assert result == {}

        result = parse_https_record(None)
        assert result == {}

    def test_parse_https_without_params(self) -> None:
        """Test parsing HTTPS record without parameters."""
        mock_rdata = Mock()
        mock_rdata.priority = 10
        mock_rdata.target = "cdn.example.com."
        mock_rdata.params = {}

        mock_answer = Mock()
        mock_answer.__iter__ = Mock(return_value=iter([mock_rdata]))
        mock_answer.__bool__ = Mock(return_value=True)

        result = parse_https_record(mock_answer)

        assert result["https_priority"] == 10
        assert result["https_target"] == "cdn.example.com."
        assert result["has_http3"] is False
        assert result["ech_config"] is False

    def test_parse_multiple_https_records(self) -> None:
        """Test parsing multiple HTTPS records without discarding either one."""
        mock_rdata1 = Mock()
        mock_rdata1.priority = 10
        mock_rdata1.target = "backup.example.com."
        mock_rdata1.params = {}

        mock_rdata2 = Mock()
        mock_rdata2.priority = 1
        mock_rdata2.target = "primary.example.com."
        mock_rdata2.params = {1: Mock(ids=["h3"])}

        mock_answer = Mock()
        mock_answer.__iter__ = Mock(return_value=iter([mock_rdata1, mock_rdata2]))
        mock_answer.__bool__ = Mock(return_value=True)

        result = parse_https_record(mock_answer)

        # Should use the record with priority 1 (lower is better)
        assert result["https_priority"] == 1
        assert result["https_target"] == "primary.example.com."
        assert result["alpn_protocols"] == "h3"
        assert result["has_http3"] is True
        assert result["record_count"] == 2
        assert [record["priority"] for record in result["records"]] == [1, 10]

    def test_parse_real_complete_rrset(self) -> None:
        """Known and unknown parameters remain JSON-safe in a full RRset."""
        answers = [
            https_rdata(
                '1 . alpn="h3,h2" no-default-alpn port="8443" '
                'ipv4hint="192.0.2.1,192.0.2.2" ech="AAEC" '
                'ipv6hint="2001:db8::1"'
            ),
            https_rdata('2 backup.example. alpn="h2" key65400="opaque"'),
        ]

        result = parse_https_record(answers, owner_name="example.com")

        assert result["schema_version"] == 2
        assert result["probe_type"] == "dns"
        assert result["validation_status"] == "valid"
        assert result["record_count"] == 2
        first, second = result["records"]
        assert first["mode"] == "service"
        assert first["params"]["alpn"] == ["h3", "h2"]
        assert first["params"]["no-default-alpn"] is True
        assert first["params"]["port"] == 8443
        assert first["params"]["ipv4hint"] == ["192.0.2.1", "192.0.2.2"]
        assert first["params"]["ech"] == {"encoding": "base64", "value": "AAEC"}
        assert first["params"]["ipv6hint"] == ["2001:db8::1"]
        assert first["raw"].startswith("1 .")
        assert second["params"]["key65400"] == {
            "encoding": "base64",
            "value": "b3BhcXVl",
        }
        assert second["param_details"][1]["known"] is False

    def test_unknown_mandatory_key_is_incompatible(self) -> None:
        """Unknown listed mandatory keys classify a record as incompatible."""
        answers = [https_rdata('1 svc.example. mandatory="key65400" key65400="opaque"')]

        result = parse_https_record(answers, owner_name="example.com")

        assert result["validation_status"] == "valid_but_incompatible"
        assert result["records"][0]["validity"] == "valid_but_incompatible"
        assert result["records"][0]["usable"] is False
        assert result["validation_issues"][0]["code"] == "unsupported_mandatory_param"

    def test_answer_metadata_is_preserved(self) -> None:
        """Query and post-CNAME RRset names remain distinct in metadata."""

        class RRset:
            ttl = 300
            name = "rrset-owner.example."

        class Answer(list):
            nameserver = "1.1.1.1"
            port = 53
            qname = "query.example."
            rrset = RRset()
            name = "wrong-fallback.example."
            canonical_name = "canonical.example."

        answer = Answer([https_rdata('1 . alpn="h2"')])

        result = parse_https_record(answer)

        assert result["ttl"] == 300
        assert result["resolver"] == "1.1.1.1"
        assert result["resolver_port"] == 53
        assert result["query_name"] == "query.example."
        assert result["rrset_owner_name"] == "rrset-owner.example."
        assert result["owner_name"] == "rrset-owner.example."
        assert result["canonical_name"] == "canonical.example."

    def test_registry_metadata_distinguishes_registration_and_support(self) -> None:
        """The IANA registry does not overstate parser or client capabilities."""
        result = parse_https_record(
            [https_rdata('1 . mandatory="key9" key9="\\000\\002"')],
            owner_name="example.com",
        )

        assert REGISTERED_PARAM_KEYS == frozenset(range(13))
        assert DECODED_PARAM_KEYS == frozenset(range(7))
        assert OPAQUE_REGISTERED_PARAM_KEYS == frozenset(range(7, 13))
        assert DECODED_PARAM_KEYS.isdisjoint(OPAQUE_REGISTERED_PARAM_KEYS)
        assert DECODED_PARAM_KEYS | OPAQUE_REGISTERED_PARAM_KEYS == REGISTERED_PARAM_KEYS
        assert CLIENT_SUPPORTED_PARAM_KEYS <= DECODED_PARAM_KEYS
        assert 5 not in CLIENT_SUPPORTED_PARAM_KEYS
        assert not set(range(7, 13)).intersection(CLIENT_SUPPORTED_PARAM_KEYS)
        assert param_key_name(9) == "tls-supported-groups"
        assert SVCPARAM_REGISTRY_METADATA["version"] == "2026-06-25"
        assert SVCPARAM_REGISTRY_METADATA["snapshot_date"] == "2026-07-10"
        assert SVCPARAM_REGISTRY_METADATA["content_sha256"] == (
            "2a1695a17ab72f36585d166efb9eda2c911d547158a8963adf7914df74de9231"
        )
        assert result["validator_ruleset_version"] == VALIDATOR_RULESET_VERSION
        detail = next(item for item in result["records"][0]["param_details"] if item["key"] == 9)
        assert detail["registered"] is True
        assert detail["decoded"] is False
        assert detail["client_supported"] is False
        assert detail["registry_reference"].startswith("draft-ietf-tls")
        assert result["validation_status"] == "valid_but_incompatible"

    def test_compatibility_http3_projection_requires_exact_h3(self) -> None:
        """Historic draft ALPN IDs are not reported as current HTTP/3 support."""
        result = parse_https_record([https_rdata('1 . alpn="h3-29"')], owner_name="example.com")

        assert result["alpn_protocols"] == "h3-29"
        assert result["has_http3"] is False

    def test_parser_discloses_only_remaining_wire_decoder_limit(self) -> None:
        """Direct object fixtures are explicit when no transport bytes exist."""
        result = parse_https_record([https_rdata('1 . alpn="h2"')])

        assert tuple(result["parser_limitations"]) == PARSER_LIMITATIONS
        assert any("opaque" in limitation for limitation in PARSER_LIMITATIONS)
        assert result["wire_validation"]["status"] == "not_collected"
        assert result["wire_capture"]["responses"] == []
        assert result["wire_capture"]["unavailable_reason"] == (
            "input did not pass through the DNS transport capture layer"
        )


class TestParseSvcbRecord:
    """Test suite for SVCB record parsing."""

    def test_parse_valid_svcb_record(self) -> None:
        """Test parsing of valid SVCB record."""
        mock_rdata = Mock()
        mock_rdata.priority = 1
        mock_rdata.target = "service.example.com."
        mock_rdata.params = {1: "test_param"}

        mock_answer = [mock_rdata]

        result = parse_svcb_record(mock_answer)

        assert result["svcb_priority"] == 1
        assert result["svcb_target"] == "service.example.com."
        assert "svcb_params" in result
        assert result["svcb_params"][1] == "test_param"

    def test_parse_empty_svcb(self) -> None:
        """Test parsing of empty SVCB answers."""
        result = parse_svcb_record([])
        assert result == {}

        result = parse_svcb_record(None)
        assert result == {}


class TestParseAlpn:
    """Test suite for ALPN parsing."""

    def test_parse_alpn_with_ids(self) -> None:
        """Test parsing ALPN with ids attribute."""
        mock_value = Mock()
        mock_value.ids = [b"h3", b"h2"]

        result = _parse_alpn(mock_value)
        assert result == ["h3", "h2"]

    def test_parse_alpn_as_list(self) -> None:
        """Test parsing ALPN as list."""
        result = _parse_alpn(["h3", "h2"])
        assert result == ["h3", "h2"]

    def test_parse_alpn_as_tuple(self) -> None:
        """Test parsing ALPN as tuple."""
        result = _parse_alpn(("h3", "h2"))
        assert result == ["h3", "h2"]

    def test_parse_alpn_unknown_format(self) -> None:
        """Test parsing ALPN with unknown format."""
        result = _parse_alpn("unknown")
        assert result == []


class TestParsePort:
    """Test suite for port parsing."""

    def test_parse_port_with_attribute(self) -> None:
        """Test parsing port with port attribute."""
        mock_value = Mock()
        mock_value.port = 8443

        result = _parse_port(mock_value)
        assert result == 8443

    def test_parse_port_as_int(self) -> None:
        """Test parsing port as integer."""
        result = _parse_port(443)
        assert result == 443

    def test_parse_port_as_string(self) -> None:
        """Test parsing port as string."""
        result = _parse_port("8080")
        assert result == 8080

    def test_parse_port_invalid(self) -> None:
        """Test parsing invalid port."""
        result = _parse_port("not_a_port")
        assert result is None

        result = _parse_port(None)
        assert result is None


class TestParseIpHint:
    """Test suite for IP hint parsing."""

    def test_parse_ip_with_addresses(self) -> None:
        """Test parsing IP hint with addresses attribute."""
        mock_value = Mock()
        mock_value.addresses = ["192.0.2.1", "192.0.2.2"]

        result = _parse_ip_hint(mock_value)
        assert result == ["192.0.2.1", "192.0.2.2"]

    def test_parse_ip_as_list(self) -> None:
        """Test parsing IP hint as list."""
        result = _parse_ip_hint(["10.0.0.1", "10.0.0.2"])
        assert result == ["10.0.0.1", "10.0.0.2"]

    def test_parse_ip_single_value(self) -> None:
        """Test parsing single IP value."""
        result = _parse_ip_hint("172.16.0.1")
        assert result == ["172.16.0.1"]

    def test_parse_ip_empty(self) -> None:
        """Test parsing empty IP hint."""
        result = _parse_ip_hint(None)
        assert result == []

        result = _parse_ip_hint([])
        assert result == []
