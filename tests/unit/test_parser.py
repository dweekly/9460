"""Unit tests for parser module."""

from unittest.mock import Mock

from src.rfc9460_checker.parser import (
    _parse_alpn,
    _parse_ip_hint,
    _parse_port,
    parse_https_record,
    parse_svcb_record,
)


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
        """Test parsing multiple HTTPS records (chooses lowest priority)."""
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
