"""Unit tests for validator module."""

from src.rfc9460_checker.validator import (
    validate_alpn_protocol,
    validate_dns_response,
    validate_domain,
    validate_label,
)


class TestValidateDomain:
    """Test suite for domain validation."""

    def test_valid_domains(self) -> None:
        """Test validation of valid domain names."""
        valid_domains = [
            "example.com",
            "sub.example.com",
            "a.b.c.d.example.com",
            "example.co.uk",
            "xn--example.com",  # IDN
            "123.456.789.com",  # Numeric labels with valid TLD
            "a-b.example.com",
            "a1b2c3.example.com",
        ]

        for domain in valid_domains:
            assert validate_domain(domain), f"Should accept {domain}"

    def test_invalid_domains(self) -> None:
        """Test rejection of invalid domain names."""
        invalid_domains = [
            "",  # Empty
            ".",  # Just dot
            ".com",  # Starting with dot
            "example..com",  # Double dot
            "-example.com",  # Starting with hyphen
            "example-.com",  # Ending with hyphen
            "exam ple.com",  # Space
            "example.com-",  # Ending with hyphen
            "a" * 64 + ".com",  # Label too long (>63 chars)
            "example." + "a" * 64,  # TLD too long
            "exam@ple.com",  # Invalid character
            "example.c",  # TLD too short (but actually valid in practice)
        ]

        for domain in invalid_domains:
            assert not validate_domain(domain), f"Should reject {domain}"

    def test_domain_with_trailing_dot(self) -> None:
        """Test domain with trailing dot (FQDN)."""
        assert validate_domain("example.com.")
        assert validate_domain("sub.example.com.")


class TestValidateLabel:
    """Test suite for label validation."""

    def test_valid_labels(self) -> None:
        """Test validation of valid labels."""
        valid_labels = [
            "example",
            "a",
            "a1",
            "a-b",
            "a1b2c3",
            "test-123",
            "xn--test",
        ]

        for label in valid_labels:
            assert validate_label(label), f"Should accept {label}"

    def test_invalid_labels(self) -> None:
        """Test rejection of invalid labels."""
        invalid_labels = [
            "",  # Empty
            "-",  # Just hyphen
            "-test",  # Starting with hyphen
            "test-",  # Ending with hyphen
            "te st",  # Space
            "te_st",  # Underscore
            "te.st",  # Dot
            "a" * 64,  # Too long (>63 chars)
        ]

        for label in invalid_labels:
            assert not validate_label(label), f"Should reject {label}"


class TestValidateDnsResponse:
    """Test suite for DNS response validation."""

    def test_valid_response_with_https_record(self, sample_https_result: dict) -> None:
        """Test validation of valid DNS response with HTTPS record."""
        assert validate_dns_response(sample_https_result)

    def test_valid_response_without_https_record(self) -> None:
        """Test validation of valid DNS response without HTTPS record."""
        response = {
            "domain": "example.com",
            "subdomain": "root",
            "full_domain": "example.com",
            "has_https_record": False,
            "query_error": "No HTTPS record",
        }
        assert validate_dns_response(response)

    def test_invalid_response_missing_fields(self) -> None:
        """Test rejection of response missing required fields."""
        invalid_responses = [
            {},  # Empty
            {"domain": "example.com"},  # Missing other fields
            {
                "domain": "example.com",
                "subdomain": "root",
                "full_domain": "example.com",
                # Missing has_https_record
            },
            {
                "domain": "example.com",
                "subdomain": "root",
                "full_domain": "example.com",
                "has_https_record": True,
                # Missing https_priority and https_target
            },
        ]

        for response in invalid_responses:
            assert not validate_dns_response(response)


class TestValidateAlpnProtocol:
    """Test suite for ALPN protocol validation."""

    def test_valid_alpn_protocols(self) -> None:
        """Test validation of valid ALPN protocols."""
        valid_protocols = [
            "http/1.1",
            "h2",
            "h2c",
            "h3",
            "h3-29",
            "h3-Q050",
            "hq",
            "doq",
        ]

        for protocol in valid_protocols:
            assert validate_alpn_protocol(protocol), f"Should accept {protocol}"

    def test_invalid_alpn_protocols(self) -> None:
        """Test rejection of invalid ALPN protocols."""
        invalid_protocols = [
            "",
            "invalid",
            "http/2.0",  # Not a standard ALPN
            "h4",  # Doesn't exist yet
            "HTTP/1.1",  # Wrong case
        ]

        for protocol in invalid_protocols:
            assert not validate_alpn_protocol(protocol), f"Should reject {protocol}"
