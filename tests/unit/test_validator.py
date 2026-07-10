"""Unit tests for validator module."""

from src.rfc9460_checker.validator import (
    validate_alpn_id,
    validate_alpn_protocol,
    validate_dns_response,
    validate_domain,
    validate_label,
    validate_port,
    validate_svcb_record,
    validate_svcb_rrset,
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


class TestValidateSvcb:
    """RFC 9460 validity and client-compatibility classification."""

    def test_arbitrary_nonempty_alpn_id_is_rfc_valid(self) -> None:
        """RFC validity is not limited to a hard-coded ALPN registry subset."""
        assert validate_alpn_id("example-protocol")
        assert not validate_alpn_id("")
        assert not validate_alpn_id("x" * 256)

    def test_no_default_alpn_requires_alpn(self) -> None:
        """A no-default-alpn parameter without alpn is self-inconsistent."""
        record = {
            "priority": 1,
            "target": ".",
            "mode": "service",
            "params": {"no-default-alpn": True},
            "param_details": [{"key": 2, "name": "no-default-alpn"}],
        }

        result = validate_svcb_record(record, owner_name="example.com")

        assert result["status"] == "invalid"
        assert {issue["code"] for issue in result["issues"]} == {"no_default_alpn_without_alpn"}

    def test_missing_mandatory_key_is_invalid(self) -> None:
        """Every key named by mandatory must occur in the same record."""
        record = {
            "priority": 1,
            "target": "svc.example.",
            "mode": "service",
            "params": {"mandatory": ["alpn"]},
            "param_details": [{"key": 0, "name": "mandatory"}],
        }

        result = validate_svcb_record(record)

        assert result["status"] == "invalid"
        assert any(issue["code"] == "missing_mandatory_param" for issue in result["issues"])

    def test_unknown_optional_key_is_valid_but_mandatory_is_incompatible(self) -> None:
        """Unknown optional keys are ignored while unknown mandatory keys are not."""
        base = {
            "priority": 1,
            "target": "svc.example.",
            "mode": "service",
            "params": {"key65400": "opaque"},
            "param_details": [{"key": 65400, "name": "key65400"}],
        }
        assert validate_svcb_record(base)["status"] == "valid"

        mandatory = {
            **base,
            "params": {"mandatory": ["key65400"], "key65400": "opaque"},
            "param_details": [
                {"key": 0, "name": "mandatory"},
                {"key": 65400, "name": "key65400"},
            ],
        }
        assert validate_svcb_record(mandatory)["status"] == "valid_but_incompatible"

    def test_alias_params_are_ignored_without_becoming_invalid(self) -> None:
        """Parameters on an AliasMode record produce a warning and no feature claims."""
        alias = {
            "priority": 0,
            "target": "alias.example.",
            "mode": "alias",
            "params": {"alpn": ["h3"]},
            "param_details": [{"key": 1, "name": "alpn"}],
        }

        result = validate_svcb_record(alias, owner_name="example.com")

        assert result["status"] == "valid"
        assert result["issues"][0]["code"] == "alias_params_ignored"

    def test_alias_param_parse_errors_are_also_ignored(self) -> None:
        """Normalization errors in ignored values do not invalidate AliasMode."""
        alias = {
            "priority": 0,
            "target": "alias.example.",
            "mode": "alias",
            "params": {"ipv4hint": {"encoding": "base64", "value": "wA=="}},
            "param_details": [
                {
                    "key": 4,
                    "name": "ipv4hint",
                    "parse_error": "invalid IPv4 hint wire length",
                }
            ],
        }

        result = validate_svcb_record(alias, owner_name="example.com")

        assert result["status"] == "valid"
        assert {issue["code"] for issue in result["issues"]} == {"alias_params_ignored"}

    def test_mixed_mode_rrset_ignores_service_records(self) -> None:
        """Ignored invalid ServiceMode records do not poison an AliasMode RRset."""
        records = [
            {
                "priority": 0,
                "target": "alias.example.",
                "mode": "alias",
                "params": {},
                "param_details": [],
            },
            {
                "priority": 1,
                "target": ".",
                "mode": "service",
                "params": {"no-default-alpn": True},
                "param_details": [{"key": 2, "name": "no-default-alpn"}],
            },
        ]

        result = validate_svcb_rrset(records, owner_name="example.com")

        assert result["status"] == "valid"
        assert records[0]["usable"] is True
        assert records[1]["ignored"] is True
        assert records[1]["usable"] is False
        assert records[1]["validity"] == "invalid"
        assert not any(
            issue["code"] == "no_default_alpn_without_alpn" for issue in result["issues"]
        )
        assert any(issue["code"] == "mixed_modes" for issue in result["issues"])

    def test_alias_self_loop_is_a_resolution_warning(self) -> None:
        """A direct AliasMode loop is valid RDATA but unusable during resolution."""
        record = {
            "priority": 0,
            "target": "example.com.",
            "mode": "alias",
            "params": {},
            "param_details": [],
        }
        result = validate_svcb_record(record, owner_name="example.com")
        assert result["status"] == "valid"
        assert result["issues"][0]["code"] == "alias_loop"
        assert result["issues"][0]["severity"] == "warning"

    def test_empty_supported_set_and_https_automatic_mandatory_keys(self) -> None:
        """An explicit empty capability set is honored for mandatory HTTPS keys."""
        explicit = {
            "priority": 1,
            "target": ".",
            "mode": "service",
            "params": {"mandatory": ["alpn"], "alpn": ["h2"]},
            "param_details": [
                {"key": 0, "name": "mandatory"},
                {"key": 1, "name": "alpn"},
            ],
        }
        explicit_result = validate_svcb_record(explicit, supported_param_keys=[])
        assert explicit_result["status"] == "valid_but_incompatible"
        assert explicit_result["issues"][0]["key"] == 1

        automatic = {
            "priority": 1,
            "target": ".",
            "mode": "service",
            "params": {"port": 8443},
            "param_details": [{"key": 3, "name": "port"}],
        }
        https_result = validate_svcb_record(automatic, record_type="HTTPS", supported_param_keys=[])
        svcb_result = validate_svcb_record(automatic, record_type="SVCB", supported_param_keys=[])
        assert https_result["status"] == "valid_but_incompatible"
        assert https_result["issues"][0]["code"] == ("unsupported_automatically_mandatory_param")
        assert svcb_result["status"] == "valid"

    def test_empty_ech_is_invalid(self) -> None:
        """An empty ECHConfigList cannot be counted as a usable ECH deployment."""
        record = {
            "priority": 1,
            "target": ".",
            "mode": "service",
            "params": {"ech": {"encoding": "base64", "value": ""}},
            "param_details": [{"key": 5, "name": "ech"}],
        }
        result = validate_svcb_record(record)
        assert result["status"] == "invalid"
        assert result["issues"][0]["code"] == "empty_ech"

    def test_port_zero_and_hint_families(self) -> None:
        """Port zero is legal, while an address hint of the wrong family is not."""
        assert validate_port(0)
        record = {
            "priority": 1,
            "target": ".",
            "mode": "service",
            "params": {"port": 0, "ipv4hint": ["2001:db8::1"]},
            "param_details": [
                {"key": 3, "name": "port"},
                {"key": 4, "name": "ipv4hint"},
            ],
        }
        result = validate_svcb_record(record)
        assert result["status"] == "invalid"
        assert any(issue["code"] == "invalid_ipv4hint" for issue in result["issues"])
