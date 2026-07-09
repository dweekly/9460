"""Tests for metrics calculation module."""

import pandas as pd
import pytest

from src.analyzer.metrics import (
    analyze_alpn_protocols,
    calculate_adoption_rate,
    calculate_compliance_metrics,
    calculate_error_statistics,
    calculate_feature_distribution,
    calculate_metrics,
    calculate_priority_distribution,
    calculate_validity_metrics,
    identify_feature_leaders,
    identify_top_performers,
)


class TestMetrics:
    """Test suite for metrics calculation functions."""

    @pytest.fixture
    def sample_data(self):
        """Create sample DataFrame for testing."""
        data = [
            {
                "domain": "example1.com",
                "subdomain": "root",
                "has_https_record": True,
                "has_http3": True,
                "ech_config": True,
                "alpn_protocols": "h3,h2",
                "https_priority": 1,
                "port": None,
                "ipv4hint": "192.0.2.1",
                "ipv6hint": None,
                "query_error": None,
            },
            {
                "domain": "example1.com",
                "subdomain": "www",
                "has_https_record": True,
                "has_http3": True,
                "ech_config": False,
                "alpn_protocols": "h3,h2",
                "https_priority": 1,
                "port": None,
                "ipv4hint": None,
                "ipv6hint": "2001:db8::1",
                "query_error": None,
            },
            {
                "domain": "example2.com",
                "subdomain": "root",
                "has_https_record": False,
                "has_http3": False,
                "ech_config": False,
                "alpn_protocols": None,
                "https_priority": None,
                "port": None,
                "ipv4hint": None,
                "ipv6hint": None,
                "query_error": "No HTTPS record",
            },
            {
                "domain": "example2.com",
                "subdomain": "www",
                "has_https_record": False,
                "has_http3": False,
                "ech_config": False,
                "alpn_protocols": None,
                "https_priority": None,
                "port": None,
                "ipv4hint": None,
                "ipv6hint": None,
                "query_error": "NXDOMAIN",
            },
        ]
        return pd.DataFrame(data)

    def test_calculate_adoption_rate(self, sample_data):
        """Test adoption rate calculation."""
        metrics = calculate_adoption_rate(sample_data)

        assert metrics["overall_adoption"] == 50.0  # 2/4 records
        assert metrics["root_adoption"] == 50.0  # 1/2 root domains
        assert metrics["www_adoption"] == 50.0  # 1/2 www domains

    def test_calculate_adoption_rate_empty(self):
        """Test adoption rate with empty data."""
        empty_df = pd.DataFrame()
        metrics = calculate_adoption_rate(empty_df)

        assert metrics["overall_adoption"] == 0.0
        assert metrics["root_adoption"] == 0.0
        assert metrics["www_adoption"] == 0.0

    def test_calculate_feature_distribution(self, sample_data):
        """Test feature distribution calculation."""
        features = calculate_feature_distribution(sample_data)

        # Should only count domains with HTTPS records (2 out of 4)
        assert features["http3_support"]["count"] == 2
        assert features["http3_support"]["percentage"] == 100.0  # 2/2 HTTPS records

        assert features["ech_deployment"]["count"] == 1
        assert features["ech_deployment"]["percentage"] == 50.0  # 1/2 HTTPS records
        assert features["_deprecated_aliases"] == {
            "http3_support": "h3_advertised",
            "ech_deployment": "ech_advertised",
        }

        assert features["ipv4_hints"]["count"] == 1
        assert features["ipv6_hints"]["count"] == 1

    def test_calculate_feature_distribution_no_https(self):
        """Test feature distribution with no HTTPS records."""
        data = pd.DataFrame(
            [
                {
                    "has_https_record": False,
                    "has_http3": False,
                    "ech_config": False,
                    "port": None,
                    "ipv4hint": None,
                    "ipv6hint": None,
                }
            ]
        )
        features = calculate_feature_distribution(data)

        assert features["http3_support"]["count"] == 0
        assert features["http3_support"]["percentage"] == 0.0

    def test_custom_port_excludes_explicit_default(self):
        """An explicit HTTPS port 443 is not a custom-port deployment."""
        data = pd.DataFrame(
            [
                {"has_https_record": True, "port": 443},
                {"has_https_record": True, "port": 8443},
            ]
        )

        features = calculate_feature_distribution(data)

        assert features["custom_port"] == {
            "count": 1,
            "denominator": 2,
            "percentage": 50.0,
        }

    def test_calculate_compliance_metrics(self, sample_data):
        """Test the one-release compatibility alias."""
        metrics = calculate_compliance_metrics(sample_data)

        assert "adoption" in metrics
        assert "features" in metrics
        assert "average_compliance_score" not in metrics
        assert metrics["total_domains_checked"] == 4
        assert metrics["unique_domains"] == 2

    def test_explicit_denominators_and_validity(self, sample_data):
        """HTTPS denominators count names, not unrelated SVCB query rows."""
        metrics = calculate_metrics(sample_data)

        assert metrics["denominators"]["domains"] == 2
        assert metrics["denominators"]["https_names"] == 4
        assert metrics["denominators"]["https_present_rrsets"] == 2
        assert metrics["adoption"]["https"] == {
            "count": 2,
            "denominator": 4,
            "percentage": 50.0,
        }
        assert "h3_advertised" in metrics["features"]
        assert "ech_advertised" in metrics["features"]
        assert "http3_support" not in metrics["features"]
        assert "ech_deployment" not in metrics["features"]
        assert calculate_validity_metrics(sample_data)["https"]["unknown"]["count"] == 2

    def test_analyze_alpn_protocols(self, sample_data):
        """Test ALPN protocol analysis."""
        alpn_dist = analyze_alpn_protocols(sample_data)

        assert alpn_dist["h3"] == 2
        assert alpn_dist["h2"] == 2

    def test_analyze_alpn_protocols_empty(self):
        """Test ALPN analysis with no protocols."""
        data = pd.DataFrame([{"alpn_protocols": None}])
        alpn_dist = analyze_alpn_protocols(data)

        assert len(alpn_dist) == 0

    def test_calculate_priority_distribution(self, sample_data):
        """Test priority distribution calculation."""
        priority_dist = calculate_priority_distribution(sample_data)

        assert priority_dist[1] == 2  # Two records with priority 1

    def test_identify_top_performers(self, sample_data):
        """Test top performer identification."""
        top_performers = identify_top_performers(sample_data, top_n=2)

        assert len(top_performers) <= 2
        assert top_performers[0][0] == "example1.com"  # Should have higher score
        assert top_performers[0][1] > 0  # Should have non-zero score

    def test_identify_feature_leaders(self):
        """Domains are described by observed features, not a synthetic score."""
        data = pd.DataFrame(
            [
                {
                    "domain": "perfect.com",
                    "has_https_record": True,
                    "has_http3": True,
                    "ech_config": True,
                    "ipv4hint": "192.0.2.1",
                    "ipv6hint": "2001:db8::1",
                    "alpn_protocols": "h3,h2",
                },
                {
                    "domain": "basic.com",
                    "has_https_record": True,
                    "has_http3": False,
                    "ech_config": False,
                    "ipv4hint": None,
                    "ipv6hint": None,
                    "alpn_protocols": None,
                },
            ]
        )

        leaders = identify_feature_leaders(data, top_n=2)

        assert leaders[0]["domain"] == "perfect.com"
        assert leaders[0]["feature_count"] == 5
        assert leaders[1]["domain"] == "basic.com"
        assert leaders[1]["feature_count"] == 0

        # The compatibility API returns feature counts, not compliance percentages.
        assert identify_top_performers(data, top_n=1) == [("perfect.com", 5.0)]

    def test_calculate_error_statistics(self, sample_data):
        """Normal DNS absence is not reported as a query failure."""
        error_stats = calculate_error_statistics(sample_data)

        assert error_stats == {}

    def test_calculate_error_statistics_retains_operational_failures(self):
        """Timeouts and unexpected query errors remain visible."""
        data = pd.DataFrame(
            [
                {"query_status": "timeout", "query_error": "Timeout"},
                {"query_status": "error", "query_error": "SERVFAIL"},
            ]
        )

        assert calculate_error_statistics(data) == {"SERVFAIL": 1, "Timeout": 1}

    def test_calculate_error_statistics_no_errors(self):
        """Test error statistics with no errors."""
        data = pd.DataFrame([{"query_error": None}])
        error_stats = calculate_error_statistics(data)

        assert len(error_stats) == 0
