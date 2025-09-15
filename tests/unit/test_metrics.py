"""Tests for metrics calculation module."""

import pandas as pd
import pytest

from src.analyzer.metrics import (
    analyze_alpn_protocols,
    calculate_adoption_rate,
    calculate_compliance_metrics,
    calculate_error_statistics,
    calculate_feature_distribution,
    calculate_priority_distribution,
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

    def test_calculate_compliance_metrics(self, sample_data):
        """Test comprehensive compliance metrics calculation."""
        metrics = calculate_compliance_metrics(sample_data)

        assert "adoption" in metrics
        assert "features" in metrics
        assert "average_compliance_score" in metrics
        assert metrics["total_domains_checked"] == 4
        assert metrics["unique_domains"] == 2

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

    def test_identify_top_performers_scoring(self):
        """Test compliance scoring logic."""
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

        top_performers = identify_top_performers(data, top_n=2)

        assert top_performers[0][0] == "perfect.com"
        assert top_performers[0][1] == 100.0  # Max score
        assert top_performers[1][0] == "basic.com"
        assert top_performers[1][1] == 40.0  # Just base score

    def test_calculate_error_statistics(self, sample_data):
        """Test error statistics calculation."""
        error_stats = calculate_error_statistics(sample_data)

        assert error_stats["No HTTPS record"] == 1
        assert error_stats["NXDOMAIN"] == 1

    def test_calculate_error_statistics_no_errors(self):
        """Test error statistics with no errors."""
        data = pd.DataFrame([{"query_error": None}])
        error_stats = calculate_error_statistics(data)

        assert len(error_stats) == 0
