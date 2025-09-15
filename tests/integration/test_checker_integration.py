"""Integration tests for RFC 9460 checker."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pandas as pd
import pytest

from src.analyzer import generate_summary_report
from src.rfc9460_checker import RFC9460Checker


class TestCheckerIntegration:
    """Integration tests for the complete checker workflow."""

    @pytest.fixture
    def mock_dns_responses(self):
        """Create mock DNS responses for testing."""
        responses = {}

        # example.com root - has HTTPS with HTTP/3
        mock_https = MagicMock()
        mock_https.priority = 1
        mock_https.target = "example.com."
        mock_https.params = {
            1: b"h3,h2",  # ALPN
            5: b"ech_config",  # ECH
        }
        responses["example.com:HTTPS"] = [mock_https]

        # www.example.com - has HTTPS without HTTP/3
        mock_https_www = MagicMock()
        mock_https_www.priority = 1
        mock_https_www.target = "www.example.com."
        mock_https_www.params = {
            1: b"h2",  # ALPN without h3
        }
        responses["www.example.com:HTTPS"] = [mock_https_www]

        # test.com - no HTTPS records
        responses["test.com:HTTPS"] = None
        responses["www.test.com:HTTPS"] = None

        return responses

    @pytest.mark.asyncio
    async def test_end_to_end_workflow(self, tmp_path, mock_dns_responses):
        """Test complete workflow from DNS query to report generation."""
        checker = RFC9460Checker()
        domains = ["example.com", "test.com"]

        with patch.object(checker.resolver, "resolve", new_callable=AsyncMock) as mock_resolve:

            def resolve_side_effect(domain, record_type):
                key = f"{domain}:{record_type}"
                if key in mock_dns_responses:
                    if mock_dns_responses[key] is None:
                        raise Exception("No HTTPS record")
                    return mock_dns_responses[key]
                raise Exception("NXDOMAIN")

            mock_resolve.side_effect = resolve_side_effect

            # Check domains
            results = await checker.check_domains(domains)

            # Verify we got results for all domains and subdomains
            assert len(results) == 8  # 2 domains × 2 subdomains × 2 record types

            # Generate reports
            report_paths = generate_summary_report(results, tmp_path)

            # Verify all report types were generated
            assert "csv" in report_paths
            assert "json" in report_paths
            assert "markdown" in report_paths

            # Verify files exist
            for path in report_paths.values():
                assert Path(path).exists()

            # Load and verify CSV content
            df = pd.read_csv(report_paths["csv"])
            assert len(df) == 4
            assert "has_https_record" in df.columns
            assert "has_http3" in df.columns

    @pytest.mark.asyncio
    async def test_concurrent_domain_checking(self):
        """Test concurrent checking of multiple domains."""
        checker = RFC9460Checker()
        domains = [f"test{i}.com" for i in range(10)]

        call_count = 0

        async def mock_check_domain(domain):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.01)  # Simulate network delay
            return [
                {"domain": domain, "subdomain": "root"},
                {"domain": domain, "subdomain": "www"},
            ]

        with patch.object(checker, "check_domain", side_effect=mock_check_domain):
            results = await checker.check_domains(domains, batch_size=5)

            # Should have results for all domains
            assert len(results) == 20  # 10 domains × 2 subdomains
            assert call_count == 10

    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        """Test that rate limiting is applied."""
        checker = RFC9460Checker(rate_limit=2)  # 2 queries per second

        query_times = []

        async def mock_resolve(domain, record_type):
            query_times.append(asyncio.get_event_loop().time())
            return []

        with patch.object(
            checker.resolver, "resolve", new_callable=AsyncMock, side_effect=mock_resolve
        ):
            # Make 4 queries
            tasks = [checker.query_https_record(f"test{i}.com") for i in range(4)]
            await asyncio.gather(*tasks)

            # With rate limit of 2/sec, 4 queries should take at least 1.5 seconds
            # (first 2 immediate, next 2 after 1 second)
            if len(query_times) >= 4:
                time_diff = query_times[-1] - query_times[0]
                # Allow some tolerance for timing
                assert time_diff >= 1.0

    @pytest.mark.asyncio
    async def test_cache_effectiveness(self):
        """Test that caching reduces DNS queries."""
        checker = RFC9460Checker()

        resolve_count = 0

        async def mock_resolve(domain, record_type):
            nonlocal resolve_count
            resolve_count += 1
            return []

        with patch.object(
            checker.resolver, "resolve", new_callable=AsyncMock, side_effect=mock_resolve
        ):
            # Query same domain multiple times
            for _ in range(3):
                await checker.query_https_record("example.com")

            # Should only resolve once due to caching
            assert resolve_count == 1

            # Clear cache and query again
            checker.clear_cache()
            await checker.query_https_record("example.com")

            # Should have resolved again after cache clear
            assert resolve_count == 2

    @pytest.mark.asyncio
    async def test_error_recovery(self):
        """Test that checker continues after encountering errors."""
        checker = RFC9460Checker()

        async def mock_resolve(domain, record_type):
            if "fail" in domain:
                raise Exception("DNS failure")
            return []

        with patch.object(
            checker.resolver, "resolve", new_callable=AsyncMock, side_effect=mock_resolve
        ):
            domains = ["good1.com", "fail.com", "good2.com"]
            results = await checker.check_domains(domains)

            # Should have results for all domains
            assert len(results) == 12  # 3 domains × 2 subdomains × 2 record types

            # Check that failed domain has error recorded
            fail_results = [r for r in results if r["domain"] == "fail.com"]
            assert all(r.get("query_error") for r in fail_results)

            # Check that good domains don't have errors
            good_results = [r for r in results if "good" in r["domain"]]
            assert all(not r.get("query_error") for r in good_results)
