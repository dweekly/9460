"""Tests for DNS client module."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import pytest

from src.rfc9460_checker.dns_client import RFC9460Checker
from src.rfc9460_checker.exceptions import DNSQueryError


class TestRFC9460Checker:
    """Test suite for RFC9460Checker class."""

    @pytest.fixture
    def checker(self):
        """Create checker instance for testing."""
        return RFC9460Checker()

    @pytest.fixture
    def mock_dns_response(self):
        """Create mock DNS response with HTTPS record."""
        mock_rdata = MagicMock()
        mock_rdata.priority = 1
        mock_rdata.target = "example.com."
        mock_rdata.params = {
            1: b"h3,h2",  # ALPN
            5: b"ech_config_data",  # ECH
            4: b"\xc0\x00\x02\x01",  # IPv4 hint
        }
        return [mock_rdata]

    @pytest.mark.asyncio
    async def test_query_https_record_success(self, checker, mock_dns_response):
        """Test successful HTTPS record query."""
        domain = "example.com"

        with patch.object(checker.resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = mock_dns_response

            result = await checker.query_https_record(domain)

            assert result["has_https_record"] is True
            assert result["domain"] == domain
            assert result["subdomain"] == "root"
            assert result["query_error"] is None
            mock_resolve.assert_called_once_with(domain, "HTTPS")

    @pytest.mark.asyncio
    async def test_query_https_record_nxdomain(self, checker):
        """Test NXDOMAIN handling in HTTPS query."""
        domain = "nonexistent.example.com"

        with patch.object(checker.resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.side_effect = dns.resolver.NXDOMAIN

            result = await checker.query_https_record(domain)

            assert result["has_https_record"] is False
            assert result["query_error"] == "NXDOMAIN"

    @pytest.mark.asyncio
    async def test_query_https_record_no_answer(self, checker):
        """Test NoAnswer handling in HTTPS query."""
        domain = "example.com"

        with patch.object(checker.resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.side_effect = dns.resolver.NoAnswer

            result = await checker.query_https_record(domain)

            assert result["has_https_record"] is False
            assert result["query_error"] == "No HTTPS record"

    @pytest.mark.asyncio
    async def test_query_https_record_timeout(self, checker):
        """Test timeout handling in HTTPS query."""
        domain = "timeout.example.com"

        with patch.object(checker.resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.side_effect = dns.resolver.Timeout

            result = await checker.query_https_record(domain)

            assert result["has_https_record"] is False
            assert result["query_error"] == "Timeout"

    @pytest.mark.asyncio
    async def test_query_https_record_with_subdomain(self, checker):
        """Test HTTPS query with subdomain."""
        domain = "example.com"
        subdomain = "www"

        with patch.object(checker.resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = []

            result = await checker.query_https_record(domain, subdomain)

            assert result["subdomain"] == subdomain
            assert result["full_domain"] == f"{subdomain}.{domain}"
            mock_resolve.assert_called_once_with(f"{subdomain}.{domain}", "HTTPS")

    @pytest.mark.asyncio
    async def test_query_https_record_invalid_domain(self, checker):
        """Test invalid domain handling."""
        invalid_domain = "invalid..domain"

        with pytest.raises(DNSQueryError, match="Invalid domain"):
            await checker.query_https_record(invalid_domain)

    @pytest.mark.asyncio
    async def test_query_https_record_caching(self, checker, mock_dns_response):
        """Test that results are cached."""
        domain = "example.com"

        with patch.object(checker.resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = mock_dns_response

            # First query
            result1 = await checker.query_https_record(domain)
            # Second query (should use cache)
            result2 = await checker.query_https_record(domain)

            assert result1 == result2
            # Should only call resolve once due to caching
            mock_resolve.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_domain_both_subdomains(self, checker):
        """Test checking both root and www subdomains."""
        domain = "example.com"

        with patch.object(checker, "query_https_record", new_callable=AsyncMock) as mock_query:
            mock_query.side_effect = [
                {"subdomain": "root", "has_https_record": True},
                {"subdomain": "www", "has_https_record": False},
            ]

            results = await checker.check_domain(domain)

            assert len(results) == 2
            assert results[0]["subdomain"] == "root"
            assert results[1]["subdomain"] == "www"
            assert mock_query.call_count == 2

    @pytest.mark.asyncio
    async def test_check_domain_exception_handling(self, checker):
        """Test exception handling in check_domain."""
        domain = "example.com"

        with patch.object(checker, "query_https_record", new_callable=AsyncMock) as mock_query:
            mock_query.side_effect = [
                Exception("Query failed"),
                {"subdomain": "www", "has_https_record": True},
            ]

            results = await checker.check_domain(domain)

            assert len(results) == 2
            assert results[0]["query_error"] == "Query failed"
            assert results[1]["subdomain"] == "www"

    @pytest.mark.asyncio
    async def test_check_domains_batch_processing(self, checker):
        """Test batch processing of multiple domains."""
        domains = ["example1.com", "example2.com", "example3.com"]

        with patch.object(checker, "check_domain", new_callable=AsyncMock) as mock_check:
            mock_check.side_effect = [
                [{"domain": d, "subdomain": "root"}, {"domain": d, "subdomain": "www"}]
                for d in domains
            ]

            results = await checker.check_domains(domains, batch_size=2)

            assert len(results) == 6  # 3 domains × 2 subdomains
            assert mock_check.call_count == 3

    @pytest.mark.asyncio
    async def test_query_svcb_record(self, checker):
        """Test SVCB record query."""
        domain = "example.com"

        mock_rdata = MagicMock()
        mock_rdata.priority = 1
        mock_rdata.target = "service.example.com."

        with patch.object(checker.resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = [mock_rdata]

            result = await checker.query_svcb_record(domain)

            assert result["has_svcb_record"] is True
            assert result["svcb_priority"] == 1
            assert result["svcb_target"] == "service.example.com."

    def test_clear_cache(self, checker):
        """Test cache clearing."""
        # Add some items to cache
        checker._cache["test:HTTPS"] = {"test": "data"}
        checker._cache["test2:HTTPS"] = {"test2": "data"}

        checker.clear_cache()

        assert len(checker._cache) == 0

    def test_initialization_with_custom_params(self):
        """Test checker initialization with custom parameters."""
        dns_servers = ["1.1.1.1", "8.8.8.8"]
        timeout = 10.0
        rate_limit = 5

        checker = RFC9460Checker(dns_servers=dns_servers, timeout=timeout, rate_limit=rate_limit)

        assert checker.dns_servers == dns_servers
        assert checker.resolver.timeout == timeout
        assert checker.throttler.rate_limit == rate_limit
