"""DNS client for querying SVCB and HTTPS records."""

import asyncio
import logging
from typing import Any, Dict, List, Optional

import dns.asyncresolver
import dns.rdatatype
import dns.resolver
from asyncio_throttle import Throttler

from .exceptions import DNSQueryError
from .parser import parse_https_record, parse_svcb_record
from .validator import validate_domain

logger = logging.getLogger(__name__)


class RFC9460Checker:
    """Checker for RFC 9460 compliance (SVCB/HTTPS DNS records)."""

    def __init__(
        self,
        dns_servers: Optional[List[str]] = None,
        timeout: float = 5.0,
        rate_limit: int = 10,
    ) -> None:
        """Initialize the RFC 9460 checker.

        Args:
            dns_servers: List of DNS servers to use.
            timeout: Query timeout in seconds.
            rate_limit: Maximum queries per second.
        """
        self.dns_servers = dns_servers or ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = self.dns_servers
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        self.throttler = Throttler(rate_limit=rate_limit)
        self._cache: Dict[str, Dict[str, Any]] = {}

    async def query_https_record(self, domain: str, subdomain: str = "") -> Dict[str, Any]:
        """Query HTTPS record for a domain.

        Args:
            domain: The base domain to query.
            subdomain: Optional subdomain prefix.

        Returns:
            Dictionary containing HTTPS record data.

        Raises:
            DNSQueryError: If DNS query fails.
        """
        full_domain = f"{subdomain}.{domain}" if subdomain else domain

        # Validate domain
        if not validate_domain(full_domain):
            raise DNSQueryError(f"Invalid domain: {full_domain}")

        # Check cache
        cache_key = f"{full_domain}:HTTPS"
        if cache_key in self._cache:
            logger.debug(f"Cache hit for {cache_key}")
            return self._cache[cache_key]

        result = {
            "domain": domain,
            "subdomain": subdomain or "root",
            "full_domain": full_domain,
            "has_https_record": False,
            "https_priority": None,
            "https_target": None,
            "alpn_protocols": None,
            "has_http3": False,
            "port": None,
            "ipv4hint": None,
            "ipv6hint": None,
            "ech_config": False,
            "query_error": None,
        }

        try:
            async with self.throttler:
                logger.debug(f"Querying HTTPS record for {full_domain}")
                answers = await self.resolver.resolve(full_domain, "HTTPS")

            if answers:
                result.update(parse_https_record(answers))
                result["has_https_record"] = True

        except dns.resolver.NXDOMAIN:
            result["query_error"] = "NXDOMAIN"
            logger.info(f"NXDOMAIN for {full_domain}")
        except dns.resolver.NoAnswer:
            result["query_error"] = "No HTTPS record"
            logger.info(f"No HTTPS record for {full_domain}")
        except dns.resolver.Timeout:
            result["query_error"] = "Timeout"
            logger.warning(f"Timeout querying {full_domain}")
        except Exception as e:
            result["query_error"] = str(e)
            logger.error(f"Error querying {full_domain}: {e}")

        # Cache the result
        self._cache[cache_key] = result
        return result

    async def query_svcb_record(self, domain: str, subdomain: str = "") -> Dict[str, Any]:
        """Query SVCB record for a domain.

        Args:
            domain: The domain to query.
            subdomain: Subdomain prefix (e.g., "www").

        Returns:
            Dictionary containing SVCB record data.
        """
        full_domain = f"{subdomain}.{domain}" if subdomain else domain

        result = {
            "domain": domain,
            "subdomain": subdomain if subdomain else "root",
            "full_domain": full_domain,
            "has_svcb_record": False,
            "has_https_record": False,  # For consistency with HTTPS records
        }

        cache_key = f"{full_domain}:SVCB"
        if cache_key in self._cache:
            logger.debug(f"Cache hit for {cache_key}")
            return self._cache[cache_key]

        try:
            async with self.throttler:
                logger.debug(f"Querying SVCB record for {full_domain}")
                answers = await self.resolver.resolve(full_domain, "SVCB")

            parsed = parse_svcb_record(answers)
            if parsed:
                result.update(parsed)
                result["has_svcb_record"] = True
                logger.info(f"Found SVCB record for {full_domain}")
            else:
                result["query_error"] = "No SVCB record"
                logger.info(f"No SVCB record for {full_domain}")

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
            result["query_error"] = type(e).__name__
            logger.info(f"No SVCB record for {full_domain}: {e}")
        except Exception as e:
            result["query_error"] = str(e)
            logger.error(f"Error querying SVCB for {full_domain}: {e}")

        # Cache the result
        self._cache[cache_key] = result
        return result

    async def check_domain(self, domain: str) -> List[Dict[str, Any]]:
        """Check both root and www subdomain for HTTPS and SVCB records.

        Args:
            domain: The domain to check.

        Returns:
            List of results for root and www subdomains with both record types.
        """
        # Create tasks with metadata
        task_configs = [
            {
                "coro": self.query_https_record(domain, ""),
                "subdomain": "root",
                "record_type": "HTTPS",
            },
            {
                "coro": self.query_https_record(domain, "www"),
                "subdomain": "www",
                "record_type": "HTTPS",
            },
            {
                "coro": self.query_svcb_record(domain, ""),
                "subdomain": "root",
                "record_type": "SVCB",
            },
            {
                "coro": self.query_svcb_record(domain, "www"),
                "subdomain": "www",
                "record_type": "SVCB",
            },
        ]

        # Execute all queries
        results = await asyncio.gather(
            *[cfg["coro"] for cfg in task_configs], return_exceptions=True
        )

        # Process results with proper metadata
        processed_results = []
        for config, result in zip(task_configs, results):
            if isinstance(result, Exception):
                processed_results.append(
                    {
                        "domain": domain,
                        "subdomain": config["subdomain"],
                        "record_type": config["record_type"],
                        "full_domain": domain if config["subdomain"] == "root" else f"www.{domain}",
                        "has_https_record": False,
                        "has_svcb_record": False,
                        "query_error": str(result),
                    }
                )
            else:
                # Add record_type to successful results
                result["record_type"] = config["record_type"]
                processed_results.append(result)

        return processed_results

    async def check_domains(self, domains: List[str], batch_size: int = 5) -> List[Dict[str, Any]]:
        """Check multiple domains concurrently.

        Args:
            domains: List of domains to check.
            batch_size: Number of domains to check concurrently.

        Returns:
            List of all results.
        """
        all_results = []

        for i in range(0, len(domains), batch_size):
            batch = domains[i : i + batch_size]
            batch_tasks = [self.check_domain(domain) for domain in batch]
            batch_results = await asyncio.gather(*batch_tasks)

            for domain_results in batch_results:
                all_results.extend(domain_results)

        return all_results

    def clear_cache(self) -> None:
        """Clear the DNS query cache."""
        self._cache.clear()
        logger.info("DNS cache cleared")
