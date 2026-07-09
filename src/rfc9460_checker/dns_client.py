"""Asynchronous collection of schema-v2 HTTPS and SVCB observations."""

import asyncio
import logging
from typing import Any, cast

import dns.asyncresolver
import dns.resolver
from asyncio_throttle import Throttler

from .exceptions import DNSQueryError
from .models import (
    DEFAULT_MAX_ALIAS_DEPTH,
    PARSER_LIMITATIONS,
    SCHEMA_VERSION,
    SVCPARAM_REGISTRY_METADATA,
    VALIDATOR_RULESET_VERSION,
)
from .parser import parse_https_record, parse_svcb_record
from .validator import validate_dns_name, validate_domain

logger = logging.getLogger(__name__)


class RFC9460Checker:
    """Collect RFC 9460 record-adoption and validity observations."""

    def __init__(
        self,
        dns_servers: list[str] | None = None,
        timeout: float = 5.0,
        rate_limit: int = 10,
        max_alias_depth: int = DEFAULT_MAX_ALIAS_DEPTH,
    ) -> None:
        """Initialize the checker.

        ``max_alias_depth`` bounds HTTPS/SVCB AliasMode traversal.  Resolver
        provenance is captured from dnspython's answer object for each RRset.
        """
        if max_alias_depth < 1:
            raise ValueError("max_alias_depth must be at least 1")
        self.dns_servers = dns_servers or ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = self.dns_servers
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        self.throttler = Throttler(rate_limit=rate_limit)
        self.max_alias_depth = max_alias_depth
        self._cache: dict[str, dict[str, Any]] = {}

    async def query_https_record(self, domain: str, subdomain: str = "") -> dict[str, Any]:
        """Query one owner name for HTTPS records."""
        full_domain = f"{subdomain}.{domain}" if subdomain else domain
        if not validate_domain(full_domain):
            raise DNSQueryError(f"Invalid domain: {full_domain}")

        cache_key = f"{full_domain}:HTTPS"
        if cache_key in self._cache:
            logger.debug("Cache hit for %s", cache_key)
            return self._cache[cache_key]

        result = self._base_observation(domain, subdomain, full_domain, "HTTPS")
        try:
            answers = await self._resolve(full_domain, "HTTPS")
            parsed = parse_https_record(answers, owner_name=full_domain)
            if parsed:
                result.update(parsed)
                result["has_record"] = True
                result["has_https_record"] = True
                result["query_status"] = "present"
                await self._add_alias_resolution(result, full_domain, "HTTPS")
            else:
                result["query_error"] = "No HTTPS record"
        except dns.resolver.NXDOMAIN:
            result["query_status"] = "nxdomain"
            result["query_error"] = "NXDOMAIN"
            logger.info("NXDOMAIN for %s", full_domain)
        except dns.resolver.NoAnswer:
            result["query_error"] = "No HTTPS record"
            logger.info("No HTTPS record for %s", full_domain)
        except dns.resolver.Timeout:
            result["query_status"] = "timeout"
            result["query_error"] = "Timeout"
            logger.warning("Timeout querying %s", full_domain)
        except Exception as error:
            result["query_status"] = "error"
            result["query_error"] = str(error)
            logger.error("Error querying %s: %s", full_domain, error)

        self._cache[cache_key] = result
        return result

    async def query_svcb_record(self, domain: str, subdomain: str = "") -> dict[str, Any]:
        """Query one owner name for generic SVCB records."""
        full_domain = f"{subdomain}.{domain}" if subdomain else domain
        if not validate_dns_name(full_domain):
            raise DNSQueryError(f"Invalid domain: {full_domain}")

        cache_key = f"{full_domain}:SVCB"
        if cache_key in self._cache:
            logger.debug("Cache hit for %s", cache_key)
            return self._cache[cache_key]

        result = self._base_observation(domain, subdomain, full_domain, "SVCB")
        try:
            answers = await self._resolve(full_domain, "SVCB")
            parsed = parse_svcb_record(answers, owner_name=full_domain)
            if parsed:
                result.update(parsed)
                result["has_record"] = True
                result["has_svcb_record"] = True
                result["query_status"] = "present"
                await self._add_alias_resolution(result, full_domain, "SVCB")
                logger.info("Found SVCB record for %s", full_domain)
            else:
                result["query_error"] = "No SVCB record"
        except dns.resolver.NXDOMAIN:
            result["query_status"] = "nxdomain"
            result["query_error"] = "NXDOMAIN"
            logger.info("NXDOMAIN for SVCB %s", full_domain)
        except dns.resolver.NoAnswer:
            result["query_error"] = "No SVCB record"
            logger.info("No SVCB record for %s", full_domain)
        except dns.resolver.Timeout:
            result["query_status"] = "timeout"
            result["query_error"] = "Timeout"
            logger.warning("Timeout querying SVCB %s", full_domain)
        except Exception as error:
            result["query_status"] = "error"
            result["query_error"] = str(error)
            logger.error("Error querying SVCB for %s: %s", full_domain, error)

        self._cache[cache_key] = result
        return result

    async def _resolve(self, owner_name: str, record_type: str) -> Any:
        async with self.throttler:
            logger.debug("Querying %s record for %s", record_type, owner_name)
            return await self.resolver.resolve(owner_name, record_type)

    def _base_observation(
        self,
        domain: str,
        subdomain: str,
        full_domain: str,
        record_type: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "probe_type": "dns",
            "domain": domain,
            "subdomain": subdomain or "root",
            "full_domain": full_domain,
            "owner_name": full_domain,
            "query_name": full_domain,
            "rrset_owner_name": None,
            "record_type": record_type,
            "query_status": "no_answer",
            "query_error": None,
            "has_record": False,
            "has_https_record": False,
            "has_svcb_record": False,
            "records": [],
            "record_count": 0,
            "ttl": None,
            "resolver": None,
            "resolver_port": None,
            "configured_resolvers": list(self.dns_servers),
            "canonical_name": None,
            "svcparam_registry": dict(SVCPARAM_REGISTRY_METADATA),
            "validator_ruleset_version": VALIDATOR_RULESET_VERSION,
            "parser_limitations": list(PARSER_LIMITATIONS),
            # Absence and transport/query failures are not RFC validity claims.
            "validation_status": "not_applicable",
            "validation_issues": [],
            "alias_chain": [],
            "alias_resolution_status": "not_applicable",
            "resolution_issues": [],
            "resolved_rrsets": [],
            "effective_records": [],
            # Legacy scalar columns retained while analyzers migrate to records.
            "https_priority": None,
            "https_target": None,
            "svcb_priority": None,
            "svcb_target": None,
            "alpn_protocols": None,
            "has_http3": False,
            "port": None,
            "ipv4hint": None,
            "ipv6hint": None,
            "ech_config": False,
        }

    async def _add_alias_resolution(
        self,
        observation: dict[str, Any],
        owner_name: str,
        record_type: str,
    ) -> None:
        """Follow a bounded AliasMode chain and retain each complete RRset."""
        current_owner = str(observation.get("rrset_owner_name") or owner_name)
        current: dict[str, Any] = observation
        visited = {
            self._normalized_name(owner_name),
            self._normalized_name(current_owner),
        }
        resolved_rrsets: list[dict[str, Any]] = []
        chain: list[dict[str, Any]] = []

        while True:
            resolved_rrsets.append(self._rrset_snapshot(current, current_owner, record_type))
            alias_records = [
                record
                for record in current.get("records", [])
                if isinstance(record, dict)
                and record.get("mode") == "alias"
                and not record.get("ignored")
            ]
            if not alias_records:
                observation["alias_resolution_status"] = "resolved" if chain else "not_applicable"
                observation["effective_records"] = current.get("records", [])
                observation["effective_validation_status"] = current.get("validation_status")
                break

            alias = alias_records[0]
            target = str(alias.get("target", ""))
            chain.append(
                {
                    "depth": len(chain) + 1,
                    "owner_name": current_owner,
                    "target_name": target,
                    "ttl": current.get("ttl"),
                    "resolver": current.get("resolver"),
                }
            )
            if target == ".":
                observation["alias_resolution_status"] = "service_unavailable"
                observation["effective_records"] = []
                break

            normalized_target = self._normalized_name(target)
            if normalized_target in visited:
                observation["alias_resolution_status"] = "loop"
                observation["effective_records"] = []
                observation.setdefault("resolution_issues", []).append(
                    {
                        "code": "alias_loop",
                        "severity": "warning",
                        "message": f"AliasMode loop detected at {target}",
                    }
                )
                break
            if len(chain) >= self.max_alias_depth:
                observation["alias_resolution_status"] = "max_depth"
                observation["effective_records"] = []
                break

            visited.add(normalized_target)
            try:
                answers = await self._resolve(target, record_type)
                parser = parse_https_record if record_type == "HTTPS" else parse_svcb_record
                parsed = parser(answers, owner_name=target)
                if not parsed:
                    observation["alias_resolution_status"] = "no_answer"
                    observation["effective_records"] = []
                    break
                current = parsed
                current_owner = str(parsed.get("rrset_owner_name") or target)
            except dns.resolver.NXDOMAIN:
                observation["alias_resolution_status"] = "nxdomain"
                observation["effective_records"] = []
                break
            except dns.resolver.NoAnswer:
                observation["alias_resolution_status"] = "no_answer"
                observation["effective_records"] = []
                break
            except dns.resolver.Timeout:
                observation["alias_resolution_status"] = "timeout"
                observation["effective_records"] = []
                break
            except Exception as error:
                observation["alias_resolution_status"] = "error"
                observation["alias_resolution_error"] = str(error)
                observation["effective_records"] = []
                break

        observation["alias_chain"] = chain
        observation["resolved_rrsets"] = resolved_rrsets

    @staticmethod
    def _rrset_snapshot(
        parsed: dict[str, Any], owner_name: str, record_type: str
    ) -> dict[str, Any]:
        return {
            "probe_type": "dns",
            "owner_name": owner_name,
            "query_name": parsed.get("query_name"),
            "rrset_owner_name": parsed.get("rrset_owner_name"),
            "record_type": record_type,
            "ttl": parsed.get("ttl"),
            "resolver": parsed.get("resolver"),
            "resolver_port": parsed.get("resolver_port"),
            "canonical_name": parsed.get("canonical_name"),
            "validation_status": parsed.get("validation_status"),
            "validation_issues": parsed.get("validation_issues", []),
            "records": parsed.get("records", []),
        }

    @staticmethod
    def _normalized_name(name: str) -> str:
        return name.rstrip(".").lower()

    async def check_domain(self, domain: str) -> list[dict[str, Any]]:
        """Check root and ``www`` HTTPS names for a website domain.

        Generic SVCB requires a protocol-specific underscored query name and is
        therefore available only through the explicit ``query_svcb_record`` API.
        """
        task_configs = [
            (self.query_https_record(domain, ""), "root", "HTTPS"),
            (self.query_https_record(domain, "www"), "www", "HTTPS"),
        ]
        results = await asyncio.gather(
            *(config[0] for config in task_configs),
            return_exceptions=True,
        )

        processed_results: list[dict[str, Any]] = []
        for (_, subdomain, record_type), result in zip(task_configs, results):
            if isinstance(result, Exception):
                full_domain = domain if subdomain == "root" else f"www.{domain}"
                failed = self._base_observation(domain, subdomain, full_domain, record_type)
                failed["query_status"] = "error"
                failed["query_error"] = str(result)
                processed_results.append(failed)
            else:
                successful = cast(dict[str, Any], result)
                successful["record_type"] = record_type
                processed_results.append(successful)
        return processed_results

    async def check_domains(self, domains: list[str], batch_size: int = 5) -> list[dict[str, Any]]:
        """Check multiple domains in bounded batches."""
        all_results: list[dict[str, Any]] = []
        for index in range(0, len(domains), batch_size):
            batch = domains[index : index + batch_size]
            batch_results = await asyncio.gather(*(self.check_domain(domain) for domain in batch))
            for domain_results in batch_results:
                all_results.extend(domain_results)
        return all_results

    def clear_cache(self) -> None:
        """Clear cached observations."""
        self._cache.clear()
        logger.info("DNS cache cleared")
