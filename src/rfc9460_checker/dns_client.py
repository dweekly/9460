"""Asynchronous collection of schema-v2 HTTPS and SVCB observations."""

import asyncio
import ipaddress
import logging
from typing import Any, cast

import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver
from asyncio_throttle import Throttler

from .exceptions import DNSQueryError
from .models import (
    DEFAULT_MAX_ALIAS_DEPTH,
    PARSER_LIMITATIONS,
    SCHEMA_VERSION,
    SVCPARAM_REGISTRY_METADATA,
    VALIDATOR_RULESET_VERSION,
    WIRE_DECODER_VERSION,
)
from .parser import parse_captured_response, parse_https_record, parse_svcb_record
from .validator import validate_dns_name, validate_domain
from .wire_capture import CapturingBackend, DNSWireCapture

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
        except Exception as error:
            if self._apply_captured_response(result, error, full_domain, "HTTPS"):
                await self._add_alias_resolution(result, full_domain, "HTTPS")
            else:
                self._classify_query_error(result, error, full_domain, "HTTPS")

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
        except Exception as error:
            if self._apply_captured_response(result, error, full_domain, "SVCB"):
                await self._add_alias_resolution(result, full_domain, "SVCB")
            else:
                self._classify_query_error(result, error, full_domain, "SVCB")

        self._cache[cache_key] = result
        return result

    async def _resolve(self, owner_name: str, record_type: str) -> Any:
        async with self.throttler:
            logger.debug("Querying %s record for %s", record_type, owner_name)
            backend = CapturingBackend()
            try:
                answer = await self.resolver.resolve(owner_name, record_type, backend=backend)
            except Exception as error:
                self._attach_wire_captures(
                    error,
                    backend.captures,
                    backend.capture_metadata(),
                )
                raise
            self._attach_wire_captures(
                answer,
                backend.captures,
                backend.capture_metadata(),
            )
            return answer

    def _attach_wire_captures(
        self,
        target: Any,
        captures: list[DNSWireCapture],
        capture_metadata: dict[str, int],
    ) -> None:
        """Attach transport bytes without changing dnspython's public objects."""
        accepted = [capture for capture in captures if self._configured_peer(capture.peer)]
        metadata = dict(capture_metadata)
        configured_peer_rejections = len(captures) - len(accepted)
        if configured_peer_rejections:
            metadata["retained_capture_count"] = len(accepted)
            metadata["filtered_datagram_count"] = (
                metadata.get("filtered_datagram_count", 0) + configured_peer_rejections
            )
        try:
            setattr(target, "_rfc9460_wire_captures", accepted)
            setattr(target, "_rfc9460_wire_capture_metadata", metadata)
        except AttributeError, TypeError:
            # Lightweight list fixtures and some third-party answer proxies do
            # not allow attributes; those inputs remain explicitly uncaptured.
            return

    def _configured_peer(self, peer: Any) -> bool:
        """Accept recovery evidence only from a configured resolver address."""
        candidate = peer[0] if isinstance(peer, (tuple, list)) and peer else peer
        candidate_port = (
            peer[1]
            if isinstance(peer, (tuple, list))
            and len(peer) > 1
            and isinstance(peer[1], int)
            and not isinstance(peer[1], bool)
            else None
        )
        if not isinstance(candidate, str) or candidate_port is None:
            return False
        for configured in self.dns_servers:
            expected_port = self.resolver.nameserver_ports.get(configured, self.resolver.port)
            if candidate_port != expected_port:
                continue
            try:
                if ipaddress.ip_address(candidate) == ipaddress.ip_address(configured):
                    return True
            except ValueError:
                if candidate.rstrip(".").lower() == configured.rstrip(".").lower():
                    return True
        return False

    @staticmethod
    def _apply_captured_response(
        observation: dict[str, Any],
        error: Exception,
        owner_name: str,
        record_type: str,
    ) -> bool:
        """Recover records dnspython rejected while preserving its diagnostic."""
        recovered = parse_captured_response(error, record_type, owner_name)
        for field in (
            "wire_decoder_version",
            "wire_capture",
            "wire_validation",
            "resolver",
            "resolver_port",
        ):
            if field in recovered:
                observation[field] = recovered[field]
        if not recovered.get("records"):
            return False
        observation.update(recovered)
        observation["has_record"] = True
        observation["has_https_record"] = record_type == "HTTPS"
        observation["has_svcb_record"] = record_type == "SVCB"
        observation["query_status"] = "present"
        observation["query_error"] = None
        observation.setdefault("resolution_issues", []).append(
            {
                "code": "recovered_pre_parser_wire_response",
                "severity": "warning",
                "message": (
                    "The DNS response was classified from socket-captured bytes after "
                    f"dnspython did not return an Answer: {error}"
                ),
            }
        )
        return True

    @staticmethod
    def _classify_query_error(
        observation: dict[str, Any],
        error: Exception,
        owner_name: str,
        record_type: str,
    ) -> None:
        """Map resolver outcomes without assigning RFC validity to absence."""
        if isinstance(error, dns.resolver.NXDOMAIN):
            observation["query_status"] = "nxdomain"
            observation["query_error"] = "NXDOMAIN"
            logger.info("NXDOMAIN for %s %s", record_type, owner_name)
        elif isinstance(error, dns.resolver.NoAnswer):
            observation["query_error"] = f"No {record_type} record"
            logger.info("No %s record for %s", record_type, owner_name)
        elif isinstance(error, dns.resolver.Timeout):
            observation["query_status"] = "timeout"
            observation["query_error"] = "Timeout"
            logger.warning("Timeout querying %s %s", record_type, owner_name)
        else:
            observation["query_status"] = "error"
            observation["query_error"] = str(error)
            logger.error("Error querying %s for %s: %s", record_type, owner_name, error)

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
            "wire_decoder_version": WIRE_DECODER_VERSION,
            "wire_capture": {
                "format_version": 1,
                "responses": [],
                "capture_metadata": None,
                "unavailable_reason": "no DNS response was captured",
            },
            "wire_validation": {
                "format_version": 1,
                "ruleset_version": WIRE_DECODER_VERSION,
                "status": "not_applicable",
                "issues": [],
            },
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
                and record.get("usable") is True
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
            except Exception as error:
                recovered = parse_captured_response(error, record_type, target)
                if recovered.get("records"):
                    current = recovered
                    current_owner = str(recovered.get("rrset_owner_name") or target)
                    observation.setdefault("resolution_issues", []).append(
                        {
                            "code": "recovered_pre_parser_wire_response",
                            "severity": "warning",
                            "message": (
                                f"Alias target {target} was classified from captured bytes "
                                f"after dnspython did not return an Answer: {error}"
                            ),
                        }
                    )
                    continue
                if recovered.get("wire_capture", {}).get("responses"):
                    failed_snapshot = {
                        "query_name": target,
                        "rrset_owner_name": None,
                        "validation_status": "not_applicable",
                        "validation_issues": [],
                        "records": [],
                        **recovered,
                    }
                    resolved_rrsets.append(
                        self._rrset_snapshot(failed_snapshot, target, record_type)
                    )
                if isinstance(error, dns.resolver.NXDOMAIN):
                    observation["alias_resolution_status"] = "nxdomain"
                elif isinstance(error, dns.resolver.NoAnswer):
                    observation["alias_resolution_status"] = "no_answer"
                elif isinstance(error, dns.resolver.Timeout):
                    observation["alias_resolution_status"] = "timeout"
                else:
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
            "wire_decoder_version": parsed.get("wire_decoder_version"),
            "wire_capture": parsed.get("wire_capture"),
            "wire_validation": parsed.get("wire_validation"),
            "records": parsed.get("records", []),
        }

    @staticmethod
    def _normalized_name(name: str) -> str:
        try:
            return dns.name.from_text(name).canonicalize().to_text()
        except dns.exception.DNSException, UnicodeError, ValueError:
            return name.rstrip(".").casefold()

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
