"""Command-line scanner for RFC 9460 adoption and validity observations."""

import argparse
import asyncio
import base64
import json
import logging
import os
import platform
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any

import dns
from rich.console import Console

from . import __version__
from .analyzer import generate_summary_report
from .rfc9460_checker import RFC9460Checker
from .rfc9460_checker.models import (
    SCHEMA_VERSION,
    SVCPARAM_REGISTRY_METADATA,
    VALIDATOR_RULESET_VERSION,
)
from .utils import setup_logging

console = Console()
logger = logging.getLogger(__name__)
TOOL_VERSION = __version__


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        return {
            "encoding": "base64",
            "value": base64.b64encode(value).decode("ascii"),
        }
    if isinstance(value, datetime):
        return _iso(value)
    if hasattr(value, "item"):
        return value.item()
    if hasattr(value, "tolist"):
        return value.tolist()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def load_websites(file_path: str | None = None) -> list[str]:
    """Load and validate a JSON website cohort."""
    if file_path is None:
        source_name = "bundled top_websites.json"
        source_text = (
            resources.files("src.data").joinpath("top_websites.json").read_text(encoding="utf-8")
        )
    else:
        path = Path(file_path)
        source_name = str(path)
        try:
            source_text = path.read_text(encoding="utf-8")
        except FileNotFoundError as error:
            raise ValueError(f"website list not found: {path}") from error
    try:
        value = json.loads(source_text)
    except json.JSONDecodeError as error:
        raise ValueError(f"website list is not valid JSON: {source_name}: {error}") from error

    websites: Any
    if isinstance(value, Mapping):
        websites = value.get("websites")
    else:
        websites = value
    if not isinstance(websites, list) or not all(isinstance(item, str) for item in websites):
        raise ValueError(f"website list must contain a 'websites' string array: {source_name}")
    normalized = [item.strip().rstrip(".") for item in websites if item.strip()]
    if not normalized:
        raise ValueError(f"website list is empty: {source_name}")
    return normalized


def _failed_observations(domain: str, error: Exception) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for variant in ("root", "www"):
        name = domain if variant == "root" else f"www.{domain}"
        observations.append(
            {
                "schema_version": SCHEMA_VERSION,
                "probe_type": "dns",
                "domain": domain,
                "subdomain": variant,
                "full_domain": name,
                "owner_name": name,
                "record_type": "HTTPS",
                "query_status": "error",
                "query_error": str(error),
                "has_record": False,
                "has_https_record": False,
                "has_svcb_record": False,
                "records": [],
                "record_count": 0,
                "validation_status": "not_applicable",
                "validation_issues": [],
            }
        )
    return observations


async def check_all_domains(
    domains: Sequence[str], checker: RFC9460Checker
) -> list[dict[str, Any]]:
    """Collect root and ``www`` HTTPS observations with progress output."""
    observations: list[dict[str, Any]] = []
    last_result = ""
    with console.status("Initializing...") as status:
        for index, domain in enumerate(domains):
            progress = index / len(domains) * 100
            bar = "█" * int(progress / 5) + "░" * (20 - int(progress / 5))
            message = (
                f"[bold cyan]Checking:[/bold cyan] {domain}\n"
                f"[bold]Progress:[/bold] [{bar}] {index}/{len(domains)} ({progress:.0f}%)"
            )
            if last_result:
                message = (
                    f"[bold cyan]Checking:[/bold cyan] {domain}\n[dim]Previous:[/dim] "
                    f"{last_result}\n[bold]Progress:[/bold] [{bar}] "
                    f"{index}/{len(domains)} ({progress:.0f}%)"
                )
            status.update(message)

            try:
                results = await checker.check_domain(domain)
            except Exception as error:  # Keep a complete denominator after one-domain failure.
                logger.exception("Error checking %s", domain)
                results = _failed_observations(domain, error)
            observations.extend(results)

            has_https = any(result.get("has_https_record") for result in results)
            has_http3 = any(result.get("has_http3") for result in results)
            if has_http3:
                outcome = "[green]HTTPS + HTTP/3 advertised[/green]"
            elif has_https:
                outcome = "[yellow]HTTPS record[/yellow]"
            else:
                outcome = "[dim]No HTTPS record[/dim]"
            last_result = f"{domain}: {outcome}"

        status.update(
            f"[bold green]Complete[/bold green]\n[dim]Last:[/dim] {last_result}\n"
            f"[bold]Progress:[/bold] [{'█' * 20}] {len(domains)}/{len(domains)} (100%)"
        )
    console.print()
    return observations


def write_observation_bundle(
    observations: Sequence[Mapping[str, Any]],
    output_dir: Path,
    *,
    started_at: datetime,
    completed_at: datetime,
    resolvers: Sequence[str],
) -> Path:
    """Write the lossless scanner-to-pipeline JSON interchange document."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = started_at.astimezone(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    path = output_dir / f"rfc9460_observations_{stamp}.json"
    bundle = {
        "schema_version": SCHEMA_VERSION,
        "scan": {
            "started_at": _iso(started_at),
            "completed_at": _iso(completed_at),
            "configured_resolvers": list(resolvers),
            "probe_types": ["dns"],
            "software": {
                "name": "rfc9460-checker",
                "version": TOOL_VERSION,
                "commit": os.environ.get("GITHUB_SHA"),
                "python": platform.python_version(),
                "dnspython": getattr(dns, "__version__", "unknown"),
            },
            "validator_ruleset_version": VALIDATOR_RULESET_VERSION,
            "svcparam_registry": dict(SVCPARAM_REGISTRY_METADATA),
        },
        "observations": list(observations),
    }
    path.write_text(
        json.dumps(bundle, indent=2, sort_keys=True, default=_json_default) + "\n",
        encoding="utf-8",
    )
    return path


async def main_async(args: argparse.Namespace) -> dict[str, Path]:
    """Run collection and write the requested outputs."""
    domains = load_websites(args.websites)
    if args.limit is not None:
        if args.limit < 1:
            raise ValueError("--limit must be at least 1")
        domains = domains[: args.limit]
        console.print(f"[yellow]Limiting cohort to {len(domains)} domains[/yellow]")

    console.print(f"[green]Starting RFC 9460 adoption scan for {len(domains)} domains[/green]")
    checker = RFC9460Checker(
        dns_servers=args.dns_servers.split(",") if args.dns_servers else None,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
    )
    started_at = _utc_now()
    observations = await check_all_domains(domains, checker)
    completed_at = _utc_now()

    metadata = {
        "script_version": TOOL_VERSION,
        "timestamp": _iso(started_at),
        "dns_servers": ",".join(checker.dns_servers),
    }
    for observation in observations:
        observation.update(metadata)

    output_dir = Path(args.output)
    bundle = write_observation_bundle(
        observations,
        output_dir,
        started_at=started_at,
        completed_at=completed_at,
        resolvers=checker.dns_servers,
    )
    paths: dict[str, Path] = {"observations": bundle}
    if not args.observations_only:
        console.print("\n[cyan]Generating optional compatibility reports...[/cyan]")
        paths.update(generate_summary_report(observations, output_dir))

    console.print("\n[green]Reports generated:[/green]")
    for output_type, path in paths.items():
        console.print(f"  • {output_type.upper()}: {path}")
    return paths


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure RFC 9460 HTTPS/SVCB adoption and record validity",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-w",
        "--websites",
        help="website cohort JSON file (defaults to the bundled tracked cohort)",
    )
    parser.add_argument("-o", "--output", default="results", help="output directory")
    parser.add_argument("-l", "--limit", type=int, help="limit the number of cohort domains")
    parser.add_argument("--dns-servers", help="comma-separated recursive resolver addresses")
    parser.add_argument("--timeout", type=float, default=5.0, help="DNS query timeout")
    parser.add_argument("--rate-limit", type=int, default=10, help="maximum DNS queries/second")
    parser.add_argument(
        "--observations-only",
        action="store_true",
        help="write only the lossless JSON input used by the canonical pipeline",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="enable informational logs")
    parser.add_argument("--debug", action="store_true", help="enable debug logs")
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Run the command-line application."""
    args = _parser().parse_args(argv)
    setup_logging(
        level=logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING
    )
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        raise SystemExit(130) from None
    except (OSError, ValueError) as error:
        logger.error("Scan failed: %s", error)
        console.print(f"\n[red]Error: {error}[/red]")
        raise SystemExit(1) from error
    except Exception as error:
        logger.exception("Unexpected scan failure")
        console.print(f"\n[red]Unexpected error: {error}[/red]")
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
