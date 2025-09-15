#!/usr/bin/env python3
"""Main entry point for RFC 9460 compliance checker."""

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from src.analyzer import generate_summary_report
from src.rfc9460_checker import RFC9460Checker
from src.utils import setup_logging

console = Console()
logger = logging.getLogger(__name__)


def load_websites(file_path: str = "top_websites.json") -> List[str]:
    """Load website list from JSON file.

    Args:
        file_path: Path to JSON file containing website list.

    Returns:
        List of domain names.
    """
    try:
        with open(file_path) as f:
            data = json.load(f)
            return data.get("websites", [])
    except FileNotFoundError:
        logger.error(f"Website list file not found: {file_path}")
        console.print(f"[red]Error: Could not find {file_path}[/red]")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {file_path}: {e}")
        console.print(f"[red]Error: Invalid JSON in {file_path}[/red]")
        sys.exit(1)


async def check_all_domains(domains: List[str], checker: RFC9460Checker) -> List[dict]:
    """Check all domains with progress tracking.

    Args:
        domains: List of domains to check.
        checker: RFC9460Checker instance.

    Returns:
        List of all results.
    """
    all_results = []
    last_result = ""

    # Create a custom layout for better display
    with console.status("Initializing...") as status:
        for i, domain in enumerate(domains):
            # Build status message
            current_msg = f"[bold cyan]Checking:[/bold cyan] {domain}"
            progress_pct = (i / len(domains)) * 100
            progress_bar = "█" * int(progress_pct / 5) + "░" * (20 - int(progress_pct / 5))
            progress_msg = (
                f"[bold]Progress:[/bold] [{progress_bar}] {i}/{len(domains)} ({progress_pct:.0f}%)"
            )

            if last_result:
                status_text = f"{current_msg}\n[dim]Previous:[/dim] {last_result}\n{progress_msg}"
            else:
                status_text = f"{current_msg}\n{progress_msg}"

            status.update(status_text)

            try:
                results = await checker.check_domain(domain)
                all_results.extend(results)

                # Summarize results for this domain
                has_https = any(r.get("has_https_record") for r in results)
                has_http3 = any(r.get("has_http3") for r in results)

                if has_https:
                    if has_http3:
                        status_symbol = "[green]✓ HTTPS + HTTP/3[/green]"
                    else:
                        status_symbol = "[yellow]✓ HTTPS[/yellow]"
                else:
                    status_symbol = "[red]✗ No HTTPS[/red]"

                last_result = f"{domain}: {status_symbol}"

            except Exception as e:
                logger.error(f"Error checking {domain}: {e}")
                # Add error entries for both root and www
                for subdomain in ["root", "www"]:
                    all_results.append(
                        {
                            "domain": domain,
                            "subdomain": subdomain,
                            "full_domain": f"www.{domain}" if subdomain == "www" else domain,
                            "has_https_record": False,
                            "query_error": str(e),
                        }
                    )
                last_result = f"{domain}: [red]✗ Error[/red]"

        # Show final status
        progress_bar = "█" * 20
        final_msg = f"[bold green]Complete![/bold green]\n[dim]Last:[/dim] {last_result}\n[bold]Progress:[/bold] [{progress_bar}] {len(domains)}/{len(domains)} (100%)"
        status.update(final_msg)

    # Clear the progress display with a final summary
    console.print()  # Add blank line after progress
    return all_results


async def main_async(args: argparse.Namespace) -> None:
    """Main async function.

    Args:
        args: Command-line arguments.
    """
    # Load websites
    domains = load_websites(args.websites)

    if args.limit:
        domains = domains[: args.limit]
        console.print(f"[yellow]Limiting to first {args.limit} domains[/yellow]")

    console.print(f"[green]Starting RFC 9460 compliance check for {len(domains)} domains[/green]")

    # Initialize checker
    checker = RFC9460Checker(
        dns_servers=args.dns_servers.split(",") if args.dns_servers else None,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
    )

    # Add metadata to results
    metadata = {
        "script_version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "dns_servers": ",".join(checker.dns_servers),
    }

    # Check all domains
    results = await check_all_domains(domains, checker)

    # Add metadata to each result
    for result in results:
        result.update(metadata)

    # Generate reports
    console.print("\n[cyan]Generating reports...[/cyan]")
    output_dir = Path(args.output) if args.output else None
    report_paths = generate_summary_report(results, output_dir)

    console.print("\n[green]✓ Reports generated:[/green]")
    for format_type, path in report_paths.items():
        console.print(f"  • {format_type.upper()}: {path}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Check websites for RFC 9460 (SVCB/HTTPS DNS records) compliance",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-w",
        "--websites",
        default="top_websites.json",
        help="JSON file containing website list",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="results",
        help="Output directory for results",
    )

    parser.add_argument(
        "-l",
        "--limit",
        type=int,
        help="Limit number of domains to check",
    )

    parser.add_argument(
        "--dns-servers",
        help="Comma-separated list of DNS servers (e.g., '8.8.8.8,1.1.1.1')",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="DNS query timeout in seconds",
    )

    parser.add_argument(
        "--rate-limit",
        type=int,
        default=10,
        help="Maximum queries per second",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    # Setup logging
    if args.debug:
        log_level = logging.DEBUG
    elif args.verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    setup_logging(level=log_level)

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        logger.exception("Unexpected error")
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
