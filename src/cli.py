#!/usr/bin/env python3
"""Command-line interface for RFC 9460 compliance checker."""

import argparse
import asyncio
import csv
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import pandas as pd
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from rfc9460_checker import RFC9460Checker
from utils import load_config, load_websites, setup_logging

console = Console()


async def check_domains(
    domains: List[str],
    config: dict,
    output_file: Optional[str] = None,
) -> List[dict]:
    """Check domains for RFC 9460 compliance.

    Args:
        domains: List of domains to check.
        config: Configuration dictionary.
        output_file: Optional output CSV file path.

    Returns:
        List of check results.
    """
    checker = RFC9460Checker(
        dns_servers=config.get("dns_servers"),
        timeout=config.get("timeout", 5.0),
        rate_limit=config.get("rate_limit", 10),
    )

    all_results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Checking domains...", total=len(domains))

        batch_size = config.get("batch_size", 5)
        for i in range(0, len(domains), batch_size):
            batch = domains[i : i + batch_size]
            batch_results = await checker.check_domains(batch, batch_size)

            # Add metadata to results
            for result in batch_results:
                result["script_version"] = "1.0.0"
                result["timestamp"] = datetime.now().isoformat()
                result["dns_server"] = ",".join(checker.dns_servers)
                all_results.append(result)

            progress.update(task, advance=len(batch))

    # Save to CSV if requested
    if output_file:
        save_results_to_csv(all_results, output_file)
        console.print(f"\n[green]Results saved to {output_file}[/green]")

    return all_results


def save_results_to_csv(results: List[dict], output_file: str) -> None:
    """Save results to CSV file.

    Args:
        results: List of result dictionaries.
        output_file: Output CSV file path.
    """
    if not results:
        return

    fieldnames = [
        "script_version",
        "timestamp",
        "dns_server",
        "domain",
        "subdomain",
        "full_domain",
        "has_https_record",
        "https_priority",
        "https_target",
        "alpn_protocols",
        "has_http3",
        "port",
        "ipv4hint",
        "ipv6hint",
        "ech_config",
        "query_error",
    ]

    # Ensure output directory exists
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def display_summary(results: List[dict]) -> None:
    """Display summary statistics of results.

    Args:
        results: List of result dictionaries.
    """
    if not results:
        console.print("[yellow]No results to display[/yellow]")
        return

    df = pd.DataFrame(results)

    # Filter to only root domains for main statistics
    root_df = df[df["subdomain"] == "root"]
    www_df = df[df["subdomain"] == "www"]

    # Create summary table
    table = Table(title="RFC 9460 Compliance Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Root Domains", justify="right")
    table.add_column("WWW Domains", justify="right")

    table.add_row("Total Checked", str(len(root_df)), str(len(www_df)))

    if len(root_df) > 0:
        table.add_row(
            "Has HTTPS Record",
            f"{root_df['has_https_record'].sum()} ({root_df['has_https_record'].mean()*100:.1f}%)",
            (
                f"{www_df['has_https_record'].sum()} ({www_df['has_https_record'].mean()*100:.1f}%)"
                if len(www_df) > 0
                else "N/A"
            ),
        )

        table.add_row(
            "Supports HTTP/3",
            f"{root_df['has_http3'].sum()} ({root_df['has_http3'].mean()*100:.1f}%)",
            (
                f"{www_df['has_http3'].sum()} ({www_df['has_http3'].mean()*100:.1f}%)"
                if len(www_df) > 0
                else "N/A"
            ),
        )

        table.add_row(
            "Has ECH Config",
            f"{root_df['ech_config'].sum()} ({root_df['ech_config'].mean()*100:.1f}%)",
            (
                f"{www_df['ech_config'].sum()} ({www_df['ech_config'].mean()*100:.1f}%)"
                if len(www_df) > 0
                else "N/A"
            ),
        )

    console.print(table)

    # Show domains with HTTP/3 support
    http3_domains = df[(df["has_http3"]) & (df["subdomain"] == "root")]["domain"].tolist()
    if http3_domains:
        console.print("\n[bold green]Domains with HTTP/3 support:[/bold green]")
        for domain in http3_domains[:5]:
            console.print(f"  • {domain}")
        if len(http3_domains) > 5:
            console.print(f"  ... and {len(http3_domains) - 5} more")


def main() -> None:
    """Execute main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="Check domains for RFC 9460 (SVCB/HTTPS DNS records) compliance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--domains",
        nargs="+",
        help="Specific domains to check (overrides --websites-file)",
    )

    parser.add_argument(
        "--websites-file",
        default="top_websites.json",
        help="Path to JSON file containing websites list (default: top_websites.json)",
    )

    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to configuration file (default: config.json)",
    )

    parser.add_argument(
        "--output",
        "-o",
        help="Output CSV file path (default: results/rfc9460_compliance_TIMESTAMP.csv)",
    )

    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Skip displaying summary statistics",
    )

    parser.add_argument(
        "--dns-servers",
        nargs="+",
        help="DNS servers to use (overrides config)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        help="Query timeout in seconds (default: 5.0)",
    )

    parser.add_argument(
        "--rate-limit",
        type=int,
        help="Maximum queries per second (default: 10)",
    )

    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="RFC 9460 Checker v1.0.0",
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(level=args.log_level)

    # Load configuration
    config = load_config(args.config)

    # Override config with command-line arguments
    if args.dns_servers:
        config["dns_servers"] = args.dns_servers
    if args.timeout:
        config["timeout"] = args.timeout
    if args.rate_limit:
        config["rate_limit"] = args.rate_limit

    # Determine domains to check
    if args.domains:
        domains = args.domains
    else:
        domains = load_websites(args.websites_file)

    if not domains:
        console.print("[red]No domains to check![/red]")
        sys.exit(1)

    # Determine output file
    if args.output:
        output_file = args.output
    else:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_file = f"results/rfc9460_compliance_{timestamp}.csv"

    console.print("[bold cyan]RFC 9460 Compliance Checker v1.0.0[/bold cyan]")
    console.print(f"Checking {len(domains)} domains...\n")

    # Run the async checker
    try:
        results = asyncio.run(check_domains(domains, config, output_file))

        if not args.no_summary:
            console.print()
            display_summary(results)

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
