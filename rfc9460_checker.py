#!/usr/bin/env python3
"""
RFC 9460 Compliance Checker
Checks top websites for SVCB and HTTPS DNS records compliance
"""

import asyncio
import csv
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import dns.asyncresolver
import dns.rdatatype
import dns.resolver
import pandas as pd
from asyncio_throttle import Throttler
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

VERSION = "1.0.0"
console = Console()


class RFC9460Checker:
    def __init__(self, dns_servers: List[str] = None):
        self.dns_servers = dns_servers or ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = self.dns_servers
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 10.0
        self.throttler = Throttler(rate_limit=10)  # 10 queries per second

    async def query_https_record(self, domain: str, subdomain: str = "") -> Dict[str, Any]:
        """Query HTTPS record for a domain"""
        full_domain = f"{subdomain}.{domain}" if subdomain else domain
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
                answers = await self.resolver.resolve(full_domain, "HTTPS")

            if answers:
                result["has_https_record"] = True
                https_records = []

                for rdata in answers:
                    record_info = {
                        "priority": rdata.priority,
                        "target": str(rdata.target),
                        "params": {},
                    }

                    # Parse service parameters
                    if hasattr(rdata, "params") and rdata.params:
                        for param_key, param_value in rdata.params.items():
                            if param_key == 1:  # ALPN
                                alpn_values = []
                                if hasattr(param_value, "ids"):
                                    alpn_values = [
                                        id.decode("ascii") if isinstance(id, bytes) else str(id)
                                        for id in param_value.ids
                                    ]
                                elif isinstance(param_value, (list, tuple)):
                                    alpn_values = [str(v) for v in param_value]
                                record_info["params"]["alpn"] = alpn_values

                            elif param_key == 3:  # Port
                                record_info["params"]["port"] = (
                                    param_value.port
                                    if hasattr(param_value, "port")
                                    else str(param_value)
                                )

                            elif param_key == 4:  # IPv4 hint
                                if hasattr(param_value, "addresses"):
                                    record_info["params"]["ipv4hint"] = [
                                        str(addr) for addr in param_value.addresses
                                    ]
                                else:
                                    record_info["params"]["ipv4hint"] = str(param_value)

                            elif param_key == 6:  # IPv6 hint
                                if hasattr(param_value, "addresses"):
                                    record_info["params"]["ipv6hint"] = [
                                        str(addr) for addr in param_value.addresses
                                    ]
                                else:
                                    record_info["params"]["ipv6hint"] = str(param_value)

                            elif param_key == 5:  # ECH
                                record_info["params"]["ech"] = True

                    https_records.append(record_info)

                # Use the first (highest priority) record for main results
                if https_records:
                    main_record = min(https_records, key=lambda x: x["priority"])
                    result["https_priority"] = main_record["priority"]
                    result["https_target"] = main_record["target"]

                    if "alpn" in main_record["params"]:
                        result["alpn_protocols"] = ",".join(main_record["params"]["alpn"])
                        result["has_http3"] = "h3" in main_record["params"]["alpn"]

                    if "port" in main_record["params"]:
                        result["port"] = main_record["params"]["port"]

                    if "ipv4hint" in main_record["params"]:
                        result["ipv4hint"] = (
                            ",".join(main_record["params"]["ipv4hint"])
                            if isinstance(main_record["params"]["ipv4hint"], list)
                            else str(main_record["params"]["ipv4hint"])
                        )

                    if "ipv6hint" in main_record["params"]:
                        result["ipv6hint"] = (
                            ",".join(main_record["params"]["ipv6hint"])
                            if isinstance(main_record["params"]["ipv6hint"], list)
                            else str(main_record["params"]["ipv6hint"])
                        )

                    if "ech" in main_record["params"]:
                        result["ech_config"] = True

        except dns.resolver.NXDOMAIN:
            result["query_error"] = "NXDOMAIN"
        except dns.resolver.NoAnswer:
            result["query_error"] = "No HTTPS record"
        except dns.resolver.Timeout:
            result["query_error"] = "Timeout"
        except Exception as e:
            result["query_error"] = str(e)

        return result

    async def check_domain(self, domain: str) -> List[Dict[str, Any]]:
        """Check both root and www subdomain for a domain"""
        tasks = [self.query_https_record(domain, ""), self.query_https_record(domain, "www")]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle any exceptions that occurred
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append(
                    {
                        "domain": domain,
                        "subdomain": "root" if i == 0 else "www",
                        "full_domain": domain if i == 0 else f"www.{domain}",
                        "has_https_record": False,
                        "query_error": str(result),
                    }
                )
            else:
                processed_results.append(result)

        return processed_results


async def main():
    console.print(f"[bold cyan]RFC 9460 Compliance Checker v{VERSION}[/bold cyan]")
    console.print(f"Starting scan at {datetime.now().isoformat()}\n")

    # Load websites
    with open("top_websites.json") as f:
        data = json.load(f)
        websites = data["websites"]

    console.print(f"[green]Loaded {len(websites)} websites to check[/green]\n")

    # Create results directory
    os.makedirs("results", exist_ok=True)

    # Initialize checker
    checker = RFC9460Checker()

    # Prepare CSV file
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    csv_filename = f"results/rfc9460_compliance_{timestamp}.csv"

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

    all_results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Checking domains...", total=len(websites))

        # Process domains in batches
        batch_size = 5
        for i in range(0, len(websites), batch_size):
            batch = websites[i : i + batch_size]
            batch_tasks = [checker.check_domain(domain) for domain in batch]
            batch_results = await asyncio.gather(*batch_tasks)

            for domain_results in batch_results:
                for result in domain_results:
                    # Add metadata
                    result["script_version"] = VERSION
                    result["timestamp"] = datetime.now().isoformat()
                    result["dns_server"] = ",".join(checker.dns_servers)
                    all_results.append(result)

            progress.update(task, advance=len(batch))

    # Write to CSV
    with open(csv_filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_results)

    console.print(f"\n[green]Results saved to {csv_filename}[/green]\n")

    # Generate summary statistics
    df = pd.DataFrame(all_results)

    # Filter to only root domains for main statistics
    root_df = df[df["subdomain"] == "root"]
    www_df = df[df["subdomain"] == "www"]

    # Create summary table
    table = Table(title="RFC 9460 Compliance Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Root Domains", justify="right")
    table.add_column("WWW Domains", justify="right")

    table.add_row("Total Checked", str(len(root_df)), str(len(www_df)))

    table.add_row(
        "Has HTTPS Record",
        f"{root_df['has_https_record'].sum()} ({root_df['has_https_record'].mean()*100:.1f}%)",
        f"{www_df['has_https_record'].sum()} ({www_df['has_https_record'].mean()*100:.1f}%)",
    )

    table.add_row(
        "Supports HTTP/3 (QUIC)",
        f"{root_df['has_http3'].sum()} ({root_df['has_http3'].mean()*100:.1f}%)",
        f"{www_df['has_http3'].sum()} ({www_df['has_http3'].mean()*100:.1f}%)",
    )

    table.add_row(
        "Has ECH Config",
        f"{root_df['ech_config'].sum()} ({root_df['ech_config'].mean()*100:.1f}%)",
        f"{www_df['ech_config'].sum()} ({www_df['ech_config'].mean()*100:.1f}%)",
    )

    table.add_row(
        "Custom Port", f"{root_df['port'].notna().sum()}", f"{www_df['port'].notna().sum()}"
    )

    table.add_row(
        "IPv4 Hints", f"{root_df['ipv4hint'].notna().sum()}", f"{www_df['ipv4hint'].notna().sum()}"
    )

    table.add_row(
        "IPv6 Hints", f"{root_df['ipv6hint'].notna().sum()}", f"{www_df['ipv6hint'].notna().sum()}"
    )

    console.print(table)

    # Show top HTTP/3 adopters
    http3_domains = df[(df["has_http3"] == True) & (df["subdomain"] == "root")]["domain"].tolist()
    if http3_domains:
        console.print(f"\n[bold green]Domains with HTTP/3 support:[/bold green]")
        for domain in http3_domains[:10]:
            console.print(f"  • {domain}")
        if len(http3_domains) > 10:
            console.print(f"  ... and {len(http3_domains) - 10} more")

    # Show domains with ECH support
    ech_domains = df[(df["ech_config"] == True) & (df["subdomain"] == "root")]["domain"].tolist()
    if ech_domains:
        console.print(f"\n[bold blue]Domains with ECH support:[/bold blue]")
        for domain in ech_domains[:5]:
            console.print(f"  • {domain}")
        if len(ech_domains) > 5:
            console.print(f"  ... and {len(ech_domains) - 5} more")


if __name__ == "__main__":
    asyncio.run(main())
