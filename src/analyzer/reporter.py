"""Report generation for RFC 9460 compliance analysis."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
from rich.console import Console
from rich.table import Table

from .metrics import (
    analyze_alpn_protocols,
    calculate_compliance_metrics,
    calculate_error_statistics,
    calculate_priority_distribution,
    identify_top_performers,
)

logger = logging.getLogger(__name__)
console = Console()


class ComplianceReporter:
    """Generate reports for RFC 9460 compliance analysis."""

    def __init__(self, output_dir: Optional[Path] = None):
        """Initialize the reporter.

        Args:
            output_dir: Directory for output files. Defaults to 'results/'.
        """
        self.output_dir = output_dir or Path("results")
        self.output_dir.mkdir(exist_ok=True)

    def generate_csv_report(
        self, data: List[Dict[str, Any]], timestamp: Optional[str] = None
    ) -> Path:
        """Generate CSV report from scan results.

        Args:
            data: List of scan results.
            timestamp: Optional timestamp for filename.

        Returns:
            Path to generated CSV file.
        """
        if not timestamp:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        filename = f"rfc9460_compliance_{timestamp}.csv"
        filepath = self.output_dir / filename

        df = pd.DataFrame(data)
        df.to_csv(filepath, index=False)
        logger.info(f"CSV report saved to {filepath}")

        return filepath

    def generate_json_report(self, data: pd.DataFrame, timestamp: Optional[str] = None) -> Path:
        """Generate JSON report with comprehensive metrics.

        Args:
            data: DataFrame with scan results.
            timestamp: Optional timestamp for filename.

        Returns:
            Path to generated JSON file.
        """
        if not timestamp:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        metrics = calculate_compliance_metrics(data)
        alpn_dist = analyze_alpn_protocols(data)
        priority_dist = calculate_priority_distribution(data)
        top_performers = identify_top_performers(data)
        error_stats = calculate_error_statistics(data)

        report = {
            "metadata": {
                "version": "1.0.0",
                "scan_date": datetime.now().isoformat(),
                "total_domains": len(data),
            },
            "metrics": metrics,
            "distributions": {
                "alpn_protocols": alpn_dist,
                "priorities": priority_dist,
            },
            "top_performers": [
                {"domain": domain, "score": score} for domain, score in top_performers
            ],
            "error_statistics": error_stats,
        }

        filename = f"rfc9460_analysis_{timestamp}.json"
        filepath = self.output_dir / filename

        # Convert numpy types to Python native types for JSON serialization
        def convert_types(obj):
            """Convert numpy types to native Python types."""
            if isinstance(obj, dict):
                return {k: convert_types(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_types(v) for v in obj]
            elif hasattr(obj, "item"):  # numpy scalar
                return obj.item()
            elif hasattr(obj, "tolist"):  # numpy array
                return obj.tolist()
            else:
                return obj

        report_json = convert_types(report)

        with open(filepath, "w") as f:
            json.dump(report_json, f, indent=2)

        logger.info(f"JSON report saved to {filepath}")
        return filepath

    def print_summary_table(self, data: pd.DataFrame) -> None:
        """Print summary table to console.

        Args:
            data: DataFrame with scan results.
        """
        metrics = calculate_compliance_metrics(data)

        # Create summary table
        table = Table(title="RFC 9460 Compliance Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Root Domains", style="green")
        table.add_column("WWW Domains", style="green")

        # Get root and www specific data
        root_data = data[data["subdomain"] == "root"]
        www_data = data[data["subdomain"] == "www"]

        # Total checked
        table.add_row(
            "Total Checked",
            str(len(root_data)),
            str(len(www_data)),
        )

        # Has HTTPS record
        root_https = root_data["has_https_record"].sum()
        www_https = www_data["has_https_record"].sum()
        table.add_row(
            "Has HTTPS Record",
            f"{root_https} ({metrics['adoption']['root_adoption']}%)",
            f"{www_https} ({metrics['adoption']['www_adoption']}%)",
        )

        # HTTP/3 support
        root_http3 = root_data["has_http3"].sum()
        www_http3 = www_data["has_http3"].sum()
        table.add_row(
            "Supports HTTP/3",
            f"{root_http3} ({root_http3/len(root_data)*100:.1f}%)",
            f"{www_http3} ({www_http3/len(www_data)*100:.1f}%)",
        )

        # ECH config
        root_ech = root_data["ech_config"].sum()
        www_ech = www_data["ech_config"].sum()
        table.add_row(
            "Has ECH Config",
            f"{root_ech} ({root_ech/len(root_data)*100:.1f}%)",
            f"{www_ech} ({www_ech/len(www_data)*100:.1f}%)",
        )

        # Custom port
        root_port = root_data["port"].notna().sum()
        www_port = www_data["port"].notna().sum()
        table.add_row("Custom Port", str(root_port), str(www_port))

        # IPv4 hints
        root_ipv4 = root_data["ipv4hint"].notna().sum()
        www_ipv4 = www_data["ipv4hint"].notna().sum()
        table.add_row("IPv4 Hints", str(root_ipv4), str(www_ipv4))

        # IPv6 hints
        root_ipv6 = root_data["ipv6hint"].notna().sum()
        www_ipv6 = www_data["ipv6hint"].notna().sum()
        table.add_row("IPv6 Hints", str(root_ipv6), str(www_ipv6))

        console.print(table)

        # Print top performers
        top_performers = identify_top_performers(data, top_n=5)
        if top_performers:
            console.print("\n[bold cyan]Top 5 RFC 9460 Compliant Domains:[/bold cyan]")
            for i, (domain, score) in enumerate(top_performers, 1):
                console.print(f"  {i}. {domain}: {score:.1f}/100")

    def generate_markdown_report(self, data: pd.DataFrame, timestamp: Optional[str] = None) -> Path:
        """Generate markdown report for documentation.

        Args:
            data: DataFrame with scan results.
            timestamp: Optional timestamp.

        Returns:
            Path to generated markdown file.
        """
        if not timestamp:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        metrics = calculate_compliance_metrics(data)
        top_performers = identify_top_performers(data, top_n=10)

        content = f"""# RFC 9460 Compliance Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary

- **Total Domains Checked**: {metrics['total_domains_checked']}
- **Overall Adoption Rate**: {metrics['adoption']['overall_adoption']}%
- **Average Compliance Score**: {metrics['average_compliance_score']}/100

## Adoption Metrics

| Metric | Percentage | Count |
|--------|------------|-------|
| Overall HTTPS Records | {metrics['adoption']['overall_adoption']}% | - |
| Root Domain Adoption | {metrics['adoption']['root_adoption']}% | - |
| WWW Subdomain Adoption | {metrics['adoption']['www_adoption']}% | - |

## Feature Distribution

| Feature | Count | Percentage |
|---------|-------|------------|
| HTTP/3 Support | {metrics['features']['http3_support']['count']} | {metrics['features']['http3_support']['percentage']}% |
| ECH Configuration | {metrics['features']['ech_deployment']['count']} | {metrics['features']['ech_deployment']['percentage']}% |
| Custom Port | {metrics['features']['custom_port']['count']} | {metrics['features']['custom_port']['percentage']}% |
| IPv4 Hints | {metrics['features']['ipv4_hints']['count']} | {metrics['features']['ipv4_hints']['percentage']}% |
| IPv6 Hints | {metrics['features']['ipv6_hints']['count']} | {metrics['features']['ipv6_hints']['percentage']}% |

## Top Performers

| Rank | Domain | Compliance Score |
|------|--------|------------------|
"""

        for i, (domain, score) in enumerate(top_performers, 1):
            content += f"| {i} | {domain} | {score:.1f}/100 |\n"

        content += "\n---\n*Report generated by RFC 9460 Compliance Checker*\n"

        filename = f"rfc9460_report_{timestamp}.md"
        filepath = self.output_dir / filename

        with open(filepath, "w") as f:
            f.write(content)

        logger.info(f"Markdown report saved to {filepath}")
        return filepath


def generate_summary_report(
    data: List[Dict[str, Any]], output_dir: Optional[Path] = None
) -> Dict[str, Path]:
    """Generate all report formats from scan results.

    Args:
        data: List of scan results.
        output_dir: Optional output directory.

    Returns:
        Dictionary with paths to generated reports.
    """
    reporter = ComplianceReporter(output_dir)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Generate CSV
    csv_path = reporter.generate_csv_report(data, timestamp)

    # Convert to DataFrame for analysis
    df = pd.DataFrame(data)

    # Generate JSON report
    json_path = reporter.generate_json_report(df, timestamp)

    # Generate markdown report
    md_path = reporter.generate_markdown_report(df, timestamp)

    # Print summary to console
    reporter.print_summary_table(df)

    return {
        "csv": csv_path,
        "json": json_path,
        "markdown": md_path,
    }
