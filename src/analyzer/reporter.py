"""Human-readable reports for RFC 9460 adoption measurements."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from rich.console import Console
from rich.table import Table

from .metrics import (
    analyze_alpn_protocols,
    calculate_error_statistics,
    calculate_metrics,
    calculate_priority_distribution,
    identify_feature_leaders,
)

logger = logging.getLogger(__name__)
console = Console()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_default(value: Any) -> Any:
    if hasattr(value, "item"):
        return value.item()
    if hasattr(value, "tolist"):
        return value.tolist()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


class AdoptionReporter:
    """Generate optional CSV, JSON, Markdown, and console adoption reports."""

    def __init__(self, output_dir: Path | None = None) -> None:
        """Initialize a reporter writing to ``output_dir`` or ``results``."""
        self.output_dir = output_dir or Path("results")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_csv_report(self, data: list[dict[str, Any]], timestamp: str | None = None) -> Path:
        """Write the raw observations as an optional CSV report."""
        timestamp = timestamp or datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filepath = self.output_dir / f"rfc9460_scan_{timestamp}.csv"
        pd.DataFrame(data).to_csv(filepath, index=False)
        logger.info("CSV report saved to %s", filepath)
        return filepath

    def generate_json_report(self, data: pd.DataFrame, timestamp: str | None = None) -> Path:
        """Write an optional JSON adoption summary."""
        timestamp = timestamp or datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        metrics = calculate_metrics(data)
        report = {
            "schema_version": 2,
            "metadata": {
                "report_type": "adoption_summary",
                "scan_date": _now(),
                "domains": metrics["denominators"]["domains"],
            },
            "metrics": metrics,
            "distributions": {
                "alpn_protocols": analyze_alpn_protocols(data),
                "priorities": calculate_priority_distribution(data),
            },
            "feature_leaders": identify_feature_leaders(data),
            "error_statistics": calculate_error_statistics(data),
        }
        filepath = self.output_dir / f"rfc9460_analysis_{timestamp}.json"
        with filepath.open("w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True, default=_json_default)
            output.write("\n")
        logger.info("JSON report saved to %s", filepath)
        return filepath

    def print_summary_table(self, data: pd.DataFrame) -> None:
        """Print explicit adoption counts and denominators to the console."""
        metrics = calculate_metrics(data)
        adoption = metrics["adoption"]
        features = metrics["features"]

        table = Table(title="RFC 9460 Adoption Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", justify="right", style="green")
        table.add_column("Denominator", justify="right")
        table.add_column("Percentage", justify="right")

        rows = [
            ("HTTPS records", adoption["https"]),
            ("Root HTTPS records", adoption["root_https"]),
            ("WWW HTTPS records", adoption["www_https"]),
            ("SVCB records", adoption["svcb"]),
            ("H3 advertised by usable HTTPS", features["h3_advertised"]),
            ("ECH advertised by usable HTTPS", features["ech_advertised"]),
        ]
        for label, metric in rows:
            table.add_row(
                label,
                str(metric["count"]),
                str(metric["denominator"]),
                f"{metric['percentage']:.2f}%",
            )
        console.print(table)

        leaders = identify_feature_leaders(data, top_n=5)
        if leaders:
            console.print(
                "\n[bold cyan]Domains with the broadest observed feature sets:[/bold cyan]"
            )
            for leader in leaders:
                features_text = ", ".join(leader["features"]) or "record only"
                console.print(f"  {leader['domain']}: {features_text}")

    def generate_markdown_report(self, data: pd.DataFrame, timestamp: str | None = None) -> Path:
        """Write an optional human-readable Markdown adoption report."""
        timestamp = timestamp or datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        metrics = calculate_metrics(data)
        adoption = metrics["adoption"]
        features = metrics["features"]
        denominators = metrics["denominators"]

        lines = [
            "# RFC 9460 Adoption Report",
            "",
            f"Generated: {_now()}",
            "",
            "This report measures record and optional-feature adoption; "
            "it is not a compliance score.",
            "",
            "## Summary",
            "",
            f"- Domains in scan: {denominators['domains']}",
            f"- HTTPS names queried: {denominators['https_names']}",
            f"- SVCB names queried: {denominators['svcb_names']}",
            "",
            "## Record adoption",
            "",
            "| Metric | Count | Denominator | Percentage |",
            "|---|---:|---:|---:|",
        ]
        for label, metric in (
            ("HTTPS", adoption["https"]),
            ("Root HTTPS", adoption["root_https"]),
            ("WWW HTTPS", adoption["www_https"]),
            ("SVCB", adoption["svcb"]),
        ):
            lines.append(
                f"| {label} | {metric['count']} | {metric['denominator']} | "
                f"{metric['percentage']:.2f}% |"
            )

        lines.extend(
            [
                "",
                "## Optional features among usable HTTPS RRsets",
                "",
                "| Feature | Count | Denominator | Percentage |",
                "|---|---:|---:|---:|",
            ]
        )
        for name, metric in features.items():
            lines.append(
                f"| {name.replace('_', ' ').title()} | {metric['count']} | "
                f"{metric['denominator']} | {metric['percentage']:.2f}% |"
            )

        leaders = identify_feature_leaders(data)
        lines.extend(
            [
                "",
                "## Feature leaders",
                "",
                "| Domain | HTTPS RRsets | Observed features |",
                "|---|---:|---|",
            ]
        )
        for leader in leaders:
            lines.append(
                f"| {leader['domain']} | {leader['https_rrsets']} | "
                f"{', '.join(leader['features']) or 'record only'} |"
            )
        lines.extend(["", "---", "*Generated by the RFC 9460 adoption tracker*", ""])

        filepath = self.output_dir / f"rfc9460_report_{timestamp}.md"
        filepath.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Markdown report saved to %s", filepath)
        return filepath


# One-release compatibility alias.  Existing imports continue to work, while
# all generated language and data use adoption/validity terminology.
ComplianceReporter = AdoptionReporter


def generate_summary_report(
    data: list[dict[str, Any]], output_dir: Path | None = None
) -> dict[str, Path]:
    """Generate optional manual report formats from scan results."""
    reporter = AdoptionReporter(output_dir)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dataframe = pd.DataFrame(data)
    paths = {
        "csv": reporter.generate_csv_report(data, timestamp),
        "json": reporter.generate_json_report(dataframe, timestamp),
        "markdown": reporter.generate_markdown_report(dataframe, timestamp),
    }
    reporter.print_summary_table(dataframe)
    return paths
