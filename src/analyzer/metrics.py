"""Metrics calculation for RFC 9460 compliance analysis."""

import logging
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

logger = logging.getLogger(__name__)


def calculate_adoption_rate(data: pd.DataFrame) -> Dict[str, float]:
    """Calculate RFC 9460 adoption rates.

    Args:
        data: DataFrame containing DNS query results.

    Returns:
        Dictionary with adoption metrics:
            - overall_adoption: Overall percentage with HTTPS records
            - root_adoption: Root domain adoption rate
            - www_adoption: WWW subdomain adoption rate

    Examples:
        >>> df = pd.read_csv('results.csv')
        >>> metrics = calculate_adoption_rate(df)
        >>> print(f"Overall adoption: {metrics['overall_adoption']}%")
    """
    if data.empty:
        logger.warning("Empty dataset provided for adoption rate calculation")
        return {"overall_adoption": 0.0, "root_adoption": 0.0, "www_adoption": 0.0}

    overall_count = len(data)
    has_https_count = data["has_https_record"].sum()
    overall_adoption = (has_https_count / overall_count * 100) if overall_count > 0 else 0

    # Calculate by subdomain type
    root_data = data[data["subdomain"] == "root"]
    www_data = data[data["subdomain"] == "www"]

    root_adoption = (
        (root_data["has_https_record"].sum() / len(root_data) * 100) if len(root_data) > 0 else 0
    )

    www_adoption = (
        (www_data["has_https_record"].sum() / len(www_data) * 100) if len(www_data) > 0 else 0
    )

    return {
        "overall_adoption": round(overall_adoption, 2),
        "root_adoption": round(root_adoption, 2),
        "www_adoption": round(www_adoption, 2),
    }


def calculate_feature_distribution(data: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    """Calculate distribution of RFC 9460 features.

    Args:
        data: DataFrame containing DNS query results.

    Returns:
        Dictionary with feature distributions for domains with HTTPS records.
    """
    # Filter to only domains with HTTPS records
    https_data = data[data["has_https_record"] == True]

    if https_data.empty:
        return {
            "http3_support": {"count": 0, "percentage": 0.0},
            "ech_deployment": {"count": 0, "percentage": 0.0},
            "custom_port": {"count": 0, "percentage": 0.0},
            "ipv4_hints": {"count": 0, "percentage": 0.0},
            "ipv6_hints": {"count": 0, "percentage": 0.0},
        }

    total = len(https_data)

    def calc_feature_stats(column: str) -> Dict[str, float]:
        """Calculate count and percentage for a feature."""
        count = https_data[column].sum() if column in https_data else 0
        percentage = (count / total * 100) if total > 0 else 0
        return {"count": int(count), "percentage": round(percentage, 2)}

    return {
        "http3_support": calc_feature_stats("has_http3"),
        "ech_deployment": calc_feature_stats("ech_config"),
        "custom_port": {
            "count": https_data["port"].notna().sum(),
            "percentage": round(https_data["port"].notna().sum() / total * 100, 2),
        },
        "ipv4_hints": {
            "count": https_data["ipv4hint"].notna().sum(),
            "percentage": round(https_data["ipv4hint"].notna().sum() / total * 100, 2),
        },
        "ipv6_hints": {
            "count": https_data["ipv6hint"].notna().sum(),
            "percentage": round(https_data["ipv6hint"].notna().sum() / total * 100, 2),
        },
    }


def calculate_compliance_metrics(data: pd.DataFrame) -> Dict[str, Any]:
    """Calculate comprehensive RFC 9460 compliance metrics.

    Args:
        data: DataFrame containing DNS query results.

    Returns:
        Dictionary with all compliance metrics.
    """
    adoption_metrics = calculate_adoption_rate(data)
    feature_metrics = calculate_feature_distribution(data)

    # Calculate compliance score (0-100)
    compliance_scores = []
    for _, row in data.iterrows():
        score = 0
        if row.get("has_https_record"):
            score += 40  # Base score for having HTTPS record
            if row.get("has_http3"):
                score += 20  # HTTP/3 support
            if row.get("ech_config"):
                score += 15  # ECH configuration
            if row.get("ipv4hint") or row.get("ipv6hint"):
                score += 15  # IP hints
            if row.get("alpn_protocols"):
                score += 10  # ALPN specified
        compliance_scores.append(score)

    avg_compliance = sum(compliance_scores) / len(compliance_scores) if compliance_scores else 0

    return {
        "adoption": adoption_metrics,
        "features": feature_metrics,
        "average_compliance_score": round(avg_compliance, 2),
        "total_domains_checked": len(data),
        "unique_domains": data["domain"].nunique(),
    }


def analyze_alpn_protocols(data: pd.DataFrame) -> Dict[str, int]:
    """Analyze ALPN protocol distribution.

    Args:
        data: DataFrame containing DNS query results.

    Returns:
        Dictionary with ALPN protocol counts.
    """
    alpn_counts: Dict[str, int] = {}

    for protocols in data["alpn_protocols"].dropna():
        if isinstance(protocols, str):
            for protocol in protocols.split(","):
                protocol = protocol.strip()
                if protocol:
                    alpn_counts[protocol] = alpn_counts.get(protocol, 0) + 1

    return dict(sorted(alpn_counts.items(), key=lambda x: x[1], reverse=True))


def calculate_priority_distribution(data: pd.DataFrame) -> Dict[int, int]:
    """Calculate distribution of HTTPS record priorities.

    Args:
        data: DataFrame containing DNS query results.

    Returns:
        Dictionary mapping priority values to counts.
    """
    https_data = data[data["has_https_record"] == True]
    priority_counts = https_data["https_priority"].value_counts().to_dict()
    return {int(k): v for k, v in priority_counts.items() if pd.notna(k)}


def identify_top_performers(data: pd.DataFrame, top_n: int = 10) -> List[Tuple[str, float]]:
    """Identify domains with highest RFC 9460 compliance.

    Args:
        data: DataFrame containing DNS query results.
        top_n: Number of top performers to return.

    Returns:
        List of tuples (domain, score) for top performers.
    """
    domain_scores: Dict[str, float] = {}

    for domain in data["domain"].unique():
        domain_data = data[data["domain"] == domain]
        score = 0
        count = 0

        for _, row in domain_data.iterrows():
            count += 1
            if row.get("has_https_record"):
                score += 40
                if row.get("has_http3"):
                    score += 20
                if row.get("ech_config"):
                    score += 15
                if row.get("ipv4hint") or row.get("ipv6hint"):
                    score += 15
                if row.get("alpn_protocols"):
                    score += 10

        domain_scores[domain] = score / count if count > 0 else 0

    sorted_domains = sorted(domain_scores.items(), key=lambda x: x[1], reverse=True)
    return sorted_domains[:top_n]


def calculate_error_statistics(data: pd.DataFrame) -> Dict[str, int]:
    """Calculate statistics on query errors.

    Args:
        data: DataFrame containing DNS query results.

    Returns:
        Dictionary with error type counts.
    """
    error_data = data[data["query_error"].notna()]
    if error_data.empty:
        return {}

    error_counts = error_data["query_error"].value_counts().to_dict()
    return {str(k): int(v) for k, v in error_counts.items()}
