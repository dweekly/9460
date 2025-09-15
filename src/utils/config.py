"""Configuration management utilities."""

import json
import os
from pathlib import Path
from typing import Any, Dict, List


def load_config(config_path: str = "config.json") -> Dict[str, Any]:
    """Load configuration from JSON file.

    Args:
        config_path: Path to configuration file.

    Returns:
        Configuration dictionary.
    """
    if not os.path.exists(config_path):
        # Return default configuration
        return {
            "dns_servers": ["8.8.8.8", "1.1.1.1", "208.67.222.222"],
            "timeout": 5.0,
            "rate_limit": 10,
            "batch_size": 5,
            "cache_ttl": 3600,
        }

    with open(config_path) as f:
        config_data: Dict[str, Any] = json.load(f)
        return config_data


def load_websites(
    websites_path: str = "top_websites.json",
) -> List[str]:
    """Load website list from JSON file.

    Args:
        websites_path: Path to websites JSON file.

    Returns:
        List of domain names.
    """
    if not os.path.exists(websites_path):
        # Return a small default list for testing
        return [
            "google.com",
            "cloudflare.com",
            "github.com",
            "wikipedia.org",
            "mozilla.org",
        ]

    with open(websites_path) as f:
        data = json.load(f)

    if isinstance(data, list):
        websites: List[str] = data
        return websites
    elif isinstance(data, dict) and "websites" in data:
        websites_from_dict: List[str] = data["websites"]
        return websites_from_dict
    else:
        raise ValueError(f"Invalid websites file format: {websites_path}")


def get_project_root() -> Path:
    """Get the project root directory.

    Returns:
        Path to project root.
    """
    current = Path(__file__).resolve()
    # Go up from src/utils/config.py to project root
    return current.parent.parent.parent


def get_data_dir() -> Path:
    """Get the data directory path.

    Returns:
        Path to data directory.
    """
    return get_project_root() / "data"


def get_results_dir() -> Path:
    """Get the results directory path.

    Returns:
        Path to results directory.
    """
    results_dir = get_project_root() / "results"
    results_dir.mkdir(exist_ok=True)
    return results_dir
