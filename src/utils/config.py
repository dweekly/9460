"""Configuration management utilities."""

import json
import os
from importlib import resources
from pathlib import Path
from typing import Any


def load_config(config_path: str = "config.json") -> dict[str, Any]:
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
        config_data: dict[str, Any] = json.load(f)
        return config_data


def load_websites(
    websites_path: str | None = None,
) -> list[str]:
    """Load the bundled cohort or an explicit website list.

    Args:
        websites_path: Optional path to a websites JSON file.

    Returns:
        List of domain names.
    """
    if websites_path is None:
        source = (
            resources.files("src.data").joinpath("top_websites.json").read_text(encoding="utf-8")
        )
    else:
        source = Path(websites_path).read_text(encoding="utf-8")
    data = json.loads(source)

    if isinstance(data, list):
        websites: list[str] = data
        return websites
    if isinstance(data, dict) and isinstance(data.get("websites"), list):
        websites_from_dict: list[str] = data["websites"]
        return websites_from_dict
    raise ValueError(f"Invalid websites file format: {websites_path or 'bundled cohort'}")


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
