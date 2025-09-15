"""Shared pytest fixtures for tests."""

import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import Mock

import pytest


@pytest.fixture
def mock_dns_response() -> Mock:
    """Create a mock DNS response with HTTPS record data."""
    mock_rdata = Mock()
    mock_rdata.priority = 1
    mock_rdata.target = "example.com."
    mock_rdata.params = {
        1: Mock(ids=["h3", "h2"]),  # ALPN
        3: Mock(port=443),  # Port
        4: Mock(addresses=["192.0.2.1"]),  # IPv4 hint
        5: True,  # ECH
        6: Mock(addresses=["2001:db8::1"]),  # IPv6 hint
    }

    mock_answer = Mock()
    mock_answer.__iter__ = Mock(return_value=iter([mock_rdata]))
    mock_answer.__bool__ = Mock(return_value=True)
    mock_answer.__getitem__ = Mock(return_value=mock_rdata)

    return mock_answer


@pytest.fixture
def sample_domain_list() -> list[str]:
    """Provide a sample list of domains for testing."""
    return [
        "google.com",
        "cloudflare.com",
        "github.com",
        "wikipedia.org",
        "mozilla.org",
    ]


@pytest.fixture
def sample_https_result() -> Dict[str, Any]:
    """Provide a sample HTTPS query result."""
    return {
        "domain": "example.com",
        "subdomain": "root",
        "full_domain": "example.com",
        "has_https_record": True,
        "https_priority": 1,
        "https_target": "example.com.",
        "alpn_protocols": "h3,h2",
        "has_http3": True,
        "port": 443,
        "ipv4hint": "192.0.2.1",
        "ipv6hint": "2001:db8::1",
        "ech_config": True,
        "query_error": None,
    }


@pytest.fixture
def test_data_dir(tmp_path: Path) -> Path:
    """Create a temporary data directory for tests."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    # Create test websites file
    websites_file = data_dir / "test_websites.json"
    websites_data = {
        "source": "Test data",
        "websites": ["test1.com", "test2.com", "test3.com"],
    }
    websites_file.write_text(json.dumps(websites_data))

    return data_dir


@pytest.fixture
def mock_resolver() -> Mock:
    """Create a mock DNS resolver."""
    resolver = Mock()
    resolver.nameservers = ["8.8.8.8"]
    resolver.timeout = 5.0
    resolver.lifetime = 10.0
    return resolver
