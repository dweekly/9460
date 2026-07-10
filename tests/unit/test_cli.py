"""Tests for the scanner command-line interchange layer."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.cli import _failed_observations, load_websites, write_observation_bundle
from src.rfc9460_checker.models import (
    SCHEMA_VERSION,
    SVCPARAM_REGISTRY_METADATA,
    VALIDATOR_RULESET_VERSION,
    WIRE_DECODER_VERSION,
)
from src.utils import load_websites as load_compatibility_websites


def test_bundled_cohort_matches_the_tracked_source() -> None:
    """Installed commands retain the same fixed cohort as the repository."""
    tracked = json.loads(Path("top_websites.json").read_text(encoding="utf-8"))["websites"]

    assert load_websites() == tracked
    assert load_compatibility_websites() == tracked


def test_load_websites_accepts_documented_cohort_shape(tmp_path: Path) -> None:
    """Cohort loading normalizes whitespace and a trailing root label."""
    cohort = tmp_path / "cohort.json"
    cohort.write_text(
        json.dumps({"websites": [" example.com. ", "www.example.net"]}),
        encoding="utf-8",
    )

    assert load_websites(str(cohort)) == ["example.com", "www.example.net"]


@pytest.mark.parametrize(
    "contents, message",
    [
        ("not json", "not valid JSON"),
        (json.dumps({"websites": [1]}), "string array"),
        (json.dumps({"websites": []}), "is empty"),
    ],
)
def test_load_websites_rejects_invalid_cohorts(tmp_path: Path, contents: str, message: str) -> None:
    """Malformed cohorts fail before a scan can change its denominator."""
    cohort = tmp_path / "cohort.json"
    cohort.write_text(contents, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        load_websites(str(cohort))


def test_failed_domain_retains_both_https_denominator_rows() -> None:
    """A per-domain failure still emits apex and www HTTPS observations."""
    observations = _failed_observations("example.com", RuntimeError("resolver failed"))

    assert [item["subdomain"] for item in observations] == ["root", "www"]
    assert {item["record_type"] for item in observations} == {"HTTPS"}
    assert all(item["query_status"] == "error" for item in observations)
    assert all(item["query_error"] == "resolver failed" for item in observations)


def test_observation_bundle_records_exact_runtime_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lossless interchange records the versions needed to interpret it."""
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    started = datetime(2026, 7, 9, 12, 0, tzinfo=timezone.utc)
    completed = datetime(2026, 7, 9, 12, 1, tzinfo=timezone.utc)

    path = write_observation_bundle(
        [{"record_type": "HTTPS", "wire_value": b"\x00\x01"}],
        tmp_path,
        started_at=started,
        completed_at=completed,
        resolvers=["8.8.8.8"],
    )
    bundle = json.loads(path.read_text(encoding="utf-8"))

    assert path.name == "rfc9460_observations_2026-07-09_12-00-00.json"
    assert bundle["schema_version"] == SCHEMA_VERSION
    assert bundle["scan"]["started_at"] == "2026-07-09T12:00:00Z"
    assert bundle["scan"]["completed_at"] == "2026-07-09T12:01:00Z"
    assert bundle["scan"]["configured_resolvers"] == ["8.8.8.8"]
    assert bundle["scan"]["software"]["commit"] == "abc123"
    assert bundle["scan"]["software"]["python"]
    assert bundle["scan"]["software"]["dnspython"]
    assert bundle["scan"]["validator_ruleset_version"] == VALIDATOR_RULESET_VERSION
    assert bundle["scan"]["wire_decoder_version"] == WIRE_DECODER_VERSION
    assert bundle["scan"]["svcparam_registry"] == SVCPARAM_REGISTRY_METADATA
    assert bundle["observations"][0]["wire_value"] == {
        "encoding": "base64",
        "value": "AAE=",
    }
