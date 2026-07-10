"""Tests for canonical snapshots and generated dashboard data."""

import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from src.analyzer.pipeline import (
    build_snapshot,
    compare_snapshots,
    generate_pages_data,
    import_legacy_history,
    load_cohort,
    load_snapshot,
    normalize_observation,
    run_pipeline,
    verify_pages_data,
    write_snapshot,
)


def _row(
    domain: str,
    variant: str,
    rrtype: str,
    present: bool = False,
    **values: object,
) -> dict:
    name = domain if variant == "root" else f"www.{domain}"
    row = {
        "domain": domain,
        "subdomain": variant,
        "full_domain": name,
        "record_type": rrtype,
        "has_https_record": present if rrtype == "HTTPS" else False,
        "has_svcb_record": present if rrtype == "SVCB" else False,
        "query_error": None if present else f"No {rrtype} record",
        "timestamp": "2026-07-09T12:00:00Z",
    }
    row.update(values)
    return row


def test_bundled_pipeline_cohort_is_available_without_the_repository_file() -> None:
    """The installed pipeline can fingerprint its default fixed cohort."""
    cohort = load_cohort()

    assert cohort["count"] == 101
    assert cohort["source"] == "Similarweb/Semrush rankings - December 2024"
    assert cohort["domains"][0] == "google.com"


def test_denominators_do_not_mix_https_and_svcb_rows() -> None:
    """Unrelated SVCB queries must not dilute HTTPS adoption."""
    rows = []
    for index in range(101):
        domain = f"site{index}.example"
        rows.extend(
            [
                _row(domain, "root", "HTTPS", present=index < 8),
                _row(domain, "www", "HTTPS", present=index < 20),
                _row(domain, "root", "SVCB"),
                _row(domain, "www", "SVCB"),
            ]
        )

    snapshot = build_snapshot(rows)
    denominators = snapshot["metrics"]["denominators"]
    adoption = snapshot["metrics"]["adoption"]

    assert denominators["domains"] == 101
    assert denominators["observations"] == 404
    assert denominators["https_names"] == 202
    assert denominators["svcb_names"] == 202
    assert adoption["https"]["count"] == 28
    assert adoption["https"]["denominator"] == 202
    assert adoption["https"]["percentage"] == 13.86


def test_normalization_preserves_complete_rrset_and_extensions() -> None:
    """Normalization retains all RDATA and unknown extension data."""
    observation = normalize_observation(
        {
            "domain": "example.com",
            "name": "example.com",
            "rrtype": "HTTPS",
            "present": True,
            "resolver": "1.1.1.1",
            "records": [
                {
                    "priority": 2,
                    "target": "b.example.",
                    "params": {"alpn": ["h2"]},
                    "raw": '2 b.example. alpn="h2"',
                    "ttl": 300,
                    "usable": True,
                    "ignored": False,
                },
                {
                    "priority": 1,
                    "target": "a.example.",
                    "params": {"alpn": ["h3", "h2"], "key65400": "future"},
                    "raw": '1 a.example. alpn="h3,h2" key65400="future"',
                    "ttl": 60,
                    "usable": True,
                    "ignored": False,
                    "record_annotation": "preserve me too",
                },
            ],
            "validation": {"status": "valid", "issues": []},
            "vendor_annotation": "preserve me",
        }
    )

    assert [record["priority"] for record in observation["records"]] == [1, 2]
    assert observation["records"][0]["params"]["key65400"] == "future"
    assert observation["features"]["h3_advertised"] is True
    assert observation["extensions"]["vendor_annotation"] == "preserve me"
    assert observation["records"][0]["extensions"]["record_annotation"] == "preserve me too"
    assert observation["provenance"]["resolver"] == "1.1.1.1"
    assert normalize_observation(observation) == observation


def test_cname_rrset_owner_does_not_replace_queried_name_identity() -> None:
    """CNAME-backed answers keep the QNAME as their longitudinal identity."""
    present_row = {
        "schema_version": 2,
        "probe_type": "dns",
        "domain": "paypal.com",
        "subdomain": "www",
        "full_domain": "www.paypal.com",
        "query_name": "www.paypal.com",
        "owner_name": "www.paypal.com.cdn.cloudflare.net.",
        "rrset_owner_name": "www.paypal.com.cdn.cloudflare.net.",
        "record_type": "HTTPS",
        "query_status": "present",
        "has_record": True,
        "records": [
            {
                "priority": 1,
                "target": ".",
                "params": {"alpn": ["h2"]},
                "usable": True,
                "ignored": False,
            }
        ],
        "validation_status": "valid",
    }

    observation = normalize_observation(present_row)

    assert observation["name"] == "www.paypal.com"
    assert observation["query_name"] == "www.paypal.com"
    assert observation["owner_name"] == "www.paypal.com.cdn.cloudflare.net."
    assert observation["rrset_owner_name"] == "www.paypal.com.cdn.cloudflare.net."
    assert "query_name" not in observation.get("extensions", {})
    assert "rrset_owner_name" not in observation.get("extensions", {})

    old_canonical = dict(present_row)
    old_canonical.pop("query_name")
    old_canonical.pop("rrset_owner_name")
    old_canonical.update(
        {
            "name": "www.paypal.com.cdn.cloudflare.net",
            "extensions": {
                "query_name": "www.paypal.com",
                "rrset_owner_name": "www.paypal.com.cdn.cloudflare.net.",
                "parser_limitations": ["retained"],
            },
        }
    )
    migrated = normalize_observation(old_canonical)
    assert migrated["name"] == "www.paypal.com"
    assert migrated["query_name"] == "www.paypal.com"
    assert migrated["rrset_owner_name"] == "www.paypal.com.cdn.cloudflare.net."
    assert migrated["extensions"] == {"parser_limitations": ["retained"]}

    previous = build_snapshot(
        [
            {
                "domain": "paypal.com",
                "subdomain": "www",
                "full_domain": "www.paypal.com",
                "query_name": "www.paypal.com",
                "record_type": "HTTPS",
                "query_status": "absent",
                "records": [],
            }
        ],
        scan_started_at="2026-07-09T22:10:38Z",
    )
    current = build_snapshot([present_row], scan_started_at="2026-07-09T23:11:17Z")
    changes = compare_snapshots(previous, current)

    assert changes["summary"] == {"gained": 1, "lost": 0, "changed": 0}
    assert changes["gained"][0]["name"] == "www.paypal.com"
    assert current["metrics"]["denominators"]["https_names"] == 1


def test_normalization_accepts_native_checker_v2_shape() -> None:
    """Checker query/provenance and structured validation fields stay intact."""
    issue = {
        "code": "unsupported_mandatory_param",
        "severity": "incompatible",
        "message": "unsupported key",
        "key": 65400,
    }
    observation = normalize_observation(
        {
            "schema_version": 2,
            "probe_type": "dns",
            "domain": "example.com",
            "subdomain": "root",
            "full_domain": "example.com",
            "owner_name": "example.com",
            "record_type": "HTTPS",
            "query_status": "present",
            "has_record": True,
            "configured_resolvers": ["8.8.8.8", "1.1.1.1"],
            "resolver": "1.1.1.1",
            "resolver_port": 53,
            "records": [
                {
                    "priority": 1,
                    "target": ".",
                    "params": {"port": 443},
                    "validity": "valid_but_incompatible",
                    "validation_issues": [issue],
                    "usable": False,
                    "ignored": False,
                }
            ],
            "record_count": 1,
            "validation_status": "valid_but_incompatible",
            "validation_issues": [issue],
        }
    )

    assert observation["status"] == "present"
    assert observation["name"] == "example.com"
    assert observation["configured_resolvers"] == ["1.1.1.1", "8.8.8.8"]
    assert observation["provenance"] == {"resolver": "1.1.1.1", "resolver_port": 53}
    assert observation["validation"]["issues"] == [issue]
    assert observation["records"][0]["validity"] == "valid_but_incompatible"
    assert observation["records"][0]["validation_issues"] == [issue]
    assert observation["features"]["custom_port"] is False


def test_features_use_only_usable_effective_records() -> None:
    """Unusable siblings and flat compatibility fields cannot leak features."""
    rows = [
        {
            "schema_version": 2,
            "probe_type": "dns",
            "domain": "sibling.example",
            "owner_name": "sibling.example",
            "record_type": "HTTPS",
            "query_status": "present",
            "has_record": True,
            "has_http3": True,
            "ech_config": True,
            "features": {"http3_support": True, "ech_deployment": True},
            "validation_status": "valid",
            "records": [
                {
                    "priority": 1,
                    "target": ".",
                    "mode": "service",
                    "params": {"alpn": ["h2"]},
                    "usable": True,
                    "ignored": False,
                },
                {
                    "priority": 2,
                    "target": ".",
                    "mode": "service",
                    "params": {
                        "alpn": ["h3"],
                        "ech": {"encoding": "base64", "value": "AQ=="},
                    },
                    "usable": False,
                    "ignored": False,
                },
            ],
        },
        {
            "schema_version": 2,
            "probe_type": "dns",
            "domain": "draft.example",
            "owner_name": "draft.example",
            "record_type": "HTTPS",
            "query_status": "present",
            "has_record": True,
            "validation_status": "valid",
            "records": [
                {
                    "priority": 1,
                    "target": ".",
                    "mode": "service",
                    "params": {
                        "alpn": ["h3-29"],
                        "ech": {"encoding": "base64", "value": ""},
                    },
                    "usable": True,
                    "ignored": False,
                }
            ],
        },
        {
            "schema_version": 2,
            "probe_type": "dns",
            "domain": "invalid-ech.example",
            "owner_name": "invalid-ech.example",
            "record_type": "HTTPS",
            "query_status": "present",
            "has_record": True,
            "validation_status": "valid",
            "records": [
                {
                    "priority": 1,
                    "target": ".",
                    "mode": "service",
                    "params": {"ech": {"encoding": "base64", "value": "%%%"}},
                    "usable": True,
                    "ignored": False,
                }
            ],
        },
        {
            "schema_version": 2,
            "probe_type": "dns",
            "domain": "valid.example",
            "owner_name": "valid.example",
            "record_type": "HTTPS",
            "query_status": "present",
            "has_record": True,
            "validation_status": "valid",
            "records": [
                {
                    "priority": 1,
                    "target": ".",
                    "mode": "service",
                    "params": {
                        "alpn": ["h3"],
                        "ech": {"encoding": "base64", "value": "AQ=="},
                    },
                    "usable": True,
                    "ignored": False,
                }
            ],
        },
    ]

    snapshot = build_snapshot(rows, scan_started_at="2026-07-09T12:00:00Z")
    by_domain = {item["domain"]: item for item in snapshot["observations"]}

    assert by_domain["sibling.example"]["features"]["h3_advertised"] is False
    assert by_domain["sibling.example"]["features"]["ech_advertised"] is False
    assert by_domain["draft.example"]["features"]["h3_advertised"] is False
    assert by_domain["draft.example"]["features"]["ech_advertised"] is False
    assert by_domain["invalid-ech.example"]["features"]["ech_advertised"] is False
    assert snapshot["metrics"]["features"]["h3_advertised"]["count"] == 1
    assert snapshot["metrics"]["features"]["ech_advertised"]["count"] == 1


def test_schema_v2_empty_rrset_is_not_usable() -> None:
    """A present-but-empty native observation cannot enter feature denominators."""
    snapshot = build_snapshot(
        [
            {
                "schema_version": 2,
                "probe_type": "dns",
                "domain": "empty.example",
                "owner_name": "empty.example",
                "record_type": "HTTPS",
                "query_status": "present",
                "has_record": True,
                "validation_status": "valid",
                "records": [],
            }
        ],
        scan_started_at="2026-07-09T12:00:00Z",
    )

    assert snapshot["metrics"]["denominators"]["https_present_rrsets"] == 1
    assert snapshot["metrics"]["denominators"]["usable_https_rrsets"] == 0
    assert snapshot["metrics"]["features"]["h3_advertised"]["denominator"] == 0


def test_normal_absence_clears_error_but_failures_retain_it() -> None:
    """Status carries ordinary absence while operational failures keep details."""
    absent = normalize_observation(
        {
            "domain": "absent.example",
            "record_type": "HTTPS",
            "query_status": "no_answer",
            "query_error": "No HTTPS record",
            "records": [],
        }
    )
    nxdomain = normalize_observation(
        {
            "domain": "missing.example",
            "record_type": "HTTPS",
            "query_status": "nxdomain",
            "query_error": "NXDOMAIN",
            "records": [],
        }
    )
    timeout = normalize_observation(
        {
            "domain": "slow.example",
            "record_type": "HTTPS",
            "query_status": "timeout",
            "query_error": "Timeout",
            "records": [],
        }
    )

    assert (absent["status"], absent["error"]) == ("absent", None)
    assert (nxdomain["status"], nxdomain["error"]) == ("nxdomain", None)
    assert (timeout["status"], timeout["error"]) == ("timeout", "Timeout")


def test_future_probe_extensions_do_not_change_dns_metrics() -> None:
    """Future TLS observations coexist without changing DNS denominators."""
    rows = [
        _row("example.com", "root", "HTTPS", present=True),
        {
            "probe_type": "tls",
            "domain": "example.com",
            "name": "example.com",
            "status": "present",
            "present": True,
            "features": {"ml_kem": True},
            "telemetry_version": 1,
            "timestamp": "2026-07-09T12:00:00Z",
        },
    ]

    snapshot = build_snapshot(rows)

    assert len(snapshot["observations"]) == 2
    assert snapshot["metrics"]["denominators"]["observations"] == 1
    tls = next(item for item in snapshot["observations"] if item["probe_type"] == "tls")
    assert tls["features"] == {"ml_kem": True}
    assert tls["extensions"]["telemetry_version"] == 1


def test_snapshot_accepts_cli_scan_bundle() -> None:
    """The pipeline consumes the CLI's scan-envelope JSON directly."""
    snapshot = build_snapshot(
        {
            "scan": {
                "started_at": "2026-07-09T11:59:00Z",
                "completed_at": "2026-07-09T12:00:00Z",
                "configured_resolvers": ["1.1.1.1"],
                "tool_version": "2.0.0",
            },
            "observations": [_row("example.com", "root", "HTTPS")],
        }
    )

    assert snapshot["scan"]["id"] == "2026-07-09T11:59:00Z"
    assert snapshot["scan"]["configured_resolvers"] == ["1.1.1.1"]
    assert snapshot["scan"]["extensions"]["tool_version"] == "2.0.0"


def test_snapshot_preserves_scanner_and_validator_provenance() -> None:
    """Reproducibility metadata survives the scanner-to-snapshot boundary."""
    snapshot = build_snapshot(
        {
            "scan": {
                "started_at": "2026-07-09T11:59:00Z",
                "completed_at": "2026-07-09T12:00:00Z",
                "software": {
                    "name": "rfc9460-checker",
                    "version": "2.1.0",
                    "commit": "abc123",
                    "python": "3.12.8",
                    "dnspython": "2.7.0",
                },
                "validator_ruleset_version": "rfc9460-v1",
                "wire_decoder_version": "wire-v1",
                "svcparam_registry": {"snapshot": "2026-07-01"},
            },
            "observations": [_row("example.com", "root", "HTTPS")],
        }
    )

    assert snapshot["scan"]["provenance"] == {
        "dnspython_version": "2.7.0",
        "package_version": "2.1.0",
        "python_version": "3.12.8",
        "registry_snapshot": {"snapshot": "2026-07-01"},
        "script_version": "2.1.0",
        "software": {
            "commit": "abc123",
            "dnspython": "2.7.0",
            "name": "rfc9460-checker",
            "python": "3.12.8",
            "version": "2.1.0",
        },
        "source_commit": "abc123",
        "validator_ruleset": "rfc9460-v1",
        "wire_decoder": "wire-v1",
    }
    assert snapshot["scan"]["extensions"]["validator_ruleset_version"] == "rfc9460-v1"
    assert snapshot["scan"]["extensions"]["wire_decoder_version"] == "wire-v1"
    assert snapshot["scan"]["extensions"]["svcparam_registry"] == {"snapshot": "2026-07-01"}


def test_wire_evidence_is_canonical_verified_and_idempotent() -> None:
    """Exact packet bytes survive normalization with checked length and digest."""
    message = b"\x12\x34dns-response"
    row = {
        "schema_version": 2,
        "probe_type": "dns",
        "domain": "example.com",
        "full_domain": "example.com",
        "record_type": "HTTPS",
        "query_status": "no_answer",
        "wire_capture": {
            "format_version": 1,
            "responses": [{"used_for_observation": True, "message": message}],
            "unavailable_reason": None,
        },
        "wire_validation": {"format_version": 1, "status": "not_applicable"},
    }

    normalized = normalize_observation(row)
    blob = normalized["wire_capture"]["responses"][0]["message"]

    assert base64.b64decode(blob["value"], validate=True) == message
    assert blob["length"] == len(message)
    assert blob["sha256"] == hashlib.sha256(message).hexdigest()
    assert normalize_observation(normalized) == normalized

    bad = copy.deepcopy(normalized)
    bad["wire_capture"]["responses"][0]["message"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="SHA-256"):
        normalize_observation(bad)


def test_packet_only_wire_changes_do_not_create_deployment_change() -> None:
    """Transaction IDs and packet layout are evidence, not deployment identity."""
    before_observation = normalize_observation(
        {
            "probe_type": "dns",
            "domain": "example.com",
            "full_domain": "example.com",
            "record_type": "HTTPS",
            "query_status": "present",
            "has_record": True,
            "records": [{"priority": 1, "target": ".", "params": {}}],
            "validation_status": "valid",
            "wire_capture": {
                "format_version": 1,
                "responses": [{"message": b"first-packet", "used_for_observation": True}],
            },
        }
    )
    after_observation = copy.deepcopy(before_observation)
    after_observation["wire_capture"]["responses"][0]["message"] = {
        "encoding": "base64",
        "value": base64.b64encode(b"second-packet").decode("ascii"),
    }
    after_observation = normalize_observation(after_observation)
    previous = {
        "scan": {"id": "before", "completed_at": "2026-07-09T00:00:00Z"},
        "observations": [before_observation],
    }
    current = {
        "scan": {"id": "after", "completed_at": "2026-07-09T01:00:00Z"},
        "observations": [after_observation],
    }

    changes = compare_snapshots(previous, current)

    assert changes["summary"] == {"gained": 0, "lost": 0, "changed": 0}


def test_record_hash_must_link_to_captured_rdata() -> None:
    """Normalized semantic records cannot point at unrelated binary evidence."""
    rdata = b"\x00\x01\x00"
    digest = hashlib.sha256(rdata).hexdigest()
    row = {
        "probe_type": "dns",
        "domain": "example.com",
        "full_domain": "example.com",
        "record_type": "HTTPS",
        "query_status": "present",
        "has_record": True,
        "records": [{"priority": 1, "target": ".", "params": {}, "rdata_sha256": digest.upper()}],
        "validation_status": "valid",
        "wire_capture": {
            "format_version": 1,
            "responses": [{"rdata": [{"bytes": rdata}], "used_for_observation": True}],
        },
    }

    normalized = normalize_observation(row)

    assert normalized["records"][0]["rdata_sha256"] == digest
    bad = copy.deepcopy(row)
    bad["records"][0]["rdata_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="does not link"):
        normalize_observation(bad)

    missing_index = copy.deepcopy(row)
    missing_index["wire_capture"]["responses"][0]["rdata"] = []
    with pytest.raises(ValueError, match="does not link"):
        normalize_observation(missing_index)


def test_effective_and_resolved_record_hashes_require_their_wire_evidence() -> None:
    """Terminal alias records link to the nested RRset capture that supplied them."""
    rdata = b"\x00\x01\x00"
    digest = hashlib.sha256(rdata).hexdigest()
    terminal = {
        "priority": 1,
        "target": ".",
        "params": {},
        "rdata_sha256": digest,
    }
    row = {
        "probe_type": "dns",
        "domain": "example.com",
        "full_domain": "example.com",
        "record_type": "HTTPS",
        "query_status": "present",
        "has_record": True,
        "records": [{"priority": 0, "target": "service.example.", "params": {}}],
        "effective_records": [copy.deepcopy(terminal)],
        "validation_status": "valid",
        "resolved_rrsets": [
            {
                "owner_name": "service.example.",
                "records": [copy.deepcopy(terminal)],
                "wire_capture": {
                    "responses": [
                        {
                            "used_for_observation": True,
                            "rdata": [{"bytes": rdata}],
                        }
                    ]
                },
            }
        ],
    }

    normalized = normalize_observation(row)

    assert normalized["effective_records"][0]["rdata_sha256"] == digest
    assert normalized["resolved_rrsets"][0]["records"][0]["rdata_sha256"] == digest

    missing_nested_index = copy.deepcopy(row)
    missing_nested_index["resolved_rrsets"][0]["wire_capture"]["responses"][0]["rdata"] = []
    with pytest.raises(ValueError, match="resolved RRset record.*does not link"):
        normalize_observation(missing_nested_index)

    unrelated_effective = copy.deepcopy(row)
    unrelated_effective["effective_records"][0]["rdata_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="effective record.*does not link"):
        normalize_observation(unrelated_effective)


def test_native_empty_target_is_not_normalized_to_the_root_name() -> None:
    """A failed wire TargetName decode remains malformed in canonical data."""
    row = {
        "probe_type": "dns",
        "domain": "example.com",
        "full_domain": "example.com",
        "record_type": "HTTPS",
        "query_status": "present",
        "has_record": True,
        "records": [
            {
                "priority": 1,
                "target": "",
                "params": {},
                "validation_issues": [{"code": "invalid_target", "severity": "error"}],
            }
        ],
        "validation_status": "invalid",
    }

    normalized = normalize_observation(row)

    assert normalized["records"][0]["target"] == ""


def test_wire_issue_offsets_do_not_create_deployment_change() -> None:
    """Packet layout is non-material even when retained findings have offsets."""
    issue = {
        "code": "duplicate_svcparam_key",
        "severity": "error",
        "message": "duplicate at packet offset",
        "key": 1,
        "offset": 50,
        "length": 2,
    }
    row = {
        "probe_type": "dns",
        "domain": "example.com",
        "full_domain": "example.com",
        "record_type": "HTTPS",
        "query_status": "present",
        "has_record": True,
        "records": [
            {
                "priority": 1,
                "target": ".",
                "params": {"alpn": ["h2"]},
                "validity": "invalid",
                "validation_issues": [issue],
                "usable": False,
                "wire": {"issues": [issue], "rdata_offset": 40},
            }
        ],
        "validation_status": "invalid",
        "validation_issues": [issue],
    }
    before_observation = normalize_observation(row)
    shifted = copy.deepcopy(row)
    shifted_issue = shifted["records"][0]["validation_issues"][0]
    shifted_issue["offset"] = 60
    shifted["records"][0]["wire"]["issues"][0]["offset"] = 60
    shifted["records"][0]["wire"]["rdata_offset"] = 50
    shifted["validation_issues"][0]["offset"] = 60
    after_observation = normalize_observation(shifted)
    previous = {"scan": {"id": "before"}, "observations": [before_observation]}
    current = {"scan": {"id": "after"}, "observations": [after_observation]}

    assert compare_snapshots(previous, current)["summary"]["changed"] == 0

    semantic_change = copy.deepcopy(after_observation)
    semantic_change["validation"]["issues"][0]["code"] = "misordered_svcparam_key"
    current["observations"] = [semantic_change]
    assert compare_snapshots(previous, current)["summary"]["changed"] == 1


def test_https_only_live_scan_has_explicit_zero_svcb_denominator() -> None:
    """New HTTPS-only scans coexist with legacy four-query history."""
    rows = []
    for domain in ("one.example", "two.example"):
        for variant in ("root", "www"):
            present = domain == "one.example"
            row = _row(domain, variant, "HTTPS", present=present)
            row.update(
                {
                    "schema_version": 2,
                    "probe_type": "dns",
                    "query_status": "present" if present else "no_answer",
                    "has_record": present,
                    "validation_status": "valid" if present else "not_applicable",
                    "records": (
                        [
                            {
                                "priority": 1,
                                "target": ".",
                                "mode": "service",
                                "params": {"alpn": ["h2"]},
                                "usable": True,
                                "ignored": False,
                            }
                        ]
                        if present
                        else []
                    ),
                }
            )
            rows.append(row)

    snapshot = build_snapshot(rows)
    denominators = snapshot["metrics"]["denominators"]

    assert denominators["observations"] == 4
    assert denominators["https_names"] == 4
    assert denominators["svcb_names"] == 0
    assert snapshot["metrics"]["adoption"]["svcb"]["denominator"] == 0


def test_snapshot_serialization_is_reproducible(tmp_path: Path) -> None:
    """Equivalent snapshots produce byte-for-byte identical gzip files."""
    snapshot = build_snapshot([_row("example.com", "root", "HTTPS", present=True)])

    first = write_snapshot(snapshot, tmp_path / "first")
    second = write_snapshot(snapshot, tmp_path / "second")

    assert first.read_bytes() == second.read_bytes()
    with gzip.open(first, "rt", encoding="utf-8") as source:
        assert json.load(source) == snapshot
    assert load_snapshot(first) == snapshot


def test_compare_snapshots_reports_record_transitions() -> None:
    """Detailed snapshots expose gained, lost, and changed RRsets."""
    old = build_snapshot(
        [
            _row("gained.example", "root", "HTTPS"),
            _row("lost.example", "root", "HTTPS", present=True, https_priority=1),
            _row("changed.example", "root", "HTTPS", present=True, https_priority=1),
        ],
        scan_started_at="2026-07-08T12:00:00Z",
    )
    new = build_snapshot(
        [
            _row("gained.example", "root", "HTTPS", present=True, https_priority=1),
            _row("lost.example", "root", "HTTPS"),
            _row("changed.example", "root", "HTTPS", present=True, https_priority=2),
        ],
        scan_started_at="2026-07-09T12:00:00Z",
    )

    changes = compare_snapshots(old, new)

    assert changes["comparable"] is True
    assert changes["summary"] == {"gained": 1, "lost": 1, "changed": 1}
    assert changes["gained"][0]["domain"] == "gained.example"
    assert changes["lost"][0]["domain"] == "lost.example"
    assert changes["changed"][0]["fields"] == ["records", "effective_records"]


def test_resolver_change_is_not_a_record_change() -> None:
    """Resolver rotation changes provenance, not the observed record identity."""
    base = {
        "schema_version": 2,
        "probe_type": "dns",
        "domain": "example.com",
        "owner_name": "example.com",
        "record_type": "HTTPS",
        "query_status": "present",
        "has_record": True,
        "validation_status": "valid",
        "records": [
            {
                "priority": 1,
                "target": ".",
                "mode": "service",
                "params": {"alpn": ["h2"]},
                "usable": True,
                "ignored": False,
            }
        ],
    }
    old = build_snapshot([{**base, "resolver": "1.1.1.1"}], scan_started_at="2026-07-08T12:00:00Z")
    new = build_snapshot([{**base, "resolver": "8.8.8.8"}], scan_started_at="2026-07-09T12:00:00Z")

    assert compare_snapshots(old, new)["summary"] == {"gained": 0, "lost": 0, "changed": 0}


def test_alias_effective_record_change_is_material() -> None:
    """A terminal RRset change is visible even when the alias RRset is stable."""
    alias = {
        "priority": 0,
        "target": "service.example.",
        "mode": "alias",
        "params": {},
        "usable": True,
        "ignored": False,
    }

    def source(terminal_target: str) -> dict:
        terminal = {
            "priority": 1,
            "target": terminal_target,
            "mode": "service",
            "params": {"alpn": ["h2"]},
            "usable": True,
            "ignored": False,
        }
        return {
            "schema_version": 2,
            "probe_type": "dns",
            "domain": "example.com",
            "owner_name": "example.com",
            "record_type": "HTTPS",
            "query_status": "present",
            "has_record": True,
            "validation_status": "valid",
            "records": [alias],
            "effective_records": [terminal],
            "alias_resolution_status": "resolved",
            "alias_chain": [
                {
                    "depth": 1,
                    "owner_name": "example.com",
                    "target_name": "service.example.",
                    "resolver": "1.1.1.1",
                }
            ],
            "resolved_rrsets": [
                {
                    "owner_name": "service.example.",
                    "record_type": "HTTPS",
                    "validation_status": "valid",
                    "records": [terminal],
                    "resolver": "1.1.1.1",
                }
            ],
        }

    old = build_snapshot([source("old-target.example.")], scan_started_at="2026-07-08T12:00:00Z")
    new = build_snapshot([source("new-target.example.")], scan_started_at="2026-07-09T12:00:00Z")

    changes = compare_snapshots(old, new)

    assert changes["summary"] == {"gained": 0, "lost": 0, "changed": 1}
    assert "effective_records" in changes["changed"][0]["fields"]
    assert "resolved_rrsets" in changes["changed"][0]["fields"]


def test_legacy_history_import_marks_detail_unavailable(tmp_path: Path) -> None:
    """Legacy aggregates are retained without fabricated observations."""
    report = {
        "metadata": {"scan_date": "2025-09-16T00:00:00Z"},
        "metrics": {
            "unique_domains": 101,
            "total_domains_checked": 404,
            "adoption": {
                "overall_adoption": 8.91,
                "root_adoption": 7.92,
                "www_adoption": 9.9,
                "https_count": 18,
                "svcb_count": 0,
            },
            "features": {"http3_support": {"count": 13, "percentage": 72.22}},
        },
    }
    path = tmp_path / "rfc9460_analysis_2025-09-16_00-00-00.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    entries = import_legacy_history(tmp_path)

    assert len(entries) == 1
    assert entries[0]["schema_version"] == 1
    assert entries[0]["details_available"] is False
    assert entries[0]["metrics"]["adoption"]["https"]["denominator"] == 202
    assert entries[0]["metrics"]["features"]["h3_advertised"]["count"] == 13


def test_legacy_history_infers_missing_record_counts_from_percentages(tmp_path: Path) -> None:
    """Older aggregates recover counts without inventing per-name detail."""
    report = {
        "metadata": {"scan_date": "2025-09-15T00:00:00Z"},
        "metrics": {
            "unique_domains": 100,
            "total_domains_checked": 400,
            "adoption": {
                "overall_adoption": 9.0,
                "root_adoption": 8.0,
                "www_adoption": 10.0,
                "svcb_adoption": 0.0,
            },
            "features": {"http3_support": {"count": 13, "percentage": 72.22}},
        },
    }
    path = tmp_path / "rfc9460_analysis_2025-09-15_00-00-00.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    entry = import_legacy_history(tmp_path)[0]

    assert entry["metrics"]["adoption"]["https"]["count"] == 18
    assert entry["metrics"]["denominators"]["https_present_rrsets"] == 18
    assert entry["metrics"]["features"]["h3_advertised"]["denominator"] == 18


def test_pages_generation_and_consistency_verification(tmp_path: Path) -> None:
    """All three dashboard files agree with the canonical snapshot."""
    scan_dir = tmp_path / "scans"
    pages_dir = tmp_path / "pages"
    snapshot = build_snapshot([_row("example.com", "root", "HTTPS", present=True)])
    write_snapshot(snapshot, scan_dir)

    paths = generate_pages_data(snapshot, scan_dir=scan_dir, pages_dir=pages_dir)
    verified = verify_pages_data(paths["latest"], scan_dir=scan_dir)

    assert verified["scan_id"] == snapshot["scan"]["id"]
    assert load_snapshot(paths["latest"]) == snapshot
    assert load_snapshot(paths["changes"])["comparable"] is False
    history = load_snapshot(paths["history"])
    assert history["entries"][-1]["scan_id"] == snapshot["scan"]["id"]


def test_run_pipeline_reads_cli_json_bundle(tmp_path: Path) -> None:
    """The public pipeline entrypoint builds every artifact from a CLI bundle."""
    input_path = tmp_path / "observations.json"
    cohort_path = tmp_path / "cohort.json"
    input_path.write_text(
        json.dumps(
            {
                "scan": {
                    "started_at": "2026-07-09T11:59:00Z",
                    "completed_at": "2026-07-09T12:00:00Z",
                    "configured_resolvers": ["1.1.1.1"],
                },
                "observations": [_row("example.com", "root", "HTTPS", present=True)],
            }
        ),
        encoding="utf-8",
    )
    cohort_path.write_text(
        json.dumps({"source": "test", "last_updated": "2026-07-09", "websites": ["example.com"]}),
        encoding="utf-8",
    )

    paths = run_pipeline(
        input_path,
        scan_dir=tmp_path / "scans",
        pages_dir=tmp_path / "pages",
        legacy_dir=tmp_path / "legacy",
        cohort_path=cohort_path,
    )

    assert set(paths) == {"snapshot", "latest", "history", "changes"}
    assert verify_pages_data(paths["latest"], scan_dir=tmp_path / "scans")["files"] == 3
