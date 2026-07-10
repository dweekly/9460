"""Focused tests for deterministic IANA SvcParamKey registry generation."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import stat
from email.message import Message
from pathlib import Path
from typing import Any
from urllib.request import Request

import pytest

from src import registry_codegen
from src.rfc9460_checker._generated_svcparam_registry import (
    IANA_REGISTRY_METADATA,
    IANA_SVCPARAM_REGISTRY,
    IANA_SVCPARAM_SPECIAL_RANGES,
)


def _csv_payload(rows: list[tuple[str, str, str, str, str]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(registry_codegen.EXPECTED_CSV_HEADER)
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _valid_rows() -> list[tuple[str, str, str, str, str]]:
    return [
        ("0", "example", "Example registration", "IETF", "[RFC9460]"),
        ("1-65535", "Unassigned", "", "", ""),
    ]


def _write_fixture(
    directory: Path,
    payload: bytes,
    *,
    manifest_updates: dict[str, object] | None = None,
    encoded_payload: bytes | None = None,
) -> Path:
    payload_name = "registry.csv.b64"
    manifest: dict[str, object] = {
        "schema_version": 1,
        "registry_id": "dns-svcparamkeys",
        "registry_name": "DNS SVCB Service Parameter Keys (SvcParamKeys)",
        "registry_page_url": "https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml",
        "csv_url": "https://www.iana.org/assignments/dns-svcb/dns-svcparamkeys.csv",
        "iana_last_updated": "2026-06-25",
        "retrieved_at": "2026-07-10",
        "payload_file": payload_name,
        "payload_encoding": "base64",
        "payload_length": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    if manifest_updates:
        manifest.update(manifest_updates)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / payload_name).write_bytes(
        encoded_payload if encoded_payload is not None else base64.b64encode(payload) + b"\n"
    )
    manifest_path = directory / "registry.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path


def test_default_snapshot_preserves_hash_entries_and_special_ranges() -> None:
    """Load the pinned snapshot without losing any registry data."""
    snapshot = registry_codegen.load_snapshot()

    assert len(snapshot.payload) == 1264
    assert hashlib.sha256(snapshot.payload).hexdigest() == (
        "2a1695a17ab72f36585d166efb9eda2c911d547158a8963adf7914df74de9231"
    )
    assert [entry.key for entry in snapshot.entries] == list(range(13))
    assert snapshot.entries[5].name == "ech"
    assert snapshot.entries[5].reference == "[RFC9848]"
    assert snapshot.entries[12].name == "oots"
    assert snapshot.entries[12].meaning == (
        "Per-transport operator confidence in serving the \n"
        "nameserver's query load over that transport, as a percentage"
    )
    assert [
        (item.start, item.end, item.name, item.meaning) for item in snapshot.special_ranges
    ] == [
        (13, 65279, "Unassigned", ""),
        (65280, 65534, "N/A", "Reserved for Private Use"),
        (65535, 65535, "N/A", 'Reserved ("Invalid key")'),
    ]

    assert IANA_REGISTRY_METADATA["payload_sha256"] == snapshot.manifest.payload_sha256
    assert IANA_SVCPARAM_REGISTRY[12]["meaning"] == snapshot.entries[12].meaning
    assert IANA_SVCPARAM_SPECIAL_RANGES[-1]["start"] == 65535


def test_default_generated_module_is_an_exact_deterministic_render() -> None:
    """Keep checked-in generated output byte-for-byte reproducible."""
    snapshot = registry_codegen.load_snapshot()
    rendered = registry_codegen.render_module(snapshot)

    assert rendered == registry_codegen.render_module(snapshot)
    assert rendered.encode("utf-8") == registry_codegen.DEFAULT_OUTPUT.read_bytes()
    assert registry_codegen.generated_module_is_current()


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"Name,Number,Meaning,Change Controller,Reference\r\n", "CSV header"),
        (b"Number,Name,Meaning,Change Controller,Reference\r\n\xff", "valid UTF-8"),
    ],
)
def test_csv_rejects_malformed_header_and_utf8(payload: bytes, message: str) -> None:
    """Reject malformed CSV structure and text encoding."""
    with pytest.raises(registry_codegen.RegistrySnapshotError, match=message):
        registry_codegen.parse_registry_csv(payload)


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        (
            [
                ("0", "one", "One", "IETF", "[RFC9460]"),
                ("0", "two", "Two", "IETF", "[RFC9460]"),
                ("1-65535", "Unassigned", "", "", ""),
            ],
            "overlaps",
        ),
        (
            [
                ("0", "same", "One", "IETF", "[RFC9460]"),
                ("1", "SAME", "Two", "IETF", "[RFC9460]"),
                ("2-65535", "Unassigned", "", "", ""),
            ],
            "duplicates registered name",
        ),
        (
            [
                ("0", "one", "One", "IETF", "[RFC9460]"),
                ("1-10", "Unassigned", "", "", ""),
                ("10-65535", "Unassigned", "", "", ""),
            ],
            "overlaps",
        ),
        (
            [
                ("0", "one", "One", "IETF", "[RFC9460]"),
                ("2-1", "Unassigned", "", "", ""),
                ("2-65535", "Unassigned", "", "", ""),
            ],
            "reversed",
        ),
        (
            [
                ("0", "one", "One", "IETF", "[RFC9460]"),
                ("1-65536", "Unassigned", "", "", ""),
            ],
            "outside the 16-bit key space",
        ),
        (
            [
                ("0", "one", "One", "IETF", "[RFC9460]"),
                ("2-65535", "Unassigned", "", "", ""),
            ],
            "coverage has a gap",
        ),
        (
            [
                ("0", "key123", "One", "IETF", "[RFC9460]"),
                ("1-65535", "Unassigned", "", "", ""),
            ],
            "fallback syntax",
        ),
        (
            [
                ("0", "bad name", "One", "IETF", "[RFC9460]"),
                ("1-65535", "Unassigned", "", "", ""),
            ],
            "invalid registered name",
        ),
        (
            [
                ("0", "one", "One", "IETF", "[RFC9460]"),
                ("1-65535", "N/A", "Reserved for Other", "IETF", "[RFC9460]"),
            ],
            "unrecognized reserved range",
        ),
        (
            [
                ("0", "one", "One", "IETF", "[RFC9460]"),
                ("1-65535", "Unassigned", "unexpected", "", ""),
            ],
            "metadata on an unassigned range",
        ),
    ],
)
def test_csv_rejects_invalid_keys_names_and_coverage(
    rows: list[tuple[str, str, str, str, str]], message: str
) -> None:
    """Reject ambiguous key allocation and fallback-name collisions."""
    with pytest.raises(registry_codegen.RegistrySnapshotError, match=message):
        registry_codegen.parse_registry_csv(_csv_payload(rows))


def test_manifest_rejects_payload_hash_mismatch(tmp_path: Path) -> None:
    """Bind the decoded snapshot bytes to the manifest digest."""
    manifest_path = _write_fixture(
        tmp_path,
        _csv_payload(_valid_rows()),
        manifest_updates={"payload_sha256": "0" * 64},
    )

    with pytest.raises(registry_codegen.RegistrySnapshotError, match="SHA-256"):
        registry_codegen.load_snapshot(manifest_path)


def test_manifest_rejects_invalid_base64(tmp_path: Path) -> None:
    """Reject non-base64 characters in the armored snapshot."""
    manifest_path = _write_fixture(
        tmp_path,
        _csv_payload(_valid_rows()),
        encoded_payload=b"not+base64!\n",
    )

    with pytest.raises(registry_codegen.RegistrySnapshotError, match="valid base64"):
        registry_codegen.load_snapshot(manifest_path)


@pytest.mark.parametrize(
    "payload_file",
    ["../registry.csv.b64", "sub/registry.csv.b64", "registry\x00.csv.b64"],
)
def test_manifest_rejects_payload_path_traversal(tmp_path: Path, payload_file: str) -> None:
    """Keep manifest payload references inside their own directory."""
    manifest_path = _write_fixture(
        tmp_path,
        _csv_payload(_valid_rows()),
        manifest_updates={"payload_file": payload_file},
    )

    with pytest.raises(registry_codegen.RegistrySnapshotError, match="local basename"):
        registry_codegen.load_snapshot(manifest_path)


class _FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        url: str,
        content_length: str | None = None,
        status: int = 200,
    ) -> None:
        self._body = body
        self._url = url
        self._status = status
        self.headers = Message()
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return self._url

    def getcode(self) -> int:
        return self._status

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]


class _FakeOpener:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response
        self.request: Request | None = None
        self.timeout: float | None = None

    def open(self, request: Request, *, timeout: float) -> _FakeResponse:
        self.request = request
        self.timeout = timeout
        return self.response


def test_upstream_fetch_rejects_redirect_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a response whose final URL differs from the IANA request."""
    url = "https://www.iana.org/assignments/dns-svcb/dns-svcparamkeys.csv"
    opener = _FakeOpener(_FakeResponse(b"ignored", url="https://example.com/registry.csv"))
    monkeypatch.setattr(registry_codegen.urllib.request, "build_opener", lambda *_: opener)

    with pytest.raises(registry_codegen.RegistrySnapshotError, match="response URL"):
        registry_codegen.fetch_upstream_csv(url)


def test_redirect_handler_refuses_redirects() -> None:
    """Prevent urllib from following redirects before validating a response."""
    handler = registry_codegen._RejectRedirects()

    with pytest.raises(registry_codegen.RegistrySnapshotError, match="redirects"):
        handler.redirect_request(
            Request("https://www.iana.org/assignments/source"),
            io.BytesIO(),
            302,
            "Found",
            Message(),
            "https://www.iana.org/assignments/destination",
        )


@pytest.mark.parametrize("declared_length", [None, "101"])
def test_upstream_fetch_enforces_size_limit(
    monkeypatch: pytest.MonkeyPatch, declared_length: str | None
) -> None:
    """Enforce the cap with and without a Content-Length header."""
    url = "https://www.iana.org/assignments/dns-svcb/dns-svcparamkeys.csv"
    opener = _FakeOpener(_FakeResponse(b"x" * 101, url=url, content_length=declared_length))
    monkeypatch.setattr(registry_codegen.urllib.request, "build_opener", lambda *_: opener)

    with pytest.raises(registry_codegen.RegistrySnapshotError, match="size limit"):
        registry_codegen.fetch_upstream_csv(url, size_limit=100)


def test_mocked_upstream_compare_is_read_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Compare upstream bytes in memory without mutating local files."""
    payload = _csv_payload(_valid_rows())
    manifest_path = _write_fixture(tmp_path, payload)
    output_path = tmp_path / "generated.py"
    output_path.write_text("leave me alone\n", encoding="utf-8")
    before = {path: path.read_bytes() for path in (manifest_path, output_path)}
    snapshot = registry_codegen.load_snapshot(manifest_path)

    def fake_fetch(_url: str, **_kwargs: Any) -> bytes:
        return payload

    monkeypatch.setattr(registry_codegen, "fetch_upstream_csv", fake_fetch)

    assert registry_codegen.upstream_matches_snapshot(snapshot)
    assert (
        registry_codegen.main(
            [
                "--check-upstream",
                "--manifest",
                str(manifest_path),
                "--output",
                str(output_path),
            ]
        )
        == 0
    )
    assert {path: path.read_bytes() for path in before} == before


def test_cli_check_and_write_detect_and_repair_render_drift(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exercise stale-check, explicit write, and clean-check CLI states."""
    manifest_path = _write_fixture(tmp_path, _csv_payload(_valid_rows()))
    output_path = tmp_path / "generated.py"
    output_path.write_text("stale\n", encoding="utf-8")
    output_path.chmod(0o640)
    arguments = ["--manifest", str(manifest_path), "--output", str(output_path)]

    assert registry_codegen.main(["--check", *arguments]) == 1
    assert output_path.read_text(encoding="utf-8") == "stale\n"
    assert "stale" in capsys.readouterr().err

    assert registry_codegen.main(["--write", *arguments]) == 0
    expected = registry_codegen.render_module(registry_codegen.load_snapshot(manifest_path))
    assert output_path.read_text(encoding="utf-8") == expected
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o640

    assert registry_codegen.main(["--check", *arguments]) == 0


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0", "-1"])
def test_upstream_timeout_requires_a_finite_positive_number(value: str) -> None:
    """Non-finite and non-positive timeouts fail during argument validation."""
    with pytest.raises(registry_codegen.argparse.ArgumentTypeError, match="finite positive"):
        registry_codegen._positive_float(value)
