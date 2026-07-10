"""Validate and render the vendored IANA SvcParamKey registry snapshot.

Normal checks are deliberately offline.  ``--check-upstream`` is an explicit,
read-only comparison with IANA; it never rewrites the snapshot or generated
module.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import io
import json
import math
import os
import re
import stat
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from email.message import Message
from pathlib import Path
from typing import IO, Final, cast  # noqa: TYP001
from urllib.parse import SplitResult, urlsplit

DEFAULT_MANIFEST: Final = Path(__file__).parent / "data" / "iana" / "dns-svcparamkeys.json"
DEFAULT_OUTPUT: Final = (
    Path(__file__).parent / "rfc9460_checker" / "_generated_svcparam_registry.py"
)
EXPECTED_CSV_HEADER: Final = (
    "Number",
    "Name",
    "Meaning",
    "Change Controller",
    "Reference",
)
EXPECTED_REGISTRY_ID: Final = "dns-svcparamkeys"
IANA_HOST: Final = "www.iana.org"
DEFAULT_UPSTREAM_TIMEOUT_SECONDS: Final = 15.0
DEFAULT_UPSTREAM_SIZE_LIMIT: Final = 1_048_576
MAX_CONFIGURABLE_UPSTREAM_SIZE: Final = 16_777_216

_MANIFEST_KEYS: Final = frozenset(
    {
        "schema_version",
        "registry_id",
        "registry_name",
        "registry_page_url",
        "csv_url",
        "iana_last_updated",
        "retrieved_at",
        "payload_file",
        "payload_encoding",
        "payload_length",
        "payload_sha256",
    }
)
_NUMBER_RE: Final = re.compile(r"(?P<start>[0-9]+)(?:-(?P<end>[0-9]+))?\Z")
_FALLBACK_NAME_RE: Final = re.compile(r"key[0-9]+\Z", re.IGNORECASE)
_REGISTERED_NAME_RE: Final = re.compile(r"[a-z][a-z0-9-]*\Z")
_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}\Z")
_BASE64_WHITESPACE: Final = frozenset(b" \t\r\n")
_SPECIAL_NAMES: Final = frozenset({"N/A", "Unassigned"})


class RegistrySnapshotError(ValueError):
    """Raised when registry inputs violate the snapshot contract."""


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    """One assigned singleton SvcParamKey row."""

    key: int
    name: str
    meaning: str
    change_controller: str
    reference: str


@dataclass(frozen=True, slots=True)
class RegistryRange:
    """One unassigned or reserved interval, including a one-key interval."""

    start: int
    end: int
    name: str
    meaning: str
    change_controller: str
    reference: str


@dataclass(frozen=True, slots=True)
class SnapshotManifest:
    """Validated metadata describing the vendored payload."""

    schema_version: int
    registry_id: str
    registry_name: str
    registry_page_url: str
    csv_url: str
    iana_last_updated: str
    retrieved_at: str
    payload_file: str
    payload_encoding: str
    payload_length: int
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class RegistrySnapshot:
    """A fully validated manifest, payload, and parsed registry."""

    manifest: SnapshotManifest
    payload: bytes
    entries: tuple[RegistryEntry, ...]
    special_ranges: tuple[RegistryRange, ...]


def _validated_json_object(path: Path) -> dict[str, object]:
    try:
        text = path.read_bytes().decode("utf-8", errors="strict")
    except OSError as error:
        raise RegistrySnapshotError(f"cannot read manifest {path}: {error}") from error
    except UnicodeDecodeError as error:
        raise RegistrySnapshotError("manifest is not valid UTF-8") from error

    try:
        value: object = json.loads(text)
    except json.JSONDecodeError as error:
        raise RegistrySnapshotError(f"manifest is not valid JSON: {error.msg}") from error
    if not isinstance(value, dict):
        raise RegistrySnapshotError("manifest root must be a JSON object")

    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise RegistrySnapshotError("manifest keys must be strings")
        result[key] = cast(object, item)

    actual_keys = frozenset(result)
    if actual_keys != _MANIFEST_KEYS:
        missing = sorted(_MANIFEST_KEYS - actual_keys)
        unexpected = sorted(actual_keys - _MANIFEST_KEYS)
        details: list[str] = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected {', '.join(unexpected)}")
        raise RegistrySnapshotError(f"manifest keys do not match schema ({'; '.join(details)})")
    return result


def _required_string(values: dict[str, object], key: str) -> str:
    value = values[key]
    if not isinstance(value, str) or not value:
        raise RegistrySnapshotError(f"manifest {key!r} must be a non-empty string")
    return value


def _required_integer(values: dict[str, object], key: str) -> int:
    value = values[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise RegistrySnapshotError(f"manifest {key!r} must be an integer")
    return value


def _validate_iso_date(value: str, field: str) -> None:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise RegistrySnapshotError(f"manifest {field!r} must be an ISO date") from error
    if parsed.isoformat() != value:
        raise RegistrySnapshotError(f"manifest {field!r} must use YYYY-MM-DD")


def _split_iana_url(url: str, field: str) -> SplitResult:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise RegistrySnapshotError(f"manifest {field!r} is not a valid URL") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != IANA_HOST
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or not parsed.path.startswith("/assignments/")
        or parsed.query
        or parsed.fragment
    ):
        raise RegistrySnapshotError(
            f"manifest {field!r} must be an HTTPS URL on the exact host {IANA_HOST}"
        )
    return parsed


def load_manifest(path: Path = DEFAULT_MANIFEST) -> SnapshotManifest:
    """Load and strictly validate one snapshot manifest."""
    values = _validated_json_object(path)
    schema_version = _required_integer(values, "schema_version")
    if schema_version != 1:
        raise RegistrySnapshotError("unsupported manifest schema_version")

    registry_id = _required_string(values, "registry_id")
    if registry_id != EXPECTED_REGISTRY_ID:
        raise RegistrySnapshotError(f"manifest registry_id must be {EXPECTED_REGISTRY_ID!r}")

    registry_page_url = _required_string(values, "registry_page_url")
    csv_url = _required_string(values, "csv_url")
    _split_iana_url(registry_page_url, "registry_page_url")
    _split_iana_url(csv_url, "csv_url")

    iana_last_updated = _required_string(values, "iana_last_updated")
    retrieved_at = _required_string(values, "retrieved_at")
    _validate_iso_date(iana_last_updated, "iana_last_updated")
    _validate_iso_date(retrieved_at, "retrieved_at")

    payload_file = _required_string(values, "payload_file")
    if (
        "\x00" in payload_file
        or payload_file in {".", ".."}
        or Path(payload_file).name != payload_file
        or "/" in payload_file
        or "\\" in payload_file
    ):
        raise RegistrySnapshotError("manifest payload_file must be a local basename")

    payload_encoding = _required_string(values, "payload_encoding")
    if payload_encoding != "base64":
        raise RegistrySnapshotError("manifest payload_encoding must be 'base64'")

    payload_length = _required_integer(values, "payload_length")
    if payload_length <= 0 or payload_length > MAX_CONFIGURABLE_UPSTREAM_SIZE:
        raise RegistrySnapshotError(
            f"manifest payload_length must be between 1 and {MAX_CONFIGURABLE_UPSTREAM_SIZE}"
        )

    payload_sha256 = _required_string(values, "payload_sha256")
    if _SHA256_RE.fullmatch(payload_sha256) is None:
        raise RegistrySnapshotError("manifest payload_sha256 must be lowercase hexadecimal")

    return SnapshotManifest(
        schema_version=schema_version,
        registry_id=registry_id,
        registry_name=_required_string(values, "registry_name"),
        registry_page_url=registry_page_url,
        csv_url=csv_url,
        iana_last_updated=iana_last_updated,
        retrieved_at=retrieved_at,
        payload_file=payload_file,
        payload_encoding=payload_encoding,
        payload_length=payload_length,
        payload_sha256=payload_sha256,
    )


def _decode_base64_payload(encoded: bytes) -> bytes:
    try:
        encoded.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise RegistrySnapshotError("snapshot payload is not ASCII base64") from error
    compact = bytes(byte for byte in encoded if byte not in _BASE64_WHITESPACE)
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as error:
        raise RegistrySnapshotError("snapshot payload is not valid base64") from error


def _parse_number(value: str, row_number: int) -> tuple[int, int]:
    match = _NUMBER_RE.fullmatch(value)
    if match is None:
        raise RegistrySnapshotError(f"CSV row {row_number} has an invalid Number field")
    start = int(match.group("start"))
    end_text = match.group("end")
    end = start if end_text is None else int(end_text)
    if start > 65535 or end > 65535:
        raise RegistrySnapshotError(f"CSV row {row_number} is outside the 16-bit key space")
    if start > end:
        raise RegistrySnapshotError(f"CSV row {row_number} has a reversed key range")
    return start, end


def _validate_special_range(
    *,
    start: int,
    end: int,
    name: str,
    meaning: str,
    change_controller: str,
    reference: str,
    row_number: int,
) -> None:
    """Validate the explicit unassigned/private-use/reserved registry rows."""
    if name == "Unassigned":
        if meaning or change_controller or reference:
            raise RegistrySnapshotError(f"CSV row {row_number} has metadata on an unassigned range")
        return
    if not change_controller or not reference:
        raise RegistrySnapshotError(f"CSV row {row_number} has incomplete reserved metadata")
    normalized_meaning = meaning.casefold()
    if start != end and "private use" not in normalized_meaning:
        raise RegistrySnapshotError(
            f"CSV row {row_number} has an unrecognized reserved range designation"
        )
    if start == end and "reserved" not in normalized_meaning:
        raise RegistrySnapshotError(
            f"CSV row {row_number} has an unrecognized reserved-key designation"
        )


def parse_registry_csv(
    payload: bytes,
) -> tuple[tuple[RegistryEntry, ...], tuple[RegistryRange, ...]]:
    """Strictly parse and semantically validate an IANA registry CSV payload."""
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RegistrySnapshotError("CSV payload is not valid UTF-8") from error

    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except StopIteration as error:
        raise RegistrySnapshotError("CSV payload is empty") from error
    except csv.Error as error:
        raise RegistrySnapshotError(f"CSV header is malformed: {error}") from error
    if tuple(header) != EXPECTED_CSV_HEADER:
        raise RegistrySnapshotError("CSV header must be exactly " + ",".join(EXPECTED_CSV_HEADER))

    entries: list[RegistryEntry] = []
    special_ranges: list[RegistryRange] = []
    intervals: list[tuple[int, int, int]] = []
    names: dict[str, int] = {}
    try:
        for row_number, row in enumerate(reader, start=2):
            if len(row) != len(EXPECTED_CSV_HEADER):
                raise RegistrySnapshotError(
                    f"CSV row {row_number} has {len(row)} fields; expected "
                    f"{len(EXPECTED_CSV_HEADER)}"
                )
            number, name, meaning, change_controller, reference = row
            start, end = _parse_number(number, row_number)
            if not name or name != name.strip():
                raise RegistrySnapshotError(f"CSV row {row_number} has an invalid Name field")

            intervals.append((start, end, row_number))
            if start != end and name not in _SPECIAL_NAMES:
                raise RegistrySnapshotError(
                    f"CSV row {row_number} assigns a name to a non-singleton range"
                )

            if name in _SPECIAL_NAMES:
                _validate_special_range(
                    start=start,
                    end=end,
                    name=name,
                    meaning=meaning,
                    change_controller=change_controller,
                    reference=reference,
                    row_number=row_number,
                )
                special_ranges.append(
                    RegistryRange(
                        start=start,
                        end=end,
                        name=name,
                        meaning=meaning,
                        change_controller=change_controller,
                        reference=reference,
                    )
                )
                continue

            if start != end:
                raise RegistrySnapshotError(
                    f"CSV row {row_number} has an assigned non-singleton range"
                )
            if not meaning or not change_controller or not reference:
                raise RegistrySnapshotError(
                    f"CSV row {row_number} has an incomplete assigned registration"
                )
            if _FALLBACK_NAME_RE.fullmatch(name) is not None:
                raise RegistrySnapshotError(
                    f"CSV row {row_number} name {name!r} collides with keyNNNN fallback syntax"
                )
            folded_name = name.casefold()
            if folded_name in names:
                raise RegistrySnapshotError(
                    f"CSV row {row_number} duplicates registered name {name!r}"
                )
            if _REGISTERED_NAME_RE.fullmatch(name) is None:
                raise RegistrySnapshotError(
                    f"CSV row {row_number} has an invalid registered name {name!r}"
                )
            names[folded_name] = row_number
            entries.append(
                RegistryEntry(
                    key=start,
                    name=name,
                    meaning=meaning,
                    change_controller=change_controller,
                    reference=reference,
                )
            )
    except csv.Error as error:
        raise RegistrySnapshotError(f"CSV payload is malformed: {error}") from error

    if not intervals:
        raise RegistrySnapshotError("CSV payload has no registry rows")
    intervals.sort()
    expected_start = 0
    for start, end, row_number in intervals:
        if start < expected_start:
            raise RegistrySnapshotError(f"CSV row {row_number} overlaps an earlier key interval")
        if start > expected_start:
            raise RegistrySnapshotError(f"CSV key-space coverage has a gap before key {start}")
        expected_start = end + 1
    if expected_start != 65536:
        raise RegistrySnapshotError("CSV key-space coverage does not end at key 65535")

    entries.sort(key=lambda entry: entry.key)
    special_ranges.sort(key=lambda item: (item.start, item.end))
    return tuple(entries), tuple(special_ranges)


def load_snapshot(manifest_path: Path = DEFAULT_MANIFEST) -> RegistrySnapshot:
    """Load and validate a vendored registry snapshot without network access."""
    manifest = load_manifest(manifest_path)
    payload_path = manifest_path.parent / manifest.payload_file
    try:
        if payload_path.resolve().parent != manifest_path.parent.resolve():
            raise RegistrySnapshotError("snapshot payload resolves outside the manifest directory")
        encoded = payload_path.read_bytes()
    except OSError as error:
        raise RegistrySnapshotError(
            f"cannot read snapshot payload {payload_path}: {error}"
        ) from error
    payload = _decode_base64_payload(encoded)
    if len(payload) != manifest.payload_length:
        raise RegistrySnapshotError(
            f"snapshot payload length is {len(payload)}, expected {manifest.payload_length}"
        )
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if actual_sha256 != manifest.payload_sha256:
        raise RegistrySnapshotError(
            f"snapshot payload SHA-256 is {actual_sha256}, expected {manifest.payload_sha256}"
        )
    entries, special_ranges = parse_registry_csv(payload)
    return RegistrySnapshot(
        manifest=manifest,
        payload=payload,
        entries=entries,
        special_ranges=special_ranges,
    )


def _metadata_items(manifest: SnapshotManifest) -> tuple[tuple[str, str], ...]:
    return (
        ("schema_version", str(manifest.schema_version)),
        ("registry_id", manifest.registry_id),
        ("registry_name", manifest.registry_name),
        ("registry_page_url", manifest.registry_page_url),
        ("csv_url", manifest.csv_url),
        ("iana_last_updated", manifest.iana_last_updated),
        ("retrieved_at", manifest.retrieved_at),
        ("payload_file", manifest.payload_file),
        ("payload_encoding", manifest.payload_encoding),
        ("payload_length", str(manifest.payload_length)),
        ("payload_sha256", manifest.payload_sha256),
    )


def _string_chunks(value: str, maximum_literal_length: int = 72) -> tuple[str, ...]:
    if not value:
        return ("",)
    chunks: list[str] = []
    start = 0
    while start < len(value):
        end = start + 1
        while end <= len(value):
            encoded = json.dumps(value[start:end], ensure_ascii=True)
            if len(encoded) > maximum_literal_length:
                end -= 1
                break
            end += 1
        if end > len(value):
            end = len(value)
        if end == start:
            end += 1
        chunks.append(value[start:end])
        start = end
    return tuple(chunks)


def _python_string_literal(value: str) -> str:
    """Render the quote style Black preserves without needing Black at generation time."""
    if '"' in value and "'" not in value:
        return repr(value)
    return json.dumps(value, ensure_ascii=True)


def _render_string_field(lines: list[str], indent: str, key: str, value: str) -> None:
    key_literal = json.dumps(key)
    value_literal = _python_string_literal(value)
    single_line = f"{indent}{key_literal}: {value_literal},"
    if len(single_line) <= 100:
        lines.append(single_line)
        return
    lines.append(f"{indent}{key_literal}: (")
    for chunk in _string_chunks(value):
        lines.append(f"{indent}    {_python_string_literal(chunk)}")
    lines.append(f"{indent}),")


def render_module(snapshot: RegistrySnapshot) -> str:
    """Render a deterministic, import-only Python representation of a snapshot."""
    lines = [
        '"""Generated IANA SvcParamKey registry data; do not edit by hand."""',
        "",
        "# Generated by `python -m src.registry_codegen --write`.",
        "",
        "IANA_REGISTRY_METADATA: dict[str, str] = {",
    ]
    for key, value in _metadata_items(snapshot.manifest):
        _render_string_field(lines, "    ", key, value)
    lines.extend(("}", "", "IANA_SVCPARAM_REGISTRY: dict[int, dict[str, str]] = {"))
    for entry in snapshot.entries:
        lines.append(f"    {entry.key}: {{")
        _render_string_field(lines, "        ", "name", entry.name)
        _render_string_field(lines, "        ", "meaning", entry.meaning)
        _render_string_field(lines, "        ", "change_controller", entry.change_controller)
        _render_string_field(lines, "        ", "reference", entry.reference)
        lines.append("    },")
    lines.extend(
        (
            "}",
            "",
            "IANA_SVCPARAM_SPECIAL_RANGES: tuple[dict[str, int | str], ...] = (",
        )
    )
    for item in snapshot.special_ranges:
        lines.append("    {")
        lines.append(f'        "start": {item.start},')
        lines.append(f'        "end": {item.end},')
        _render_string_field(lines, "        ", "name", item.name)
        _render_string_field(lines, "        ", "meaning", item.meaning)
        _render_string_field(lines, "        ", "change_controller", item.change_controller)
        _render_string_field(lines, "        ", "reference", item.reference)
        lines.append("    },")
    lines.extend((")", ""))
    return "\n".join(lines)


def generated_module_is_current(
    manifest_path: Path = DEFAULT_MANIFEST,
    output_path: Path = DEFAULT_OUTPUT,
) -> bool:
    """Return whether generated output exactly matches the validated snapshot."""
    expected = render_module(load_snapshot(manifest_path)).encode("utf-8")
    try:
        return output_path.read_bytes() == expected
    except OSError:
        return False


def write_generated_module(
    manifest_path: Path = DEFAULT_MANIFEST,
    output_path: Path = DEFAULT_OUTPUT,
) -> None:
    """Atomically write deterministic generated output from a valid snapshot."""
    content = render_module(load_snapshot(manifest_path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_mode = stat.S_IMODE(output_path.stat().st_mode)
    except FileNotFoundError:
        output_mode = 0o644
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        temporary_path.chmod(output_mode)
        os.replace(temporary_path, output_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> urllib.request.Request | None:
        raise RegistrySnapshotError("upstream redirects are not allowed")


def fetch_upstream_csv(
    url: str,
    *,
    timeout: float = DEFAULT_UPSTREAM_TIMEOUT_SECONDS,
    size_limit: int = DEFAULT_UPSTREAM_SIZE_LIMIT,
) -> bytes:
    """Fetch an IANA CSV with redirect, timeout, and response-size restrictions."""
    _split_iana_url(url, "csv_url")
    if timeout <= 0:
        raise RegistrySnapshotError("upstream timeout must be positive")
    if size_limit <= 0 or size_limit > MAX_CONFIGURABLE_UPSTREAM_SIZE:
        raise RegistrySnapshotError(
            f"upstream size limit must be between 1 and {MAX_CONFIGURABLE_UPSTREAM_SIZE}"
        )

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/csv",
            "User-Agent": "rfc9460-checker-registry-audit/1",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(_RejectRedirects())
    try:
        with opener.open(request, timeout=timeout) as response:
            response_url = response.geturl()
            if response_url != url:
                raise RegistrySnapshotError("upstream response URL differs from the requested URL")
            status = response.getcode()
            if status != 200:
                raise RegistrySnapshotError(f"upstream returned HTTP status {status}")
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError as error:
                    raise RegistrySnapshotError(
                        "upstream returned an invalid Content-Length"
                    ) from error
                if declared_length < 0 or declared_length > size_limit:
                    raise RegistrySnapshotError("upstream response exceeds the size limit")
            payload = cast(bytes, response.read(size_limit + 1))
    except RegistrySnapshotError:
        raise
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as error:
        raise RegistrySnapshotError(f"upstream fetch failed: {error}") from error

    if len(payload) > size_limit:
        raise RegistrySnapshotError("upstream response exceeds the size limit")
    return payload


def fetch_validated_upstream(
    snapshot: RegistrySnapshot,
    *,
    timeout: float = DEFAULT_UPSTREAM_TIMEOUT_SECONDS,
    size_limit: int = DEFAULT_UPSTREAM_SIZE_LIMIT,
) -> bytes:
    """Fetch and structurally validate the live registry without writing it."""
    upstream = fetch_upstream_csv(
        snapshot.manifest.csv_url,
        timeout=timeout,
        size_limit=size_limit,
    )
    parse_registry_csv(upstream)
    return upstream


def upstream_matches_snapshot(
    snapshot: RegistrySnapshot,
    *,
    timeout: float = DEFAULT_UPSTREAM_TIMEOUT_SECONDS,
    size_limit: int = DEFAULT_UPSTREAM_SIZE_LIMIT,
) -> bool:
    """Validate the live registry and compare it with a snapshot in memory."""
    return (
        fetch_validated_upstream(snapshot, timeout=timeout, size_limit=size_limit)
        == snapshot.payload
    )


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return parsed


def _bounded_size(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed <= 0 or parsed > MAX_CONFIGURABLE_UPSTREAM_SIZE:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_CONFIGURABLE_UPSTREAM_SIZE}")
    return parsed


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="check generated output offline")
    action.add_argument("--write", action="store_true", help="write generated output offline")
    action.add_argument(
        "--check-upstream",
        action="store_true",
        help="compare the snapshot with IANA without writing files",
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_UPSTREAM_TIMEOUT_SECONDS,
        help="upstream timeout in seconds (only used with --check-upstream)",
    )
    parser.add_argument(
        "--size-limit",
        type=_bounded_size,
        default=DEFAULT_UPSTREAM_SIZE_LIMIT,
        help="maximum upstream response bytes (only used with --check-upstream)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the deterministic registry generator command-line interface."""
    args = _argument_parser().parse_args(argv)
    manifest_path = cast(Path, args.manifest)
    output_path = cast(Path, args.output)
    try:
        if args.write:
            write_generated_module(manifest_path, output_path)
            print(f"wrote {output_path}")
            return 0
        if args.check:
            if generated_module_is_current(manifest_path, output_path):
                print(f"generated registry is current: {output_path}")
                return 0
            command = f"{sys.executable} -m src.registry_codegen --write"
            print(
                f"generated registry is stale: run {command}",
                file=sys.stderr,
            )
            return 1

        snapshot = load_snapshot(manifest_path)
        upstream = fetch_validated_upstream(
            snapshot,
            timeout=cast(float, args.timeout),
            size_limit=cast(int, args.size_limit),
        )
        if upstream == snapshot.payload:
            print("vendored IANA registry snapshot matches upstream")
            return 0
        upstream_hash = hashlib.sha256(upstream).hexdigest()
        print(
            f"vendored IANA registry snapshot differs from upstream ({upstream_hash}); "
            "review and update it explicitly",
            file=sys.stderr,
        )
        return 1
    except RegistrySnapshotError as error:
        print(f"registry code generation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
