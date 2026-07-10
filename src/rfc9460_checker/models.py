"""Schema primitives shared by RFC 9460 parsing and DNS observations.

The public checker still returns dictionaries for backwards compatibility, but
the dictionaries now follow this schema.  Keeping the schema types here makes
the JSON contract explicit without requiring callers to serialize dataclasses
or enums.
"""

from typing import Any, Literal, TypedDict  # noqa: TYP001

from ._generated_svcparam_registry import (
    IANA_REGISTRY_METADATA,
    IANA_SVCPARAM_REGISTRY,
)

SCHEMA_VERSION = 2
DEFAULT_MAX_ALIAS_DEPTH = 8
VALIDATOR_RULESET_VERSION = "2026-07-09.2"
WIRE_DECODER_VERSION = "2026-07-09.1"

SVCPARAM_REGISTRY_REFERENCE = IANA_REGISTRY_METADATA["registry_page_url"]
SVCPARAM_REGISTRY_VERSION = IANA_REGISTRY_METADATA["iana_last_updated"]
SVCPARAM_REGISTRY_SNAPSHOT_DATE = IANA_REGISTRY_METADATA["retrieved_at"]
SVCPARAM_REGISTRY_METADATA: dict[str, str] = {
    "authority": "IANA",
    "name": IANA_REGISTRY_METADATA["registry_name"],
    "version": SVCPARAM_REGISTRY_VERSION,
    "snapshot_date": SVCPARAM_REGISTRY_SNAPSHOT_DATE,
    "reference": SVCPARAM_REGISTRY_REFERENCE,
    "source_csv": IANA_REGISTRY_METADATA["csv_url"],
    "content_sha256": IANA_REGISTRY_METADATA["payload_sha256"],
}

ValidationStatus = Literal["valid", "invalid", "valid_but_incompatible"]
ObservationValidationStatus = Literal[
    "valid", "invalid", "valid_but_incompatible", "not_applicable"
]
RecordMode = Literal["alias", "service"]
QueryStatus = Literal["present", "no_answer", "nxdomain", "timeout", "error"]


def _display_registry_reference(reference: str) -> str:
    """Normalize IANA's bracketed citation for the existing public JSON shape."""
    display = reference.removeprefix("[").removesuffix("]")
    if display.startswith("RFC") and len(display) > 3 and display[3].isdigit():
        return f"RFC {display[3:]}"
    return display


# Registration, decoding, and measurement-client support are deliberately
# independent. Updating the generated IANA data cannot silently claim a new
# decoder or a capability that the measurement client does not implement.
SVCPARAM_REGISTRY: dict[int, dict[str, str]] = {
    key: {
        "name": entry["name"],
        "meaning": entry["meaning"],
        "change_controller": entry["change_controller"],
        "reference": _display_registry_reference(entry["reference"]),
    }
    for key, entry in IANA_SVCPARAM_REGISTRY.items()
}
PARAM_KEY_NAMES: dict[int, str] = {key: entry["name"] for key, entry in SVCPARAM_REGISTRY.items()}
PARAM_NAME_KEYS: dict[str, int] = {name: key for key, name in PARAM_KEY_NAMES.items()}
REGISTERED_PARAM_KEYS = frozenset(PARAM_KEY_NAMES)
DECODED_PARAM_KEYS = frozenset({0, 1, 2, 3, 4, 5, 6})
OPAQUE_REGISTERED_PARAM_KEYS = frozenset({7, 8, 9, 10, 11, 12})
CLIENT_SUPPORTED_PARAM_KEYS = frozenset({0, 1, 2, 3, 4, 6})
# Compatibility alias; this set means client behavior, not registry knowledge.
SUPPORTED_PARAM_KEYS = CLIENT_SUPPORTED_PARAM_KEYS

if DECODED_PARAM_KEYS & OPAQUE_REGISTERED_PARAM_KEYS:
    raise RuntimeError("decoded and opaque SvcParam capability sets overlap")
if DECODED_PARAM_KEYS | OPAQUE_REGISTERED_PARAM_KEYS != REGISTERED_PARAM_KEYS:
    raise RuntimeError(
        "every registered SvcParamKey needs a reviewed decoded-or-opaque classification"
    )
if not CLIENT_SUPPORTED_PARAM_KEYS <= DECODED_PARAM_KEYS:
    raise RuntimeError("client-supported SvcParamKeys must have dedicated decoders")

PARSER_LIMITATIONS = (
    "Registered SvcParamKeys without dedicated wire decoders are preserved as opaque "
    "base64 data and do not receive key-specific format validation.",
)


class ValidationIssue(TypedDict, total=False):
    """A machine-readable validation finding."""

    code: str
    severity: Literal["error", "warning", "incompatible"]
    message: str
    key: int | None
    offset: int
    length: int


class ParamDetail(TypedDict, total=False):
    """A decoded SvcParam with its numeric identity preserved."""

    key: int
    name: str
    known: bool
    registered: bool
    decoded: bool
    client_supported: bool
    registry_reference: str | None
    value: Any
    raw: Any
    parse_error: str | None


class SVCBRecord(TypedDict, total=False):
    """JSON-safe representation of one HTTPS or SVCB RDATA value."""

    priority: int
    target: str
    mode: RecordMode
    params: dict[str, Any]
    param_details: list[ParamDetail]
    raw: str
    presentation: str
    validity: ValidationStatus
    validation_issues: list[ValidationIssue]
    compatible: bool
    usable: bool
    ignored: bool
    rdata_sha256: str
    wire: dict[str, Any]


class ProbeObservation(TypedDict, total=False):
    """Probe-neutral portion of a schema-v2 observation.

    Future TLS or HTTP probes can extend this type without changing the scan
    envelope or being forced into DNS-specific fields.
    """

    schema_version: int
    probe_type: str
    validation_status: ObservationValidationStatus


class DNSObservation(ProbeObservation, total=False):
    """DNS extension for one requested owner name and RR type."""

    domain: str
    subdomain: str
    full_domain: str
    owner_name: str | None
    query_name: str | None
    rrset_owner_name: str | None
    validator_ruleset_version: str
    svcparam_registry: dict[str, str]
    parser_limitations: list[str]
    record_type: str
    query_status: QueryStatus
    query_error: str | None
    has_record: bool
    has_https_record: bool
    has_svcb_record: bool
    records: list[SVCBRecord]
    record_count: int
    ttl: int | None
    resolver: str | None
    resolver_port: int | None
    configured_resolvers: list[str]
    canonical_name: str | None
    validation_issues: list[ValidationIssue]
    resolution_issues: list[ValidationIssue]
    alias_chain: list[dict[str, Any]]
    alias_resolution_status: str | None
    wire_decoder_version: str
    wire_capture: dict[str, Any]
    wire_validation: dict[str, Any]


def param_key_name(key: int) -> str:
    """Return the registered SvcParam name or the RFC unknown-key form."""
    return PARAM_KEY_NAMES.get(key, f"key{key}")


def param_name_key(name: str) -> int | None:
    """Return the numeric key for a registered or ``keyNNNNN`` name."""
    if name in PARAM_NAME_KEYS:
        return PARAM_NAME_KEYS[name]
    if name.startswith("key") and name[3:].isdigit():
        value = int(name[3:])
        if 0 <= value <= 65535:
            return value
    return None
