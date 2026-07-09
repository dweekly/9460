"""Schema primitives shared by RFC 9460 parsing and DNS observations.

The public checker still returns dictionaries for backwards compatibility, but
the dictionaries now follow this schema.  Keeping the schema types here makes
the JSON contract explicit without requiring callers to serialize dataclasses
or enums.
"""

from typing import Any, Literal, TypedDict  # noqa: TYP001

SCHEMA_VERSION = 2
DEFAULT_MAX_ALIAS_DEPTH = 8
VALIDATOR_RULESET_VERSION = "2026-07-09.1"

SVCPARAM_REGISTRY_REFERENCE = "https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml"
SVCPARAM_REGISTRY_VERSION = "2026-06-25"
SVCPARAM_REGISTRY_SNAPSHOT_DATE = "2026-07-09"
SVCPARAM_REGISTRY_METADATA: dict[str, str] = {
    "authority": "IANA",
    "name": "DNS SVCB Service Parameter Keys (SvcParamKeys)",
    "version": SVCPARAM_REGISTRY_VERSION,
    "snapshot_date": SVCPARAM_REGISTRY_SNAPSHOT_DATE,
    "reference": SVCPARAM_REGISTRY_REFERENCE,
}

ValidationStatus = Literal["valid", "invalid", "valid_but_incompatible"]
ObservationValidationStatus = Literal[
    "valid", "invalid", "valid_but_incompatible", "not_applicable"
]
RecordMode = Literal["alias", "service"]
QueryStatus = Literal["present", "no_answer", "nxdomain", "timeout", "error"]


# IANA registry snapshot.  Registration means that a key has a stable name;
# it does not imply that this checker implements the corresponding client
# behavior.  Unknown keys are retained as ``keyNNNNN`` rather than discarded.
SVCPARAM_REGISTRY: dict[int, dict[str, str]] = {
    0: {"name": "mandatory", "reference": "RFC 9460, Section 8"},
    1: {"name": "alpn", "reference": "RFC 9460, Section 7.1"},
    2: {"name": "no-default-alpn", "reference": "RFC 9460, Section 7.1"},
    3: {"name": "port", "reference": "RFC 9460, Section 7.2"},
    4: {"name": "ipv4hint", "reference": "RFC 9460, Section 7.3"},
    5: {"name": "ech", "reference": "RFC 9848"},
    6: {"name": "ipv6hint", "reference": "RFC 9460, Section 7.3"},
    7: {"name": "dohpath", "reference": "RFC 9461"},
    8: {"name": "ohttp", "reference": "RFC 9540, Section 4"},
    9: {
        "name": "tls-supported-groups",
        "reference": "draft-ietf-tls-key-share-prediction-01, Section 3.1",
    },
    10: {"name": "docpath", "reference": "RFC 9953, Section 3"},
    11: {
        "name": "pvd",
        "reference": "RFC-ietf-intarea-proxy-config-13, Section 2.1",
    },
    12: {
        "name": "oots",
        "reference": "draft-johani-dnsop-svcb-oots-00, Section 5",
    },
}
PARAM_KEY_NAMES: dict[int, str] = {key: entry["name"] for key, entry in SVCPARAM_REGISTRY.items()}
PARAM_NAME_KEYS: dict[str, int] = {name: key for key, name in PARAM_KEY_NAMES.items()}
REGISTERED_PARAM_KEYS = frozenset(PARAM_KEY_NAMES)
DECODED_PARAM_KEYS = frozenset({0, 1, 2, 3, 4, 5, 6})
CLIENT_SUPPORTED_PARAM_KEYS = frozenset({0, 1, 2, 3, 4, 6})
# Compatibility alias; this set means client behavior, not registry knowledge.
SUPPORTED_PARAM_KEYS = CLIENT_SUPPORTED_PARAM_KEYS

PARSER_LIMITATIONS = (
    "Parsing starts after dnspython accepts RDATA; raw-wire ordering, duplicate-key, "
    "and truncation checks are not independently repeated.",
    "Registered keys without dedicated decoders are preserved generically as base64 data.",
)


class ValidationIssue(TypedDict, total=False):
    """A machine-readable validation finding."""

    code: str
    severity: Literal["error", "warning", "incompatible"]
    message: str
    key: int | None


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
    validity: ValidationStatus
    validation_issues: list[ValidationIssue]
    compatible: bool
    usable: bool
    ignored: bool


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
