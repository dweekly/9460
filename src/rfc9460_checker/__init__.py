"""RFC 9460 DNS record checking functionality."""

from .dns_client import RFC9460Checker
from .models import (
    CLIENT_SUPPORTED_PARAM_KEYS,
    DECODED_PARAM_KEYS,
    OPAQUE_REGISTERED_PARAM_KEYS,
    PARSER_LIMITATIONS,
    REGISTERED_PARAM_KEYS,
    SCHEMA_VERSION,
    SVCPARAM_REGISTRY,
    SVCPARAM_REGISTRY_METADATA,
    VALIDATOR_RULESET_VERSION,
    WIRE_DECODER_VERSION,
    DNSObservation,
    ProbeObservation,
)
from .parser import (
    parse_captured_response,
    parse_https_record,
    parse_svcb_record,
    parse_svcb_records,
)
from .validator import (
    validate_alpn_id,
    validate_dataset,
    validate_dns_name,
    validate_dns_response,
    validate_domain,
    validate_scan_result,
    validate_svcb_record,
    validate_svcb_rrset,
)
from .wire import decode_dns_message, decode_svcb_rdata, wire_evidence

__all__ = [
    "RFC9460Checker",
    "SCHEMA_VERSION",
    "VALIDATOR_RULESET_VERSION",
    "WIRE_DECODER_VERSION",
    "SVCPARAM_REGISTRY",
    "SVCPARAM_REGISTRY_METADATA",
    "REGISTERED_PARAM_KEYS",
    "DECODED_PARAM_KEYS",
    "OPAQUE_REGISTERED_PARAM_KEYS",
    "CLIENT_SUPPORTED_PARAM_KEYS",
    "PARSER_LIMITATIONS",
    "ProbeObservation",
    "DNSObservation",
    "parse_https_record",
    "parse_captured_response",
    "parse_svcb_record",
    "parse_svcb_records",
    "decode_dns_message",
    "decode_svcb_rdata",
    "wire_evidence",
    "validate_domain",
    "validate_dns_name",
    "validate_dns_response",
    "validate_alpn_id",
    "validate_svcb_record",
    "validate_svcb_rrset",
    "validate_scan_result",
    "validate_dataset",
]
