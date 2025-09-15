"""Parser for SVCB and HTTPS DNS records."""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def parse_https_record(answers: Any) -> Dict[str, Any]:
    """Parse HTTPS DNS record answers.

    Args:
        answers: DNS query answers containing HTTPS records.

    Returns:
        Dictionary with parsed HTTPS record data.
    """
    if not answers:
        return {}

    https_records = []

    for rdata in answers:
        record_info = {
            "priority": rdata.priority,
            "target": str(rdata.target),
            "params": {},
        }

        # Parse service parameters if available
        if hasattr(rdata, "params") and rdata.params:
            for param_key, param_value in rdata.params.items():
                if param_key == 1:  # ALPN
                    record_info["params"]["alpn"] = _parse_alpn(param_value)
                elif param_key == 3:  # Port
                    record_info["params"]["port"] = _parse_port(param_value)
                elif param_key == 4:  # IPv4 hint
                    record_info["params"]["ipv4hint"] = _parse_ip_hint(param_value)
                elif param_key == 5:  # ECH
                    record_info["params"]["ech"] = True
                elif param_key == 6:  # IPv6 hint
                    record_info["params"]["ipv6hint"] = _parse_ip_hint(param_value)

        https_records.append(record_info)

    # Use the first (highest priority) record for main results
    if not https_records:
        return {}

    main_record = min(https_records, key=lambda x: x["priority"])
    result = {
        "https_priority": main_record["priority"],
        "https_target": main_record["target"],
    }

    # Extract parameters
    params = main_record.get("params", {})

    if "alpn" in params:
        result["alpn_protocols"] = ",".join(params["alpn"])
        result["has_http3"] = "h3" in params["alpn"]
    else:
        result["has_http3"] = False

    if "port" in params:
        result["port"] = params["port"]

    if "ipv4hint" in params:
        hints = params["ipv4hint"]
        result["ipv4hint"] = ",".join(hints) if isinstance(hints, list) else str(hints)

    if "ipv6hint" in params:
        hints = params["ipv6hint"]
        result["ipv6hint"] = ",".join(hints) if isinstance(hints, list) else str(hints)

    if "ech" in params:
        result["ech_config"] = True
    else:
        result["ech_config"] = False

    return result


def parse_svcb_record(answers: Any) -> Dict[str, Any]:
    """Parse SVCB DNS record answers.

    Args:
        answers: DNS query answers containing SVCB records.

    Returns:
        Dictionary with parsed SVCB record data.
    """
    if not answers:
        return {}

    # For now, just parse the first record
    rdata = answers[0]
    result = {
        "svcb_priority": rdata.priority,
        "svcb_target": str(rdata.target),
    }

    # Add parameter parsing similar to HTTPS if needed
    if hasattr(rdata, "params") and rdata.params:
        result["svcb_params"] = {}
        for param_key, param_value in rdata.params.items():
            result["svcb_params"][param_key] = str(param_value)

    return result


def _parse_alpn(param_value: Any) -> List[str]:
    """Parse ALPN parameter value.

    Args:
        param_value: The ALPN parameter value.

    Returns:
        List of ALPN protocol identifiers.
    """
    alpn_values = []

    if hasattr(param_value, "ids"):
        alpn_values = [
            id.decode("ascii") if isinstance(id, bytes) else str(id) for id in param_value.ids
        ]
    elif isinstance(param_value, (list, tuple)):
        alpn_values = [str(v) for v in param_value]
    else:
        logger.warning(f"Unknown ALPN format: {type(param_value)}")

    return alpn_values


def _parse_port(param_value: Any) -> Optional[int]:
    """Parse port parameter value.

    Args:
        param_value: The port parameter value.

    Returns:
        Port number or None.
    """
    if hasattr(param_value, "port"):
        return param_value.port
    elif isinstance(param_value, int):
        return param_value
    else:
        try:
            return int(str(param_value))
        except (ValueError, TypeError):
            logger.warning(f"Could not parse port: {param_value}")
            return None


def _parse_ip_hint(param_value: Any) -> List[str]:
    """Parse IP hint parameter value.

    Args:
        param_value: The IP hint parameter value.

    Returns:
        List of IP addresses.
    """
    if hasattr(param_value, "addresses"):
        return [str(addr) for addr in param_value.addresses]
    elif isinstance(param_value, (list, tuple)):
        return [str(addr) for addr in param_value]
    elif param_value:
        return [str(param_value)]
    else:
        return []
