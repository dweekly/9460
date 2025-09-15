# RFC 9460 Compliance Checker

A Python tool to check the top 100 websites for compliance with RFC 9460 (SVCB and HTTPS DNS Resource Records).

## Overview

RFC 9460 defines the Service Binding (SVCB) and HTTPS DNS resource record types, which enable clients to:
- Discover HTTP/3 (QUIC) support directly via DNS
- Find alternative service endpoints
- Obtain connection parameters like ALPN protocols, ports, and IP hints
- Support Encrypted Client Hello (ECH) configurations

This tool queries HTTPS records for both root domains (e.g., `google.com`) and www subdomains (e.g., `www.google.com`) to assess RFC 9460 adoption.

## Features

- **Comprehensive DNS Queries**: Checks SVCB/HTTPS records for top 100 websites
- **HTTP/3 Detection**: Identifies QUIC support via ALPN "h3" parameter
- **Parameter Analysis**: Extracts service parameters including:
  - ALPN protocols (h2, h3, etc.)
  - Non-default ports
  - IPv4/IPv6 hints
  - ECH configuration presence
- **Structured Output**: Generates timestamped CSV files for analysis
- **Progress Tracking**: Real-time progress bar during scanning
- **Summary Statistics**: Displays adoption rates and key metrics

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd rfc9460-check
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the checker:
```bash
python rfc9460_checker.py
```

The script will:
1. Query HTTPS records for all domains in `top_websites.json`
2. Save results to `results/rfc9460_compliance_YYYY-MM-DD_HH-MM-SS.csv`
3. Display summary statistics in the terminal

## Output Format

### CSV Schema

| Field | Description |
|-------|-------------|
| `script_version` | Version of the checker script |
| `timestamp` | ISO 8601 timestamp of the query |
| `dns_server` | DNS servers used for queries |
| `domain` | Base domain (e.g., "google.com") |
| `subdomain` | "root" or "www" |
| `full_domain` | Complete domain queried |
| `has_https_record` | Boolean - whether HTTPS record exists |
| `https_priority` | Priority value from HTTPS record |
| `https_target` | Target hostname from HTTPS record |
| `alpn_protocols` | Comma-separated ALPN identifiers |
| `has_http3` | Boolean - whether "h3" is in ALPN |
| `port` | Non-default port if specified |
| `ipv4hint` | IPv4 address hints |
| `ipv6hint` | IPv6 address hints |
| `ech_config` | Boolean - whether ECH is configured |
| `query_error` | Error message if query failed |

### Example Output

```
RFC 9460 Compliance Summary
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Metric             ┃ Root Domains  ┃ WWW Domains   ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ Total Checked      │ 100           │ 100           │
│ Has HTTPS Record   │ 45 (45.0%)    │ 48 (48.0%)    │
│ Supports HTTP/3    │ 38 (38.0%)    │ 40 (40.0%)    │
│ Has ECH Config     │ 12 (12.0%)    │ 14 (14.0%)    │
│ Custom Port        │ 0             │ 0             │
│ IPv4 Hints         │ 25            │ 28            │
│ IPv6 Hints         │ 20            │ 22            │
└────────────────────┴───────────────┴───────────────┘
```

## Configuration

### Modifying the Website List

Edit `top_websites.json` to change the domains being checked:

```json
{
  "source": "Your data source",
  "last_updated": "2024-12-15",
  "websites": [
    "example.com",
    "another-site.org"
  ]
}
```

### DNS Servers

The script uses multiple DNS servers by default:
- 8.8.8.8 (Google)
- 1.1.1.1 (Cloudflare)
- 208.67.222.222 (OpenDNS)

You can modify these in the `RFC9460Checker` class initialization.

## Requirements

- Python 3.7+
- dnspython >= 2.6.0 (for SVCB/HTTPS record support)
- pandas >= 2.0.0
- asyncio-throttle >= 1.0.2
- rich >= 13.0.0

## Technical Details

### RFC 9460 Parameters

The tool checks for these key service parameters:

| Key | Name | Description |
|-----|------|-------------|
| 1 | alpn | Application-Layer Protocol Negotiation |
| 3 | port | Alternative port number |
| 4 | ipv4hint | IPv4 address hints |
| 5 | ech | Encrypted Client Hello configuration |
| 6 | ipv6hint | IPv6 address hints |

### HTTP/3 Support Detection

The tool identifies HTTP/3 support by looking for the "h3" ALPN identifier in HTTPS records. This indicates the server supports QUIC transport protocol.

## Limitations

- DNS query timeout is set to 5 seconds per query
- Rate limited to 10 queries per second to avoid overwhelming DNS servers
- Some domains may have HTTPS records but not all parameters are publicly visible
- ECH configuration detection only checks presence, not validity

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License

## References

- [RFC 9460: Service Binding and Parameter Specification via the DNS](https://datatracker.ietf.org/doc/html/rfc9460)
- [RFC 9114: HTTP/3](https://datatracker.ietf.org/doc/html/rfc9114)
- [dnspython Documentation](https://dnspython.readthedocs.io/)
