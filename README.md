# RFC 9460 Adoption & Validity Tracker

A reproducible, longitudinal measurement of HTTPS and SVCB DNS resource records across a fixed cohort of popular websites.

The project reports **record adoption**, **RFC validity/client usability**, and **optional feature advertising** as separate concepts. RFC 9460 does not require a website to publish an HTTPS or SVCB record, so absence is not non-compliance and this project does not publish a “compliance score.”

The public dashboard is at [dweekly.github.io/9460](https://dweekly.github.io/9460/), the implementation and data are in [github.com/dweekly/9460](https://github.com/dweekly/9460), and the durable stack-ranked plan is in [ROADMAP.md](ROADMAP.md).

## What is measured

For the apex and `www` name of each cohort domain, the web scanner queries HTTPS records and retains:

- complete RRsets rather than one selected answer;
- priority, target, AliasMode/ServiceMode, TTL, and all known or unknown parameters;
- raw DNS presentation text and the resolver that supplied the observation;
- absent, NXDOMAIN, timeout, and resolver-error outcomes;
- structural validity, client compatibility, and validation findings;
- advertised ALPN identifiers (including exact `h3`), ECH parameters, ports, and IPv4/IPv6 hints.

Every aggregate metric carries its own count and denominator. In particular, HTTPS adoption is divided by queried HTTPS names—not the combined number of HTTPS and SVCB query rows.

The current cohort contains 101 domains from a December 2024 Similarweb/Semrush-derived list. It stays fixed during the schema-v2 migration so a cohort change cannot masquerade as an adoption change. The source and date live in [`top_websites.json`](top_websites.json).

## Quick start

Python 3.14 or newer is required. Dependency minimums reflect the current toolchain tested on July 9, 2026, while each scan records the exact runtime versions used so historical observations remain interpretable.

The project deliberately uses compatible minimums (`>=`) for Python packages rather than freezing every installation to one build. CI and scheduled scans therefore receive compatible fixes, while scan provenance records the exact Python, dnspython, validator, registry, package, and commit versions that produced each observation. Pre-commit `rev` values are concrete because pre-commit hooks require a Git revision for reproducibility; `pre-commit autoupdate` refreshes those revisions as a tested change.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py --output results
```

Useful scanner options include:

```bash
python main.py --websites top_websites.json --limit 10
python main.py --dns-servers 1.1.1.1,8.8.8.8 --timeout 5 --rate-limit 10
```

Manual CSV, JSON, and Markdown reports remain available for compatibility. Scheduled automation uses the canonical schema-v2 pipeline instead of committing those reports.

## Canonical data pipeline

Build a versioned snapshot and all dashboard data from the scanner's lossless JSON bundle:

```bash
python -m src.analyzer.pipeline build \
  --input results/rfc9460_observations_YYYY-MM-DD_HH-MM-SS.json \
  --scan-dir data/scans \
  --pages-dir docs/data \
  --legacy-dir results \
  --cohort top_websites.json
```

Verify that the newest compressed snapshot and every published view identify the same scan:

```bash
python -m src.analyzer.pipeline verify \
  --latest docs/data/latest.json \
  --scan-dir data/scans
```

The build is deterministic for the same inputs. A successful scheduled run commits `data/scans/` and `docs/data/` in one commit only after verification passes.

## Data contracts

### Canonical snapshot

`data/scans/rfc9460_scan_<timestamp>.json.gz` uses `schema_version: 2` and contains:

- `scan`: stable scan ID, start/end timestamps, and resolver metadata;
- `cohort`: cohort identity, source, update date, domains, and count;
- `observations`: one query observation per name and record type, with complete RRsets, status, validation, features, resolver, and errors;
- `metrics`: explicit denominators plus adoption, validity, and feature metrics;
- `distributions` and `error_statistics`: supporting aggregate data.

The decompressed newest canonical snapshot has the same JSON content as `docs/data/latest.json`.

### Dashboard views

- `docs/data/latest.json` is the full current canonical snapshot used by headline metrics and domain inspection.
- `docs/data/history.json` is the aggregate time series. Legacy schema-v1 entries contain only the information available in historical reports; missing detailed history is never invented.
- `docs/data/changes.json` reports gained, lost, and materially changed record identities between compatible detailed scans. The first schema-v2 scan explicitly has no comparable detailed predecessor.

Serve the dashboard through HTTP so the browser can load those files:

```bash
python -m http.server 8000 --directory docs
```

Then open <http://localhost:8000/>.

## Methodology

### Adoption

Adoption means a configured resolver returned an RRset for a queried name and record type. The website cohort reports HTTPS adoption separately for apex and `www` names. Generic SVCB requires a protocol-specific Attrleaf owner name, so the website scan does not issue misleading SVCB queries at apex or `www`; the library retains an explicit SVCB query API for callers with a defined protocol mapping. An absent record is a valid deployment choice.

### RFC validity and compatibility

Validation preserves and evaluates the complete RRset. It distinguishes AliasMode from ServiceMode, follows bounded aliases, detects loops, checks target and parameter forms, enforces `mandatory`, interprets ALPN and `no-default-alpn`, and validates port and IP-hint encodings.

An observation can be:

- `valid`: structurally valid and usable by the scanner’s supported parameter set;
- `valid_but_incompatible`: valid, but requiring a mandatory parameter the scanner/client does not implement;
- `invalid`: malformed or semantically invalid under the implemented RFC rules;
- absent or a DNS outcome such as NXDOMAIN, timeout, or resolver error, which is not assigned RFC validity.

### Feature advertising

Feature metrics are computed only from the appropriate usable records. For example, an `h3` ALPN value is evidence that DNS advertises HTTP/3; it is not proof that a QUIC connection succeeds. Parameters on AliasMode records are not feature-scored.

### Reproducibility and limitations

- The current scanner records which configured resolver answered; independent per-resolver consensus is roadmap work.
- DNS and CDN answers can vary by resolver, network, time, and geography. A single-day change is not automatically a deployment event.
- Historical schema-v1 reports provide aggregate trends but cannot support per-name change attribution.
- The cohort represents a selected popular-site sample, not the whole web.
- Current validity checks run after dnspython parses the response. Some malformed wire encodings can be rejected or normalized before the tracker sees them; strict raw-wire capture and decoding is stack-ranked in the roadmap.
- ECH configuration presence is a DNS observation. It does not prove an ECH handshake was attempted or accepted.
- ML-KEM or hybrid post-quantum TLS adoption cannot be inferred from HTTPS/SVCB DNS records.

## TLS, post-quantum, and HTTP telemetry

The roadmap extends this project through 2028 with separate, versioned active probes for:

- ECH advertisement versus attempted and accepted ECH handshakes;
- offered and negotiated ML-KEM-based hybrid TLS named groups;
- evolving TLS versions, groups, signatures, certificates, ALPN, and deprecation state;
- HTTP transport, security, privacy, isolation, cache, and reporting headers.

These probes will retain their client implementation/version, network vantage, raw numeric protocol IDs, resolved names, raw evidence, and the exact standards/registry snapshot used for interpretation. Their results will remain separate from RFC 9460 DNS validity.

[ML-KEM is standardized by NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), published August 13, 2024. As of the project’s July 9, 2026 standards review, the hybrid ECDHE/ML-KEM profile for TLS 1.3 is still [`draft-ietf-tls-ecdhe-mlkem-05`](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/). ECH itself is standardized by [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html), with its SVCB/HTTPS binding in [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html). Draft revisions, registries, and codepoints remain versioned inputs rather than timeless constants. See [ROADMAP.md](ROADMAP.md) for the quarterly review cadence, stack rank, and acceptance criteria.

## Automation

- `.github/workflows/scan.yml` runs the daily scanner, builds and verifies the canonical snapshot and Pages data, then commits both atomically.
- `.github/workflows/deploy.yml` verifies tracked data again and deploys the existing `docs/` artifact to GitHub Pages.
- `.github/workflows/ci.yml` runs formatting, linting, strict typing, tests, dependency audit, package build, and data freshness checks.

The scan workflow has only repository-content write permission. Pages and OIDC permissions are isolated to the Pages workflow; the build job needs Pages metadata access and the deployment job performs the write.

## Development

```bash
python -m pip install -r requirements-dev.txt
black --check --line-length=100 main.py src tests
isort --check-only --profile=black --line-length=100 main.py src tests
flake8 --max-line-length=100 --extend-ignore=E203,W503 main.py src tests
mypy --strict --ignore-missing-imports src/
pytest
node tests/dashboard_smoke.js
python -m build
```

Contributions are welcome through [issues](https://github.com/dweekly/9460/issues) and pull requests. Changes that affect interpretation or output should update tests, this README, and `ROADMAP.md` in the same pull request.

## References

- [RFC 9460: Service Binding and Parameter Specification via the DNS](https://www.rfc-editor.org/rfc/rfc9460.html)
- [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [dnspython documentation](https://dnspython.readthedocs.io/)

MIT licensed; see [LICENSE](LICENSE).
