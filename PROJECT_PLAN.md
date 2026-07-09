# RFC 9460 Tracker Project Plan

`ROADMAP.md` is the durable, stack-ranked source of truth for sequencing. This document describes the implemented target architecture and the decisions an implementation session must preserve.

## Outcome

The project measures RFC 9460 deployment without treating optional record publication or optional features as compliance requirements. It produces a reproducible daily canonical dataset, a deterministic set of public views, and a dashboard that fails visibly instead of falling back to stale embedded values.

The fixed migration cohort contains 101 domains. Each domain produces apex and `www` HTTPS queries. Generic SVCB is measured only when a caller supplies a protocol mapping and the corresponding Attrleaf owner name; it is not queried at website apex or `www`.

## Data flow

```text
versioned cohort
      │
      ▼
DNS scanner ──► raw manual report
                     │
                     ▼
              schema-v2 pipeline
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
compressed canonical scan   deterministic Pages JSON
data/scans/                 docs/data/{latest,history,changes}.json
        └────────────┬────────────┘
                     ▼
              freshness verifier
                     │
                     ▼
           atomic commit and deploy
```

The scheduled workflow does not commit redundant daily Markdown or legacy analysis files. Manual CSV/JSON/Markdown reporters remain available for compatibility.

## Canonical model

The schema-v2 snapshot contains:

- scan identity, timestamps, and actual resolver provenance;
- a versioned cohort identity, source, date, complete domain list, and count;
- one observation per queried name and RR type;
- complete observed RRsets with TTL, priority, target, mode, parameters, unknown keys, and raw presentation text;
- query status and errors separate from record validation;
- validation status and machine-readable findings;
- explicit adoption, validity, compatibility, and optional-feature metrics;
- distributions and error summaries derived from observations.

Snapshot serialization is deterministic. The newest decompressed canonical snapshot is content-equivalent to `docs/data/latest.json`. Historical schema-v1 reports are imported only as labeled aggregate entries.

## RFC behavior

The parser and validator preserve all answers and:

- distinguish priority-zero AliasMode from ServiceMode;
- ignore AliasMode parameters for feature analysis;
- follow aliases within a fixed bound and report loops;
- validate targets and service-parameter wire/presentation forms;
- enforce `mandatory`, including unknown mandatory keys;
- validate `alpn` and `no-default-alpn` combinations;
- validate port and IPv4/IPv6 hints;
- distinguish valid, invalid, and valid-but-incompatible records.

Absent, NXDOMAIN, timeout, and resolver-error outcomes remain distinguishable and are not converted into invalid RFC records.

## Metrics and views

The pipeline reports denominators for domains, observations, queried names, HTTPS/SVCB names and observations, apex/`www` HTTPS names, present RRsets, and usable RRsets. Every adoption, validity, or feature metric stores its count, denominator, and percentage.

The public views are:

- `latest.json`: current canonical observations and metrics;
- `history.json`: sorted legacy and schema-v2 aggregate history;
- `changes.json`: gained, lost, and materially changed record identities between comparable detailed snapshots.

The dashboard loads all three at runtime. It contains no scan-specific date, metric, chart data, domain result, or ranking in HTML or JavaScript. It presents adoption, validity, optional features, history, recent changes, and inspectable complete observations.

## Automation contract

The daily scan workflow:

- runs on a single concurrency group;
- has repository-content write permission only;
- writes raw scanner output to ephemeral runner storage;
- calls `python -m src.analyzer.pipeline build` with the raw input, snapshot directory, Pages directory, legacy history, and cohort;
- calls `python -m src.analyzer.pipeline verify` before staging output;
- stages `data/scans/` and `docs/data/` together and creates at most one bot commit;
- does not trigger itself from that bot commit.

The Pages workflow checks out the committed state, runs the same verifier, and uploads `docs/` unchanged. It grants only the Pages metadata and deployment permissions required by the official Pages actions. Deployment is blocked when `latest.json`, the newest schema-v2 history entry, `changes.json`, and the canonical snapshot do not identify the same scan.

## Verification

Required automated coverage includes:

- textual and wire-format fixtures for multi-record ServiceMode, AliasMode, aliases, loops, targets, priorities, unknown keys, `mandatory`, ALPN, `no-default-alpn`, ECH, ports, and IP hints;
- malformed, incompatible, absent, NXDOMAIN, timeout, and resolver-error classifications;
- denominator regressions proving HTTPS metrics use only queried HTTPS names and remain compatible with legacy files that also contain generic SVCB rows;
- feature aggregation across complete RRsets;
- deterministic schema-v2 serialization and round trips;
- legacy history import without fabricated detail;
- gained, lost, changed, and first-detailed-scan comparisons;
- end-to-end raw-input to snapshot/Pages generation and freshness verification;
- local dashboard loading, charts, filtering, and full-observation inspection;
- formatting, linting, strict typing, tests, dependency audit, and package build.

## Future telemetry boundary

The RFC 9460 DNS scanner is one probe family. Planned TLS and HTTP probes use distinct versioned observation types and capability registries.

ECH verification requires an active TLS client and reports advertisement, attempt, acceptance, rejection, or inability to verify. ML-KEM adoption requires evidence from offered and negotiated TLS named groups and distinguishes hybrid from non-hybrid key agreement. HTTP telemetry retains redirects and raw response headers before normalized analysis.

Old observations are interpreted with the registry version stored at collection time. Every TLS observation retains numeric protocol IDs as seen on the wire as well as names resolved from that scan's registry snapshot. Standards and IANA registries are reviewed at least quarterly through December 2028, and changes receive explicit schema or interpretation notes. The July 9, 2026 baseline is NIST FIPS 203 for ML-KEM, `draft-ietf-tls-ecdhe-mlkem-05` for its hybrid ECDHE/TLS 1.3 profile, RFC 9849 for TLS ECH, and RFC 9848 for the ECH SVCB/HTTPS binding. DNS evidence is never used as proof of TLS or HTTP behavior.

## Fixed assumptions

- The December 2024 cohort remains unchanged during core migration.
- Existing `results/` history remains immutable.
- Detailed snapshots are committed rather than relying on expiring Actions artifacts.
- The first schema-v2 scan has no detailed predecessor.
- Independent per-resolver consensus, cohort refresh, persistent-change alerting, multi-region probes, and data-retention policy remain follow-up work in `ROADMAP.md`.
