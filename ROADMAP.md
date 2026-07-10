# RFC 9460 Tracker Roadmap

This file is the durable source of truth for project direction across development sessions. Read it before planning or implementation. Update it whenever scope, sequencing, decisions, or completion state changes.

## How stack rank works

Items are stack-ranked by their position within `Now`, `Next`, and `Later`. The first unfinished bullet is the highest-priority work. Keep the backlog unnumbered: move bullets when priorities change rather than assigning priority numbers.

## Product goal

Build a reproducible longitudinal dataset that distinguishes:

- DNS record adoption: whether HTTPS or SVCB RRsets were observed.
- RFC validity and client usability: whether observed RRsets are structurally valid and whether supported clients can use their mandatory parameters.
- Optional feature advertising: what usable ServiceMode records advertise, including HTTP/3, ECH, ports, and address hints.
- Endpoint behavior: what separate active TLS and HTTP probes actually negotiate or receive.

Publishing an HTTPS or SVCB record is optional, so record absence is not RFC non-compliance. DNS advertisements also cannot prove TLS negotiation, ECH use, post-quantum key agreement, or HTTP response behavior.

## Now

- [ ] Audit the first scheduled wire-enabled production scan: confirm wire-decoder provenance, linked response/RDATA evidence, bounded capture counters, the one-time non-comparable zero-change migration marker, artifact-size gates, canonical/Pages identity, and downstream deployment before beginning the active-probe tranche.
- [ ] Design an extensible active-probe framework with a shared provenance envelope and independently versioned DNS, ECH-handshake, TLS-key-agreement, and HTTP observation contracts; store probe implementation/version, capability-registry version, network vantage, timestamps, and raw evidence without merging their outcome semantics.

## Next

- [ ] Add a versioned TLS capability registry for evolving protocol versions, cipher suites, signature algorithms, named groups, certificate properties, ALPN, OCSP behavior, and deprecation state. Store both observed numeric IDs and names resolved from the exact IANA/IETF registry snapshot used for that scan; never reinterpret old scans silently with a newer registry.
- [ ] Define and enforce repository retention, compression, public-view, and archival policy for DNS wire captures and future TLS/HTTP evidence, including per-probe size budgets and schema-migration rules.
- [ ] Add a dedicated ECH behavior probe, separate from DNS advertisement and other TLS measurements: retain the ECHConfigList, record client support and public-name handling, attempt controlled handshakes, and report advertised, attempted, accepted, rejected, and unverifiable states without weakening privacy.
- [ ] Add a dedicated ML-KEM key-agreement probe, separate from ECH: use FIPS 203 terminology and parameter sets, record the observed numeric IDs and offered/negotiated named groups, distinguish hybrid from non-hybrid key agreement, retain TLS implementation/version, and treat successful negotiation—not DNS—as the adoption signal. Track the evolving `draft-ietf-tls-ecdhe-mlkem` TLS profile rather than freezing a draft codepoint in analysis code.
- [ ] Add a versioned HTTP response probe and header registry for transport, security, privacy, isolation, caching, and reporting signals such as Alt-Svc, HSTS, CSP, Permissions-Policy, Reporting-Endpoints, COOP, COEP, and CORP; retain raw header fields and redirects while publishing normalized metrics.
- [ ] Schedule and record a standards/registry review at least quarterly through December 2028, covering IETF TLS, HTTP, QUIC, ECH, post-quantum transition guidance, and relevant IANA registries; add new telemetry only with a versioned interpretation and migration note.
- [ ] Query each configured DNS resolver independently, retain all answers, and report resolver agreement without treating resolver variance as deployment change.
- [ ] Require persistence across multiple scans or resolvers before alerting on gained, lost, or materially changed deployment signals.
- [ ] Version and periodically refresh the target cohort while keeping each cohort’s longitudinal series separate; document the ranking source and inclusion rules.
- [ ] Add per-domain history, filters, machine-readable exports, and opt-in change notifications.

## Later

- [ ] Add multiple geographic and network vantage points and explicitly model CDN, split-horizon, and regional behavior.
- [ ] Add DNSSEC validation and related DNS transport observations without conflating them with RFC 9460 validity.
- [ ] Publish a documented, versioned dataset API after the on-disk contracts and retention policy stabilize.
- [ ] Support additional versioned cohorts and comparative studies without changing historical denominators.
- [ ] Add reproducible research exports and citation metadata for academic and industry use.

## Current decisions and defaults

- The December 2024 cohort remains fixed during the schema-v2 migration so cohort changes do not masquerade as adoption changes.
- Existing `results/` summaries are immutable legacy history. Their missing per-name details must never be inferred or fabricated.
- The website cohort queries HTTPS at apex and `www`. Generic SVCB requires an explicit protocol mapping and Attrleaf owner name and is not inferred by querying those website names.
- Detailed canonical snapshots are committed because workflow artifacts are not durable public longitudinal storage.
- `latest.json` is byte-for-byte equivalent in content to the decompressed newest canonical snapshot. `history.json` and `changes.json` are deterministic derived views.
- The first schema-v2 scan has no comparable detailed predecessor and must say so explicitly.
- The first scan with wire-decoder provenance is a one-time migration baseline: `changes.json` is non-comparable with `reason_code: wire_decoder_baseline` and zero per-name changes; normal comparison resumes only between wire-enabled scans.
- A changed SvcParam registry version or content hash creates a one-time non-comparable interpretation baseline with `reason_code: registry_snapshot_baseline`; adding a content hash to the same version does not. This prevents registry names or references from masquerading as DNS deployment changes.
- Each metric carries its own count and denominator. Domain count, queried HTTPS names, queried SVCB names, observations, present RRsets, and usable RRsets are not interchangeable.
- Active TLS and HTTP probes will publish their own capability and methodology metadata and will not be folded into an RFC 9460 “score.”
- A shared provenance and storage envelope does not merge probe semantics: DNS validity, ECH handshake behavior, TLS key agreement, and HTTP responses retain independent outcomes, denominators, and release criteria.
- Protocol identifiers and header interpretations are data in a versioned registry, not timeless assumptions embedded only in analysis code.
- Python package manifests declare tested compatible minimums rather than universal exact pins. Every scan records the exact runtime, parser, ruleset, registry, package, and commit versions used; pre-commit hook revisions remain concrete because that tool requires reproducible Git revisions and are refreshed explicitly.
- Raw DNS evidence means the exact UDP datagram or unframed DNS-over-TCP message body received at the socket boundary before parsing. Parser reserialization is never labeled raw evidence, and historical scans are not backfilled with invented packets.
- Each resolution filters captures to the contacted resolver and retains a configurable bounded window (default 32, newest retained), with drop, filter, oversize, and stream-buffer counters stored alongside the evidence.
- Wire captures use a versioned additive schema-v2 field with canonical base64, decoded length, and SHA-256. Packet-only changes are excluded from deployment alerts, while RDATA identity and aggregate validity remain material.
- Scheduled scans fail before staging if the newest compressed canonical snapshot exceeds 8 MiB or any public Pages JSON file exceeds 16 MiB. These reviewed, configurable ceilings are intentionally far above the observed wire-enabled scan (about 62 KiB compressed and 1.1 MiB for `latest.json`) while bounding accidental raw-evidence amplification.
- The `ech` SvcParam is structurally validated as an RFC 9849 ECHConfigList, including the standardized `0xfe0d` contents, but remains a DNS advertisement rather than evidence that this scanner can negotiate ECH.
- Standards baseline checked 2026-07-09: ML-KEM itself is standardized by NIST FIPS 203 (August 13, 2024), including ML-KEM-512, ML-KEM-768, and ML-KEM-1024. Its hybrid use with ECDHE in TLS 1.3 remains `draft-ietf-tls-ecdhe-mlkem-05`, which expires 2026-11-27. ECH is standardized by RFC 9849 and its SVCB/HTTPS binding by RFC 9848, both published March 2026. Draft revision, retrieval date, observed numeric IDs, and the resolving IANA registry snapshot must accompany measurements.

## Core-overhaul acceptance criteria

- A scheduled run produces one canonical snapshot and all three Pages JSON files, verifies their shared scan identity, and commits them together.
- The public dashboard contains no hard-coded scan date, metric, chart series, or domain result and visibly fails closed if generated data cannot be loaded.
- Complete multi-record RRsets survive collection, serialization, display, and comparison.
- Exact pre-parser DNS bytes and RDATA survive deterministic, idempotent serialization; malformed-wire fixtures cover bounds, TargetName compression, parameter ordering/duplication, value formats, and whole-RRset rejection.
- Adoption denominators count queried names of the relevant RR type; SVCB query rows cannot dilute HTTPS adoption or feature metrics.
- Valid, invalid, valid-but-incompatible, absent, NXDOMAIN, timeout, and resolver-error outcomes remain distinguishable.
- Legacy aggregate history remains visible and is labeled separately from schema-v2 detailed history.
- Unit, integration, packaging, pipeline, freshness, and local dashboard smoke checks pass.

## Completed changes

- 2026-07-10: Replaced hand-maintained SvcParam registry data with deterministic generated artifacts from a checked-in, dated exact IANA CSV snapshot, required a reviewed decoded-or-opaque classification for every assigned key, and kept registry knowledge, decoder availability, and measurement-client support as separate versioned capabilities.
- 2026-07-09: Added a reusable pre-commit generated-artifact size check and scheduled-workflow gate, with explicit 8 MiB compressed-snapshot and 16 MiB per-Pages-JSON defaults that fail closed before `git add`.
- 2026-07-09: Added bounded socket-boundary UDP/TCP DNS capture with observable drop/filter counters, canonical message/RDATA evidence, and a bounded independent SVCB/HTTPS decoder. Wire validity now detects DNS/EDNS framing errors, truncation, compressed TargetName, duplicate or misordered keys, and key 0–6 format errors—including RFC 9849 ECHConfigList structure—before parser normalization. Safe pre-parser recovery verifies the transaction, follows only unambiguous CNAME/DNAME chains, and treats AliasMode parameters as ignored rather than malformed.
- 2026-07-09: Established scheduled schema-v2 scan `2026-07-09T23:11:17Z` as the first detailed longitudinal baseline and confirmed the deployed `latest.json` was byte-for-byte identical to the canonical snapshot committed by the workflow.
- 2026-07-09: Promoted queried names and post-CNAME RRset owners to separate first-class fields so longitudinal identity, changes, and dashboard labels remain anchored to the name that was queried.
- 2026-07-09: Added the schema-v2 canonical scan with complete parsed RRsets, query/owner identity, resolver and software provenance, post-parser validity findings, explicit denominators, and extensible probe types.
- 2026-07-09: Added AliasMode/ServiceMode handling, bounded alias traversal, loop outcomes, mandatory and automatic-mandatory checks, current IANA SvcParam metadata, and explicit raw-wire validation limitations.
- 2026-07-09: Replaced the synthetic compliance score with separate adoption, validity, compatibility, and feature-advertisement metrics; legacy names remain documented compatibility aliases only.
- 2026-07-09: Imported 300 legacy aggregate scans without inventing per-name details and generated the first tracked detailed snapshot plus deterministic latest, history, and changes views.
- 2026-07-09: Rebuilt the dashboard around generated JSON with freshness, denominators, trends, changes, filtering, full observation inspection, and visible partial/failure states.
- 2026-07-09: Reworked scan and Pages Actions for lossless JSON input, atomic generated-data commits, freshness verification, least privilege, and deployment after bot-authored scan workflows.
- 2026-07-09: Expanded parser, validator, analyzer, pipeline, and integration regressions; moved the tested runtime baseline to Python 3.14 and current dependency minimums.
- 2026-07-09: Added packaged-cohort and installed-wheel checks, updated the Python, pre-commit, and GitHub Actions toolchains, and made dashboard rendering, filtering, escaping, partial-failure behavior, and generated-data identity part of CI.
- Historical daily aggregate reports collected from September 2025 onward.
- The March 2026 workflow repair stopped analysis failures caused by assuming ignored CSV inputs were committed.

When a `Now` item is complete, move a concise outcome here with the completion date and keep any unfinished follow-up in stack-ranked order above.
