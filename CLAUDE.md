# Project Engineering Guide

Read `ROADMAP.md` before planning or implementation. It is the durable, unnumbered, stack-ranked source of truth across development sessions. Update it whenever sequencing, scope, decisions, or completion state changes. `PROJECT_PLAN.md` describes the architecture that current work must preserve.

## Measurement semantics

- Measure DNS record adoption, RFC validity, client compatibility, and optional feature advertising separately.
- HTTPS and SVCB publication is optional; absence is not RFC non-compliance.
- DNS advertising is not evidence that HTTP/3, ECH, ML-KEM, TLS, or HTTP behavior negotiated successfully.
- Keep query outcomes separate from record validity: absent, NXDOMAIN, timeout, resolver error, valid, invalid, and valid-but-incompatible are distinct states.
- Every metric carries its count and its correct denominator.
- Preserve complete RRsets, unknown parameters, raw presentation evidence, provenance, and historical interpretation metadata.
- Do not fabricate unavailable detail when importing legacy aggregate reports.

## Runtime and dependencies

Python 3.14 or newer is required. Runtime and development manifests use current tested compatible minimums rather than exact universal pins. Each scan records the exact runtime, dnspython, ruleset, registry, package, and commit versions used.

Pre-commit hook revisions are concrete because pre-commit requires reproducible Git revisions. Refresh them with `pre-commit autoupdate`, review the result, prefer stable releases, and rerun the full hook suite.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

## Required checks

Format only project Python paths so local environments are never traversed:

```bash
black --line-length=100 main.py src tests
isort --profile=black --line-length=100 main.py src tests
```

Before handing off a change, run the checks appropriate to its scope. The full local gate is:

```bash
black --check --line-length=100 main.py src tests
isort --check-only --profile=black --line-length=100 main.py src tests
flake8 --max-line-length=100 --extend-ignore=E203,W503 main.py src tests
mypy --strict --ignore-missing-imports src/
pytest
node tests/dashboard_smoke.js
python -m src.analyzer.pipeline verify \
  --latest docs/data/latest.json \
  --scan-dir data/scans \
  --max-age-hours 48
python -m build
pip-audit --requirement requirements.txt
pre-commit run --all-files
```

## Implementation boundaries

- The fixed website cohort queries HTTPS at apex and `www`; do not invent generic SVCB owner names without an explicit protocol mapping and Attrleaf.
- dnspython-normalized validation is not strict raw-wire validation. Keep that limitation visible until the raw decoder roadmap item is complete.
- Treat IANA/IETF identifiers as dated registry data. Store observed numeric IDs and the snapshot used to resolve their names.
- Maintain schema compatibility intentionally. Use explicit versioning and migration notes instead of silently reinterpreting old observations.
- Keep active DNS, TLS, and HTTP observations separate even when the dashboard presents them together.
- Escape all retained network data before inserting it into HTML.

## Data and automation

- `data/scans/` is canonical durable schema-v2 storage.
- `docs/data/latest.json`, `history.json`, and `changes.json` are deterministic public views.
- The newest decompressed canonical snapshot and `latest.json` must be content-equivalent.
- Existing `results/` files are immutable legacy input. Do not reformat or rewrite them.
- A scheduled scan must build and verify all data, then commit `data/scans/` and `docs/data/` together.
- Pages deployment must verify scan identity and freshness before uploading `docs/`.
- Keep GitHub token permissions least-privileged and keep scan concurrency serialized.

## Documentation and review

- Prefer plain-language names based on adoption, validity, compatibility, and advertisement; retain old “compliance” names only as documented compatibility interfaces.
- Update tests, `README.md`, and `ROADMAP.md` with interpretation or output changes.
- Use semantic versioning for packaged releases.
- Never commit secrets, local environments, caches, build products, or transient raw scanner output.
