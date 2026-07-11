# Changelog

All notable changes to euvd-watch are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project uses
[Semantic Versioning](https://semver.org/); until `1.0.0`, minor versions may contain
breaking changes (each one listed explicitly below).

## [Unreleased]

### Added
- **`watch` mode (milestone M5, Step 5.4)**: `euvd-watch watch <sbom>` re-matches an SBOM
  and reports only **new/resolved/changed** findings since the last run (no flag or
  `--once` runs a single cycle; `--interval 6h`-style loops forever until interrupted).
  Diff identity is `(component, EUVD record)`; "changed" covers `confidence`,
  `record.exploited`, `in_kev`, `epss_score`, `record.cvss_score`. Two sinks: stdout
  (human mode) / structured JSON (`--output json`), and `--webhook URL` (one POST per
  changed finding, via the same disciplined `ApiClient` retry/backoff as everywhere else
  in the project — `ApiClient` gained `post_json`). A findings snapshot persists in
  `state_dir/watch/` between runs. See `docs/watch.md`.
- **The CRA Article 14 workflow (milestone M4)**: `cra check` (configurable trigger over
  EUVD-exploited / CISA-KEV / EPSS signals with a confidence floor; persists events; exit
  1 when a new event opens; idempotent re-runs), `cra status` (config-driven deadline
  stages — 24 h early warning, 72 h vulnerability notification, 14 d final report
  anchored on remediation availability — all UTC), `cra draft` (prefilled Markdown/JSON
  notification drafts with `TODO-HUMAN` markers; never upgrades a signal into an
  exploitation claim), `cra mark` (records human stage completions and remediation
  availability), and `cra verify-log` (hash-chained tamper-evident audit log with an
  honestly documented threat model). See `docs/cra.md`. Nothing is ever submitted
  automatically.
- New config: `state_dir` (durable records, separate from the purgeable cache),
  `cra_trigger.min_confidence` / `require_all`, configurable `cra_stages`, and
  `tier2_product_search` (privacy toggle: tier-2 matching sends SBOM-derived product
  names to the EUVD API; disable for confidential inventories).
- Config values that gate the CRA trigger are now bounds-checked (`epss_threshold` must
  be 0–1, stage hours positive, stage names unique, TTL non-negative) — semantically
  impossible values used to load silently and could deaden trigger signals.
- `match --timestamp` pins the findings artifact's `generated_at`, so identical inputs
  produce byte-identical JSON output (same contract as `vex generate --timestamp`).
- `vex generate --fail-on-conflict`: exit 1 when a human decision contradicts automated
  evidence — a CI gate; the document is still written and the human decision still wins.
- Romanian README (`README.ro.md`); the English README now marks per-command
  implementation status (✅ available / 🚧 planned).
- `docs/AUDIT_AND_REMEDIATION_PLAN.md`: full-repository audit (2026-07-10) with the
  remediation roadmap to `1.0.0`.

### Changed
- **Breaking (VEX output):** auto-drafted `not_affected` statements now carry
  justification `component_not_present` instead of `vulnerable_code_not_present` — the
  machine-checked proof is that the component *at an affected version* is not present; no
  code is ever inspected. Human decisions keep the full justification vocabulary.
- The dashboard (`web serve`, milestone M6) moved out of the `1.0.0` scope; it ships
  in `1.1`.

### Fixed
- Match candidates, alias-table lookups, and versionless VEX decision patterns now derive
  package identity via `packageurl-python` instead of string splitting. Previously,
  qualifiers on a *versionless* purl (`pkg:deb/debian/curl?arch=amd64`) polluted the
  product name, lost the vendor hint (degrading provable `high` matches to `medium`), and
  leaked qualifier text into EUVD search queries; percent-encoded npm scopes (`%40babel`)
  now decode into a usable vendor hint.

## [0.1.0] — unreleased

Milestones M0–M3 as built: project scaffolding and quality gates; SBOM ingestion and
normalization (CycloneDX 1.4–1.6 JSON, SPDX 2.3 JSON) with the `scan` command; the EUVD
client, matching engine with confidence scoring, EPSS/CISA-KEV enrichment, and the `match`
command; conservative OpenVEX generation (`vex generate`, `vex init-decisions`) with the
human `vex-decisions.yaml` override mechanism. Not yet published to PyPI.
