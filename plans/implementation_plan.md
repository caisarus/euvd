# euvd-watch — Complete Implementation Plan

> **Audience:** an AI coding agent (or a developer) implementing the project step by step.
> **How to use this document:** implement the steps **strictly in order**. Do not start a step until the previous step's *Acceptance criteria* all pass. Every step defines: **Purpose** (why it exists), **What to implement**, **How to implement**, **How to test**, and **Acceptance criteria**.
> **Language/stack:** Python 3.11+, packaged with `pyproject.toml`. License: EUPL-1.2.
> **Living amendments:** after M0/M1 shipped, a verified-findings review (`plans/feedback_m0_m1.md`) surfaced defect classes the original rules didn't prevent. The *Hardening rules* and *Post-milestone review gate* subsections below, plus inline notes marked "M0/M1 review item N.N" in later steps, were added from that experience and are as binding as the original text.

---

## 0. Project summary

`euvd-watch` is a self-hostable, open-source pipeline that:

1. **Ingests an SBOM** (CycloneDX or SPDX) and normalizes it into a component inventory (M1).
2. **Matches every component against the EUVD** — the European Union Vulnerability Database operated by ENISA — including the *actively exploited* flag and EPSS scores, supplemented by CISA KEV (M2).
3. **Generates OpenVEX statements** conservatively, to cut false-positive noise without hiding risk (M3).
4. **Drafts EU Cyber Resilience Act (CRA) Article 14 notifications** when a reporting trigger fires, starts the 24-hour clock, and writes a tamper-evident audit log. A human always confirms; nothing is ever submitted automatically (M4).
5. **Runs in CI/CD and on a schedule** via GitHub Actions / GitLab CI templates, a Docker image, and a `watch` mode (M5).
6. **Provides a self-hostable, WCAG-compliant dashboard** (M6).

### Design principles (apply to every step)

- **Reuse, don't reinvent.** Wrap existing tools/specs (packageurl, OpenVEX, EPSS, KEV). Build only the missing glue.
- **EUVD-first.** EUVD is the primary source; OSV/KEV/EPSS are supplements.
- **Conservative VEX.** Never auto-suppress anything that might be real risk. Only `not_affected` with an explainable justification; everything uncertain stays `under_investigation`.
- **Human-in-the-loop.** The tool drafts; a human confirms. No automatic filings, ever.
- **Auditable.** Every decision is explainable and logged.
- **Deterministic outputs.** Same inputs → byte-identical outputs (stable ordering, no timestamps in content except where semantically required).

### Global engineering rules

- Type-annotated code everywhere; `mypy --strict` must pass.
- Lint/format with `ruff` (lint + format). Line length 100.
- Tests with `pytest`; target ≥ 85% line coverage per module; never mock what you can fixture. **The full testing methodology, per-step test plans, fixture governance, invariant suite, and CI test topology live in [TEST_PLAN.md](TEST_PLAN.md) — it is authoritative on all testing matters and its infrastructure is built incrementally alongside the milestones.**
- All HTTP is done through one client module with retry/backoff — no scattered `httpx.get` calls.
- All CLI commands must have `--output json|table` and meaningful exit codes: `0` = success/no findings, `1` = findings above threshold, `2` = execution error.
- No network access in unit tests. API interactions are tested with recorded/mocked responses (`respx`).
- Every public function has a docstring stating what it does and why it exists.
- Conventional Commits for every commit (`feat(sbom): ...`, `test(euvd): ...`).

#### Hardening rules (added after the M0/M1 review — see `plans/feedback_m0_m1.md`)

Each of these encodes a defect class that actually shipped in M0/M1 and was caught only by
a post-milestone review. They are binding for every subsequent step.

- **No unhandled exception may escape a CLI command.** Third-party exceptions (pydantic
  `ValidationError`, `UnicodeDecodeError`, library errors) are wrapped into the owning
  module's typed error at the module boundary; commands exit only 0/1/2. *(M1 shipped a
  pydantic traceback with exit 1 for an SBOM with a numeric version field.)*
- **All text file I/O uses explicit `encoding="utf-8"`** — read and write, including cache
  files, state stores, YAML, JSONL audit logs, and rendered templates. Never rely on the
  platform locale. *(M1's own fixture failed to decode under a cp1252 locale.)*
- **Config models are `extra="forbid"`.** A typo'd key must fail loudly and name itself,
  never silently fall back to a default — this config gates a legal reporting trigger. When
  a step adds config fields, update `examples/config/euvd-watch.yaml` and the config tests
  *in the same step*.
- **Validate identity/key fields at every ingest boundary.** Anything that gets deduped,
  keyed, or persisted (components, EUVD records by `euvd_id`, state-store rows by
  `(purl, euvd_id)`, audit entries) must have its key fields checked on ingest; entities
  with missing/empty keys are skipped **with a logged warning**, never allowed to collide.
  *(M1 let nameless components collapse to one `("", version)` key and vanish silently —
  the exact "silently missed finding" failure mode this project exists to prevent.)*
- **Structured identifiers are constructed by their libraries, never by string
  formatting.** Purls via `PackageURL(...)`, not f-strings; canonical form is a tested
  fixed point (`normalize(x) == x`). The same applies to any query strings or VEX product
  identifiers built later.
- **Every machine-readable output carries a `schema_version`.** Not just the findings
  artifact (Step 2.5) — inventories, drafts, webhook payloads: anything a third party or a
  later pipeline stage parses.
- **Every milestone adds its "must never happen" rules to `tests/invariants/`** (test plan
  §6) in the step that introduces the rule, not retroactively. M2's confidence caps are the
  next entries.
- **Any new third-party import must be added to the mypy hook's `additional_dependencies`
  in `.pre-commit-config.yaml` in the same commit** — the hook runs in an isolated env and
  fails with misleading "untyped" errors otherwise. Pin hook revs to the versions actually
  installed by `pip install -e ".[dev]"`, not to remembered version numbers.
- **Logging goes through `logging.getLogger(__name__)` on top of the existing
  `src/euvd_watch/log.py` bootstrap** (wired to `--verbose`); log output is stderr-only.
  Stdout is reserved exclusively for command output — `--output json` stdout purity is a
  contract, tested.

### Post-milestone review gate (added after the M0/M1 review)

A milestone is not finished when its acceptance criteria pass. Before starting the next
milestone: run a critical review of everything the milestone shipped against this plan and
TEST_PLAN.md, **empirically reproducing every suspected defect before reporting it** (write
a repro script per claim; only verified claims go in the review). Record findings in
`plans/feedback_<milestone>.md` with severity tiers (P1 correctness / P2 plan-compliance /
P3 future traps naming the milestone they'll bite), fix at least all P1s and the P2s the
next milestone builds on, and re-run the original repros — not just new unit tests — to
confirm the fixes. The M0/M1 review caught six user-visible correctness bugs this way that
97% line coverage had not.

```
euvd-watch/
├── pyproject.toml
├── README.md                  # detailed readme (provided separately)
├── README.simple.md           # kid-friendly readme (provided separately)
├── GLOSSARY.md                # plain-language glossary of every technical term (provided separately)
├── TEST_PLAN.md               # authoritative test plan & testing infrastructure (provided separately)
├── LICENSE                    # EUPL-1.2
├── CHANGELOG.md
├── ARCHITECTURE.md
├── ROADMAP.md
├── CONTRIBUTING.md
├── .gitlab-ci.yml / .github/workflows/ci.yml
├── docker/Dockerfile
├── docs/
├── examples/
│   ├── sboms/                 # real-world SBOM fixtures
│   └── config/euvd-watch.yaml
├── src/euvd_watch/
│   ├── __init__.py            # __version__
│   ├── cli.py                 # Typer app, all commands
│   ├── config.py              # config loading/validation
│   ├── http.py                # shared HTTP client (retry, cache, rate limit)
│   ├── models.py              # shared pydantic models
│   ├── sbom/                  # M1
│   ├── euvd/                  # M2
│   ├── enrich/                # M2 (EPSS, KEV)
│   ├── vex/                   # M3
│   ├── cra/                   # M4
│   ├── integrations/          # M5
│   └── web/                   # M6
└── tests/
    ├── unit/
    ├── integration/
    └── fixtures/
```

---

## Milestone M0 — Project scaffolding & quality gates

**Goal:** a repo where every later step lands on green CI from day one.
**Estimated effort:** 1 week part-time (~8 h).

### Step 0.1 — Package skeleton and tooling

- **Purpose:** establish the build system, dependency management, and code-quality gates so that every subsequent commit is automatically checked. Without this, quality erodes silently.
- **What to implement:**
  - `pyproject.toml` with project metadata (name `euvd-watch`, `requires-python >=3.11`, license EUPL-1.2), dependencies (`typer`, `pydantic>=2`, `httpx`, `packageurl-python`, `pyyaml`, `jinja2`, `rich`), dev dependencies (`pytest`, `pytest-cov`, `respx`, `freezegun`, `mypy`, `ruff`, `pre-commit`).
  - `src/euvd_watch/__init__.py` exposing `__version__` (single source of truth, read by CLI).
  - `ruff.toml`/config in `pyproject.toml`, `mypy` strict config, `.pre-commit-config.yaml` (ruff, ruff-format, mypy, end-of-file fixer).
- **How to implement:** use the `src/` layout. Pin minimum versions, not exact versions. Configure `pytest` with `--cov=euvd_watch --cov-fail-under=85` in `pyproject.toml`.
- **How to test:** `pip install -e ".[dev]" && ruff check . && mypy src && pytest` runs cleanly (zero tests is OK at this point — add one trivial `test_version.py` asserting `__version__` matches pyproject).
- **Acceptance criteria:** fresh clone + editable install + lint + typecheck + tests all pass with a single documented command sequence.

### Step 0.2 — CLI skeleton

- **Purpose:** a stable command surface that later milestones fill in; users and CI scripts can rely on command names/flags from the start.
- **What to implement:** `cli.py` with a Typer app and stub commands: `version`, `scan`, `match`, `vex`, `cra`, `watch`. Global options: `--config PATH`, `--output [table|json]`, `--verbose`. Stubs print "not implemented yet" and exit `2`, except `version`.
- **How to implement:** one Typer app, sub-apps per domain (`vex generate`, `cra status`, etc.). Entry point `euvd-watch = "euvd_watch.cli:app"` in `pyproject.toml`.
- **How to test:** `pytest` with Typer's `CliRunner`: `version` prints the version and exits 0; every stub exits 2 with a clear message; `--help` renders for every command.
- **Acceptance criteria:** `pip install -e . && euvd-watch version` works; help text exists for all commands.

### Step 0.3 — Config loading

- **Purpose:** one validated configuration object used everywhere (API base URLs, cache dir, thresholds, org identity for CRA drafts) instead of scattered constants.
- **What to implement:** `config.py` with a pydantic `Settings` model: `euvd_api_base_url`, `cache_dir`, `cache_ttl_hours`, `epss_threshold` (default 0.5), `min_confidence` (default `medium`), `organization` block (name, contact email, product name) used later by M4. Load order: defaults → YAML file (`--config` or `./euvd-watch.yaml`) → environment variables (`EUVD_WATCH_*`).
- **How to implement:** pydantic-settings or manual merge; validate on load and fail fast with a human-readable error listing the invalid field.
- **How to test:** unit tests for each load source, precedence order, and validation failure messages. Fixture YAML files in `tests/fixtures/config/`.
- **Acceptance criteria:** invalid config produces exit code 2 and names the bad field; example config exists at `examples/config/euvd-watch.yaml`.

### Step 0.4 — CI pipeline

- **Purpose:** enforce the quality gates automatically on every push; also serves as the reference for the M5 user-facing CI templates.
- **What to implement:** GitHub Actions workflow (and mirrored `.gitlab-ci.yml`) with jobs: lint (ruff), typecheck (mypy), test (pytest with coverage, Python 3.11 and 3.12 matrix), build (`python -m build`).
- **How to test:** push a branch; all jobs green. Break a lint rule locally, confirm CI fails.
- **Acceptance criteria:** badge-ready CI, all green on main.

---

## Milestone M1 — SBOM ingestion & normalization

**Goal:** `euvd-watch scan sbom.json` reads CycloneDX/SPDX and prints a normalized component inventory.
**Estimated effort:** 2 weeks part-time (~16 h).

### Step 1.1 — Core component model

- **Purpose:** a single normalized `Component` shape so the matcher (M2) never cares which SBOM format the data came from. This is the contract for the whole pipeline.
- **What to implement:** in `models.py`: `Component` (pydantic, frozen) with fields `name: str`, `version: str | None`, `purl: str | None`, `cpe: str | None`, `licenses: list[str]`, `hashes: dict[str, str]`, `type: ComponentType` (library/application/os/container/other), `source_format: SourceFormat` (cyclonedx/spdx), `raw_ref: str` (bom-ref / SPDXID for traceability). Also `Inventory` = list of components + metadata (document name, tool, timestamp, format version).
- **How to implement:** frozen pydantic models with strict types; a `dedupe_key` property (`purl` if present, else `(name.lower(), version)`), used to deduplicate inventories deterministically.
- **How to test:** unit tests for construction, validation errors, dedupe-key behavior (purl beats name/version; case-insensitive names).
- **Acceptance criteria:** model importable, 100% covered, `mypy --strict` clean.

### Step 1.2 — CycloneDX parser

- **Purpose:** CycloneDX (JSON) is the most common SBOM output of Syft/cdxgen; parsing it correctly is the highest-value input path.
- **What to implement:** `sbom/cyclonedx.py` with `parse(path_or_bytes) -> Inventory`. Support spec versions 1.4, 1.5, 1.6 (JSON only). Extract components (including nested `components`), purl, cpe, licenses (both `expression` and `license.id/name` forms), hashes. Ignore services/dependencies graphs for now.
- **How to implement:** parse with `json`, validate the minimal fields yourself (do not pull a heavyweight validator); tolerate unknown fields; raise a typed `SbomParseError` with file/line context on malformed input.
- **How to test:** fixtures in `tests/fixtures/sboms/`: (a) a real Syft-generated CycloneDX SBOM of a small public project, (b) a handcrafted minimal SBOM, (c) a malformed one, (d) one with nested components and license expressions. Golden-file test: parsed inventory serialized to JSON must match a committed golden file byte-for-byte.
- **Acceptance criteria:** all fixtures parse or fail as expected; golden files stable across runs.

### Step 1.3 — SPDX parser

- **Purpose:** SPDX 2.3 (JSON) is the second major format (GitHub's SBOM export, ORT, etc.); supporting it doubles the addressable input.
- **What to implement:** `sbom/spdx.py` with the same `parse() -> Inventory` signature. Map SPDX `packages` → `Component`: `name`, `versionInfo`, external refs of type `purl` and `cpe23Type`, `licenseConcluded`/`licenseDeclared`, checksums.
- **How to implement:** same tolerant-parse philosophy as 1.2. A shared `sbom/detect.py` sniffs the format (`bomFormat: CycloneDX` vs `spdxVersion`) and dispatches; raise `UnsupportedFormatError` otherwise.
- **How to test:** fixture from GitHub's SBOM export of a public repo + handcrafted minimal/malformed fixtures; golden files; a detection test matrix (cdx, spdx, garbage, empty file).
- **Acceptance criteria:** `parse_any(path)` correctly routes both formats; identical `Component` semantics regardless of source.

### Step 1.4 — Identifier normalization & reconciliation

- **Purpose:** matching quality (M2) lives or dies on identifiers. PURLs and CPEs from real SBOMs are messy: mixed case, missing qualifiers, vendor quirks. Normalizing here means the matcher can be simple and testable.
- **What to implement:** `sbom/normalize.py`: (a) parse/normalize purl via `packageurl-python` (lowercase type/namespace where the spec says so, strip irrelevant qualifiers, rebuild canonical string); (b) parse CPE 2.3 formatted strings into structured fields; (c) when a component has no purl but has enough data (ecosystem inferable from SBOM metadata + name + version), synthesize a *low-confidence* purl and mark it `synthesized=True` on the component; (d) version cleanup (strip leading `v`, epoch handling for deb/rpm).
- **How to implement:** pure functions, no I/O. Extend `Component` with `normalized_purl`, `cpe_parts`, `synthesized` fields.
- **How to test:** table-driven unit tests with ≥ 30 real-world messy identifier cases (collect from the fixture SBOMs); property test: normalize(normalize(x)) == normalize(x) (idempotence).
- **Acceptance criteria:** idempotence property holds; messy-case table passes; synthesized purls always flagged.

### Step 1.5 — `scan` command

- **Purpose:** the first end-to-end user-visible feature; also the demo used in the grant application and README GIF.
- **What to implement:** `euvd-watch scan <sbom>` → parse, normalize, dedupe, then output: `table` (rich table: name, version, purl, type, flags) or `json` (the `Inventory` model). Summary line: "N components (M deduplicated, K with synthesized identifiers)". Exit 0 on success, 2 on parse errors.
- **How to implement:** wire `sbom.detect → parse → normalize → dedupe` behind a single `load_inventory(path)` function in `sbom/__init__.py` — M2 will reuse it.
- **How to test:** CLI tests over the fixtures; JSON output validated against the golden inventory; exit-code matrix.
- **Acceptance criteria:** `euvd-watch scan examples/sboms/demo.cdx.json` produces a correct, readable table in < 2 s.

---

## Milestone M2 — EUVD client & matching engine

**Goal:** `euvd-watch match sbom.json --exploited-only` returns real EUVD findings with confidence scores.
**Estimated effort:** 3 weeks part-time (~24 h). **This is the heart of the project — do not rush it.**

### Step 2.1 — Shared HTTP layer

- **Purpose:** the EUVD API is beta and rate limits are unknown/changeable; a single disciplined HTTP layer (retry, backoff, caching) protects both the user and ENISA's service, and makes everything testable.
- **What to implement:** `http.py`: an `ApiClient` wrapping `httpx.Client` with: exponential backoff + jitter on 429/5xx (max 5 retries), timeout defaults (10 s connect / 30 s read), a persistent on-disk cache (SQLite, keyed by URL+params, TTL from config, honoring ETag/If-None-Match when the server supports it), a `User-Agent` of `euvd-watch/<version> (+repo URL)`, and structured logging of every request (URL, status, cache hit/miss, duration) — built on the existing `src/euvd_watch/log.py` bootstrap (M0/M1 review item 2.3), not a new logging setup.
- **How to implement:** cache as a small `Cache` class (get/set/purge, `cachedir/euvd-cache.sqlite`); do not use third-party caching libs. All other modules receive an `ApiClient` instance — never construct their own.
- **How to test:** unit tests with `respx`: retry behavior on 429 then success; TTL expiry (freezegun); cache hit avoids network; corrupted cache file self-heals (drops and recreates).
- **Acceptance criteria:** zero direct `httpx` usage outside `http.py` (enforce with a ruff banned-import rule or a grep test).

### Step 2.2 — EUVD API client & record model

- **Purpose:** turn ENISA's EUVD API responses into stable, typed records the matcher can consume, insulating the rest of the code from beta-API churn.
- **What to implement:** `euvd/client.py` + `euvd/models.py`. First, **discover and document the current API surface** (the API is beta — verify endpoints at implementation time at `https://euvd.enisa.europa.eu/` and encode findings in `docs/euvd-api.md`). **Important reality check for the implementer:** EUVD records describe affected software as *vendor / product / version-range text strings* (CVE-style), **not** as purls — do not expect or invent purl fields in API data. Implement these access patterns: (a) retrieval of the full **exploited-vulnerabilities feed** (small enough to sync wholesale each run), (b) retrieval of the **latest/recent vulnerabilities feed**, (c) **keyword search** by vendor and/or product name, (d) **lookup by EUVD ID or CVE alias**, all with pagination handling. `EuvdRecord` model: `euvd_id`, `aliases` (CVE IDs), `description`, `affected_products` (list of `{vendor, product, version_range}` as published), `exploited: bool`, `epss: float | None`, `cvss`, `references`, `dates`.
- **How to implement:** every parse of an API response must tolerate missing/extra fields (beta!) — but per the hardening rules, a record with a missing/empty `euvd_id` (its identity key) is skipped **with a logged warning**, never stored or matched: empty keys colliding silently was M1's worst bug class. Record fixtures: capture 5–10 real API responses into `tests/fixtures/euvd/` (a small script `scripts/capture_fixtures.py` does this once, manually run — fixtures are committed, tests never hit the network).
- **How to test:** `respx`-mocked tests over the committed fixtures: pagination, empty results, malformed record (skipped with warning, not crash), exploited-list retrieval.
- **Acceptance criteria:** `docs/euvd-api.md` documents every endpoint used; all client methods typed and fixture-tested.

### Step 2.3 — Matching engine with confidence scoring

- **Purpose:** the core intellectual property of the project: deciding *whether EUVD record X affects component Y* with an honest confidence level, so downstream VEX/CRA logic can be conservative. Low-confidence matches are flagged for human review rather than silently trusted.
- **What to implement:** `euvd/match.py`. **Core problem statement:** the SBOM side speaks purl/CPE; the EUVD side speaks `(vendor, product, version_range)` text. The matcher's first job is therefore to derive **(vendor, product) candidates** for every component: from the component's CPE fields when present (best signal), else from the purl's namespace/name, assisted by a small curated alias table shipped with the tool (`euvd/aliases.yaml`, e.g. `pkg:pypi/pillow → vendor "python-pillow", product "pillow"`) that users can extend. Then, for each component, run strategies in order and keep the best result:
  1. **Structured product match** — a (vendor, product) candidate equals the record's affected `(vendor, product)` (normalized: lowercase, punctuation-insensitive) **and** the component version is provably inside the affected range → confidence `high`.
  2. **Partial structured match** — (vendor, product) equality but the version range is open-ended/ambiguous; **or** product-name equality with unknown/mismatched vendor while the version is in range → confidence `medium`.
  3. **Fuzzy name heuristic** — normalized token similarity between component name and affected product, without a reliable version evaluation on either side → confidence `low` (exists to surface candidates for human review, never for automated downstream decisions).
  - **Confidence caps (hard invariants):** a component whose identifier was `synthesized` in Step 1.4 can never exceed `medium`; a version comparison done by the fallback comparator can never support `high`.
  - Version-range evaluation: implement a small `versions.py` supporting semver and PEP 440, falling back to tokenwise comparison; the comparator must report *which* scheme it used so the caps above are enforceable. **deb/rpm caution (M0/M1 review item 3.3):** `Component.normalized_version` strips debian epochs (`1:1.0` → `1.0`), which destroys deb ordering (`1:1.0` sorts *after* `2.0`) — the comparator must evaluate deb/rpm schemes against the **raw** `Component.version`, never the normalized form. Document this in `docs/matching.md`.
  - Output model `Finding`: `component`, `record`, `confidence: high|medium|low`, `strategy`, `explanation: str` (one human-readable sentence: *why* this matched — mandatory, this feeds VEX/CRA auditability).
- **How to implement:** pure functions over `Inventory` + iterable of `EuvdRecord`; no I/O. Deterministic ordering of findings (by component dedupe_key, then euvd_id).
- **How to test:** a curated truth table in `tests/fixtures/matching/cases.yaml`: ≥ 25 cases of known true positives, known false positives (e.g., same product name, different vendor), edge versions (boundary of a range), and expected confidence. Include at least one **mis-inferred-ecosystem case** (M0/M1 review item 3.4): a component whose synthesized purl guessed the wrong ecosystem from a CPE prefix (e.g. a pypi package whose CPE product starts with `go-`) — asserting the synthesized-purl confidence cap actually contains the damage. Note that `Component.cpe_parts` values arrive **decoded** (backslash escapes already removed by `sbom/normalize.py`) — do not unescape again. This file is the regression suite for all future matcher changes.
- **Acceptance criteria:** truth table passes 100%; every `Finding.explanation` is non-empty; no `high` confidence ever produced from the fallback version comparator (asserted in tests).

### Step 2.4 — Enrichment: EPSS & CISA KEV

- **Purpose:** the CRA trigger (M4) needs exploitation-likelihood signals. EUVD carries some, but independent EPSS scores and CISA KEV membership make the trigger defensible.
- **What to implement:** `enrich/epss.py` (FIRST.org EPSS API, batch queries by CVE) and `enrich/kev.py` (download + cache the KEV JSON catalog, membership check by CVE). `enrich(findings) -> findings` fills `epss_score` and `in_kev` on each finding.
- **How to implement:** both go through `ApiClient` with long cache TTLs (EPSS 24 h, KEV 24 h). Failures degrade gracefully: enrichment errors log a warning and leave fields `None` — never fail the run.
- **How to test:** respx fixtures for both APIs; graceful-degradation test (API down → findings still produced, fields None, exit code unaffected).
- **Acceptance criteria:** enrichment adds fields without mutating match results; offline mode (`--no-enrich`) skips it entirely.

### Step 2.5 — `match` command

- **Purpose:** the flagship command; what CI pipelines will call; the demo for users and grant reviewers.
- **What to implement:** `euvd-watch match <sbom> [--exploited-only] [--min-confidence low|medium|high] [--no-enrich] [--fail-on none|any|exploited] [--save-findings findings.json]`. Table output grouped by component with color-coded confidence; JSON output = list of `Finding`. `--save-findings` writes a versioned artifact (`{schema_version: 1, generated_at, inventory_digest, findings: [...]}`) that `vex generate --findings` and `cra check --findings` accept, so later stages can run without re-querying the API. Exit codes: 0 no findings above policy, 1 findings, 2 error — so a CI job can gate on it.
- **How to implement:** compose `load_inventory → fetch → match → enrich → filter → render`. **Query strategy (two tiers, documented in `docs/matching.md`):** tier 1 — always sync the full exploited feed (Step 2.2a) into the cache and match the entire inventory against it locally (cheap, covers the CRA-critical case even for huge SBOMs); tier 2 — unless `--exploited-only`, run per-component keyword searches using the (vendor, product) candidates from Step 2.3, deduplicated across components and served from cache. **EUVD unreachable:** if the cache holds data within TTL, proceed with a loud warning and stamp `data_freshness` (cache timestamp) into every output; with no usable cache, exit 2 with a clear message — never silently report "no findings" on missing data.
- **How to test:** end-to-end CLI test with fully mocked API (respx) over the demo SBOM; exit-code matrix for `--fail-on`; JSON schema snapshot test.
- **Acceptance criteria:** the README quickstart commands work verbatim; a run over the demo SBOM with fixtures produces the documented example output.

---

## Milestone M3 — OpenVEX generation

**Goal:** `euvd-watch vex generate` turns findings + human decisions into valid OpenVEX, reducing noise without hiding risk.
**Estimated effort:** 2 weeks part-time (~16 h).

### Step 3.1 — OpenVEX document model & writer

- **Purpose:** VEX is the machine-readable answer to "does this vulnerability actually affect this product?" — emitting spec-valid OpenVEX lets downstream scanners consume the decisions.
- **What to implement:** `vex/model.py`: OpenVEX document + statement models per the OpenVEX spec (status: `not_affected`, `affected`, `fixed`, `under_investigation`; justification enum for `not_affected`; product/subcomponent identifiers as purls; `@id`, `author`, `timestamp`, `version`). `vex/write.py`: deterministic serialization (sorted keys, stable statement ordering).
- **How to implement:** validate against the published OpenVEX JSON schema in tests (vendor the schema file into `tests/fixtures/openvex/schema.json`).
- **How to test:** schema-validation tests; golden-file test; round-trip (write → read → write) is byte-stable.
- **Acceptance criteria:** output validates against the vendored OpenVEX schema.

### Step 3.2 — Conservative statement rules

- **Purpose:** the credibility of the tool: it must *never* auto-suppress real risk. Automation only asserts safety when it can prove and explain it.
- **What to implement:** `vex/rules.py`, a rule engine mapping findings → draft statements:
  - Default for every finding: `under_investigation`.
  - `not_affected` may be auto-drafted **only** for rules with machine-checkable evidence, initially exactly one rule: *component version provably outside the affected range with a `high`-confidence range evaluation* → justification `vulnerable_code_not_present`, plus the explanation string.
  - `affected`/`fixed` are never auto-asserted; they come only from human decisions (Step 3.3).
  - Every auto-drafted statement embeds the matcher explanation in an `impact_statement`/annotation field.
- **How to implement:** rules as small pure classes with `applies(finding) -> Decision | None`; a registry list; first-match-wins is forbidden — if two rules disagree, fall back to `under_investigation` and log.
- **How to test:** unit tests per rule incl. the disagreement fallback; an adversarial test set: findings engineered to *look* dismissible but lacking proof must stay `under_investigation`.
- **Acceptance criteria:** grep-able invariant enforced in tests: no code path can produce `not_affected` without a justification and explanation.

### Step 3.3 — Human decisions file & merge

- **Purpose:** humans must be able to record judgments ("we don't ship that code path") that persist across runs and merge with automated drafts — the human-in-the-loop mechanism.
- **What to implement:** a `vex-decisions.yaml` format: list of `{euvd_id/cve, purl (or pattern), status, justification, statement, author, date}`. `vex/merge.py`: decisions override automated drafts; conflicts (decision vs. stronger automated evidence) produce a loud warning; stale decisions (matching nothing) are reported.
- **How to implement:** schema-validate the decisions file with pydantic; provide `euvd-watch vex init-decisions` to scaffold it from current findings.
- **How to test:** merge matrix tests (decision beats draft; stale detection; conflict warning); YAML validation error messages are actionable.
- **Acceptance criteria:** a documented workflow: run match → init-decisions → edit YAML → `vex generate` → downstream scanner consumes it.

### Step 3.4 — `vex generate` command

- **Purpose:** ties M3 together into the pipeline.
- **What to implement:** `euvd-watch vex generate <sbom> [--decisions vex-decisions.yaml] [-o openvex.json]`: match (reusing M2 internals or a saved findings JSON via `--findings`), apply rules, merge decisions, write OpenVEX. Print a summary: counts per status, number of auto-drafted `not_affected`, warnings.
- **How to test:** e2e CLI test over demo SBOM + fixtures + a decisions file, validated against the schema; determinism test (two runs, identical bytes given `--timestamp` pinned).
- **Acceptance criteria:** demo produces a valid OpenVEX file consumable by at least one third-party tool (verify manually once with `vexctl` or Grype, note result in docs).

---

## Milestone M4 — CRA Article 14 reporting workflow

**Goal:** when an actively-exploited vulnerability hits a component, draft the notification, start the clock, log everything tamper-evidently — and never submit anything automatically.
**Estimated effort:** 2 weeks part-time (~16 h).

### Step 4.1 — Trigger policy engine

- **Purpose:** the CRA requires notification of *actively exploited* vulnerabilities within 24 hours of awareness. Organizations need one configurable, defensible definition of "this crossed the line."
- **What to implement:** `cra/trigger.py`: a policy evaluated per finding, configurable in YAML: `euvd_exploited == true` OR `in_kev == true` OR `epss >= threshold` (each toggleable; conjunction/disjunction configurable; minimum confidence gate, default `medium`). Output: `TriggerEvent` with fields `finding`, `fired_rules`, `first_seen` (UTC), `policy_snapshot` (the exact policy config that fired — needed for later defensibility).
- **How to implement:** pure evaluation; persistence of first-seen state in a local SQLite state store `cra/state.py` keyed by (purl, euvd_id) so re-runs don't re-fire or reset clocks.
- **How to test:** policy matrix unit tests; state-store tests: same finding twice → one event; freezegun for time.
- **Acceptance criteria:** re-running `match`/`cra` never duplicates events or resets `first_seen`.

### Step 4.2 — 24 h / 72 h clock tracking

- **Purpose:** CRA Article 14 imposes *staged* deadlines on manufacturers for actively exploited vulnerabilities — an early warning, a fuller vulnerability notification, and a final report. Teams need one unambiguous countdown per stage.
- **What to implement:** `cra/clock.py`: deadlines are modeled as **configurable stages**, not a single hardcoded timer. Ship defaults reflecting the CRA as understood today — early warning **24 h** and vulnerability notification **72 h** from awareness (`first_seen`), plus a final report stage anchored to remediation — but **verify the exact current stages, durations, and anchor points against the CRA text/ENISA guidance at implementation time and document them in `docs/cra.md`**; the stage list lives in config so legal changes never require code changes. Per stage and event, compute deadline timestamps and remaining time; states `pending → due_soon (<25% of stage remaining) → overdue → completed (human marked per stage)`. `euvd-watch cra status` renders a table of open events with one countdown per open stage.
- **How to test:** freezegun tests across every state transition and boundary (exactly at deadline, off-by-one-second) for multiple configured stages; config with custom stages honored.
- **Acceptance criteria:** all times stored/computed in UTC; rendered with explicit timezone.

### Step 4.3 — Notification draft renderer

- **Purpose:** under time pressure, a prefilled draft with everything the tool knows (component, versions, EUVD/CVE IDs, exploitation evidence, org identity from config) is the difference between meeting the deadline and chaos. Drafting only — a human reviews, completes, and files it through the official channel.
- **What to implement:** `cra/report.py`: Jinja2 templates (Markdown + JSON) for an early-warning draft: reporter/org fields from config, vulnerability identification, affected product/component, exploitation-awareness basis (which rule fired, evidence links), timeline. Command `euvd-watch cra draft <event-id> -o draft.md`. Verify the actually-required notification fields against current ENISA/CRA guidance at implementation time; keep templates easy to update.
- **How to test:** snapshot tests of rendered drafts from fixture events; missing-org-config produces a clear error telling the user which config fields to fill.
- **Acceptance criteria:** a draft renders complete from demo data with zero manual editing needed except human judgment fields (clearly marked `TODO-HUMAN`).

### Step 4.4 — Tamper-evident audit log

- **Purpose:** if a regulator or auditor asks "when did you know and what did you do," the tool must answer with an evidence trail whose integrity is verifiable.
- **What to implement:** `cra/audit.py`: append-only JSONL log; each entry `{ts, actor (tool|human), action, payload_digest, prev_hash, entry_hash}` where `entry_hash = SHA-256(prev_hash + canonical_json(entry))` — a hash chain. Log every trigger event, clock transition, draft render, and human `cra mark` action. `euvd-watch cra verify-log` recomputes the chain and reports the first broken link if any.
- **How to implement:** canonical JSON (sorted keys, no whitespace) before hashing; the genesis entry uses a fixed documented seed.
- **How to test:** chain verification on a fixture log; tamper tests (modify one byte mid-file → verify-log pinpoints the entry); append-after-tamper detection.
- **Acceptance criteria:** verify-log is O(n), deterministic, and its failure output names the exact corrupted entry.

### Step 4.5 — `cra` command group

- **Purpose:** unify M4 for users.
- **What to implement:** `cra check <sbom>` (match → trigger → persist events, exit 1 if new events; also accepts `--findings findings.json` from Step 2.5 to skip re-matching), `cra status`, `cra draft <id>`, `cra mark <id> --completed --note "..."`, `cra verify-log`.
- **How to test:** e2e scenario test: seeded fixtures → check fires one event → status shows countdown → draft renders → mark completes → verify-log passes; second `check` run is idempotent.
- **Acceptance criteria:** the full scenario runs green in CI as an integration test.

---

## Milestone M5 — CI/CD integrations, packaging & watch mode

**Goal:** anyone can adopt euvd-watch in their pipeline in under 10 minutes.
**Estimated effort:** 2 weeks part-time (~16 h).

### Step 5.1 — PyPI packaging & release automation

- **Purpose:** `pip install euvd-watch` is the adoption funnel; releases must be reproducible and boring. Note: the *first* release (`0.1.0`, after M2) was manual — this step replaces that manual process with automation for every release after it.
- **What to implement:** release workflow (GitHub Actions): on tag `vX.Y.Z` → build sdist+wheel → publish to PyPI (trusted publishing/OIDC, no long-lived tokens) → GitHub release with changelog section. `CHANGELOG.md` in Keep-a-Changelog format.
- **How to test:** dry-run against TestPyPI first; verify `pip install` from TestPyPI in a clean venv in CI.
- **Acceptance criteria:** one tag push produces an installable release with zero manual steps.

### Step 5.2 — Docker image

- **Purpose:** CI jobs and cron/watch deployments want a pinned container, not a Python environment.
- **What to implement:** `docker/Dockerfile`: multi-stage, `python:3.12-slim` base, non-root user, `euvd-watch` as entrypoint; image published to GHCR on release; `docker run ghcr.io/<org>/euvd-watch match /sbom.json` documented.
- **How to test:** CI job builds the image and runs `version` + a mocked `scan` inside it; image size budget < 200 MB.
- **Acceptance criteria:** documented one-liner works on a clean machine.

### Step 5.3 — GitHub Action & GitLab CI template

- **Purpose:** meet users where they are; a copy-paste CI snippet is the single best adoption lever.
- **What to implement:** (a) a composite GitHub Action (`action.yml`) with inputs `sbom-path`, `fail-on`, `min-confidence`, uploading findings JSON as an artifact; (b) a GitLab CI include template (`templates/euvd-watch.gitlab-ci.yml`) doing the same — GitLab first-class matters (author's ecosystem). Document both with full examples including SBOM generation via Syft as a prior step.
- **How to test:** a real workflow in this repo dogfoods the action against `examples/sboms/`; template linted with `gitlab-ci-lint` equivalent (schema check).
- **Acceptance criteria:** copy-paste snippet from README works in a fresh repo (verified once manually, noted in docs).

### Step 5.4 — `watch` mode

- **Purpose:** vulnerabilities appear *after* you shipped; scheduled re-matching of a stored SBOM against fresh EUVD data is the "watch" in euvd-watch.
- **What to implement:** `euvd-watch watch <sbom> [--interval 6h | --once]`: re-run match+trigger on a schedule (or once, for cron), diff against previous findings snapshot (state store), report **only new/changed findings**; notification sinks: stdout, webhook POST (generic JSON), with a pluggable interface for future sinks (email, Slack).
- **How to test:** unit tests for the differ (new, resolved, changed-severity cases); webhook tested with a local respx-intercepted endpoint; `--once` in an integration test.
- **Acceptance criteria:** two consecutive runs with unchanged data produce zero notifications.

---

## Milestone M6 — Self-hostable dashboard

**Goal:** a WCAG-compliant web UI over the state store: findings, VEX statuses, CRA clocks.
**Estimated effort:** 3 weeks part-time (~24 h).

### Step 6.1 — Storage consolidation

- **Purpose:** M2–M5 each persist bits of state; the dashboard needs one coherent read model.
- **What to implement:** `web/store.py`: consolidate findings snapshots, VEX statuses, trigger events, and audit-log references into the single SQLite DB (schema with migrations via simple numbered SQL files + a `migrate()` runner). CLI gains `euvd-watch db migrate`.
- **How to test:** migration tests from empty and from each prior schema version; concurrent read test (dashboard reads while watch writes — WAL mode).
- **Acceptance criteria:** all earlier commands keep working; single DB file documented.

### Step 6.2 — Web application

- **Purpose:** visibility for the humans in the loop — reviewers of low-confidence matches, owners of CRA clocks.
- **What to implement:** FastAPI + server-rendered Jinja2 (no SPA, no JS build chain): pages: Overview (counts, open CRA clocks with countdown), Findings (filter by confidence/exploited/status, **paginated** — M1's CLI table renders unbounded rows, which is tolerable in a terminal but not in a page; while here, give the CLI table a "… and N more" cap too, M0/M1 review item 3.7), Finding detail (explanation, EUVD data, VEX status, decision shortcut instructions), CRA events, Audit log viewer (+ verify button). Read-mostly; the only writes are `cra mark` and VEX-decision hints, both requiring the auth below.
- **How to implement:** `euvd-watch web serve [--host 127.0.0.1 --port 8642]`; basic auth from config (hashed password) — document clearly it's designed to sit behind a reverse proxy; bind to localhost by default.
- **How to test:** FastAPI TestClient route tests; auth tests (401 without credentials); HTML contains no inline event handlers (CSP-friendly).
- **Acceptance criteria:** dashboard renders real data from the demo scenario end-to-end.

### Step 6.3 — Accessibility (WCAG 2.1 AA)

- **Purpose:** WCAG compliance is an explicit project commitment (and an NLnet review criterion): the dashboard must be usable with keyboard and screen reader.
- **What to implement:** semantic HTML landmarks, skip-link, focus states, color-contrast-checked palette, table headers/scope, countdowns with `aria-live=polite`, all functionality keyboard-reachable.
- **How to test:** automated: `pa11y`/axe run in CI against rendered pages of the demo scenario; manual keyboard pass documented as a checklist in `docs/accessibility.md`.
- **Acceptance criteria:** zero serious/critical axe violations in CI.

### Step 6.4 — Deployment docs

- **Purpose:** "self-hostable" only counts if a stranger can host it.
- **What to implement:** `docs/deploy.md`: docker-compose example (watch + web + volume), reverse-proxy TLS example (Caddy), backup guidance (the one SQLite file + audit log), upgrade procedure.
- **How to test:** follow the doc verbatim on a clean VM/container once; fix every deviation found.
- **Acceptance criteria:** cold-start to running dashboard in < 15 minutes following only the doc.

---

## Cross-cutting final steps

### Step X.1 — Documentation pass
Write/refresh: `ARCHITECTURE.md` (module map mirrors milestones), `docs/matching.md`, `docs/euvd-api.md`, `docs/cra.md`, `CONTRIBUTING.md`. README quickstart re-verified verbatim.

### Step X.2 — Demo & fixtures pack
`examples/` gets a scripted demo (`examples/demo.sh`) that runs scan → match (mock or live) → vex → cra on a bundled SBOM, plus an asciinema recording embedded in the README.

### Step X.3 — Security & license hygiene
`pip-audit` in CI; SPDX headers on all source files (EUPL-1.2); a `SECURITY.md` with a disclosure contact. The project must pass its own scan: generate its SBOM with Syft and run euvd-watch on itself in CI (dogfood job).

---

## Timeline

Assumptions: one developer, part-time (~8–10 h/week), AI-assisted implementation. Full-time roughly halves calendar time.

| Weeks | Milestone | Key demo at the end |
|---|---|---|
| 1 | M0 scaffolding | green CI, `euvd-watch version` |
| 2–3 | M1 SBOM ingestion | `scan` over real Syft/GitHub SBOMs |
| 4–6 | M2 EUVD matching | `match --exploited-only` with confidence scores |
| 7–8 | M3 OpenVEX | valid OpenVEX consumed by a third-party scanner |
| 9–10 | M4 CRA workflow | full trigger → clock → draft → audit scenario |
| 11–12 | M5 integrations | PyPI release, Docker, GH Action + GitLab template, watch mode |
| 13–15 | M6 dashboard | self-hosted WCAG dashboard over demo data |
| 15 | X.1–X.3 polish | docs, demo pack, dogfood scan |

**Total: ~15 weeks part-time (~3.5 months); ~7 weeks full-time.**

Suggested public checkpoints: publish to PyPI as `0.1.0` **immediately after M2** (scan+match alone is already useful) — this first release is done **manually** (`python -m build && twine upload`, using a project name reserved on PyPI as early as M0 — **status: still not reserved as of the post-M1 review; outstanding owner action, and a real squatting risk the longer it waits**); Step 5.1 then *automates* what was manual, it is not the first release. Then `0.2.0` after M3, `0.3.0` after M4, `1.0.0-rc` after M6.

---

## Definition of done (whole project)

- All milestone acceptance criteria pass; CI fully green including dogfood, coverage ≥ 85%, mypy strict, axe zero-critical.
- A stranger can: `pip install euvd-watch`, run the README quickstart against their own SBOM, adopt the CI snippet, and self-host the dashboard — using only the documentation.
- No code path can silently suppress a finding; every automated decision carries a human-readable explanation; nothing is ever filed/submitted automatically.
