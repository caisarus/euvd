# Changelog

All notable changes to euvd-watch are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project uses
[Semantic Versioning](https://semver.org/); until `1.0.0`, minor versions may contain
breaking changes (each one listed explicitly below).

## [Unreleased]

### Added
- **The package now ships a `py.typed` marker** (PEP 561), so the strict annotations that
  were already there finally reach downstream type-checkers — importing `euvd_watch` in a
  typed codebase no longer produces `module is installed, but missing library stubs or
  py.typed marker`. The `Typing :: Typed` classifier is now honest and was added alongside.

### Fixed
- **`ruff format --check` runs in CI.** The `ruff-format` pre-commit hook was never a gate:
  a commit made with `--no-verify`, or a branch cut before the hook existed, landed
  unformatted and nothing noticed — 11 files had drifted by `1.0.0`. They are reformatted
  here (whitespace only, no behaviour change) and the lint job now checks. `ruff` is pinned
  in the `dev` extra to the hook's rev so CI and the hook cannot disagree about what
  "formatted" means.

## [1.0.0] — 2026-08-20

**The stable release.** From here the CLI contract (commands, flags, exit codes), the
findings/VEX/CRA JSON schemas, and the config file format are covered by semantic
versioning: breaking changes require a major bump, and deprecations are announced at least
one minor version ahead. Nothing in this release changes behaviour you depended on in
`0.4.1` — it is the same code plus the `Retry-After` fix below, promoted once the last
Definition-of-Done item closed.

Scope of the `1.0.0` claim: SBOM ingestion, EUVD matching and enrichment, conservative
OpenVEX drafting, the CRA Article 14 trigger with its audit log, watch mode, and the CI/CD
integrations. **The dashboard (`web serve`) is present but stays beta** and is explicitly
outside the stability promise — it goes GA in `1.1`.

Anyone still on a release before `0.4.1` should read that release's note first: those
versions could report *no findings, with a success exit code*, for a component affected by
an actively exploited vulnerability.

### Added
- **INV-8 is now enforced, not just promised.** "Nothing is ever submitted or filed
  automatically" was the one invariant of the ten with no test — it had been deferred to
  "M5, when webhooks add POST", and M5 shipped the webhook sink without it.
  `tests/invariants/test_m5_invariants.py` closes it with five AST tests over the package
  source: only `GET` and `POST` reach the transport and only from `get_json`/`post_json`;
  no HTTP verb is called on a client object directly (including a reach-around such as
  `self._api._client.post(...)`); `post_json` has exactly one caller, `WebhookSink`; the
  `cra/` module that drafts Article 14 notifications contains no URL to send one to; and
  no submission endpoint can be introduced through configuration. Each test was verified
  to fail against a deliberate mutation before being kept.

### Changed
- **The HTTP client honours `Retry-After` instead of guessing at a backoff** (RFC 9110
  §10.2.3, both the delay-seconds and HTTP-date forms). Retries used to run on a fixed
  exponential schedule that ignored the server's own answer, and coming back sooner than
  asked just earns another 429 — relevant in practice, since ENISA has been observed
  returning 429 to shared CI runner IPs during EU working hours. Three deliberate
  boundaries: a cooldown longer than 60 s stops the run immediately with the requested
  wait in the message rather than sleeping through it (a scan that silently hangs for an
  hour is worse than one that fails with a number you can schedule around); the new
  `RateLimited` subclasses `ApiError`, so every caller already treats it as "no usable
  data, fail loudly" and the CLI turns it into exit `2` — being rate limited must never be
  mistaken for an empty result; and an unparseable header is ignored in favour of the
  normal backoff, because a malformed value must never be a reason to stop retrying.

### Documentation
- **The PyPI project page is now usable, not just the GitHub one.** The README's 20 doc
  links were relative, which resolves on GitHub but not on PyPI, where the long
  description is served from a different root — they are now absolute URLs, each one
  HTTP-checked. The package also had **no project URLs at all**, so the PyPI sidebar
  offered no Homepage, Source, Issues, Changelog or Security link; `[project.urls]` now
  supplies all six. Classifiers gained `Development Status :: 5 - Production/Stable`,
  which is the metadata that states what this version number claims.
- **The README now exists where GitHub looks for it.** It lived at `readme/readme.md`, a
  leftover from when this repository held only planning documents, so
  `https://github.com/caisarus/euvd` served a **404** for its own front page and four of
  the README's links were dead. `README.md`, `README.ro.md`, `README.simple.md` and
  `GLOSSARY.md` now sit at the repo root (moved with history preserved); a link check over
  all 22 markdown files reports zero broken relative links. PyPI was unaffected and stays
  correct.
- **`ARCHITECTURE.md`** — the module map, by milestone: the pure-core / I/O-at-the-edges
  shape, what each package owns, the ten invariants, and why the boundaries sit where they
  do (matcher separate from trigger, state separate from audit log, human decisions
  separate from machine conclusions, drafting separate from filing).
- **`CONTRIBUTING.md`** — setup, the checks, and the rules that are not negotiable, each
  with its reasoning. Includes the truth-table rule (every wild bug becomes a row *before*
  its fix merges), the alias-table evidence rule (every `aliases.yaml` entry cites a real
  EUVD record id and adds a truth-table row), and fixture/golden governance.
- **`GLOSSARY.ro.md`** — the glossary in Romanian, all 43 terms, cross-linked with the
  English one. The "documentation in English and Romanian" claim is now fully true rather
  than partly.
- README housekeeping found by the sweep: the "🚧 coming with their milestones" list is
  replaced by links to all ten shipped `docs/` pages, and the CI snippet's action pin moves
  `@v0.3.1` → `@v0.4.1`.
- The README ↔ implementation traceability matrix (`docs/AUDIT_AND_REMEDIATION_PLAN.md`
  §4) was a 2026-07-10 snapshot describing `watch` as a stub, `web serve` as nonexistent
  and PyPI as unreserved. Every row is re-verified against `v0.4.1` and now cites
  `module::function` rather than line numbers, which had drifted.
- §18's Definition of Done for `1.0.0` is checked off against evidence rather than
  memory. With the documentation debt above closed, **all nine items are done** and
  nothing in that section blocks `1.0.0`.

## [0.4.1] — 2026-08-11

**Security release. Upgrade if you rely on euvd-watch as a CI gate or as your CRA
Article 14 trigger.** Every earlier release (`0.3.0`, `0.3.1`, `0.4.0`) could report *no
findings, with a success exit code*, for a component affected by an actively exploited
vulnerability — and in one case publish a high-confidence OpenVEX `not_affected` claiming
the opposite. A previously clean run is not evidence of a clean result. After upgrading,
re-run `match` against your current SBOMs, re-check any OpenVEX documents you distributed,
and re-run `cra check`: a trigger that never fired may fire now.

### Fixed
- **Two false negatives in the matcher, both of which hid an actively exploited
  vulnerability completely** (found in the pre-1.0 audit; each reproduced end to end
  before its fix, each pinned by new truth-table rows):
  - **An inverted version range is no longer proof of safety.** A distro-style exact
    version is also a valid hyphen-range shape, and the range parser claimed it
    unconditionally: `2.4.0-2` became low=`2.4.0`, high=`2`. That range contains nothing,
    so *every* version read as "provably outside" with a trusted pep440 comparison. A
    component sitting on exactly the affected, actively exploited version produced **zero
    findings** and a **high-confidence `not_affected`** for the VEX engine to auto-draft —
    a silent suppression plus a missed CRA Article 14 trigger. Inverted ranges are now
    never trusted: the hyphen form is re-read as the exact version it is (equal ⇒
    affected), and inverted compound/comma ranges are treated as unevaluable, which keeps
    the finding alive at `medium` for a human.
  - **A purl namespace no longer vetoes a product-name match.** The namespace is a weak
    vendor hint (reverse-DNS or a scope), but it could contradict EUVD's prose vendor text
    and erase the finding: `pkg:maven/org.apache.logging.log4j/log4j-core` reported
    nothing where the identical component without a namespace reported normally, making
    every namespaced ecosystem (maven, scoped npm, golang, composer) systematically
    blinder. Veto power now belongs only to the CPE and the curated alias table; an
    authoritative vendor contradiction still vetoes.
- **An unreadable EUVD search page is treated as missing data, not "no results".** The
  paginator used to stop on any unexpected response and return what it had, so a beta-API
  envelope change produced a confident `0 findings` and **exit 0** — a green CI gate built
  on no vulnerability data at all, including for a body that said `"total": 1742`. Any page
  that is not an object with an `items` list now raises, which the CLI already surfaces as
  exit `2` and *"Refusing to report 'no findings' on missing data."* The legitimately empty
  `{"items": [], "total": 0}` is unchanged.
- **Webhook URLs are redacted in logs.** Slack/Discord/Teams put the secret in the URL
  path, and a failed delivery printed it in full across six retry/error log lines — into
  CI output that is public for most open-source projects. Webhook lines now read
  `https://hooks.slack.com/<redacted>`; EUVD paths stay readable for debugging.
- `examples/demo.sh` and `scripts/run_a11y_check.sh` tolerated only exit `1` from
  `cra check`, so 0.4.0's new exit `3` would abort both CI jobs under `set -e`. Both ran in
  exactly the enrichment-less conditions that produce `3`, and passed only because the
  seeded demo record fires the exploited signal first.

### Changed
- `ci.yml` now declares `permissions: contents: read` like every other workflow, instead of
  inheriting the repository default into a workflow that runs on fork pull requests.

### Documentation
- `docs/storage.md` documents what a **downgrade** to `0.3.x` actually does: it reports
  "0 open event(s) of 0 total" and exits `0` against a migrated state directory, because it
  cannot see `euvd-watch.sqlite` — with the stop-writers/rename-back procedure and the
  warning that the restored originals are only a point-in-time snapshot.
- The README shows that `--output` is a **global** option (`euvd-watch --output json match
  …`, not `… match --output json`, which exits `2`), and states the stdout-purity
  guarantee. `web hash-password`'s docstring no longer claims the plaintext "never lands in
  shell history" when `--password` is passed.

## [0.4.0] — 2026-08-11

Milestone **M6** in full: all operational state consolidated into one migrating SQLite
database, a self-hostable web dashboard (beta) behind the `[web]` extra, an accessibility
gate (WCAG 2.1 AA) in CI, and a tested Docker Compose + Caddy deployment guide. Plus a
round of untrusted-input hardening from a dedicated security audit, and a CRA correctness
fix: an unavailable trigger signal no longer reads as an all-clear.

### Added
- **Deployment guide + deployable image (milestone M6, Step 6.4)**: `docs/deploy.md` with
  a tested Docker Compose stack (`examples/deploy/`) — a `watch` service, the dashboard
  `web` service, and Caddy terminating TLS — plus backup and upgrade procedures. Exercised
  end-to-end (cold-start to a running, authenticated dashboard over TLS in well under the
  15-minute target). Testing it caught and fixed three real deployment blockers: the
  Docker image now installs the `[web]` extra (so `web serve` runs out of the box; still
  < 200 MB), the image pre-creates its cache/state dirs owned by the non-root user (so a
  persisted named volume is writable rather than root-owned), and the documented local-TLS
  Caddy block now names a host (a bare `:443 { tls internal }` cannot provision a cert).
  Two new image-CI assertions guard the `[web]` extra and non-root volume writability.
- **`cra check` now distinguishes "signal unavailable" from "signal absent" (indeterminate
  state + exit code 3).** For a CRA gate, a required trigger signal whose data source was
  unavailable (KEV/EPSS feed down, or `--no-enrich`) must not read as a confirmed all-clear
  — that is a false-negative-by-omission. The trigger engine now evaluates each signal as
  fired / confirmed-absent / **unknown**; a finding that does not fire but has an
  unevaluable enabled signal is **indeterminate**. `cra check` warns loudly on stderr,
  reports `indeterminate`/`unavailable_signals` under `--output json`, and **exits `3`**
  instead of `0` (a confirmed new event still takes precedence with exit `1`). Applies to
  both trigger modes; with `require_all: true`, an unknown required signal blocks the
  conjunction as indeterminate rather than as a silent non-fire. See `docs/cra.md`.
- **Consolidated state DB (milestone M6, Step 6.1)**: all operational state now lives in
  one WAL-mode SQLite file, `state_dir/euvd-watch.sqlite` — CRA trigger events and watch
  snapshots included. Schema changes ship as numbered SQL migrations applied
  transparently by every state-touching command; the new `euvd-watch db migrate` runs
  them explicitly and reports what happened. State from the pre-0.4 layout
  (`cra-events.sqlite`, `state_dir/watch/*.json`) is imported automatically; originals
  are renamed `.migrated-<timestamp>`, never deleted. The audit log and
  `vex-decisions.yaml` deliberately stay files (tamper-evidence / human input of
  record). See `docs/storage.md`.
- **Web dashboard, beta (milestone M6, Step 6.2)**: `euvd-watch web serve <sbom>`
  serves a read-mostly dashboard over the state store — Overview, Findings
  (filterable/paginated), Finding detail (verbatim match explanation, EUVD data, a VEX
  decision-shortcut snippet), CRA events with deadline countdowns, and a hash-chain
  audit-log viewer with a re-verify control. HTTP Basic auth on every route
  (`euvd-watch web hash-password` sets the credential; PBKDF2-HMAC-SHA256, 600k
  iterations); the one write action ("Mark stage complete") records the same audit
  trail as `cra mark`. Server-rendered Jinja2, no SPA, no inline styles/handlers.
  Requires the new `[web]` extra (`pip install 'euvd-watch[web]'`); the core CLI stays
  dependency-lean. Design spec: `docs/dashboard-design.md`; usage: `docs/web.md`.
  Accessibility verification (Step 6.3) and a deployment guide (Step 6.4) are still
  open before `1.1` GA.
- The CLI's human-readable tables (`scan`, `match`) now cap at 50 rows with an
  "… and N more" footer instead of printing unbounded output (M0/M1 review 3.7);
  `--output json` is unaffected.
- **Accessibility gate (milestone M6, Step 6.3)**: `scripts/run_a11y_check.sh` runs
  axe-core (via Puppeteer, `scripts/a11y_check.mjs`) against every dashboard page
  using the same offline demo scenario as `examples/demo.sh`; new CI job `a11y` gates
  on zero serious/critical violations (PRs touching the dashboard + nightly). Fixed
  two real WCAG defects the gate caught: a disclaimer link distinguishable only by
  color, and three scrollable `<pre>` blocks unreachable by keyboard. Manual
  keyboard-pass checklist and the automated gate's design rationale (including two
  documented, investigated axe "incomplete"/indeterminate results that are not real
  violations) are in the new `docs/accessibility.md`.

### Changed
- **Breaking (CLI contract): `cra check` has a new exit code `3`.** Previously every
  non-firing check exited `0`; a check whose required trigger signals could not all be
  evaluated now exits `3` (indeterminate). Scripts that treated any non-`1` exit as an
  all-clear must be updated to fail closed on `3`. Rationale and the full state machine
  are in `docs/cra.md`; the `0` (clear) and `1` (new event) meanings are unchanged.
- **Breaking (on-disk layout): operational state moved into `state_dir/euvd-watch.sqlite`.**
  `cra-events.sqlite` and `state_dir/watch/*.json` are imported automatically on first
  run of any state-touching command and the originals renamed `.migrated-<timestamp>`
  (never deleted), so no action is required — but anything reading those paths directly,
  or backing them up individually, must follow `docs/storage.md` instead. Downgrading to
  `0.3.x` after the migration requires restoring the renamed files.

### Fixed
- **Security/robustness (untrusted-input hardening, from a dedicated audit).** Four
  ways a crafted SBOM or EUVD response could crash or hang the tool are closed; each
  was reproduced end-to-end before its fix:
  - **Version-comparator ReDoS**: a crafted EUVD version-range string caused quadratic
    backtracking in the internal "looks like a version?" regex (40 KB hung ~6 s). The
    redundant regex group was removed (proven to accept an identical language); now
    linear.
  - **Version-comparator crash on oversized numeric segments**: a component version
    with a >4300-digit numeric run (e.g. `"9"*5000`) raised an uncaught `ValueError`
    (Python 3.11's int-conversion guard), aborting the *entire* `match` run and
    suppressing findings for every other component. All numeric conversions in the
    comparator are now guarded; such a run is treated as a low-trust opaque token.
  - **`RecursionError` on pathologically nested JSON**, in both the SBOM loader and the
    `--findings` artifact loader (`json.loads` is itself recursive). Both now fail as a
    clean parse error with exit code `2` instead of a traceback with exit `1`.
- The Overview page's "recent findings" row rendered with a **solid filled severity
  background** instead of a thin left-border stripe — a CSS class name
  (`s-crit`/`s-warn`/etc.) was shared between two different components (the findings
  table's stripe cell and the row-link) without being scoped, so the stripe cell's
  `background` rule leaked onto the row. Found by the Step 6.3 accessibility gate's
  screenshot, not by code review.

## [0.3.1] — 2026-08-08

First PyPI release: `pip install euvd-watch` now works. Functionally identical to
`0.3.0` plus the release automation itself and the security policy.

### Added
- **Release automation (milestone M5, Step 5.1)**: pushing a `vX.Y.Z` tag now builds
  sdist+wheel, publishes to PyPI via trusted publishing (OIDC, no tokens), verifies a
  clean-venv `pip install euvd-watch==X.Y.Z` + `euvd-watch version`, and creates a GitHub
  release whose notes are this file's section for that version
  (`scripts/extract_changelog.py`, unit-tested). `vX.Y.ZrcN` pre-release tags exercise the
  same path against TestPyPI. Process and version/deprecation policy in `docs/release.md`.
- `SECURITY.md`: private disclosure channel (GitHub private vulnerability reporting, email
  fallback), response targets, and explicit scope notes (audit-log threat model, tier-2
  data sharing).

## [0.3.0] — 2026-07-13

Everything below ships as a **git tag + GHCR container image** (`0.3.0`); PyPI
publication still waits on the `euvd-watch` name reservation (Step 5.1). Covers
milestones M4 (CRA workflow), M5 minus release automation (watch mode, Docker image,
GitHub Action, GitLab template), and the pre-M6 quality sweep.

### Fixed
- **Comma version ranges** (`"0.40.0, < 0.46.2"`, the introduced-at/fixed-before shape
  seen live on EUVD-2026-4133) are now parsed: in-range versions get the confidence the
  evidence supports instead of an AMBIGUOUS `medium` cap, and versions *below* the
  introduced-at bound no longer produce a false-positive finding (M2 review 3.1).
- **`EuvdClient` deduplicates paginated search results** by EUVD id (first occurrence
  wins) — a catalog shift between page fetches can no longer surface the same record
  twice (M2 review 3.2).
- **`data_freshness` is now the honest worst-case bound**: the oldest EUVD response
  actually served during the run, instead of the newest row anywhere in the shared cache
  (which EPSS/KEV entries and unrelated later runs inflated) (M2 review 2.2).

### Added
- **CI hygiene & doc-drift jobs (test-plan X.1–X.3 + M2 review 2.3)**: every `src/**`
  file carries an `SPDX-License-Identifier: EUPL-1.2` header, enforced by a test;
  `security` CI job (pip-audit); `self-sbom` CI job (Syft generates this repo's SBOM,
  euvd-watch matches it offline, gated `--fail-on exploited`); `examples/demo.sh` — the
  full pipeline scan→match→vex→cra→watch, offline, executed on every PR; the README
  Quickstart block is now executed by `tests/e2e/test_readme_quickstart.py`; nightly
  `live.yml` workflow runs the `live`-marked tests against the real EUVD/EPSS/KEV and
  opens a drift issue on failure (never blocks PRs).
- **Docker image (milestone M5, Step 5.2)**: `docker/Dockerfile` — multi-stage build on
  `python:3.12-slim`, non-root user (uid 1000), `euvd-watch` entrypoint, ~152 MB.
  `.github/workflows/image.yml` re-runs the four image assertions on PRs (version exit 0,
  scan of a mounted fixture, non-root, size < 200 MB) and publishes to GHCR on pushes to
  `main` (`:edge`) and on `vX.Y.Z` tags (`:X.Y.Z` + `:latest`). See `docs/integrations.md`.
- **GitHub Action (milestone M5, Step 5.3)**: composite `action.yml` at the repo root —
  inputs `sbom-path`/`fail-on`/`min-confidence` (plus `output-file`, `artifact-name`,
  `extra-args`, `version`, `python-version`), outputs `exit-code`/`findings-file`; the
  findings JSON is uploaded as a workflow artifact even when the gate fails. Dogfooded by
  this repo's CI over a fail-on matrix against a **network-free** cache primed from a
  committed, clearly-seeded fixture (`scripts/prime_cache.py`).
- **GitLab CI include template (milestone M5, Step 5.3)**:
  `templates/euvd-watch.gitlab-ci.yml`, configured via `EUVDWATCH_*` variables
  (deliberately not `EUVD_WATCH_*`, which the CLI reserves for config overrides and
  where unknown keys are rejected). Template, workflows, and `action.yml` are all
  schema-linted offline in `tests/integration/test_ci_templates.py`.
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
