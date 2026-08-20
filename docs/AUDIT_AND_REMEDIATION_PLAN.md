# euvd-watch — Audit & Remediation Plan

> Full-repository audit performed **2026-07-10** against commit `e80e49e` plus the
> uncommitted M4 work-in-progress (`src/euvd_watch/cra/`, `tests/unit/test_cra_*.py`,
> `tests/fixtures/cra/`, modified `config.py` / `examples/config/euvd-watch.yaml`).
> Every claim below is either (a) verified by running the code/tests, (b) verified by
> reading a cited file, or (c) explicitly marked `NECESITĂ CLARIFICARE`.
>
> Verification snapshot on this machine (Python 3.11.15, project venv):
> `pytest` → **355 passed, 3 deselected (live), coverage 95.74%** (gate ≥ 85%);
> `mypy src` (strict) → **clean**; `ruff check .` → **5 errors, all in the uncommitted
> M4 files** (line length ×4, one unused import/variable — normal mid-flight state).

> **Status update — 2026-07-10, post-approval.** The owner approved this plan and
> answered all seven open questions (§17). Executed the same day: **R1** in full
> (TECH-001 `bc52538`, TECH-003 `4a79ace`, REQ-VEX-004 `705a1db`, justification decision
> `6faa494`, DOC-001 + RO README + CHANGELOG `fe9c1d1`) and **M4-completion** in full
> (`3c32eaa`…: Steps 4.1–4.5 with SEC-001/002/003, TECH-002, SEC-004 fixed before/at
> first commit; scenario S3, INV-6/7, `docs/cra.md` shipped — closing DOC-002).
> Still open: OPS-001 (owner-blocked: no GitHub org decided, PyPI name unreserved), the
> M4 post-milestone review gate, then M5. Sections below are kept as written at audit
> time; this note supersedes their status claims where they differ.

---

## 1. Executive summary

1. **The project is a mid-build, not a finished product.** Milestones M0–M3 (scaffolding,
   SBOM ingestion, EUVD matching, OpenVEX generation) are implemented, tested, and each
   passed a documented post-milestone review with empirically-reproduced findings
   (`plans/feedback_m0_m1.md`, `feedback_m2.md`, `feedback_m3.md` — all findings fixed).
   M4 (CRA workflow) is roughly 40% done and uncommitted; M5 (integrations/watch) and
   M6 (dashboard) do not exist.
2. **Implemented code quality is genuinely high.** Strict typing, frozen pydantic models,
   deterministic outputs, committed API fixtures, truth-table regression suites, an
   executable invariant suite, and honest confidence capping are all real, not aspirational.
3. **The main gap is promise vs. delivery in the README**, which describes the 1.0 target
   state (`cra status/draft/mark/verify-log`, `watch`, `web serve`, GitHub Action, GitLab
   template, `pip install euvd-watch`, bilingual docs) without per-command status. Several
   linked documents (`ARCHITECTURE.md`, `docs/cra.md`, `docs/deploy.md`, `CONTRIBUTING.md`)
   do not exist yet.
4. **Three real defects were found and empirically reproduced** in this audit (see §13):
   unbounded config values that can silently deaden the CRA trigger (`epss_threshold=50`
   accepted), CRA event-store self-heal that deletes the legal awareness record, and
   purl-derived match candidates polluted by qualifiers on versionless purls. None affect
   the committed M0–M3 surface's test-verified behavior; two live in the uncommitted M4 code.
5. **Operational debts are the biggest 1.0 risks:** no git remote (CI has never actually
   executed), PyPI name still unreserved (squatting risk flagged since the M1 review),
   and the tamper-evident audit log — the project's headline compliance feature — not yet
   implemented.

## 2. What the application actually does today

Verified by running the CLI and the test suite:

- `euvd-watch version` — prints version, exit 0.
- `euvd-watch scan <sbom>` — parses CycloneDX 1.4–1.6 **JSON** and SPDX 2.3 **JSON**,
  normalizes identifiers (canonical purls, decoded CPE 2.3 parts, synthesized low-confidence
  purls flagged `synthesized=True`), dedupes deterministically, renders table/JSON.
  (`src/euvd_watch/sbom/*`, `cli.py:126-167`)
- `euvd-watch match <sbom>` — two-tier EUVD query (full exploited catalog + per-candidate
  product search), matching with `high/medium/low` confidence and mandatory explanations,
  EPSS/KEV enrichment with graceful degradation, `--exploited-only`, `--min-confidence`,
  `--no-enrich`, `--fail-on none|any|exploited`, `--save-findings` (versioned artifact,
  `schema_version: 1`). Exit codes 0/1/2 as documented. (`cli.py:271-351`, `euvd/*`,
  `enrich/*`)
- `euvd-watch vex generate <sbom>` — conservative OpenVEX: auto-`not_affected` only for
  provably-outside-range with strong identity and non-synthesized identifier; everything
  else `under_investigation`; human `vex-decisions.yaml` overrides with conflict warnings
  and stale-entry reporting; deterministic serialization validated against the vendored
  OpenVEX 0.2.0 schema and round-tripped once through `vexctl` (recorded in
  `docs/matching.md:102-116`). `vex init-decisions` scaffolds the decisions file.
- `euvd-watch watch`, `euvd-watch cra check` — **stubs, exit 2** (`cli.py:354-358, 577-581`).
  `cra status/draft/mark/verify-log`, `web serve` — **do not exist at all** (not even stubs).
- Uncommitted M4 modules (trigger policy engine, event state store, deadline clock) are
  implemented and unit-tested but **wired to nothing** — no CLI command uses them yet.

## 3. Architecture & data-flow map

```
                       src/euvd_watch/
  cli.py ── Typer app; the only orchestration layer; exit-code boundary decorator
  config.py ── Settings (pydantic, extra="forbid"); defaults → YAML → EUVD_WATCH_* env
  log.py ── stderr-only logging bootstrap (--verbose); stdout purity contract
  http.py ── the ONLY httpx user (invariant-tested); retry+backoff+jitter, SQLite TTL
             cache (~/.cache/euvd-watch/euvd-cache.sqlite), ETag-ready, User-Agent
  models.py ── Component / Inventory (frozen, schema_version=1, dedupe_key)
  sbom/ ── detect.py (format sniff) → cyclonedx.py | spdx.py → normalize.py (purl
           canonicalization, CPE 2.3 decode, purl synthesis, version cleanup) → dedupe
  euvd/ ── client.py (search/enisaid/lastvulnerabilities; pagination, page-cap),
           models.py (tolerant parse; id-less records skipped loudly; EPSS 0-100→0-1),
           match.py (candidates → strategies → Evaluation{MATCH|NOT_AFFECTED}),
           versions.py (PEP440 → semver → tokenwise; scheme reported for caps),
           aliases.yaml (curated purl→vendor/product table)
  enrich/ ── epss.py (FIRST.org batch), kev.py (CISA KEV catalog); degrade-to-None
  vex/ ── model.py (OpenVEX 0.2.0), rules.py (registry; disagreement→under_investigation),
          decisions.py (vex-decisions.yaml), merge.py (human overrides + conflicts/stale),
          build.py, write.py (sorted, byte-stable)
  cra/ ── [UNCOMMITTED] trigger.py (policy engine), state.py (SQLite event store,
          first_seen immutable), clock.py (config-driven stages, 5-state machine)
          [MISSING] report.py (draft renderer), audit.py (hash-chained log)
  integrations/ (M5), web/ (M6) ── do not exist
```

Data flow (target vs. today): `SBOM → parse → normalize → match EUVD → enrich EPSS/KEV →
findings → VEX` is fully live. `findings → CRA trigger → event store → clock` exists as
tested library code with no entry point. `→ draft → audit log → watch → dashboard` does
not exist.

**Persistence:** two SQLite files by design — HTTP response cache (TTL, purgeable,
self-healing: `http.py:36-114`) and the CRA event store (no TTL, "legal record":
`cra/state.py:51-158`). No migrations framework yet (planned Step 6.1).

**Config precedence** (verified in `tests/unit/test_config.py`): defaults → YAML
(`--config` or `./euvd-watch.yaml`) → `EUVD_WATCH_*` env (nested via `__`). Unknown keys
rejected (`extra="forbid"`), invalid values exit 2 naming the field.

## 4. README ↔ implementation traceability matrix

Source of truth: `README.md` (moved to the repo root 2026-08-19). Its Commands table
carries an explicit
✅ / 🧪 beta / 🚧 planned status column, so the "unbuilt features presented without
status" problem this section originally recorded is closed.

> **Refreshed 2026-08-18** against `v0.4.1` (M0–M6 shipped). The original table was a
> 2026-07-10 snapshot taken when M4–M6 did not exist; every row below was re-verified
> against the code, the test suite (601 passing, 94.54 % coverage) and the published
> artifacts rather than carried forward. Evidence now cites `module::function` instead
> of line numbers, which drifted. §18's DoD item requires every row to read
> IMPLEMENTAT ȘI VERIFICAT or be removed — **three rows still do not**, and they are the
> remaining 1.0 blockers: the docs-links row, the EN+RO row, and the `docs/vex.md` gap
> noted inside the `vex generate` row.

| Funcționalitate promisă | Dovezi în cod | Status | Probleme/gap-uri | Teste existente | Documentație necesară |
|---|---|---|---|---|---|
| `scan` CycloneDX/SPDX → inventory | `sbom/*`, `cli.py::scan` | IMPLEMENTAT ȘI VERIFICAT | JSON-only — the README now says so explicitly | unit+integration+e2e+golden, M1 invariants | docs/matching.md ✔ |
| `match` + confidence + EPSS/KEV, all flags | `euvd/*`, `enrich/*`, `cli.py::match` | IMPLEMENTAT ȘI VERIFICAT | TECH-001 purl-qualifier defect closed (`bc52538`) | 38-row truth table, fail-on matrix, M2 invariants | docs/matching.md ✔ |
| `vex generate` conservative + decisions merge | `vex/*`, `cli.py::vex_generate`, `cli.py::vex_init_decisions` | IMPLEMENTAT ȘI VERIFICAT | **`docs/vex.md` still unwritten** — VEX behaviour is documented only in the README and docs/matching.md | schema+golden+adversarial+merge matrix, M3 invariants | **docs/vex.md — remaining gap** |
| `--output json\|table`, exit codes everywhere | `cli.py::main` (global `--output`), `cli.py::cli_command` | IMPLEMENTAT ȘI VERIFICAT | contract is `0`/`1`/`2` plus `cra check`'s `3` (indeterminate, 0.4.0); `--output` is global — the postfix form exits `2`, README corrected in `e73225a` | e2e exit-code tests per command | docs/cra.md exit-code table ✔ |
| `cra check` (trigger + events) | `cra/trigger.py`, `cra/state.py`, `web/store.py`, `cli.py::cra_check` | IMPLEMENTAT ȘI VERIFICAT | three-valued since 0.4.0: an unavailable KEV/EPSS source is INDETERMINATE, never a clean result | 15-row trigger truth table + `evaluate_run` unit tests | docs/cra.md ✔ |
| `cra status` / `cra draft` / `cra mark` | `cra/clock.py`, `cra/report.py`, `cra/actions.py` | IMPLEMENTAT ȘI VERIFICAT | draft is deliberately incomplete: `TODO-HUMAN` markers where only a human can answer | clock transition matrix, golden draft, e2e | docs/cra.md ✔ |
| `cra verify-log` + tamper-evident audit log | `cra/audit.py`, `cli.py::cra_verify_log` | IMPLEMENTAT ȘI VERIFICAT | tamper-*evident*, not tamper-proof — limits documented, not defects | INV-7 tamper matrix, chain + JSON-line tests | docs/cra.md §threat model ✔ |
| `watch` (diff, notify new/changed, webhook) | `watch/*`, `cli.py::watch` | IMPLEMENTAT ȘI VERIFICAT | webhook URLs redacted in logs since 0.4.1 (`e782fee`) — the URL is the credential | differ/sink units, e2e, offline dead-proxy run | docs/watch.md ✔ |
| `web serve` WCAG dashboard | `web/*` (`app.py`, `dashboard.py`, `store.py`, `auth.py`) | IMPLEMENTAT — 🧪 BETA, GA at `1.1` | no CSRF token on the single write form (documented limitation, accepted threat model) | e2e dashboard tests + axe-core a11y CI gate on 7 pages | docs/web.md, docs/deploy.md, docs/accessibility.md ✔ |
| `pip install euvd-watch` | PyPI `0.3.1`, `0.4.0`, `0.4.1` | IMPLEMENTAT ȘI VERIFICAT | PyPI name reserved 2026-07-14; squatting risk closed | release workflow's `verify-pypi` clean-venv install | docs/release.md ✔ |
| GitHub Action | `action.yml` at the repo root; `uses: caisarus/euvd@vX.Y.Z` | IMPLEMENTAT ȘI VERIFICAT | README pin bumped to `@v0.4.1` in the 2026-08-19 sweep; `docs/integrations.md` still shows `@v0.3.1` in its worked example, which is harmless (the tag pins only the action YAML — `version: ""` installs latest from PyPI) | ci.yml `dogfood` job (network-free) + 5.3 fresh-repo acceptance | docs/integrations.md ✔ |
| GitLab CI user template | `templates/euvd-watch.gitlab-ci.yml` | IMPLEMENTAT ȘI VERIFICAT | raw.githubusercontent include verified reachable anonymously | manual fresh-repo acceptance | docs/integrations.md ✔ |
| Deterministic byte-identical outputs | `vex/write.py`, `models.py`, `--timestamp` pin | IMPLEMENTAT ȘI VERIFICAT | TECH-003 closed (`4a79ace`) — `match --output json` pins `generated_at` | INV-9 double-run diff over the demo pipeline | docs ✔ |
| Human-in-the-loop, never submits | POST exists but is confined: `http.py::post_json` ← only `watch/sinks.py::WebhookSink`; `cra/*` contains no URL at all | IMPLEMENTAT ȘI VERIFICAT | the row's old evidence ("no POST anywhere; ApiClient is GET-only") went stale when M5 added webhooks — the guarantee is now structural rather than incidental | **INV-8 AST tests — `tests/invariants/test_m5_invariants.py` (5 tests, each mutation-verified to fail)** | keep prominent ✔ |
| Hash-chained auditability of every decision | explanation on every Finding/statement + `cra/audit.py` chain | IMPLEMENTAT ȘI VERIFICAT | — | INV-10 explanation assertion, INV-7 tamper matrix | docs/cra.md ✔ |
| Config file/env/flags | `config.py` | IMPLEMENTAT ȘI VERIFICAT | SEC-002 closed — every numeric bounded (`epss_threshold` 0–1, `cache_ttl_hours` ≥ 0, stage `hours` > 0); no `docs/configuration.md`, reference lives in the README | precedence matrix + out-of-bounds rejection tests | README §Configuration (a dedicated page is optional) |
| Docs links: ARCHITECTURE.md, GLOSSARY.md, CONTRIBUTING.md, README.simple.md | all four shipped at the repo root 2026-08-19, alongside `README.md`, `README.ro.md`, `GLOSSARY.ro.md` and the ten `docs/*.md` pages | IMPLEMENTAT ȘI VERIFICAT | the README lived at `readme/readme.md`, so GitHub served a 404 for the repo's front page and four of its links were dead; all four targets now exist at the root and **a link checker over all 22 markdown files reports 0 broken relative links** | link check + `tests/e2e/test_readme_quickstart.py` executes the quickstart | — |
| "Documentation provided in English and Romanian" | `README.ro.md` (2026-07-10) + `GLOSSARY.ro.md` (2026-08-19), cross-linked both ways | IMPLEMENTAT ȘI VERIFICAT | RO glossary covers all 43 terms of the EN one, one-to-one; `docs/*.md` remain English and are marked *(engleză)* in the RO README | n/a | — |
| EUPL-1.2 license | `LICENSE` + SPDX headers on every source | IMPLEMENTAT ȘI VERIFICAT | — | `tests/unit/test_spdx_headers.py` enforces the headers | — |

## 5. Feature inventory & status (by milestone)

- **M0 scaffolding** — done, committed (`19dcab8`). CI YAML exists for GitHub+GitLab, but:
  **no git remote configured** (`git remote -v` empty) → the pipelines have never executed
  on a hosted runner. Acceptance "green CI on main" is therefore NEVERIFICABIL until pushed.
- **M1 SBOM ingestion** — done (`b24fae2` + fixes `d32085f`). Golden files, parity test
  CDX↔SPDX, hypothesis idempotence, real Syft + GitHub-export fixtures.
- **M2 EUVD matching** — done (`5dd4a97` + fixes `041e346`). Live API surface verified and
  documented (`docs/euvd-api.md`), real captured fixtures, truth table, confidence-cap
  invariants, EUVD-down → exit 2 (never silent "no findings").
- **M3 OpenVEX** — done (`aee188a` + fixes `24a8929`). Vendored schema validation,
  `vexctl` round-trip verified, adversarial rule tests, decisions merge matrix.
- **M4 CRA** — in flight, uncommitted. Done: Step 4.1 trigger engine + truth table
  (16 cases), 4.1 state store + idempotence tests, 4.2 clock + transition matrix.
  Missing: Step 4.3 draft renderer, 4.4 audit log, 4.5 `cra` command group,
  `tests/invariants/test_m4_invariants.py` (INV-6/INV-7), scenario S3, `docs/cra.md`
  (already referenced by `config.py:64` and `cra/clock.py:9` — dangling reference).
- **M5 integrations, M6 dashboard, X.1–X.3 polish** — not started (as planned).

## 6. Security audit

**No secrets found** in the repository (grep sweep over src/scripts/examples/CI configs:
only benign matches). No credentials, no internal endpoints; the three external endpoints
(EUVD, FIRST EPSS, CISA KEV) are public and configurable (`config.py:79-83`).

Verified positives:
- All YAML parsing uses `yaml.safe_load` (`config.py:113`, `vex/decisions.py:64`,
  `euvd/match.py:132`). All file I/O is explicit UTF-8 (hardening rule, spot-checked).
- No `eval`/`exec`/`subprocess`/pickle. JSON-only SBOM input (no XML/XXE surface).
- Input validation at ingest boundaries: nameless components/packages skipped with warning
  (`sbom/cyclonedx.py:94-97`, `sbom/spdx.py:91-94`); id-less EUVD records skipped with
  warning (`euvd/models.py:94-99`); malformed cache self-heals (`http.py:60-71`).
- Error-status HTTP bodies can never be mistaken for data (`http.py:173-177`).
- The tool performs **zero POST/PUT requests anywhere** — nothing can be "submitted"
  even by accident. (Will need the INV-8 guard test once M5 webhooks introduce POST.)

Findings (full details in §13):
- **SEC-001 (MAJOR, uncommitted M4):** `EventStore._connect` self-heal **unlinks the event
  database** on corruption (`cra/state.py:78-81`). For a store the module's own docstring
  calls "a legal record", destruction-on-corruption is the wrong trade — the file should be
  moved aside (`events.sqlite.corrupt-<ts>`), never deleted, and the run should continue on
  a fresh store while telling the user exactly where the quarantined file is.
- **SEC-002 (MAJOR, confirmed by repro):** config accepts semantically impossible values
  silently: `Settings(epss_threshold=50)` → accepted (a user confusing EUVD's 0–100 scale
  with FIRST's 0–1 — the exact confusion `euvd/models.py:111` normalizes away — would
  silently deaden the EPSS trigger signal forever); `cache_ttl_hours=-5` accepted (cache
  permanently stale → hammers the beta API); `CraStageConfig(hours=-4)` accepted; duplicate stage
  names accepted (collide in `Event.stage_completions`, `cra/state.py:44`). This config
  gates a legal reporting trigger; it must be bounds-checked like it's load-bearing.
- **SEC-003 (MEDIU, uncommitted M4):** `EventStore.get_or_create` **overwrites
  `fired_rules` and `policy_snapshot` on every re-run** (`cra/state.py:104-113`). The plan
  defines `policy_snapshot` as "the exact policy config that fired — needed for later
  defensibility" (`implementation_plan.md:324`). After a policy change, the stored snapshot
  no longer reflects what actually fired at `first_seen`; the original awareness basis is
  lost (the audit log would have captured it, but it doesn't exist yet). Freeze the
  first-fire snapshot; append later evaluations rather than overwrite (or defer the
  refresh until the audit log records the transition).
- **SEC-004 (MINOR, by design but undocumented):** tier-2 matching sends every derived
  product name of every SBOM component as query strings to the EUVD API
  (`cli.py:236-243`). For confidential inventories this is a data-sharing decision the user
  should get to make knowingly (`--exploited-only` already avoids it). Document it in
  security/privacy docs; consider a `tier2: false` config toggle.
- Webhooks/SSRF/redaction, dashboard auth/CSRF/XSS/headers/rate limiting: **not applicable
  yet** (M5/M6 code doesn't exist). Requirements for them are pre-registered in §12 so
  they're built in, not bolted on.

## 7. Matching / EPSS / KEV audit

Verified strengths (code + truth table + invariants all green):
- Candidate derivation CPE → alias table → purl → bare name, informed-vendor candidates
  decisive over vendor-less fallbacks (`euvd/match.py:342-364`) — prevents the
  "vendor-contradicted match resurrected by name fallback" false-positive class.
- Confidence semantics honest: hard caps for synthesized identifiers and tokenwise
  comparisons enforced at construction (`match.py:220-267`) and re-asserted in
  `tests/invariants/test_m2_invariants.py` over both the truth table and real fixture data.
- Version ranges: recognized shapes documented from live observation
  (`versions.py:81-88`, `docs/euvd-api.md:33-35`); everything unrecognized → AMBIGUOUS
  (capped), never guessed. deb-epoch trap documented and handled (raw version used:
  `match.py:214`).
- Every finding explains itself (INV-10 asserted); deterministic ordering by
  `(dedupe_key, euvd_id)`; EUVD-unreachable → loud exit 2 with explicit "refusing to
  report no findings" (`cli.py:307-313`) and `data_freshness` stamping from cache age.
- EPSS scale mismatch (EUVD 0–100 vs FIRST 0–1) found and normalized (`euvd/models.py:112`);
  KEV malformed feed → ApiError → degrade-to-None rather than false `in_kev=False`
  (`enrich/kev.py:14-30` — encodes feedback_m2 finding 2.1).
- Enrichment degradations tested per-API independently; `--no-enrich` performs zero calls.

Findings:
- **TECH-001 (MEDIU, confirmed by repro):** `derive_candidates` parses purls by string
  splitting (`match.py:159-164`) instead of `PackageURL.from_string`, violating the
  project's own hardening rule ("structured identifiers are constructed by their
  libraries", `implementation_plan.md:63-66`). Repro: versionless purl with qualifiers
  `pkg:deb/debian/curl?arch=amd64&distro=debian-12` yields candidate product
  `"curl?arch=amd64&distro=debian-12"` — which then also leaks into tier-2 search queries
  (`cli.py:236-243`). Versioned purls are unaffected (qualifiers sit after `@`), which is
  why the truth table never caught it. Fix: parse with `PackageURL`, add a truth-table row.
- **Distinguishing exploitation claims (correct today, keep it):** `exploited` =
  EUVD `exploitedSince` present; `in_kev` = CISA catalog membership; `epss_score` =
  probability, not evidence. The trigger records *which* rule fired (`fired_rules`).
  The future draft renderer (Step 4.3) must preserve this distinction verbatim and never
  collapse "EPSS over threshold" into "actively exploited" prose. — carried as REQ-CRA-004.
- `NECESITĂ CLARIFICARE`: alias table (`euvd/aliases.yaml`) governance — who curates it,
  what's the acceptance bar for a new entry? docs/matching.md says "only add entries after
  seeing the EUVD-side naming in real records" but there's no contributor-facing process.

## 8. OpenVEX & human decisions audit

Verified: document/statement models mirror the vendored 0.2.0 schema with validators
enforcing status-specific requirements (`vex/model.py:82-90`); serialization is sorted,
byte-stable, shuffle-proof (`vex/write.py`, hypothesis-tested); the single auto-rule
(`ProvablyOutsideRule`) fires only on matcher-certified `NOT_AFFECTED` evaluations;
rule disagreement → `under_investigation` + warning (`vex/rules.py:79-97`); adversarial
test set (looks-dismissible-but-unproven) all stay `under_investigation`; human decisions
override with loud conflict warnings and stale reporting (`vex/merge.py`); human-entered
purls normalized before matching (feedback_m3 P1.1 fixed); document `@id` derived from
inventory **and** statement content (P1.2 fixed); `--findings` replay is deliberately
auto-`not_affected`-blind (conservative; documented in `docs/matching.md:54-59` and
surfaced to the user at runtime, `cli.py:442-447`).

Gaps / observations:
- **Authorization/auditing of manual decisions is file-trust-based**: `author`/`date` are
  free-text fields, unverified (`vex/decisions.py:39-40`). Acceptable pre-1.0 with docs
  stating that access control = repository permissions on `vex-decisions.yaml`; the future
  audit log should record decision applications (REQ-VEX-003). No signing mechanism —
  don't promise one.
- Conflicts don't affect the exit code of `vex generate` (`cli.py:516-530` prints counts
  only). `NECESITĂ CLARIFICARE`: should `--fail-on-conflict` exist for CI? Proposed as
  REQ-VEX-004 (Should).
- Justification is fixed to `vulnerable_code_not_present` for the auto-rule. For a
  version-outside-range proof, `component_not_present` is arguably the truer OpenVEX
  justification. `NECESITĂ CLARIFICARE` — semantic choice worth an explicit doc note either
  way (docs/vex.md).

## 9. CRA Article 14 flow & 24-hour clock audit

*(Operational review only — no legal interpretation; the tool prepares and evidences,
humans validate and submit.)*

What exists (uncommitted, unit-tested, unwired):
- **Trigger** (`cra/trigger.py`): per-finding policy — `euvd_exploited` / `cisa_kev` /
  `epss_over_threshold`, each toggleable, disjunction or conjunction (`require_all`),
  with a confidence floor (default `medium`) so low-confidence matches can never start a
  legal clock. 16-case truth table green, including the subtle
  "conjunction only considers enabled signals" case.
- **State** (`cra/state.py`): `first_seen` set once, never reset (idempotence tested with
  time advancing); events keyed `(dedupe_key, euvd_id)`.
- **Clock** (`cra/clock.py`): stages are config, not code (`early_warning` 24 h,
  `vulnerability_notification` 72 h from `first_seen`; `final_report` 14 d anchored on
  `remediation_available` — a deliberate, documented 5th state `AWAITING_ANCHOR` for the
  not-yet-existing anchor). All UTC; transition matrix tested at exact boundaries.
  Config comments claim verification against Regulation (EU) 2024/2847 on 2026-07-10
  (`config.py:63-65`) — but the `docs/cra.md` that should carry the verbatim source
  **doesn't exist yet** (DOC-002). `NECESITĂ CLARIFICARE`: confirm the stage durations,
  anchors, and the intended recipient formulation once `docs/cra.md` is written, before
  `cra check` ships.
- **Clock-start semantics:** the 24 h clock anchors on `first_seen` = the moment
  *euvd-watch first persisted the trigger event*, which is the tool's proxy for
  "awareness". A human may have become aware earlier through other channels. This proxy
  must be documented prominently (docs/cra.md) — the tool cannot know true awareness.
- **Protection against retroactive modification of `first_seen`:** currently only
  code discipline (`get_or_create` never updates it) — the SQLite file is user-writable.
  Real protection arrives only with the hash-chained audit log (4.4) recording the trigger
  event at creation time; until then "tamper-evident" must not be claimed for events.

What's missing before M4 closes: draft renderer with `TODO-HUMAN` markers (4.3), audit
log (4.4), the whole `cra` command group (4.5), INV-6 invariant file, scenario S3, and
fixes for SEC-001/SEC-003 above. Nothing is submitted automatically anywhere — there is no
transport code to submit with, and none is planned (INV-8).

## 10. Audit log (hash chaining) audit

**Not implemented** (`cra/audit.py` absent). The plan's design (Step 4.4: JSONL,
`entry_hash = SHA-256(prev_hash + canonical_json(entry))`, fixed documented genesis seed,
`verify-log` naming the first broken link, tamper-matrix tests) is sound. Requirements to
lock in before it's built (→ REQ-AUDIT-001..004):

1. **Canonicalization must be specified exactly** (sorted keys, separators, UTF-8, no
   float ambiguity) and fixture-frozen — a canonicalization change invalidates every
   existing chain.
2. **Honest threat model in docs:** a local hash chain detects *casual/accidental*
   tampering and ordering violations; an attacker with write access to the file can
   recompute the entire chain. "Tamper-evident" holds only against actors who can't
   rewrite the whole file, or when the chain head is anchored externally (e.g. the head
   hash periodically committed to a ticket/git/notary — optional post-1.0 feature; do not
   claim more than what ships). System-clock trust is likewise a documented limitation.
3. **Append atomicity**: single-writer assumption must be stated; O_APPEND semantics and
   crash-mid-write behavior (truncated last line) must be tested and handled (a truncated
   tail should be reported distinctly from tampering).
4. Log entries must cover: trigger event creation (with the *original* policy snapshot —
   ties into SEC-003), clock-stage transitions observed, draft renders, human `cra mark`
   actions, and decision-file applications.

## 11. CLI, CI/CD, watch, dashboard audit

- **CLI contract:** `--output json|table` global; stdout purity for JSON (summaries →
  stderr, verified in e2e tests); exit codes 0/1/2 with a uniform `cli_command` boundary
  decorator so no traceback ever escapes (`cli.py:77-98`). README's "all commands support
  …" is true for built commands. Missing-subcommand UX: `euvd-watch cra status` today
  errors with Typer's "no such command" — acceptable mid-build, but add stubs (exit 2,
  "not implemented yet") for every README-promised command so the surface is stable
  (cheap; M0 Step 0.2 actually required this).
- **CI:** GitHub + GitLab configs mirror each other (lint/typecheck/test×2/build) but have
  **never run** (no remote). Coverage gate, markers, and `-m "not live"` default verified
  locally. Missing (all planned): `pip-audit`, SPDX-header check, scenario job, dogfood job.
- **watch:** not implemented. Differ semantics, webhook auth/signing/redaction/SSRF
  posture pre-registered as requirements (§12) so M5 doesn't improvise them.
- **Dashboard:** not implemented. Localhost-bind default, hashed basic auth, no-inline-JS,
  reverse-proxy guidance are already specified in the plan (Step 6.2) — keep them as
  acceptance criteria, and treat WCAG as "tested with axe/pa11y zero-serious" not as a
  self-declared adjective.
- **Live tests:** 3 deselected `live`-marked tests exist (`tests/live/test_live_smoke.py`);
  nightly wiring pending a remote.

## 12. Revised requirements (extract + gaps; MoSCoW for 1.0.0)

Functional (existing behavior → codified):

| ID | Requirement | MoSCoW | Status / acceptance evidence |
|---|---|---|---|
| REQ-SBOM-001 | Parse CycloneDX 1.4–1.6 JSON + SPDX 2.3 JSON into the normalized Inventory; malformed input → exit 2 with file/line context | Must | Done — golden + parity + error tests |
| REQ-SBOM-002 | Identifier normalization: canonical purls (library-built), decoded CPE parts, synthesized purls always flagged; idempotent | Must | Done — hypothesis + invariants |
| REQ-SBOM-003 | Document (and test) behavior for huge SBOMs: streaming not required, but a documented size expectation and a non-crash guarantee | Could | Open — no size cap today (whole-file `json.loads`) |
| REQ-MATCH-001 | Confidence semantics + hard caps (synthesized ≤ medium; tokenwise never high); every finding explains itself | Must | Done — invariants INV-1/2/10 |
| REQ-MATCH-002 | All purl handling via packageurl-python incl. candidate derivation (fixes TECH-001) | Must | Open — repro'd defect |
| REQ-MATCH-003 | EUVD-unreachable behavior: cache-fresh → proceed + `data_freshness`; no cache → exit 2; never silent clean exit | Must | Done — INV-4 e2e |
| REQ-ENRICH-001 | EPSS/KEV degrade to None on failure; malformed KEV never yields `in_kev=False`; `--no-enrich` = zero calls | Must | Done |
| REQ-VEX-001 | Auto-`not_affected` only from machine-checked proof (outside range, trustworthy scheme, non-synthesized, uncontradicted vendor); default `under_investigation`; `affected`/`fixed` human-only | Must | Done — adversarial + INV-3 |
| REQ-VEX-002 | Deterministic, schema-valid OpenVEX; `@id` changes iff content changes | Must | Done |
| REQ-VEX-003 | Decision applications recorded in the audit log once it exists | Should | Open (depends REQ-AUDIT-001) |
| REQ-VEX-004 | CI-facing conflict gate (`--fail-on-conflict` or exit-code policy) | Should | NECESITĂ CLARIFICARE (owner) |
| REQ-CRA-001 | Trigger policy configurable (signals, conjunction, confidence floor ≥ medium default); `first_seen` immutable across runs | Must | Engine done; CLI wiring open |
| REQ-CRA-002 | Config-driven deadline stages, UTC-only, rendered with explicit timezone; stage config validated (unique names, hours > 0) | Must | Clock done; validation open (SEC-002) |
| REQ-CRA-003 | Original `policy_snapshot`/`fired_rules` at first fire preserved immutably (SEC-003) | Must | Open |
| REQ-CRA-004 | Drafts/report language never upgrades a signal ("EPSS ≥ t") into a claim of active exploitation; `TODO-HUMAN` markers; nothing auto-submitted, ever | Must | Renderer not built; INV-8 pending |
| REQ-CRA-005 | Event store corruption quarantines (rename-aside), never deletes (SEC-001) | Must | Open |
| REQ-AUDIT-001..004 | Audit log per §10 (canonicalization spec, tamper matrix, truncation vs tamper distinction, documented threat-model limits) | Must | Not built |
| REQ-WATCH-001 | `watch`: two identical consecutive runs → zero notifications; webhook payload versioned (`schema_version`), redaction documented, sink allowlist (INV-8) | Must (for 1.0 as scoped) | Not built |
| REQ-WEB-001 | Dashboard: localhost default bind, auth required for writes, axe zero-serious gate | Must (for 1.0 as scoped) | Not built |

Non-functional:

| ID | Requirement | MoSCoW |
|---|---|---|
| REQ-NF-001 | Config bounds: `epss_threshold ∈ [0,1]`, `cache_ttl_hours ≥ 0`, stage `hours > 0`, unique stage names — violation exits 2 naming the field | Must |
| REQ-NF-002 | Determinism: scan/vex byte-identical; match byte-identical given a pinned timestamp mechanism | Must |
| REQ-NF-003 | Every machine-readable artifact carries `schema_version`; a version bump policy documented in release docs (already the pattern: `models.py:68`, `cli.py:213`) | Must |
| REQ-NF-004 | Python 3.11 + 3.12 supported and CI-tested (actually executed, not just configured) | Must |
| REQ-NF-005 | Coverage ≥ 85% overall; trust-critical five (`models`, `match`, `rules`, `trigger`, `audit`) ≥ 95% | Must |
| REQ-NF-006 | Data-retention/cache policy documented: what's stored where, TTLs, how to purge, what must never be purged (event store, audit log) | Must |
| REQ-NF-007 | Privacy: tier-2 query data-sharing documented; optional toggle | Should |
| REQ-NF-008 | Versioning policy: SemVer; breaking CLI/JSON changes only at majors post-1.0; deprecation window documented | Must |
| REQ-NF-009 | `pip-audit` + SPDX headers + SECURITY.md with disclosure contact | Must |
| REQ-NF-010 | Romanian documentation: deliver or remove the claim | Must (either way) — NECESITĂ CLARIFICARE |

## 13. Issues, ordered by severity

Every issue verified as described in §6–§11; repro commands were run in the project venv.

**OPS-001 · MAJOR · deployment** — No remote, CI never executed, PyPI name unreserved.
*Evidence:* `git remote -v` empty; `implementation_plan.md:461` ("still not reserved …
real squatting risk"). *Impact:* quality gates are local-only; the install command in the
README can be hijacked by a squatter. *Fix:* owner action — create the remote, push, watch
CI go green, register the PyPI name (even with a 0.0.1 placeholder). *Effort:* S.
*Acceptance:* CI green on hosted runner; `pip index` shows the name owned.

**SEC-001 · MAJOR · data integrity (uncommitted M4)** — Event-store self-heal deletes the
legal record. *Evidence:* `cra/state.py:78-81` (`unlink`). *Scenario:* disk corruption or
a half-written file at the wrong moment silently destroys every "when did we know"
record; the warning tells the user to "check for a backup" that the tool itself just
deleted. *Fix:* rename to `events.sqlite.corrupt-<UTC-ts>`, recreate fresh, log the
quarantine path; test it. *Effort:* S. *Acceptance:* corruption test shows old file
preserved on disk.

**SEC-002 · MAJOR · correctness/config (confirmed repro)** — Unbounded config values
silently deaden the CRA trigger. *Evidence:* `Settings(epss_threshold=50)`,
`cache_ttl_hours=-5`, `CraStageConfig(hours=-4)`, duplicate stage names — all accepted
(repro in audit session). *Fix:* pydantic `Field(ge=…, le=…, gt=0)` + a stage-list
validator (unique names, ≥ 1 stage); config tests per bound. *Effort:* S.
*Acceptance:* each bad value exits 2 naming the field.

**SEC-003 · MEDIU · CRA defensibility (uncommitted M4)** — `policy_snapshot`/`fired_rules`
overwritten on re-runs, losing the first-fire basis. *Evidence:* `cra/state.py:104-113`
vs. plan Step 4.1. *Fix:* freeze first-fire values; store latest evaluation separately
(e.g. `last_evaluation` field) or defer refresh until the audit log records transitions.
*Effort:* S–M. *Acceptance:* state test — policy change between runs leaves original
snapshot intact.

**TECH-001 · MEDIU · matching (confirmed repro)** — String-split purl parsing pollutes
candidates for versionless purls with qualifiers; violates own hardening rule.
*Evidence:* `match.py:159-164`; repro yields product `curl?arch=amd64&distro=debian-12`.
*Fix:* `PackageURL.from_string` in `derive_candidates` + `_versionless_purl`; add
truth-table row. *Effort:* S. *Acceptance:* new row green; alias lookup unaffected.

**DOC-001 · MEDIU · documentation** — README presents M4–M6 commands and integrations as
present-tense without per-command status; links to six nonexistent docs; claims bilingual
docs. *Fix:* status column in the Commands table (✅ / 🚧 planned), quickstart split into
"works today" vs "coming", fix/remove dead links, resolve the RO-docs claim (owner).
*Effort:* S. *Acceptance:* every README claim maps to a shipped artifact or a marked plan.

**DOC-002 · MEDIU · documentation (uncommitted M4)** — `docs/cra.md` referenced by shipped
comments (`config.py:64`, `cra/clock.py:9`) but absent; the CRA stage defaults' legal-text
verification exists only as a code comment. *Fix:* write `docs/cra.md` in the same commit
as the M4 code, carrying the verbatim Article 14 stage source, the awareness-proxy caveat
(§9), and the disclaimer language. *Effort:* M.

**TECH-002 · MEDIU · robustness (uncommitted M4)** — `EventStore.get/list_all/_save` have
no corruption handling (unlike `Cache`) and `Event.model_validate_json` on a
schema-evolved row raises `ValidationError` uncaught → traceback exit ≠ 2 once wired to
CLI. *Evidence:* `cra/state.py:83-154`. *Fix:* typed `StateError` at the module boundary +
event-schema-version field now (cheap before rows exist in the wild). *Effort:* M.

**TECH-003 · MINOR · determinism** — `match --output json` embeds `generated_at=now`
(`cli.py:214`): two identical runs differ on stdout; INV-9 promises byte-identical with a
pinned timestamp but match has no pin. *Fix:* honor a `--generated-at` (or reuse
`--timestamp`) override; document that the artifact's `generated_at` is semantically
required. *Effort:* S.

**SEC-004 · MINOR · privacy** — Tier-2 sends component-derived names to EUVD; undocumented
data-sharing. *Fix:* document + optional config toggle. *Effort:* S.

**TEST-001 · MINOR · testing (tracked, in-plan)** — M4 remainder: `test_m4_invariants.py`
(INV-6/7), scenario S3, e2e `cra` tests, tamper matrix; plus the 5 ruff errors in the WIP
files. All already mandated by the test plan — listed here so they can't slip.

**UX-001 · MINOR · UX (tracked since M0/M1 review 3.7)** — Unbounded CLI tables
(`cli.py:152-166, 248-268, 417-441`); deferred to M6 by prior decision; keep tracked.

**OPS-002 · MINOR · project hygiene** — Missing `CHANGELOG.md`, `CONTRIBUTING.md`,
`SECURITY.md`, `ROADMAP.md`, SPDX headers, `pip-audit` CI job (all planned X.1/X.3;
CHANGELOG should start **now** — reconstructing it at 1.0 loses information).

## 14. Remediation & delivery plan to 1.0.0

Ordering follows: data integrity → correctness → CRA → external contracts → CLI/CI →
dashboard → docs/release. No refactors beyond the listed fixes — the codebase doesn't
need them.

**R0 — Repository operations (owner + 1 session, S)**
Create remote, push, CI green; reserve PyPI name. Unblocks everything ops-related.
*DoD:* hosted CI green; name owned. *Rollback:* n/a.

**R1 — Hardening quick-wins on committed code (S, one commit-series)**
SEC-002 config bounds; TECH-001 purl-library candidates (+ truth-table row); TECH-003
timestamp pin; DOC-001 README status pass; start CHANGELOG.md.
*Commits:* `fix(config): bound trigger-gating numeric fields`, `fix(euvd): derive
candidates via packageurl`, `feat(cli): pin match artifact timestamp`, `docs(readme):
per-command status`. *DoD:* new tests green; README truthful.

**M4-completion — CRA workflow (M/L)**
Fix SEC-001, SEC-003, TECH-002 in the uncommitted code *before* first commit of `cra/`;
then Step 4.3 renderer (TODO-HUMAN markers, signal-vs-claim language per REQ-CRA-004),
Step 4.4 audit log (per §10 requirements incl. canonicalization spec + tamper matrix +
truncation distinction), Step 4.5 command group (+ stubs for anything still unshipped),
INV-6/7 invariants, scenario S3, `docs/cra.md` (DOC-002), ruff clean.
*Commit shape:* state+trigger+clock (with fixes) → renderer → audit log → CLI group →
scenario+docs. *Risks:* legal-stage wording — mitigate via docs disclaimer + config-not-code
stages (already done). *Rollback:* feature-gated by command absence; no migrations yet.
*DoD:* S3 scenario green in CI; `0.3.0` tagged (per plan's release cadence).

**M5 — Packaging, CI templates, watch (M/L, as planned Steps 5.1–5.4)**
Additions from this audit: INV-8 AST test lands *with* the first webhook code; webhook
payload `schema_version`; webhook redaction + HTTPS-only + no-redirect policy documented;
SEC-004 toggle. *DoD:* TestPyPI dry-run; two identical watch runs → zero notifications.

**M6 — Dashboard (L, as planned Steps 6.1–6.4) — moved to `1.1` (owner decision
2026-07-10):** `1.0.0` ships at CLI + CRA + watch/integrations scope; the dashboard is the
first post-1.0 milestone. Additions when it lands: auth threat-model in
`docs/security.md`; axe zero-serious CI gate is the WCAG claim's only basis; storage
consolidation includes a migration for the M4 event store (schema-version field from
TECH-002 pays off here). *DoD:* cold-start < 15 min from `docs/deploy.md` alone.

**X — Docs & release readiness (M)**
The §16 documentation set; `pip-audit` + SPDX headers + SECURITY.md + dogfood job;
README-quickstart runner test (test plan X.1); RO-docs decision executed. Then `1.0.0-rc`.

**Quick wins (already enumerated):** R0 + R1 entirely; `docs/cra.md` skeleton;
stub registration for promised commands.
**1.0 blockers (must not stay vague):** audit-log threat model wording; JSON
schema_version bump policy; retention policy; awareness-proxy caveat; PyPI name.
(Dashboard auth moved to the `1.1` gate with M6; the RO-docs decision is resolved —
deliver, English as reference.)
**Nice-to-have post-1.0:** external chain anchoring; OSV supplement source; deb/rpm
comparators; `--sarif` output; email/Slack sinks; decision signing.

**Risk register (top 5):**
| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| EUVD beta API breaking change | Medium | High | fixtures + nightly live-smoke + tolerant parsing (already in place); re-verify docs/euvd-api.md quarterly |
| PyPI name squatted before release | Medium | High | R0 immediately |
| CRA guidance shifts (stages/fields) | Medium | Medium | stages-as-config (done); docs/cra.md re-verification checklist per release |
| "Tamper-evident" overclaim reputational risk | Low | High | §10 threat-model language shipped with the feature, not after |
| Solo-maintainer bus factor | High | Medium | plans/ + docs/ already excellent; keep the review-gate discipline |

## 15. Test strategy (delta to the existing TEST_PLAN.md)

`plans/test_plan.md` remains authoritative and is largely being followed faithfully
(355 tests, 95.7% coverage, invariants live, truth tables in place, no-network verified).
Audit deltas to fold in:

1. New regression rows before fixes merge (per the plan's own rule): TECH-001 purl
   qualifiers row in `matching/cases.yaml`; SEC-002 bounds cases in config tests;
   SEC-001/003 state-store cases.
2. Audit log: add the **truncated-tail vs tampered** distinction and the
   **canonicalization-freeze fixture** to the 4.4 test list.
3. INV-6/7/8/9 still unimplemented — schedule: INV-6/7 with M4-completion, INV-8 with M5's
   first POST code, INV-9 needs TECH-003's pin first.
4. Coverage gate per trust-critical file (≥ 95% for `models/match/rules/trigger/audit`) is
   currently met for the first four (98–100%) — enforce it in CI config, not just by
   observation.
5. SBOM parser fuzzing (test plan mentions it as optional): a cheap hypothesis strategy
   over JSON-ish structures into `parse_any` asserting "SbomParseError or Inventory, never
   anything else" would close REQ-SBOM-003. Could-level.

## 16. Documentation plan

| Document | Action | Key content (from this audit) |
|---|---|---|
| `README.md` (from `readme/readme.md`) | update | per-command status, tested quickstart split, exit codes, limitations (JSON-only, EUVD beta), CRA disclaimer, no-auto-submit, dead links fixed |
| `README.simple.md` | light update | already excellent; add one line: the robot is still being built — the countdown-timer/diary parts are coming |
| `ARCHITECTURE.md` | create | §3 of this doc is the seed; module map, data flow, trust boundaries, threat-model pointer |
| `docs/matching.md` | keep | already strong; add TECH-001 note + alias governance |
| `docs/euvd-api.md` | keep | re-verify quarterly (nightly smoke feeds this) |
| `docs/vex.md` | create | auto vs human decisions, status semantics, `vex-decisions.yaml` schema, justification-choice rationale (§8), conflict/stale behavior |
| `docs/cra.md` | create (with M4) | operational flow, awareness-proxy caveat, stage config + verbatim legal source, TODO-HUMAN fields, explicit "preparation aid, not legal compliance engine" disclaimer |
| `docs/security.md` | create | threat model, audit-log limits (§10), tier-2 privacy note, secrets handling (none stored), disclosure policy → SECURITY.md |
| `docs/configuration.md` | create | every field + bounds + precedence + env mapping + examples (no secrets) |
| `docs/ci-cd.md` | create (M5) | Actions/GitLab usage, exit codes, fail-on, artifacts |
| `docs/deploy.md` | create (M6) | per plan Step 6.4 |
| `docs/testing.md` | create | distill test_plan.md for contributors; fixture governance; `--update-goldens` |
| `docs/release.md` + `CHANGELOG.md` | create now | SemVer policy, schema_version bump policy, release checklist |
| `CONTRIBUTING.md`, `SECURITY.md` | create (X) | includes VEX/security decision policy |
| `.env.example` | not needed | config is YAML-first; env vars documented in configuration.md instead (no secret-bearing env vars exist) |
| Romanian versions | NECESITĂ CLARIFICARE | owner decision: translate README + glossary (S effort, ongoing maintenance cost) or drop the claim |

## 17. Risks, limitations, assumptions, open questions

**Assumptions made by this audit:** the uncommitted M4 files represent current intent;
`plans/implementation_plan.md` remains the governing scope for 1.0; no other deployment
of this code exists (nothing to migrate).

**Inherent limitations to document, never to "fix":** EUVD text-based product naming caps
matching certainty (hence confidence tiers); `first_seen` is an awareness *proxy*; a local
hash chain cannot bind a fully-privileged attacker; EPSS is probabilistic, KEV is
membership, neither is proof of exploitation *of you*.

**Open questions — owner decisions received 2026-07-10:**
1. Romanian documentation — **deliver it.** `README.ro.md` shipped (English is the
   reference version on divergence); glossary translation follows in the docs milestone.
2. `vex generate` conflict exit-code policy — **yes**: `--fail-on-conflict` shipped
   (off by default; exit 1; document still written).
3. Auto-`not_affected` justification — **`component_not_present`** (the proof is that the
   component at an affected version is not present; no code inspected). Shipped.
4. Tier-2 privacy toggle — delegated; decision: **default ON** (`tier2_product_search:
   true`) — disabling by default would silently reduce coverage, the exact "dangerous
   silence" failure mode; documented data-sharing note + toggle land with M4/M5 config work.
5. 1.0 scope — **dashboard moves to `1.1`**; 1.0 = CLI + CRA + watch/integrations + docs.
6. Alias-table governance — delegated; decision: **evidence-based curation** — every new
   `aliases.yaml` entry must cite a real EUVD record id showing the vendor/product naming
   and add a matching truth-table row; goes into `CONTRIBUTING.md` and `docs/matching.md`.
7. GitHub org/name — **not yet decided**; placeholders remain, OPS-001 stays owner-blocked.
   *(Resolved 2026-07-13: `github.com/caisarus/euvd`, public since 2026-07-14.)*

**M6 sign-off — owner delegated all four decisions 2026-07-14; decisions taken:**

1. **Storage source of truth (Step 6.1):** the consolidated SQLite DB becomes the
   authoritative store for *operational* state — CRA trigger events and watch snapshots
   migrate in via `db migrate` (numbered SQL migrations; the `Event.schema_version` field
   from TECH-002 drives the event migration). Two explicit carve-outs stay files, by
   design: the **audit log** remains the append-only hash-chained file (the DB stores
   references only — moving it into a mutable DB would gut the tamper-evidence claim),
   and **`vex-decisions.yaml`** remains the human-edited input of record (the DB caches
   derived VEX statuses as a read model, rebuildable from the file). Rationale: a single
   DB gives the dashboard one coherent read model and WAL concurrency, while the two
   trust-critical artifacts keep their integrity properties.
2. **`[web]` extra:** yes — FastAPI/uvicorn/Jinja2 ship as `pip install euvd-watch[web]`;
   the core CLI stays dependency-lean. `web serve` without the extra exits 2 with an
   actionable install hint.
3. **SECURITY.md contact:** GitHub private vulnerability reporting on `caisarus/euvd` as
   the primary channel, owner email as fallback. Shipped 2026-07-14 (`SECURITY.md`).
4. **`1.1` target:** confirmed — M6 ships as `1.1`; `1.0.0` scope stays CLI + CRA +
   watch/integrations + docs, unblocked by dashboard work.

## 18. Definition of Done — 1.0.0

All of the plan's own DoD (`implementation_plan.md:465-469`) — **minus the dashboard
items (axe zero-critical, self-host walkthrough), which move to the `1.1` gate per the
owner's 2026-07-10 scope decision** — **plus**, from this audit:

> **Verified 2026-08-18 against `v0.4.1`** — every box below was checked against the
> code, a full suite run (606 passing, 94.54 % coverage, ruff + mypy strict clean) and
> the published artifacts, not against memory. **All nine items are now done**
> (2026-08-19, when the documentation debt closed), so nothing in this section blocks
> `1.0.0`.

- [x] Every README claim maps to a shipped, tested artifact (traceability matrix all
      IMPLEMENTAT ȘI VERIFICAT or removed). — closed 2026-08-19: `README.md`,
      `README.ro.md`, `README.simple.md`, `GLOSSARY.md`, `GLOSSARY.ro.md`,
      `ARCHITECTURE.md` and `CONTRIBUTING.md` all live at the repo root, every §4 row
      reads IMPLEMENTAT ȘI VERIFICAT, and a link check over all 22 markdown files reports
      **0 broken relative links**. `docs/vex.md` is still unwritten but is not a README
      claim — VEX behaviour is documented in the README, ARCHITECTURE.md and
      docs/matching.md; it stays on the backlog as a nice-to-have.
- [x] SEC-001..004, TECH-001..003, DOC-001..002 closed with regression tests. — DOC-001
      was the last one open; its acceptance clause "fix/remove dead links" is now met, so
      it closes with the item above.
- [x] Audit log shipped with the §10 threat-model documentation and tamper matrix green.
      — `cra/audit.py` + `cli.py::cra_verify_log`; threat model and the explicit limits of
      "tamper-evident" in `docs/cra.md`; INV-7 tamper matrix and JSON-line tests green.
- [x] Config rejects out-of-bounds trigger-gating values (REQ-NF-001). — SEC-002 closed:
      `epss_threshold` `ge=0.0, le=1.0`, `cache_ttl_hours` `ge=0`, CRA stage `hours` `gt=0`,
      `extra="forbid"`; rejection tests in `tests/unit/test_config.py`.
- [x] Hosted CI green including scenario, dogfood, pip-audit, SPDX-header jobs; coverage
      gate ≥ 85% overall and ≥ 95% on the trust-critical five. — `ci.yml` runs lint,
      typecheck, test (3.11 + 3.12), `dogfood`, `security` (pip-audit), `self-sbom`, `demo`,
      `build`; a11y and live-smoke run nightly, all green. Scenario and SPDX-header checks
      are pytest tests inside the `test` job (`tests/unit/test_spdx_headers.py`), not
      separate jobs — the intent is met, the job list in this line was aspirational.
      Coverage: **94.54 %** overall; trust-critical five all ≥ 95 % — `models.py`,
      `vex/rules.py`, `cra/trigger.py` at 100 %, `euvd/match.py` 99 %, `cra/audit.py` 95 %.
- [x] `pip install euvd-watch` from PyPI works; Docker image published; version/deprecation
      policy in docs/release.md. — PyPI `0.3.1`/`0.4.0`/`0.4.1`, each verified by the release
      workflow's clean-venv install; GHCR `:0.4.1` == `:latest`; policy in `docs/release.md`.
- [x] All ten invariants (INV-1..10) implemented and green. — INV-8 was the last one
      outstanding (deferred to "M5, when webhooks add POST"); shipped 2026-08-18 as
      `tests/invariants/test_m5_invariants.py`, five AST tests, each verified to fail
      against a deliberate mutation (new verb, direct client call, reach-around client
      call, a second `post_json` caller, a CRA endpoint constant, a configurable
      submission URL).
- [x] CRA documentation carries the explicit disclaimer: the tool assists preparation and
      record-keeping; legal validation and submission remain human responsibilities. —
      `docs/cra.md` opening note ("it does **not decide** whether something is legally
      reportable, and it **never submits**") plus the disclaimer on both CRA dashboard
      pages.
- [x] Romanian-docs decision executed: deliver — `README.ro.md` shipped 2026-07-10 (as
      `readme/readme.ro.md`; moved to the repo root 2026-08-19 with the rest of the
      README set), and the glossary translation `GLOSSARY.ro.md` followed 2026-08-19.
