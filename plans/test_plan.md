# euvd-watch — Test Plan & Testing Infrastructure

> **Companion to [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).** The implementation plan says *how to test each step*; this document is the authority on **what the complete testing infrastructure looks like**, how it's assembled step by step, and what "tested" means for this project. When the two disagree, this document wins on testing matters.
>
> **Audience:** the AI coding agent (or developer) implementing the project. Testing is not a phase — every implementation step in the plan ships **with** its tests, and the infrastructure below is built incrementally alongside the milestones.

---

## 1. Testing philosophy

euvd-watch makes claims with legal and security consequences ("this vulnerability doesn't affect you", "your 24-hour clock started at T"). The test suite exists to make those claims trustworthy. Principles, in priority order:

1. **The dangerous direction is silence.** A crash is annoying; a *silently missed finding* or a *silently suppressed one* is the actual failure mode. Tests bias toward proving that nothing disappears quietly.
2. **No network in unit or integration tests. Ever.** All external APIs (EUVD, EPSS, KEV) are represented by committed fixtures replayed through `respx`. One clearly-marked nightly job talks to the real world (§7).
3. **Fixtures over mocks.** Mock objects encode our assumptions; captured fixtures encode reality. When they conflict, reality wins.
4. **Truth tables are the regression memory.** The matcher (2.3), the VEX rules (3.2), and the CRA trigger (4.1) are each governed by a curated YAML case table. Every bug found in the wild becomes a new row *before* the fix is merged.
5. **Determinism is testable and tested.** Same inputs → byte-identical outputs. Any test may run twice and diff.
6. **Invariants are enforced by tests, not by review.** The "must never happen" list (§6) is executable.

## 2. Tooling & layout

| Concern | Tool | Notes |
|---|---|---|
| Test runner | `pytest` | config in `pyproject.toml` |
| HTTP replay | `respx` | intercepts `httpx`; no real sockets |
| Time control | `freezegun` | all clock/TTL tests |
| CLI testing | Typer `CliRunner` | asserts output + exit codes |
| Property tests | `hypothesis` | normalization idempotence, version comparator |
| Coverage | `pytest-cov` | gate: **≥ 85% line** overall, `--cov-fail-under=85` |
| Static safety | `mypy --strict`, `ruff` | run as separate CI jobs, count as "tests" |
| Accessibility | `pa11y` (axe engine) | M6 dashboard pages |
| Dependency security | `pip-audit` | CI job |
| Dogfood | Syft + euvd-watch itself | project scans its own SBOM in CI |

```
tests/
├── unit/                    # fast, pure, one module per file (test_<module>.py)
├── integration/             # multi-module flows, respx-mocked APIs, state stores on tmp_path
├── e2e/                     # CliRunner end-to-end command tests + scenario tests
├── invariants/              # §6 — the executable "must never happen" list
├── fixtures/
│   ├── sboms/               # real + handcrafted CycloneDX/SPDX files
│   ├── euvd/                # captured EUVD API responses (see §5)
│   ├── epss/  kev/          # captured enrichment responses
│   ├── matching/cases.yaml  # matcher truth table
│   ├── vex/                 # rules truth table, decisions files, OpenVEX schema + goldens
│   ├── cra/                 # trigger policy table, event fixtures, audit-log fixtures
│   └── golden/              # golden output files (inventories, findings JSON, drafts)
└── conftest.py              # shared fixtures: tmp state stores, frozen clock, ApiClient-with-respx
```

Naming convention: `test_<unit>_<behavior>_<expected>` (e.g. `test_normalize_purl_is_idempotent`). Every test file header states *which plan step it covers*.

Pytest markers: `@pytest.mark.unit / integration / e2e / invariant / live / slow`. Default run excludes `live`.

## 3. Test levels (the pyramid, project-specific)

- **Unit (target ~70% of tests):** pure functions — parsers, normalizers, matcher strategies, version comparator, VEX rules, trigger policy, clock math, hash chain. No I/O; `tmp_path` where files are unavoidable.
- **Integration (~20%):** module seams — SBOM loader end-to-end over fixture files; EUVD client against respx fixtures incl. pagination/retry/cache; enrichment degradation; state-store idempotence; DB migrations.
- **E2E CLI (~10%):** every command via `CliRunner` with fully mocked network: output snapshots, exit-code matrices, `--output json` schema checks.
- **Scenario tests (few, precious):** multi-command stories asserting the *product promise* (§8). Run in CI as the `scenario` job.
- **Non-functional:** accessibility (M6), security (pip-audit, SPDX headers check), light performance budgets (scan of the demo SBOM < 2 s; match against cached feed < 10 s for a 500-component SBOM).

## 4. Per-step test plans

Each entry: **Focus** (what can break), **Tests** (the concrete cases to write), **Fixtures**, **Exit criteria** (step's tests are done when…). Coverage expectation per step is ≥ 85% of the step's new code unless stated.

### M0 — Scaffolding

**0.1 Package skeleton & tooling**
- Focus: the quality gates themselves work.
- Tests: `test_version.py` — `__version__` matches `pyproject.toml`; a deliberate-failure meta-check during setup (break a lint rule locally, confirm CI fails, then revert) documented in the PR description.
- Exit: `ruff && mypy && pytest` green on a fresh clone.

**0.2 CLI skeleton**
- Focus: command surface stability.
- Tests (e2e): `version` → exit 0, prints version; each stub (`scan/match/vex/cra/watch`) → exit 2 + "not implemented"; `--help` renders for every command and subcommand (parametrized).
- Exit: full command matrix parametrized in one test file.

**0.3 Config loading**
- Focus: precedence and failure clarity.
- Tests (unit): defaults only; YAML overrides defaults; env overrides YAML; invalid value → error message **names the field**; missing file passed via `--config` → exit 2.
- Fixtures: `tests/fixtures/config/{valid,invalid_type,partial}.yaml`.
- Exit: precedence matrix (3 sources × present/absent) fully covered.

**0.4 CI pipeline**
- Focus: the pipeline is the meta-test.
- Tests: none in-repo beyond a trivially-green suite; acceptance is the green matrix (3.11 + 3.12) on a PR.
- Exit: lint/typecheck/test/build all green; coverage gate active and observed to fail when forced below 85% once.

### M1 — SBOM ingestion

**1.1 Component model**
- Focus: the pipeline's core contract.
- Tests (unit): construction with minimal/maximal fields; frozen-ness (mutation raises); `dedupe_key`: purl beats (name, version); case-insensitive name fallback; two components, same purl, different raw_ref → same key.
- Exit: 100% coverage on `models.py` (this file is the contract — hold it higher).

**1.2 CycloneDX parser**
- Focus: real-world messiness.
- Tests (integration): parse Syft-real fixture → golden inventory JSON matches byte-for-byte; nested components flattened; license `expression` and `license.id/name` both extracted; malformed JSON → `SbomParseError` with context; unknown fields ignored without warning-spam; spec versions 1.4/1.5/1.6 parametrized.
- Fixtures: `sboms/syft-demo.cdx.json` (real), `minimal.cdx.json`, `nested-licenses.cdx.json`, `malformed.cdx.json`.
- Exit: golden stable across two consecutive runs (determinism check built into the test).

**1.3 SPDX parser + detection**
- Focus: format routing and semantic parity.
- Tests: GitHub-export fixture → golden; purl and cpe23Type external refs extracted; detection matrix — cdx/spdx/garbage/empty/valid-JSON-but-neither → correct parser or `UnsupportedFormatError`; **parity test**: the same logical package expressed in both formats yields equal `Component`s (minus `source_format`/`raw_ref`).
- Exit: parity test passes — this is the proof the M2 matcher can be format-blind.

**1.4 Normalization**
- Focus: correctness of the matcher's raw material.
- Tests (unit + property): table of ≥ 30 messy real identifiers → expected canonical form; **hypothesis** property `normalize(normalize(x)) == normalize(x)` over generated purls; CPE 2.3 parse of escaped chars; version cleanup (`v1.2.3`, deb epochs); synthesized purls always `synthesized=True` — asserted here *and* re-asserted as an invariant (§6).
- Fixtures: messy-case table lives in the test as parametrize data (reviewable in diffs).
- Exit: property test 500 examples clean; table complete.

**1.5 `scan` command**
- Focus: the first user-visible promise.
- Tests (e2e): table output contains expected component rows; `--output json` validates against the Inventory schema and matches golden; summary line counts (N components, M deduplicated, K synthesized) asserted exactly; exit codes — valid → 0, malformed → 2, missing file → 2; performance budget: demo SBOM < 2 s.
- Exit: README quickstart's `scan` line reproduced verbatim in a test.

### M2 — EUVD & matching

**2.1 HTTP layer**
- Focus: politeness and resilience.
- Tests (integration, respx + freezegun): 429 → backoff → success (assert attempt count and growing delays); 5 failures → raises typed error; TTL: fresh hit no network, expired hit refetches; ETag 304 path; corrupted SQLite cache file → self-heals (drops, recreates, logs); User-Agent asserted on every request.
- Invariant hook: "no httpx outside http.py" test (§6).
- Exit: all retry/cache branches covered; zero real sockets (enforced by respx strict mode globally in conftest).

**2.2 EUVD client**
- Focus: surviving a beta API.
- Tests (integration over committed fixtures): pagination joins pages completely (fixture with 3 pages); empty result → empty list, not error; malformed record in a page → skipped + warning logged, rest parsed; exploited-feed retrieval parses `exploited=true` correctly; every `EuvdRecord` field populated from at least one fixture.
- Fixtures: 5–10 captured real responses (§5 governs capture/refresh).
- Exit: `docs/euvd-api.md` cross-checked — every documented endpoint has ≥ 1 fixture test.

**2.3 Matching engine** — *the most important tests in the project*
- Focus: honest confidence.
- Tests: the **truth table** `matching/cases.yaml`, ≥ 25 cases minimum at creation, grown forever: true positives at each confidence level; false positives that must NOT match (same product, different vendor; same name, different ecosystem); boundary versions (first affected, last affected, one-off each side); open-ended ranges → capped at `medium`; synthesized-identifier component → capped at `medium`; fallback comparator → capped at `medium`; alias-table-driven match (purl → vendor/product) at `high`. Plus unit tests for `versions.py`: semver, PEP 440, fallback tokenwise — each comparator reports its scheme. Determinism: findings order stable across runs.
- Exit: 100% of table passes; `explanation` non-empty on every finding (asserted in the table runner itself).

**2.4 Enrichment**
- Focus: graceful degradation.
- Tests: EPSS batch query maps scores to the right CVEs; KEV membership true/false; EPSS API down → warning + `epss_score=None`, run succeeds, exit code unchanged; KEV cache TTL honored; `--no-enrich` performs zero enrichment requests (respx asserts no calls); enrichment never mutates confidence/strategy (before/after deep-compare).
- Exit: degradation matrix (each API up/down independently) covered.

**2.5 `match` command**
- Focus: the CI contract.
- Tests (e2e): exit-code matrix — `--fail-on none/any/exploited` × findings present/absent/exploited-present (9 cells, parametrized); `--min-confidence` filters correctly; `--exploited-only` runs tier 1 only (respx asserts no search calls); `--save-findings` artifact validates against its schema, `inventory_digest` matches; **EUVD-down behavior**: valid cache → succeeds + warning + `data_freshness` stamped; no cache → exit 2, and output does NOT contain "no findings" (explicit negative assertion); JSON output schema snapshot.
- Exit: README quickstart `match` line reproduced verbatim; the 9-cell matrix green.

### M3 — OpenVEX

**3.1 Model & writer**
- Tests: every generated document validates against the **vendored** OpenVEX JSON schema; golden-file doc; write→read→write byte-stable; statement ordering stable under input shuffling (hypothesis: shuffle input findings, output identical).
- Exit: schema validation wired into every later VEX test automatically (a shared assertion helper).

**3.2 Conservative rules**
- Focus: the credibility rule.
- Tests: rules truth table (`vex/rules-cases.yaml`): the one auto-`not_affected` rule fires only on provable out-of-range with high confidence; **adversarial set** — findings engineered to look dismissible (right name wrong vendor at medium; out-of-range but fallback comparator; out-of-range but synthesized purl) must all stay `under_investigation`; two-rules-disagree → `under_investigation` + logged; every auto-statement carries justification + explanation.
- Exit: adversarial set green; invariant test (§6) re-asserts the no-unjustified-not_affected rule against *randomized* findings via hypothesis.

**3.3 Decisions & merge**
- Tests: decision overrides draft (each status); stale decision (matches nothing) → reported by id; conflict (human says not_affected, automation says exploited+high) → merged as human choice **plus loud warning** (asserted); invalid YAML → error names the offending entry; `vex init-decisions` scaffold round-trips through the validator.
- Exit: merge matrix (decision × draft status) fully parametrized.

**3.4 `vex generate`**
- Tests (e2e): demo SBOM + fixtures + decisions → valid OpenVEX + correct per-status counts in the summary; determinism with pinned `--timestamp`; `--findings` path produces identical output to the full-pipeline path (equivalence test).
- Exit: one output file manually verified once against a third-party consumer (`vexctl`/Grype), result recorded in `docs/matching.md`.

### M4 — CRA workflow

**4.1 Trigger policy**
- Tests: policy truth table (`cra/trigger-cases.yaml`): each condition alone (exploited / KEV / EPSS≥t), conjunction vs disjunction config, confidence gate blocks low/medium as configured; state store — same finding twice → one event, `first_seen` unchanged (freezegun advances time between runs); `policy_snapshot` captured verbatim on the event.
- Exit: idempotence test runs the full check twice inside one test and diffs the event store.

**4.2 Clocks**
- Tests (freezegun): multi-stage config (24 h + 72 h defaults) — per stage: pending → due_soon (at 25% remaining, boundary exact) → overdue (deadline + 1 s) → completed; custom stage config honored; all stored timestamps UTC (asserted by parsing); rendering includes timezone.
- Exit: transition matrix per stage covered; a two-stage event shows two independent countdowns in `cra status` output.

**4.3 Draft renderer**
- Tests: snapshot of Markdown and JSON drafts from a fixture event (golden files); every `TODO-HUMAN` marker present where human judgment is required; missing org config → error listing the exact missing fields; template renders with unicode org names (RO diacritics in fixture).
- Exit: snapshot review is part of PR review (goldens change = reviewer sees the diff).

**4.4 Audit log**
- Focus: tamper evidence is only as good as its tests.
- Tests: chain verifies on a 100-entry fixture; **tamper matrix** — flip one byte in entry k ∈ {first, middle, last} → `verify-log` names exactly entry k; delete an entry → detected; append valid entries after a tampered one → still detected at k; canonical JSON: key order and whitespace changes in input produce identical hashes; genesis seed documented and asserted.
- Exit: verify-log O(n) sanity (time two sizes, ratio ≈ linear, generous tolerance — marked `slow`).

**4.5 `cra` commands / scenario**
- Tests: the **CRA scenario test** (§8, scenario S3) plus per-command exit codes; `cra check --findings` equivalence with full-pipeline `cra check`.
- Exit: scenario green in CI.

### M5 — Integrations & packaging

**5.1 Release automation**
- Tests: TestPyPI dry-run workflow — a clean venv `pip install`s from TestPyPI and runs `euvd-watch version` (CI job, release branch only); changelog section extraction unit-tested.
- Exit: one tagged pre-release exercised the full path end-to-end.

**5.2 Docker**
- Tests (CI): image builds; `docker run … version` exit 0; `scan` of a mounted fixture SBOM works; runs as non-root (asserted with `id -u` ≠ 0); size < 200 MB gate.
- Exit: all four assertions in the image-test job.

**5.3 CI templates**
- Tests: the repo **dogfoods its own GitHub Action** on `examples/sboms/` in every CI run (network-mocked mode or cache-primed); `action.yml` inputs validated by a matrix run (fail-on values); GitLab template passes schema lint.
- Exit: a fresh test repo consumed the copy-paste snippet successfully once (documented).

**5.4 Watch mode**
- Tests (unit for the differ): new finding → notified; resolved → notified as resolved; changed severity/confidence → notified as changed; unchanged → **zero** notifications (explicit); webhook payload schema snapshot; respx-intercepted webhook receives exactly one POST per changed finding; `--once` integration test with pre-seeded prior snapshot.
- Exit: two consecutive identical runs produce zero notifications (asserted, not assumed).

### M6 — Dashboard

**6.1 Storage**
- Tests: migrations from empty and from every prior schema version (fixture DBs per version, kept forever); WAL concurrent read-while-write test; `db migrate` idempotent (run twice, no-op second time).
**6.2 Web app**
- Tests (FastAPI TestClient): every route 200 with demo data; 401 without credentials on all routes; write endpoints (mark) reject unauthenticated; HTML has no inline event handlers (regex sweep — CSP-friendliness); finding detail shows explanation + confidence verbatim from the store.
**6.3 Accessibility**
- Tests: `pa11y` (axe) against every page rendered with the demo scenario data, in CI: **zero serious/critical violations** gate; keyboard-pass checklist in `docs/accessibility.md` re-executed manually per release and dated.
**6.4 Deploy docs**
- Test: the doc *is* the test — cold-start on a clean container following only `docs/deploy.md`, timed < 15 min; deviations found become doc fixes before the milestone closes.

### X — Cross-cutting

- **X.1 docs:** README quickstart blocks are extracted and executed by a `test_readme_quickstart.py` (code-block runner with mocked network) — docs can't drift silently.
- **X.2 demo:** `examples/demo.sh` runs in CI end-to-end (mocked/cached mode).
- **X.3 hygiene:** `pip-audit` job; SPDX-header presence test over `src/**`; **dogfood job** — Syft generates this repo's SBOM, euvd-watch matches it; the job fails on `--fail-on exploited`.

## 5. Fixture & golden-file governance

- **Capture:** `scripts/capture_fixtures.py` hits real APIs, scrubs volatile fields (dates it doesn't need), writes to `tests/fixtures/{euvd,epss,kev}/`. Run manually; never in CI.
- **Refresh policy:** fixtures refreshed when the nightly live-smoke (§7) detects drift, or quarterly, whichever first. Refresh = its own PR, so behavioral diffs are reviewable.
- **Golden files:** updated only via `pytest --update-goldens` (a documented flag in conftest); golden diffs must be human-reviewed in the PR — a golden update with no explanation is a review blocker.
- **Truth tables** (`matching/cases.yaml`, `vex/rules-cases.yaml`, `cra/trigger-cases.yaml`) are append-mostly: rows are never deleted without a comment referencing why; every field bug found post-release adds a row *first* (red), then the fix (green).

## 6. Invariant suite (`tests/invariants/`) — the executable "must never happen" list

Run in every CI pipeline; each maps to a promise in the README:

| ID | Invariant | How enforced |
|---|---|---|
| INV-1 | No `high` confidence from the fallback version comparator | hypothesis over randomized comparisons + truth-table rows |
| INV-2 | No `high` confidence for `synthesized=True` components | same |
| INV-3 | No `not_affected` without machine-checkable justification + explanation | hypothesis over randomized findings through the rules engine |
| INV-4 | Missing/unreachable EUVD data can never yield a clean "no findings" exit 0 | e2e negative test (2.5) |
| INV-5 | No HTTP usage outside `http.py` | import-graph test (grep/AST) |
| INV-6 | Re-running match/cra never duplicates events or resets `first_seen` | double-run diff test |
| INV-7 | Audit-log tampering of any single entry is detected and located | tamper matrix (4.4) |
| INV-8 | Nothing is ever submitted/filed automatically — no code path calls a submission endpoint | AST/grep test: no outbound POST targets outside webhook sink allowlist |
| INV-9 | Identical inputs → byte-identical outputs for scan/match/vex (pinned timestamp) | double-run diff over the demo pipeline |
| INV-10 | Every Finding carries a non-empty explanation | truth-table runner assertion |

## 7. CI test topology

| Job | Trigger | Contents | Blocking? |
|---|---|---|---|
| `lint` / `typecheck` | every PR | ruff, mypy --strict | yes |
| `test` (matrix 3.11/3.12) | every PR | unit + integration + e2e + invariants, coverage ≥ 85% | yes |
| `scenario` | every PR | §8 scenario tests | yes |
| `dogfood` | every PR | self-SBOM scan + GitHub Action self-consumption | yes |
| `a11y` | PRs touching `web/` + nightly | pa11y zero serious/critical | yes |
| `security` | every PR | pip-audit, SPDX headers | yes |
| `image` | PRs touching docker/ + release | Docker build + 4 assertions | yes |
| `live-smoke` | **nightly only** | marked `live`: real EUVD/EPSS/KEV calls, tiny SBOM; detects API drift | **no** — failure opens an issue, never blocks PRs |
| `release-verify` | tags | TestPyPI/PyPI install-and-run in clean venv | yes |

## 8. Scenario tests (the product promises, executable)

- **S1 — "From SBOM to findings":** scan → match(--save-findings) → assert known-vulnerable fixture component found at `high`, known-clean absent, findings artifact valid.
- **S2 — "Noise goes down, risk doesn't":** S1 → vex generate with a decisions file → downstream: the not_affected statement exists **with justification**; an uncertain finding remains under_investigation; counts reconcile (no finding unaccounted for across statuses — conservation check).
- **S3 — "The 24-hour story":** seeded exploited finding → cra check fires exactly one event → status shows both stage countdowns → freeze-advance to due_soon and overdue, states follow → draft renders with TODO-HUMAN markers → mark completed → verify-log passes → second cra check is a no-op.
- **S4 — "Watch only tells me news":** watch --once with prior snapshot → only the delta notified; repeat unchanged → zero notifications.
- **S5 — "A stranger's cold start":** (manual, per release) deploy doc followed on a clean machine < 15 min; README quickstart executed verbatim.

## 9. Quality gates summary (Definition of Tested)

- Coverage ≥ 85% overall; `models.py`, `match.py`, `rules.py`, `trigger.py`, `audit.py` ≥ 95% (the trust-critical five).
- All truth tables green; all 10 invariants green; all blocking CI jobs green on main at all times.
- Every released bug has a regression row/test merged before or with its fix.
- Nightly live-smoke drift issues triaged within one week (fixture refresh PR if real).
