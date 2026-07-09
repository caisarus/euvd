# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

Planning and documentation for **euvd-watch** — an EUVD-native software supply-chain
vulnerability watch and EU Cyber Resilience Act (CRA) reporting toolkit. It ingests SBOMs
(CycloneDX/SPDX), matches components against ENISA's European Union Vulnerability Database,
drafts conservative OpenVEX statements, and drafts CRA Article 14 notifications with a
tamper-evident audit log when an actively exploited vulnerability fires the trigger.

**There is no code yet.** The repo currently contains only:

- `plans/implementation_plan.md` — the complete step-by-step build plan (M0–M6 milestones).
  Implement steps **strictly in order**; do not start a step until the previous step's
  acceptance criteria all pass. Every step defines Purpose / What / How / Tests / Acceptance.
- `plans/test_plan.md` — **authoritative on all testing matters**; when it disagrees with the
  implementation plan on testing, the test plan wins. Testing infrastructure is built
  incrementally alongside the milestones, never as a separate phase.
- `readme/readme.md` — the user-facing README (becomes `README.md` in the built project),
  `readme/readme.simple` (kid-friendly version), `readme/glossary` (plain-language glossary).

## Stack and layout (target state, defined in the plan)

Python 3.11+, `src/` layout (`src/euvd_watch/`), packaged via `pyproject.toml`, license
EUPL-1.2. CLI with Typer, models with pydantic v2, HTTP via httpx. One module per milestone:
`sbom/` (M1), `euvd/` + `enrich/` (M2), `vex/` (M3), `cra/` (M4), `integrations/` (M5),
`web/` (M6, FastAPI + server-rendered Jinja2, no SPA).

## Commands (once scaffolding exists — Step 0.1)

```bash
pip install -e ".[dev]"      # editable install with dev deps
ruff check .                 # lint (line length 100)
mypy src                     # strict mode must pass
pytest                       # coverage gate: --cov-fail-under=85
pytest tests/unit/test_foo.py::test_case   # single test
pytest -m "not live"         # default; 'live' marker is the only networked job
```

## Non-negotiable engineering rules (from the plans)

- **No network in unit/integration tests, ever.** External APIs (EUVD, EPSS, KEV) are
  committed fixtures replayed through `respx`. Fixtures over mocks.
- **All HTTP goes through the single `http.py` ApiClient** (retry/backoff/cache) — zero
  direct `httpx` usage elsewhere; this is enforced by a test.
- **Deterministic outputs**: same inputs → byte-identical outputs (stable ordering, sorted
  keys, no gratuitous timestamps). Golden-file tests rely on this.
- **Conservative VEX**: `not_affected` only with machine-checkable proof and an explanation;
  everything uncertain stays `under_investigation`. `affected`/`fixed` come only from human
  decisions. No code path may silently suppress a finding.
- **Human-in-the-loop**: the tool drafts CRA notifications; it never submits anything.
- **Confidence caps are hard invariants**: synthesized identifiers can never yield `high`
  confidence; the fallback version comparator can never support `high`.
- Truth tables (`tests/fixtures/matching/cases.yaml`, VEX rules, CRA trigger) are the
  regression memory — every wild bug becomes a new row *before* its fix merges.
- CLI contract: every command supports `--output json|table`; exit codes `0` clean,
  `1` findings above threshold, `2` execution error.
- Type annotations everywhere; every public function has a docstring; Conventional Commits
  (`feat(sbom): ...`, `test(euvd): ...`).

## Reality checks flagged in the plan

- The EUVD API is **beta**: verify endpoints at implementation time and document them in
  `docs/euvd-api.md`. EUVD records describe affected software as vendor/product/version-range
  **text**, not purls — the matcher bridges that gap; don't invent purl fields in API data.
- CRA deadline stages (24 h / 72 h) are **config, not code** — verify current CRA/ENISA
  guidance at implementation time and document in `docs/cra.md`.
