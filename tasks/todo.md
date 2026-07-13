# euvd-watch — current plan (post-audit, owner-approved 2026-07-10)

Roadmap authority: `docs/AUDIT_AND_REMEDIATION_PLAN.md` §14. Owner decisions §17.

## R1 — hardening quick wins on committed code

- [x] TECH-001: purls parsed via packageurl-python everywhere (match candidates, alias
      keys, merge patterns) + 2 truth-table rows (`bc52538`)
- [x] TECH-003: `match --timestamp` pins `generated_at`; INV-9 e2e test (`4a79ace`)
- [x] REQ-VEX-004: `vex generate --fail-on-conflict` CI gate (`705a1db`)
- [x] Owner decision: auto `not_affected` justification -> `component_not_present` (`6faa494`)
- [x] DOC-001: README per-command status, honest quickstart, dead links annotated
- [x] Romanian README (`readme/readme.ro.md`) — owner decision: deliver RO docs
- [x] CHANGELOG.md started (Keep a Changelog)
- [x] Audit doc updated with owner decisions; dashboard rescoped to 1.1

## M4-completion — CRA workflow (DONE 2026-07-10, commits 3c32eaa..HEAD)

- [x] SEC-001 fixed before first commit of cra/ (quarantine, never delete; tested)
- [x] SEC-003 fixed (first-fire finding/fired_rules/policy_snapshot immutable;
      latest_finding carries new knowledge; fire-time epss_threshold captured too)
- [x] TECH-002 fixed (StateError boundary + Event.schema_version guard)
- [x] SEC-002 config bounds (epss_threshold 0..1, TTL >= 0, stage hours > 0, unique
      non-empty stage names, >= 1 stage) — each errors naming the field
- [x] Tier-2 privacy toggle `tier2_product_search` (default on) + docs + e2e test
- [x] Step 4.3 renderer (Jinja2 Markdown + deterministic JSON; goldens; TODO-HUMAN;
      REQ-CRA-004 signal-vs-claim language tested; RO diacritics)
- [x] Step 4.4 audit log (frozen canonicalization; tamper matrix incl. delete/reorder/
      append-after-tamper; truncated-tail distinguished; honest threat model)
- [x] Step 4.5 `cra` command group (check/status/draft/mark/verify-log) + state_dir
- [x] INV-6 + INV-7 invariants; scenario S3 green
- [x] docs/cra.md (stages source, awareness-proxy caveat, audit-log limits, disclaimer)
- [x] ruff + mypy strict clean; READMEs (EN+RO) flipped to ✅ for cra commands
- [x] Post-milestone review gate (feedback_m4.md with empirical repros) before M5
- [ ] Tag 0.3.0 after the review gate passes

## M5 — CI/CD integrations, packaging & watch mode

- [x] Step 5.4 `watch` mode: differ (`watch/differ.py`, new/resolved/changed keyed by
      component+euvd_id), pluggable sinks (`watch/sinks.py`: stdout, webhook via new
      `ApiClient.post_json`), `watch` CLI command (`--interval`/`--once`, `--webhook`,
      `--output json|table`), snapshot persisted in `state_dir/watch/`. 442 tests (was
      414), ruff + mypy strict clean, coverage 94.38%. Manual smoke against the live EUVD:
      first run 14 new (exit 1), identical second run 0 notifications (exit 0) — the
      literal test_plan.md 5.4 / implementation_plan.md acceptance criterion. docs/watch.md
      written; READMEs (EN+RO) flipped to ✅.
- [ ] Step 5.1 PyPI packaging & release automation — still owner-blocked (needs the
      reserved PyPI name; trusted publishing can't even be configured without it)
- [x] Step 5.2 Docker image: `docker/Dockerfile` (multi-stage, python:3.12-slim, non-root
      uid 1000, entrypoint `euvd-watch`, ~152 MB) + `.dockerignore`;
      `.github/workflows/image.yml` runs the four test-plan assertions on PRs and
      publishes to GHCR (`:edge` on main, `:X.Y.Z`+`:latest` on tags) with the
      workflow-scoped GITHUB_TOKEN only. All four assertions verified locally with
      Docker 29.3.1. Docs in `docs/integrations.md`.
- [x] Step 5.3 GitHub Action & GitLab CI template: composite `action.yml` (repo root;
      sbom-path/fail-on/min-confidence + output-file/artifact-name/extra-args/version/
      python-version; outputs exit-code/findings-file; artifact uploaded even when the
      gate fails); `templates/euvd-watch.gitlab-ci.yml` (EUVDWATCH_* variables — NOT
      EUVD_WATCH_*, which the config env parser owns and extra="forbid" would reject);
      dogfood job in ci.yml (fail-on matrix none/any/exploited → exit 0/1/1, network-free
      via `scripts/prime_cache.py` + seeded fixture
      `tests/fixtures/euvd/dogfood-seeded-exploited.json`, asserts exactly one
      EUVD-DOGFOOD-0001 finding); offline schema lint of template+workflows+action in
      `tests/integration/test_ci_templates.py` (new dev dep check-jsonschema). Offline
      flow verified locally through a dead proxy. REMAINING (owner-gated): the literal
      acceptance criterion "copy-paste snippet works in a fresh repo" needs the public
      repo + first PyPI release; dogfood/image CI runs on GitHub not yet observed (no
      gh/token in the sandbox — owner to relay).

## Cross-cutting sweep (2026-07-13, after 5.2/5.3)

- [x] M2 review debt closed: 3.1 comma ranges ("A, < B" parsed; truth-table rows from the
      real EUVD-2026-4133 wheel record, red-then-green), 3.2 client-level pagination
      dedupe by euvd_id, 3.3 npm-scoped vendor row (already fixed by the TECH-001 purl
      rework — row pins it), 2.2 data_freshness = oldest EUVD response *served* this run
      (ApiClient._served_stored_at; one timestamp shared with the cache row so INV-9
      byte-identity holds).
- [x] X.3 hygiene: SPDX EUPL-1.2 headers on all 37 src files + presence test; `security`
      CI job (pip-audit); `self-sbom` CI job (Syft SBOM of this repo matched offline,
      --fail-on exploited; rehearsed locally: 330 components, 0 findings, exit 0).
- [x] X.2 examples/demo.sh: scan→match→vex→cra check/status→watch --once ×2, fully
      offline (prime_cache + TIER2_PRODUCT_SEARCH=false), verified through a dead proxy;
      `demo` CI job runs it every PR.
- [x] X.1 tests/e2e/test_readme_quickstart.py executes every euvd-watch line of the
      README Quickstart block (mocked network; --interval rewritten to --once).
- [x] 2.3 nightly live-smoke workflow (live.yml): pytest -m live, cron 03:17 UTC,
      failure opens a deduplicated drift issue; never blocks PRs.
- Deliberately not done: feedback_m2 3.4 "smaller items" (cache purge sweep, get_by_cve
  page cap, fixture annotations) — unchanged priority, revisit with M6's storage work.

## Owner-blocked (cannot proceed without)

- [x] GitHub org/name -> create remote, push (DONE 2026-07-13: private
      github.com/caisarus/euvd, branch renamed master->main, 27 commits force-pushed over
      the stub initial commit). CI green still UNVERIFIED from the sandbox — owner to
      check the Actions tab or install gh.
- [ ] Reserve PyPI name `euvd-watch` (squatting risk, open since M1) — blocks M5 step 5.1
      and the action/template default install path
- [ ] Make the repo public (or pick the public org/home) — blocks the 5.3 copy-paste
      acceptance check and external `uses:`/`include:`/GHCR consumption

## Review — R1 (2026-07-10)

Shipped 5 commits on top of `e80e49e` (still no remote to push to). Full suite after R1:
all tests pass, coverage >= gate, mypy strict clean, ruff clean on touched files. The four
audit repro findings on committed code are closed; the three findings inside the
uncommitted M4 code (SEC-001/003, TECH-002) are deliberately left for the M4 commit series
so the fixes land before that code's first commit.

## Review — M4 post-milestone gate (2026-07-11)

`plans/feedback_m4.md` — 2 new verified findings, both fixed in the same commit: a raw
`TypeError` escaping `AuditLog.append` on a non-dict audit-log tail (recurrence of the
"no raw exception escapes to the CLI" class), and a documentation gap where renaming a
`cra_stages` entry silently un-completes an already-marked stage. 415 tests (was 414),
ruff + mypy strict clean, coverage 93.96%. SEC-001/002/003 and TECH-002 all re-verified
holding under direct testing. Nothing blocks M5; ready to tag `0.3.0`.
