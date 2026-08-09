# euvd-watch — current plan (post-audit, owner-approved 2026-07-10)

> **Forward plan:** `plans/next_steps_plan.md` (2026-08-08) sequences everything from
> here — M6 completion, docs debt, 0.4.0→1.0.0→1.1 releases (1.0.0 targeted before
> the CRA Art. 14 applicability date 2026-09-11), publication, NLnet funding, and
> community mechanics. Execute it phase by phase.

## M6 — Self-hostable dashboard (started 2026-08-08; decisions in AUDIT §17)

- [x] Step 6.1 storage consolidation: `web/store.py` — one WAL-mode SQLite file
      (`state_dir/euvd-watch.sqlite`), numbered SQL migrations
      (`web/migrations/0001_initial.sql`: events, watch_snapshots, plus the 6.2 read
      models vex_status_cache/audit_log_refs) applied transparently by every
      state-touching command; `euvd-watch db migrate` runs them explicitly (json|table
      output). Pre-6.1 layout (cra-events.sqlite + watch/*.json) auto-imported,
      originals renamed `.migrated-<stamp>` (never deleted; stale legacy copies never
      overwrite consolidated rows — INSERT OR IGNORE); corruption quarantine pattern
      carried over from EventStore. Audit log + vex-decisions.yaml stay files
      (§17 carve-outs). Per-version fixture DBs committed under tests/fixtures/db/
      (kept forever) + scripts/make_db_fixtures.py. Tests: empty/v1/legacy migrations,
      idempotency, WAL read-during-write, quarantine, loud failure on unreadable or
      schema-mismatched legacy events; CLI e2e incl. transparent migration via
      `cra status`. 482 tests / 94.49%, ruff+mypy clean; demo.sh + dead-proxy watch
      cycle verified (snapshot row lands in DB, WAL, exit codes 1 then 0).
      docs/storage.md written; cra.md/watch.md storage sections updated; README EN+RO
      `db migrate` row.
- [x] Step 6.2 web application — DONE 2026-08-08 (beta). FastAPI + server-rendered
      Jinja2 (`web/app.py`, `web/dashboard.py` view-model layer, `web/store.py`
      read-model methods, `web/auth.py` PBKDF2 basic-auth, `web/templates/*.html`,
      `web/static/dashboard.css` — all from docs/dashboard-design.md's tokens/spec).
      New `[web]` extra (fastapi/uvicorn/python-multipart); `euvd-watch web serve
      <sbom>` (exits 2 with install hint if extra missing, exits 2 if
      `web.password_hash` unset) + `euvd-watch web hash-password`. All 5 pages:
      Overview, Findings (filter+paginate), Finding detail (verbatim explanation + VEX
      decision-shortcut snippet, never auto-sets affected/fixed), CRA events + detail
      (deadline bars, the one write action "Mark stage complete" reusing
      `cra/actions.py::mark` — same audit trail as `cra mark`), Audit log (re-verify,
      only ever shows chain-verified entries). HTTP Basic on every route (401 without
      creds, WWW-Authenticate header — native browser prompt, not a custom login page;
      design doc §7 corrected to match). CRA event URLs use a hashed `url_id` (purl-derived
      event_ids routinely contain '/', which breaks a plain path segment — found via
      real smoke test, not by inspection). Refactors done alongside: shared
      `findings_artifact.py` (was duplicated in cli.py), shared `cra/actions.py` (CLI
      `cra mark` and the web route now call the identical function), `watch/differ.py`
      `_key`→public `finding_identity`. CLI table cap (M0/M1 review 3.7) also closed:
      `scan`/`match` tables cap at 50 rows + "… and N more" footer, `--output json`
      unaffected. `from __future__ import annotations` deliberately OMITTED from
      web/app.py — it stringifies annotations, which broke FastAPI's dependency
      resolution for closure-local `Depends(...)` in nested route functions (silent
      fallback to treating them as query params, 422s on every route) — caught by
      manually smoke-testing the real app, not by tests alone.
      Verified: 568 tests (was 482) / 94.34%, ruff+mypy strict clean; real `uvicorn`
      server run end-to-end offline (dead-proxy `watch`/`cra check` to seed state, then
      curl every page + the write flow + audit-chain-stays-intact, not just
      TestClient). Docs: new docs/web.md, CHANGELOG entry, README EN+RO `web serve`
      row flipped 🚧→🧪 beta. **Deliberately NOT done here** (belongs to 6.3/6.4): no
      CSRF token on the mark form (documented limitation in docs/web.md — same-origin
      HTTP Basic, single-operator tool behind a reverse proxy); WCAG audit; deploy
      guide.
- [ ] Revisit parked feedback_m2 3.4 small items: cache purge sweep, get_by_cve page
      cap, fixture annotations.
- [x] Step 6.3 accessibility — DONE 2026-08-09. Automated gate:
      `scripts/a11y_check.mjs` (axe-core direct via Puppeteer, NOT the `pa11y` CLI —
      pa11y's own axe runner collapses `incomplete` and `violation` into the same
      severity, which would make the gate permanently red for a documented axe
      heuristic limitation; see the script's header + docs/accessibility.md) +
      `scripts/run_a11y_check.sh` (seeds the demo scenario offline exactly like
      examples/demo.sh, serves the real dashboard, runs the check against all 7
      pages) + new CI job `a11y` (`.github/workflows/a11y.yml`, PRs touching web/ +
      nightly). New root `package.json` (puppeteer+axe-core devDeps, committed
      package-lock.json); `node_modules/` gitignored.
      Gate found and fixed two REAL WCAG defects (only by running the real page, not
      by reading templates): `link-in-text-block` on Finding detail's CRA-event
      disclaimer (link distinguishable only by color — now underlined via
      `.disclaimer a`) and `scrollable-region-focusable` on all three `<pre
      class="snippet">` blocks (VEX snippet/CLI hint/CRA draft — now
      `tabindex="0"`), both with regression tests. Also found and fixed a real CSS
      bug the gate's screenshot surfaced: `.s-crit`/`.s-warn`/etc. severity classes
      were unscoped, so Overview's "recent findings" row (which reuses the same
      class name for its left-border stripe) got a solid filled background instead
      of a thin stripe — scoped to `td.stripecell > i.s-crit` etc. Zero
      serious/critical axe violations across all 7 pages, confirmed offline.
      docs/accessibility.md: the gate's design rationale, the documented/investigated
      axe `incomplete` cases (nav icons + audit checkmark — confirmed via direct
      axe.run() to be indeterminate, not failing; verified by eye), and a manual
      keyboard-pass checklist executed via Puppeteer-driven real Tab-key navigation
      (skip link first, every control gets a visible focus ring, logical order, the
      mark-stage form fully keyboard-operable, no traps) — dated, to be re-run per
      release. 570 tests (was 568)/94.34%, ruff+mypy clean.
- [ ] Step 6.4 deployment docs (docs/deploy.md: compose, Caddy TLS, backup, upgrade;
      cold-start < 15 min test).

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
- [x] Step 5.1 PyPI packaging & release automation — DONE 2026-08-08. Owner added the
      TestPyPI pending publisher; `v0.3.1rc1` then exercised the full TestPyPI path
      green (publish via OIDC + clean-venv install check — the test-plan 5.1 exit
      criterion), and `v0.3.1` shipped as the **first real PyPI release**: publish +
      clean-venv `pip install euvd-watch==0.3.1` + GitHub release with changelog notes,
      all in one green `workflow.yaml` run. image.yml published GHCR `:0.3.1`+`:latest`
      on the same tag. Infra (built 2026-07-14): workflow.yaml (filename load-bearing
      for trusted publishing), version-agreement guard, `scripts/extract_changelog.py`
      (rc→base-section fallback), docs/release.md, SECURITY.md.
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
      flow verified locally through a dead proxy. Fresh-repo acceptance exercised
      2026-08-08 (`caisarus/euvd-action-smoke`, README snippet verbatim): action
      resolves at caisarus/euvd@v0.3.1, installs 0.3.1 from PyPI, SBOM handoff works —
      first four attempts hit EUVD 429ing GitHub's shared runner IPs during EU hours
      (euvd-watch honestly exits 2, "Refusing to report 'no findings' on missing
      data"), then a rerun went **green end-to-end** the same day — snippet fetched,
      0.3.1 from PyPI, live EUVD match, gate exit 0. ACCEPTANCE MET. Noted in
      docs/integrations.md §Copy-paste verification. (Owner: delete the throwaway
      repo caisarus/euvd-action-smoke — gh token here lacks the delete_repo scope.)

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

## Release 0.3.0 (2026-07-13)

- [x] Tagged `v0.3.0` at `a142bff` (version bump 0.1.0→0.3.0, CHANGELOG cut). Git tag +
      GHCR image only; PyPI name reserved 2026-07-14, 5.1 unblocked. GHCR `:0.3.0` and
      `:latest` confirmed pushed (same digest, verified in the image.yml run log) — but
      the ghcr.io/caisarus/euvd-watch package is PRIVATE (anonymous pull denied; GHCR
      does not inherit repo visibility). Owner: flip package visibility to public in
      GitHub UI (Packages → euvd-watch → Package settings → Change visibility).
- [x] M6 sign-off — owner delegated all four decisions 2026-07-14; taken and recorded in
      docs/AUDIT_AND_REMEDIATION_PLAN.md §17: (1) SQLite = source of truth for
      operational state (CRA events + watch snapshots migrate in), audit log stays the
      append-only hash-chained file (refs only in DB), vex-decisions.yaml stays the
      human-edited input of record (DB caches derived statuses); (2) [web] extra: yes,
      core stays lean, `web serve` without it exits 2 with an install hint;
      (3) SECURITY.md: GitHub private vulnerability reporting primary + owner email
      fallback — shipped; (4) 1.1 target confirmed. M6 implementation starts after 5.1
      ships and the 5.3 fresh-repo acceptance is verified.
- [x] GHCR package flipped public by owner 2026-07-14 (anonymous pull now possible).

## Owner-blocked (cannot proceed without)

- [x] GitHub org/name -> create remote, push (DONE 2026-07-13: private
      github.com/caisarus/euvd, branch renamed master->main, 27 commits force-pushed over
      the stub initial commit). CI VERIFIED 2026-07-14 via gh (now installed+authed):
      demo job was red on the last two main pushes — examples/demo.sh committed as
      100644 (WSL /mnt/c masks the missing exec bit; exit 126 on runners). Fixed in
      `418772d`; full CI green (11 jobs), Image and nightly Live smoke green throughout.
- [x] Reserve PyPI name `euvd-watch` (DONE 2026-07-14, owner) — 5.1 unblocked; trusted
      publishing config on PyPI still pending (part of 5.1)
- [x] Make the repo public (DONE 2026-07-14, owner; confirmed via API) — 5.3 copy-paste
      acceptance now checkable once 5.1 ships the pip-installable release. GHCR package
      visibility is separate and still private (see Release 0.3.0 note).

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
