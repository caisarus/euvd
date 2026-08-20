# euvd-watch — current plan (post-audit, owner-approved 2026-07-10)

> **Forward plan:** `plans/next_steps_plan.md` (2026-08-08) sequences everything from
> here — M6 completion, docs debt, 0.4.0→1.0.0→1.1 releases (1.0.0 targeted before
> the CRA Art. 14 applicability date 2026-09-11), publication, NLnet funding, and
> community mechanics. Execute it phase by phase.

## Toward 1.0.0 (target: tag before 2026-09-11, CRA Art. 14 applicability)

- [x] **`fix/retry-after` merged into main 2026-08-20** (`1dbbaa2` + `b3aff3a`, pushed as
      `b3aff3a`). The branch was cut 2026-08-11 and parked for CI observation; settled in
      favour of shipping it *inside* 1.0.0 rather than after, because 1.0.0 is the release
      that gets the attention and ENISA 429s to shared CI runner IPs are exactly what new
      users hit first. Rebased (clean — main never touched `http.py` after the branch
      point), then two merge-prep fixes in `b3aff3a`: the change had no CHANGELOG entry
      (1.0.0's build fails without one) and its own backoff expression was the one file in
      the tree `ruff format` would rewrite — the branch predates the hook catching it.
      **Reviewed for the false-negative class before merging, not assumed:** `RateLimited`
      subclasses `ApiError`, and every `ApiError` consumer was traced — the paginator does
      not catch it (a mid-pagination cooldown propagates instead of returning partial pages
      as complete), `enrich/` degrades to `in_kev=None` which the CRA trigger already
      classifies INDETERMINATE/exit 3 rather than CLEAR, and a webhook sink failure aborts
      the watch cycle *before* `_save_watch_snapshot`, so the next cycle re-reports rather
      than skips. Verified on the merge result, not the branch point: 611 tests (606 + the
      branch's 5), coverage 94.50%, ruff check + format + mypy strict clean.
      Known-and-accepted edge, not a blocker: `Retry-After: 0` (or a past HTTP-date) yields
      a zero-delay retry with no jitter — RFC-correct, deliberately tested, and bounded by
      `MAX_RETRIES`, but it does remove backoff entirely for that case. Revisit only if a
      real server is seen doing it.
- [ ] Cut `1.0.0`: CHANGELOG section from `[Unreleased]`, version in `pyproject.toml` +
      `__init__.py`, CI green, tag. §18 DoD is 9/9 as of 2026-08-19 — nothing blocks it.
      Decide rc-or-not (an rc needs its own `chore(release): 1.0.0rc1` commit or the
      Release workflow's version guard kills it — see the 0.4.1 note below).
- [ ] Fix the stale path in `docs/AUDIT_AND_REMEDIATION_PLAN.md` §18's last checkbox: it
      still cites `readme/readme.ro.md`, which moved to the repo root on 2026-08-19.

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
- [x] Step 6.4 deployment docs — DONE 2026-08-10. **M6 COMPLETE.** docs/deploy.md +
      examples/deploy/ (compose.yaml watch+web+caddy, Caddyfile, euvd-watch.example.yaml):
      shared state named-volume, SBOM at an identical path in both services (snapshot key
      is a hash of the resolved path), web bound 0.0.0.0 internal-only with Caddy as sole
      TLS ingress. Backup (stop+tar OR python-sqlite online backup since the slim image
      has NO sqlite3 CLI + append-only audit-log copy) and upgrade (pull + db-migrate-
      transparent) procedures. TESTED end-to-end on a real compose stack: cold-start ~13s
      (<<15min), 401-without-auth / 200-with-auth / exploited finding shown through Caddy
      TLS, watch wrote the shared state volume as uid 1000. **3 REAL DEPLOY BLOCKERS found
      + fixed by testing** (Dockerfile): (1) image didn't install the [web] extra → web
      serve exited 2; now `pip install "${wheel}[web]"`, still 155MB<200MB; (2) state/cache
      dirs not pre-created euvd-owned → named volume mounted ROOT-owned → non-root EACCES;
      now mkdir+chown in the image so the volume inherits euvd ownership; (3) documented
      local-TLS Caddy block `:443 { tls internal }` can't provision a cert (no hostname,
      TLS internal-error alert) → fixed to `localhost { tls internal }`. Added image.yml
      assertions 5 (web extra reaches password check) + 6 (non-root named-volume write).
      NOTE: fixes reach GHCR `:latest` only on the 0.4.0 tag (`:edge` on next main push);
      doc notes this. Docs updated: web.md/README EN+RO status (M6 fully implemented, beta
      = surface may change pre-1.1), CHANGELOG.
- [ ] Revisit parked feedback_m2 3.4 small items: cache purge sweep, get_by_cve page
      cap, fixture annotations (carry into a future cleanup).
- [x] **0.4.0 RELEASED 2026-08-11** (M6 storage+dashboard+a11y+deploy, audit hardening
      fixes, cra indeterminate exit 3) — see "Release 0.4.0" below.

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

## Documentation debt closed (2026-08-19) — the 1.0 gate is now empty

- [x] **`README.md` moved to the repo root** (`git mv`, history preserved), with
      `README.ro.md`, `README.simple.md` and `GLOSSARY.md`. It had been at
      `readme/readme.md` since the planning-only era, so `gh api repos/caisarus/euvd/readme`
      returned **404** — the project's GitHub front page was a bare file listing. Updated
      every reference: `pyproject.toml` `readme =`, `tests/e2e/test_readme_quickstart.py`,
      CLAUDE.md (whose "There is no code yet" intro was also years stale).
- [x] **All four dead README links now resolve.** Wrote a link checker over every markdown
      file at the root and in `docs/`: **22 files, 0 broken relative links.** Also replaced
      the stale "🚧 coming with their milestones" list with links to all ten shipped
      `docs/*.md` pages, and bumped the CI snippet's action pin `@v0.3.1` → `@v0.4.1`
      (harmless either way — `version: ""` installs latest from PyPI — but it read as stale).
- [x] **`ARCHITECTURE.md`** — pipeline shape (pure core, I/O at the edges), module map by
      milestone, `http.py` as the only way out, the ten invariants as a table, and a
      closing section on *why* the boundaries sit where they do.
- [x] **`CONTRIBUTING.md`** — setup, checks (incl. the single-file coverage-gate trap that
      looks like a test failure), the non-negotiable rules with their reasons, truth-table
      governance, the alias-table evidence rule (§17 decision 6), fixture/golden
      governance, Conventional Commits, good first contributions. Documents the golden-file
      procedure **as it is** — byte comparison, updated by hand, diff explained in the PR —
      because the `--update-goldens` flag `test_plan.md` §5 describes was never
      implemented. Worth a follow-up: implement it or amend the test plan.
- [x] **`GLOSSARY.ro.md`** — the Romanian glossary, all 43 terms one-to-one with the
      English one, cross-linked both ways. Register matches the existing RO docs
      (ecosystem anglicisms kept: finding-uri, tamper-evident, hash-chained).
- [x] **§4 rows and §18 boxes updated**: the docs-links row and the EN+RO row both go
      green, DOC-001's "fix/remove dead links" acceptance clause is met, and **§18 is now
      9 of 9 — nothing in it blocks `1.0.0`.**
- [x] **Fixed the Image-workflow break this caused** (`docker/Dockerfile:14` did
      `COPY readme/ readme/` — the wheel build needs pyproject's `readme =` target — and
      `.dockerignore` allow-listed `!readme/`). CI was green on the same push, so only the
      Image workflow caught it, in 7 s. **Why my pre-flight grep missed it: I filtered by
      file extension (`--include="*.py" --include="*.toml" …`), and `Dockerfile` and
      `.dockerignore` have none.** Search extension-blind when checking whether a path is
      still referenced. Also added `README.md` to image.yml's PR `paths:` filter — the
      build depends on it now, so a PR moving it again would otherwise skip the very
      workflow that catches this. Verified by building the image locally and running all
      six of the workflow's own assertions (version, mounted-SBOM scan, non-root uid 1000,
      155 MB < 200 MB, [web] extra reaches the password check, named volume writable).
- Remaining Phase 2 item: the asciinema cast (item 4). `docs/vex.md` stays on the backlog
  as a nice-to-have — it is not a README claim.

## 1.0 gate work (2026-08-18) — INV-8 + traceability refresh

- [x] **INV-8 now has a test** (`tests/invariants/test_m5_invariants.py`, 5 AST tests) —
      it was the only one of the ten invariants never written, deferred to "M5, when
      webhooks add POST" and then forgotten when M5 shipped the webhook sink. Walls:
      (1) only GET/POST reach the transport, only from `get_json`/`post_json`;
      (2) no HTTP verb called on a client receiver directly — the receiver check matches
      `httpx`/`requests`, anything named `client` or `*_client`, so the plausible
      reach-around `self._api._client.post(...)` is caught too, while FastAPI's *inbound*
      `@app.post` route decorator deliberately is not; (3) `post_json` has exactly one
      caller — `("watch/sinks.py", "WebhookSink")`, an exact-set assertion;
      (4) `cra/*` holds no `://` string at all, so the module that drafts Article 14
      notifications has nowhere to file one; (5) config's URL defaults are exactly the
      three read-only data sources, so no deployment can configure a submission target
      (the webhook is a per-run `--webhook` flag only).
- [x] **Each test proven to fail against a real mutation** before being kept — added a
      `put_json`, swapped `self._client.request` → `.post`, added
      `self._api._client.post(...)` in the sink, added a second `post_json` caller in
      `vex/write.py`, added `SUBMIT_ENDPOINT = "https://…"` to `cra/report.py`, added a
      `cra_submit_url` config field. Six mutations, six red tests, tree reverted clean.
- [x] **§4 traceability matrix refreshed** — it was a 2026-07-10 snapshot (said `watch`
      was a stub, `web serve` didn't exist, PyPI was unreserved). All 19 rows re-verified
      against `v0.4.1`; evidence now cites `module::function`, not line numbers that drift.
- [x] **§18 DoD checked off against evidence**: 7 of 9 done. Verified rather than
      assumed — coverage 94.54 % and the trust-critical five all ≥95 % (`models.py`,
      `vex/rules.py`, `cra/trigger.py` 100 %, `match.py` 99 %, `audit.py` 95 %); SEC-002
      bounds present with rejection tests; pip-audit in the `security` job; SPDX headers
      enforced by `tests/unit/test_spdx_headers.py` (a test, not the separate job the DoD
      line imagined — noted in the doc).
- Gate: 606 tests (was 601), 94.54 % coverage, ruff clean, mypy strict clean.
- **The 1.0 gate is now exactly two items, both documentation**: (1) no root `README.md`
  — `gh api repos/caisarus/euvd/readme` returns 404 — plus the missing `ARCHITECTURE.md`,
  `CONTRIBUTING.md`, and the `GLOSSARY.md`/`README.simple.md` link targets that exist only
  under `readme/`; (2) the Romanian glossary. `docs/vex.md` is the third, smaller gap.
- Found while verifying, NOT fixed (out of scope, no ticket yet): `http.py::USER_AGENT`
  advertises `https://github.com/euvd-watch/euvd-watch`, which does not exist — the repo
  is `github.com/caisarus/euvd`. It goes out on every request to ENISA/FIRST/CISA.
  README + `docs/integrations.md` also still pin `uses: caisarus/euvd@v0.3.1`; harmless
  (the tag pins the action YAML, and `version: ""` installs latest from PyPI) but stale.

## Release 0.4.1 (2026-08-12) — security release, on PyPI + GHCR

- [x] Pushed the 11 audit commits that had been sitting unpushed on `main`
      (`cfd1a31..c645a7d`). Full local gate first: 601 passed / 94.54%, ruff + mypy
      strict clean. CI green on all 11 jobs (the `dogfood (any, 1)` job's "exit code 1"
      is that job's *expected* exit code — findings above threshold, not a failure).
- [x] Tagged `v0.4.1`. Release workflow green: build → publish-pypi → verify-pypi →
      github-release. Image workflow green.
- [x] **`v0.4.1rc1` was tagged first and failed**, then deleted (nothing published — the
      run died at the version guard, all publish jobs skipped). Cause worth remembering:
      the Release workflow requires the tag to equal the version in `pyproject.toml` +
      `__init__.py`, so an rc needs **its own `chore(release): X.Y.Zrc1` commit** setting
      the version to the rc (that is how `v0.4.0rc1` was done — `4916d1a`, then `71c66e8`
      bumped to final). The `0.4.1` commit already carried the final version. Owner
      decision: skip the rc for this one — packaging inputs are byte-identical to
      `v0.4.0` except the version string (`release.yml` untouched), so the rc would only
      re-test a path `v0.4.0rc1` validated the day before, and the security fix ships now.
- [x] Verified independently, not just via the workflow's own check: PyPI `latest` =
      0.4.1 (wheel + sdist), fresh-venv `pip install euvd-watch==0.4.1` → `version`
      prints `0.4.1`, GitHub release `v0.4.1` published (not draft/prerelease), GHCR
      `:0.4.1` and `:latest` share the new digest `sha256:f613ca8e…3aea54` (distinct
      from 0.4.0's `sha256:ba9420e8…aeb2e`).
- [x] **The fix proven against the published artifacts**, both bug and fix reproduced
      from PyPI rather than from the working tree:
      `evaluate_range('2.4.0-2', '2.4.0-2')` → 0.4.0 gives `OUTSIDE`/`pep440` (a
      high-confidence "provably safe" for a component sitting on exactly the affected
      version), 0.4.1 gives `INSIDE` (finding survives). A genuinely inverted
      `>=2.0 <1.0` → 0.4.0 `OUTSIDE`/`pep440`, 0.4.1 `AMBIGUOUS` (unevaluable, kept for
      a human).
- [x] **Advisory re-drafted 2026-08-13 and committed** (the first draft died in a session
      scratchpad, so these live in the repo): `docs/advisories/draft-ghsa-01-silent-false-negatives.md`
      (the three false negatives — inverted range, purl-namespace veto, unreadable search
      page; High, CWE-697 + CWE-754) and `docs/advisories/draft-ghsa-02-webhook-url-in-logs.md`
      (webhook credential in logs; Moderate, CWE-532). Split in two because the impacts and
      remediations differ — the second needs webhook **rotation**, which upgrading does not do.
      Each file leads with the GHSA form fields (ecosystem pip, `euvd-watch`, affected
      `< 0.4.1`, patched `0.4.1`, suggested CVSS vector) and a paste-ready body.
      Affected-version claim verified against the tags, not just the CHANGELOG: `v0.3.0`,
      `v0.3.1` and `v0.4.0` each carry all four defects. PyPI holds only `0.3.1`/`0.4.0`
      (`0.3.0` was git tag + GHCR only), so `< 0.4.1` is right for the pip ecosystem and
      the GHCR tags are called out in prose.
- [ ] **Owner to publish** — paste both at
      https://github.com/caisarus/euvd/security/advisories/new; decide GHSA vs.
      release-note only, and whether to request CVEs. Replace each draft file with its
      published GHSA link afterwards.

## Release 0.4.0 (2026-08-11) — M6 in full, on PyPI + GHCR

- [x] CHANGELOG `## [0.4.0] — 2026-08-11` cut from `[Unreleased]`, with a new **Changed**
      section making the two breaking items explicit (docs/release.md's version policy
      requires pre-1.0 breaking changes under **Changed** with a `Breaking` prefix, and
      the Added prose alone didn't satisfy it): (1) `cra check`'s new exit code `3` —
      scripts treating any non-`1` exit as an all-clear must fail closed on `3`; (2) the
      on-disk state move to `state_dir/euvd-watch.sqlite` — auto-migrated and originals
      renamed not deleted, but direct readers/backup scripts must follow docs/storage.md,
      and downgrading to `0.3.x` requires restoring the renamed files.
- [x] `4916d1a` `chore(release): 0.4.0rc1` → CI + Image green → tag `v0.4.0rc1` →
      Release workflow green in 57s with exactly the rc job set (`build`,
      `publish-testpypi`, `verify-testpypi` success; the three PyPI/GitHub-release jobs
      skipped).
- [x] `71c66e8` `chore(release): 0.4.0` → CI + Image green → tag `v0.4.0` → Release
      workflow green (`build`, `publish-pypi`, `verify-pypi` clean-venv install check,
      `github-release` all success).
- [x] Published artifacts verified independently of the workflow's own reporting: PyPI
      `euvd-watch` latest = `0.4.0` (wheel + sdist); GitHub release `v0.4.0` published
      (not draft/prerelease) with both assets; GHCR **anonymous** pull of `:latest` and
      `:0.4.0` OK and **identical digest** `sha256:ba9420e8…aeb2e`, 163 MB, `version`
      prints `0.4.0`, and `import fastapi, uvicorn, jinja2` succeeds inside the image —
      i.e. `:latest` is now web-capable, so docs/deploy.md's `:latest` references are
      correct (this was the 6.4 blocker-fix's whole point).
- Gate before the rc commit: 588 tests pass, coverage 94.50%, ruff clean, mypy strict
  clean, `scripts/extract_changelog.py 0.4.0rc1` resolves via the rc→base fallback.
- NEXT per `plans/next_steps_plan.md`: Phase 2 documentation debt (ARCHITECTURE.md,
  CONTRIBUTING.md incl. alias-table governance, Romanian glossary, asciinema cast,
  README traceability sweep, CRA disclaimer on the web surface), then the §18 DoD audit
  gating `1.0.0` — targeted before 2026-09-11. Dashboard GA stays `1.1`.

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
