# euvd-watch — next-steps plan: to 1.0, 1.1, publication, and funding

Written 2026-08-08, after M6 Step 6.1 shipped (`8d11dd3`). This is the working plan
for everything that remains. It is written to be executed step by step by an
implementing agent (Claude Sonnet 5), with the funding/publication actions explicitly
split between "agent drafts" and "owner submits".

## How to use this plan

- **Read first, every session:** `CLAUDE.md` (non-negotiable engineering rules),
  `tasks/todo.md` (live state), and the step you are about to implement in
  `plans/implementation_plan.md` + `plans/test_plan.md` (§M6). The test plan wins on
  testing questions. This document sequences and annotates; it does not override them.
- **Strict order within a phase; phases 1–3 are sequential.** Phases 4–6
  (publication/funding/community) can proceed in parallel with engineering, because
  their critical path runs through the owner, not the code.
- **Never mark a step done without demonstrating it** (run the suite, exercise the
  changed flow, watch CI green on the pushed commit). Update `tasks/todo.md` and the
  docs in the same commit as the behavior they describe.
- **Hard stop-points for the owner** are marked `OWNER:`. The agent prepares
  everything up to the submission/announcement boundary and stops — the same
  human-in-the-loop principle the tool itself follows.

## Why the calendar matters (the one-paragraph strategy)

The CRA's Article 14 reporting obligations — the exact duty this tool operationalizes
— **become applicable on 11 September 2026** (Regulation (EU) 2024/2847; verify the
date and any ENISA implementation guidance at execution time, and record it in
`docs/cra.md`). Every EU manufacturer of products with digital elements acquires a
24-hour reporting duty for actively exploited vulnerabilities on that date, ~5 weeks
from this plan's writing. A working, documented, installable tool that drafts those
notifications, published *before* that date with a visible 1.0, is the single
strongest positioning and funding argument this project will ever have. The schedule
below is built backwards from it.

---

## Phase 1 — Finish M6 (dashboard)

### Step 6.2 — Web application (the big one; ~4–6 sessions)

Authoritative spec: `implementation_plan.md` §Step 6.2, `test_plan.md` §M6 6.2,
decisions in `docs/AUDIT_AND_REMEDIATION_PLAN.md` §17. Condensed sequence:

1. **`[web]` extra plumbing.** Add `web = ["fastapi", "uvicorn", "jinja2"]` (pin
   compatible ranges, not exact versions) to `pyproject.toml`. `euvd-watch web serve`
   without the extra installed must exit `2` with an actionable
   `pip install euvd-watch[web]` hint — test this with the extra absent (subprocess or
   import-mock), because the dev environment will have it installed.
2. **Read models.** Populate the two tables 6.1 created empty:
   `vex_status_cache` (rebuilt from `vex-decisions.yaml` + current findings — it is a
   cache; a rebuild function, not incremental bookkeeping) and `audit_log_refs`
   (path + recorded_at of the audit log file(s) in `state_dir`). Both are read models:
   losing them must never lose information.
3. **App skeleton.** FastAPI + server-rendered Jinja2, **no SPA, no JS build chain, no
   inline event handlers** (CSP-friendliness is a regex-swept test). Basic auth from
   config (**hashed** password in `euvd-watch.yaml`; document the hash-generation
   command), bind `127.0.0.1:8642` by default, document loudly that TLS/termination
   belongs to a reverse proxy. All reads go through `web/store.py` — never a second
   SQLite connection layer.
4. **Pages, in build order:** Overview (counts + open CRA clocks with countdown) →
   Findings (filter by confidence/exploited/status, **paginated**) → Finding detail
   (explanation + confidence verbatim from the store, EUVD data, VEX status, decision
   shortcut instructions) → CRA events → Audit-log viewer with a verify button
   (re-uses `cra/audit.py::verify`; never reimplement the chain check).
5. **The only writes** are `cra mark` equivalents and VEX-decision *hints*; both
   require auth; nothing on the web surface may ever submit anything externally
   (INV-8 applies to the web app too — extend the invariant test's allowlist scan to
   `web/`).
6. **CLI table cap (M0/M1 review item 3.7, folded in here by the plan):** the CLI
   findings table gets an "… and N more" cap; the web Findings page paginates.
7. **Tests** (test_plan §6.2): every route 200 with demo-scenario data via FastAPI
   TestClient; 401 without credentials on all routes; write endpoints reject
   unauthenticated; no-inline-handlers regex sweep; finding detail shows explanation +
   confidence verbatim. Respect the no-network rule — demo data comes from the primed
   fixtures, exactly like `examples/demo.sh`.
8. **Acceptance:** dashboard renders real data from the demo scenario end-to-end.
   Extend `examples/demo.sh` (or a sibling script) to seed state and `web serve`, and
   verify by driving the real server once (curl the pages), not only TestClient.

While in the storage/query code, close the **parked feedback_m2 3.4 small items**
(recorded in `tasks/todo.md`): cache purge sweep, `get_by_cve` page cap, fixture
annotations. Separate commit, before or after 6.2 — not mixed into it.

### Step 6.3 — Accessibility (WCAG 2.1 AA)

1. Build semantics in from the start of 6.2 (landmarks, skip-link, focus states,
   table headers/scope, `aria-live=polite` countdowns, keyboard reachability) — 6.3
   is then a verification step, not a rework step.
2. Add the `a11y` CI job: pa11y (axe engine) against every page rendered with demo
   data; **zero serious/critical violations** is the gate. Runs on PRs touching
   `web/` + nightly (test_plan §CI matrix).
3. Write `docs/accessibility.md` with the manual keyboard-pass checklist; execute it
   once, date it. Acceptance: CI gate green + dated checklist.

### Step 6.4 — Deployment docs

1. `docs/deploy.md`: docker-compose example (watch + web + volume), Caddy
   reverse-proxy TLS example, backup guidance (point to `docs/storage.md` — the DB
   file + audit log together), upgrade procedure (`pip install -U` / image tag bump +
   `db migrate`).
2. The doc *is* the test: cold-start on a clean container following only the doc,
   timed **< 15 minutes**; every deviation found becomes a doc fix before the
   milestone closes. The agent can execute this itself with Docker.

---

## Phase 2 — Documentation debt & 1.0 gaps (can interleave with Phase 1)

Verified missing as of 2026-08-08. **Items 1, 2, 3, 5 and 6 closed 2026-08-19; only
the asciinema cast (4) remains.**

1. **`ARCHITECTURE.md`** — DONE 2026-08-19. Module map by milestone, the pure-core /
   I/O-at-the-edges shape, the web/store layering, the ten invariants as a table, and a
   closing section on *why* the boundaries sit where they do.
2. **`CONTRIBUTING.md`** — DONE 2026-08-19. Setup, the checks (incl. the single-file
   coverage-gate trap), the non-negotiable rules, truth-table governance ("every wild bug
   becomes a row *before* its fix merges"), the **alias-table evidence rule** from §17
   decision 6, fixture/golden governance, Conventional Commits, and good first
   contributions. Documents the golden-file procedure **as it actually is** — byte
   comparison, updated by hand, diff explained in the PR — because the `--update-goldens`
   flag test_plan §5 describes was never implemented.
3. **Romanian glossary translation** — DONE 2026-08-19 (`GLOSSARY.ro.md`, all 43 terms,
   cross-linked with the English one). The committed follow-up to
   the Romanian-docs decision.
4. **Asciinema recording** embedded in the README (X.2 leftover) — record
   `examples/demo.sh`.
5. **README traceability sweep** (§18) — DONE 2026-08-19. The README moved to the repo
   root (it had been at `readme/readme.md`, so GitHub served a **404** for the project's
   front page), its four dead links now resolve, the "🚧 coming with their milestones"
   list is replaced by links to all ten shipped `docs/*.md` pages, and the CI snippet's
   action pin moved `@v0.3.1` → `@v0.4.1`. A link checker over all 22 markdown files
   reports 0 broken relative links.
6. **CRA disclaimer check** (§18) — DONE, verified 2026-08-17: present in `docs/cra.md`
   ("it does **not decide** whether something is legally reportable, and it **never
   submits**") and on both CRA dashboard pages.

---

## Phase 3 — Releases: 0.4.0 → 1.0.0 → 1.1

The release mechanics are automated and proven (`docs/release.md`; tag → TestPyPI rc
→ PyPI). Sequencing:

1. **`0.4.0` — after 6.2 lands.** Storage consolidation + dashboard (beta) + small
   items. Dashboard documented as beta; `[web]` extra keeps core lean.
2. **`1.0.0-rc1` → `1.0.0` — gated on the §18 DoD audit.** Run
   `docs/AUDIT_AND_REMEDIATION_PLAN.md` §18 as an explicit checklist commit: each
   item verified with evidence or fixed. The 1.0 *claim* scope is CLI + CRA + watch +
   integrations + docs (owner decision §17.5); the dashboard being present-but-beta
   does not block it. **Target: tag `1.0.0` before 2026-09-11** (CRA Art. 14
   applicability). If 6.3/6.4 threaten the date, ship 1.0.0 first — they gate 1.1,
   not 1.0.
3. **`1.1.0` — dashboard GA** once 6.3 (a11y gate) and 6.4 (cold-start test) pass.
4. Every release: changelog section first (the build fails without it), version in
   two files, CI green before tagging — per `docs/release.md`, which held up
   perfectly for 0.3.1.

---

## Phase 4 — Publication & visibility

Engineering-adjacent (agent does, owner reviews):

1. **Documentation site**: MkDocs Material over the existing `docs/` + README,
   published via GitHub Pages workflow. Low effort, large credibility gain; do after
   6.4 so deploy docs are included.
2. **Demo assets**: the asciinema cast (Phase 2.4) + screenshots of the dashboard for
   the README once 6.2 renders.
3. **Comparison/positioning page** (`docs/why.md` or README section): honest table vs
   Trivy/Grype/OSV-scanner/Dependency-Track. The wedge: those tell you *what's
   vulnerable*; euvd-watch is **EUVD-native** (the EU's own database, exploited flag
   included) and operationalizes the **CRA Article 14 duty** end-to-end (trigger →
   24h/72h clocks → notification draft → tamper-evident audit trail). No mainstream
   tool drafts Article 14 notifications today. Never disparage; position.
4. **Zenodo DOI** for the repo (citability for the funding applications).

Announcement (agent drafts, **OWNER: submits/posts**, sequenced around 1.0.0 and the
2026-09-11 news cycle):

5. Show HN ("Show HN: euvd-watch – open-source CRA Article 14 reporting toolkit,
   EUVD-native"), r/netsec + r/python + r/devops, fosstodon/LinkedIn. The CRA
   deadline week itself will produce compliance-panic coverage — time the push to it.
6. **Awesome lists**: PRs to awesome-sbom / awesome-supply-chain-security /
   awesome-cyber-resilience-act (check current list names at execution).
7. **Communities**: OpenSSF (SBOM Everywhere / vuln-disclosure WGs), CycloneDX slack,
   OWASP chapters. **ENISA**: submit structured feedback on the EUVD beta API
   (`docs/euvd-api.md` documents real quirks — that feedback builds the relationship
   with the data provider this tool depends on).
8. **Talks** (owner decides venue; agent drafts abstracts): DefCamp Bucharest
   (Nov 2026, home turf), FOSDEM security devroom (Feb 2027, CfP ~Nov 2026), OWASP
   chapter meetups anytime.

---

## Phase 5 — Funding

Primary target — **NLnet Foundation / NGI Zero (Commons Fund)**:

- **Why it fits, precisely**: EU-funded, funds exactly this profile (small
  open-source infrastructure, €5k–€50k, no equity), the implementation plan already
  name-drops NLnet review criteria (accessibility!), and the pitch writes itself:
  *European vulnerability data (ENISA's EUVD) + European regulation (CRA) + European
  license (EUPL-1.2) + WCAG-compliant dashboard*. Calls run roughly every two months;
  **check the current deadline at nlnet.nl immediately**.
- **Agent prepares**: the application draft — abstract (~1200 chars), "compare with
  existing efforts" (Phase 4.3 feeds this), budget/milestone breakdown (use the
  remaining roadmap: 1.1 dashboard GA, alias-table curation program, EUVD API
  hardening, packaging for distros, sustained maintenance), amount requested, and
  answers on licensing/governance. Keep it in `plans/funding/nlnet-application.md`.
- **OWNER: submits** the form, is the named applicant, handles the interview.

Secondary / parallel:

1. **GitHub Sponsors + funding.yml** — enable now; near-zero effort, signals
   sustainability intent on every repo view. (Open Collective only if fiscal hosting
   is ever needed for contractor payments.)
2. **Sovereign Tech Agency (Germany)** — funds *critical open infrastructure in use*;
   realistic after 1.1 + demonstrable adoption (downloads, dependents, distro
   packages). Keep on a 2027 calendar, not now.
3. **EU cascade funding** (NGI/Horizon open calls, e.g. via F6S) — monitor for
   CRA-tooling-shaped calls; the 2026–27 window will likely produce them.
4. **Revenue-shaped sustainability** (owner's call, post-1.0): paid support/CRA
   compliance consulting around the free tool; hosted watch instances for SMEs. The
   tool stays fully open (EUPL) — services, not licenses, are the model that fits it.
5. **OpenSSF Alpha-Omega / Tidelift** — only meaningful with adoption; revisit 2027.

Sequencing note: funding applications *strengthen* with each phase-4 artifact (docs
site, DOI, comparison page, 1.0 tag, first external users/issues). Submit the NLnet
application as soon as 1.0.0 is tagged — do not wait for 1.1.

---

## Phase 6 — Community & adoption mechanics

1. Issue + PR templates (bug/feature/EUVD-data-mismatch — the last one feeds the
   alias table + truth tables, turning users into curators of the matching memory).
2. 5–10 `good first issue`s seeded from real small work (glossary translation,
   alias-table entries, a new sink, distro packaging).
3. Roadmap visibility: a `ROADMAP.md` distilled from this plan (public-friendly, no
   internal process notes), linked from the README.
4. Adoption instrumentation you can ethically have: PyPI download stats
   (pypistats/pepy), GitHub stars/dependents, GHCR pulls — recorded monthly in
   `plans/adoption-log.md`; this series is funding-application evidence.
5. Nightly live-smoke drift issues (already automated) get triaged within a week —
   the EUVD API is beta; visible responsiveness to drift is the project's reliability
   story.

---

## Suggested calendar (aggressive but honest; owner adjusts)

| When | What |
|---|---|
| Aug w2–w3 2026 | Step 6.2 web app + small items; `0.4.0` |
| Aug w4 | §18 DoD audit commit; Phase 2 docs debt; `1.0.0-rc1` |
| Sep w1 | **`1.0.0` tag**; NLnet draft finalized; OWNER submits; announcement assets ready |
| Sep 11 + week | OWNER: Show HN / posts, riding the CRA applicability news cycle |
| Sep w3–w4 | 6.3 a11y + 6.4 deploy docs; `1.1.0`; docs site live |
| Oct–Nov | DefCamp/FOSDEM CfPs, ENISA feedback, adoption log, distro packaging explorations |

## Execution rules recap (for the implementing agent)

- Follow `CLAUDE.md` invariants without exception; the test plan is authoritative on
  tests; wild bugs become truth-table rows before their fix.
- One step per commit sequence; verify → commit → push → CI green → `tasks/todo.md`
  updated. Re-plan instead of patching forward when a step goes sideways.
- Anything that leaves the repo (posts, applications, emails, PRs to other repos) is
  drafted in `plans/` and handed to the owner. Nothing is submitted automatically —
  the project's own principle, applied to the project.
