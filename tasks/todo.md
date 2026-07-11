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

## Owner-blocked (cannot proceed without)

- [ ] GitHub org/name -> create remote, push, CI green (OPS-001)
- [ ] Reserve PyPI name `euvd-watch` (squatting risk, open since M1)

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
