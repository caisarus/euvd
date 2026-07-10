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

## M4-completion — CRA workflow (next)

- [ ] Fix SEC-001 (event store quarantines, never deletes) BEFORE first commit of cra/
- [ ] Fix SEC-003 (freeze first-fire policy_snapshot/fired_rules) BEFORE first commit
- [ ] Fix TECH-002 (typed StateError boundary + event schema_version field)
- [ ] SEC-002: config bounds (epss_threshold 0..1, cache_ttl_hours >= 0, stage hours > 0,
      unique stage names) — lands here because config.py is part of the M4 diff
- [ ] Tier-2 privacy toggle `tier2_product_search: true` (+ docs note) — same config diff
- [ ] Step 4.3 draft renderer (TODO-HUMAN markers; never upgrade a signal to an
      exploitation claim — REQ-CRA-004)
- [ ] Step 4.4 audit log (canonicalization spec frozen in a fixture; tamper matrix;
      truncated-tail vs tamper distinction; threat-model documented honestly)
- [ ] Step 4.5 `cra` command group + stubs for still-unshipped commands
- [ ] tests/invariants/test_m4_invariants.py (INV-6, INV-7); scenario S3
- [ ] docs/cra.md (verbatim Art. 14 stage source, awareness-proxy caveat, disclaimer)
- [ ] ruff clean over cra/ files; tag 0.3.0 after review gate

## Owner-blocked (cannot proceed without)

- [ ] GitHub org/name -> create remote, push, CI green (OPS-001)
- [ ] Reserve PyPI name `euvd-watch` (squatting risk, open since M1)

## Review — R1 (2026-07-10)

Shipped 5 commits on top of `e80e49e` (still no remote to push to). Full suite after R1:
all tests pass, coverage >= gate, mypy strict clean, ruff clean on touched files. The four
audit repro findings on committed code are closed; the three findings inside the
uncommitted M4 code (SEC-001/003, TECH-002) are deliberately left for the M4 commit series
so the fixes land before that code's first commit.
