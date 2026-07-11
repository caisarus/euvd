# Critical review — M4 (CRA Article 14 reporting workflow)

> Post-milestone review gate (mandated by `plans/implementation_plan.md` since `c207fef`),
> covering commits `3c32eaa`..`842a2f6` (trigger, state, clock, report, audit, `cra` CLI
> group, docs/cra.md). Reviewed 2026-07-11 against Steps 4.1–4.5, the hardening rules, and
> TEST_PLAN.md. Every finding marked **[verified]** was reproduced with a running repro
> before being written down.

## Status: both findings fixed (this commit)

414 tests before this review; the audit trigger/state/clock/report/audit modules read
cleanly against their own documented invariants (SEC-001/002/003 and TECH-002 from the
pre-commit audit all check out under direct testing — quarantine renames, never deletes;
`first_seen`/`fired_rules`/`policy_snapshot` are genuinely immutable across re-evaluations;
config rejects out-of-range `epss_threshold`, non-positive stage hours, empty/duplicate
stage names). Two new issues surfaced this review, both now fixed and regression-tested.

## P1 — correctness bug

### 1.1 `AuditLog.append` crashes with a raw `TypeError` on a non-dict last entry **[verified]**

`cra/audit.py::AuditLog._last_hash` reads the log's last line, calls
`json.loads(lines[-1])`, then immediately does `last["entry_hash"]`. If that line is
valid JSON but not an object — an array, a bare number, `null`, a string — indexing it
with a string key raises `TypeError`, which the `except (json.JSONDecodeError,
KeyError)` clause does not catch. Reproduced: an audit log whose last line is `[1,2,3]\n`
makes `AuditLog(path).append(...)` raise an uncaught `TypeError: list indices must be
integers or slices, not str`. `cli.py`'s `cli_command` decorator only converts escaping
`OSError` into a clean exit 2 — a `TypeError` propagates as a raw traceback to whichever
`cra` command tried to append (`check`, `draft`, `mark`). This is a direct recurrence of
the exact "no raw exception escapes to the CLI" rule this module's own docstring commits
to ("nothing here ever lets a raw sqlite3/pydantic exception escape to the CLI") and that
`feedback_m2.md` findings 1.2/1.3 already fixed once for `OSError` — the non-dict-tail
shape just wasn't in that generalization. Notably, `verify()` already guards this exact
shape correctly (`isinstance(entry, dict)` check, tested by
`test_entry_that_is_not_an_object_is_rejected`) — only the sibling code path in `append()`
was missing the same guard.

**Fix applied:** `_last_hash` now raises `TypeError` itself when the parsed last line
isn't a dict, caught by the same `except` clause as the pre-existing cases, producing the
documented `AuditError` ("Refusing to append... run 'euvd-watch cra verify-log'") instead
of a traceback. Regression test added:
`test_append_refuses_when_last_entry_is_not_an_object`.

## P2 — robustness/documentation gap

### 2.1 Renaming a configured stage silently un-completes it **[verified]**

`EventStore.mark_stage_completed`/`ClockState` key completions by `CraStageConfig.name`
(`event.stage_completions: dict[str, StageCompletion]`), and `cra_stages` is explicitly
config, not code (Step 4.2's whole point — legal text changes shouldn't need a code
change). Reproduced: mark `"early_warning"` completed on a real event, then edit
`euvd-watch.yaml` to rename that stage to `"early-warning"` (same stage, new name) —
`is_event_open(event, new_stages)` flips from `False` to `True`, and
`compute_all(event, new_stages, now)` reports the (already-filed) stage as `overdue`
using the original `first_seen` anchor, because the renamed stage's name no longer
matches the dict key the completion was recorded under. No data is lost (the orphaned
completion stays in the stored JSON, recoverable by reverting the name), but `cra
status`/`cra check` would falsely re-flag an already-handled legal deadline as
open/overdue — a real "cry wolf" risk given the whole point of this workflow is trustworthy
deadline tracking. SEC-002 already guards *creation-time* stage-list sanity (non-empty,
unique names); this is the *edit-time* sibling case that validation can't catch statically
(there's no way to tell "renamed this stage" from "removed one stage and added a
different one" from the config alone).

**Fix applied:** documented as an explicit operational caveat in `docs/cra.md` ("Do not
rename a configured stage once events exist... Add or remove stages freely - only
renaming an in-use name is unsafe"), alongside the existing `first_seen`-vs-real-awareness
caveat this section already carries. A code fix (e.g. stable stage IDs independent of the
display name) would be a real architecture change for a self-inflicted admin-edit
scenario with a cheap, honest documentation mitigation — not proportionate here.

## What held up well

- SEC-001 (quarantine-never-delete), SEC-003 (first-fire immutability), TECH-002
  (`StateError` boundary for corrupted/incompatible rows) all behaved exactly as the
  pre-commit audit intended under direct re-testing — no regressions found.
- The hash chain's tamper detection (edit/delete/insert/reorder, truncated-tail vs.
  tamper) is precise and correctly located the exact bad line in every scenario tried,
  including ones not in the existing test file (a non-dict tail during `verify()` was
  already covered; only the `append()`-side twin was missing).
- `docs/cra.md`'s "awareness caveat" and "what tamper-evident honestly means" sections are
  honest about the tool's real limits (proxy for awareness, not tamper-proof) — no
  overclaiming found anywhere in the CLI output or docs.
- Config validation (`epss_threshold` bounds, stage hours > 0, non-empty/unique stage
  names) correctly rejects the exact silent-footgun inputs the audit worried about at
  *creation* time.

## Suggested sequencing

Both findings are fixed in this same commit (small, isolated, fully test-covered) — no
further gating work needed before M5. Full suite must be re-verified green after this
commit (see below) before tagging `0.3.0`.
