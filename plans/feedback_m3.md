# Critical review — M3 (OpenVEX generation)

> Post-milestone review gate (mandated by `plans/implementation_plan.md` since `c207fef`),
> covering commit `aee188a`. Reviewed 2026-07-10 against Steps 3.1–3.4, the hardening
> rules, and TEST_PLAN.md. Every finding marked **[verified]** was reproduced with a
> running repro before being written down. P1 = correctness bugs to fix before M4;
> P2 = spec-conformance debt; P3 = consistency/forward-compat improvements.

## Status: all findings fixed (commit `24a8929`)

Both P1s, the P2, and both P3s are fixed and regression-tested; every original repro was
re-run to confirm before writing tests. 311 tests (was 306), live smoke tests and a live
`vex generate` run against the real EUVD both still pass. Nothing outstanding from this
review blocks M4.

## P1 — correctness bugs

### 1.1 Decision matching doesn't normalize the human-entered purl **[verified]**

`vex/merge.py::_matches` compares `entry.purl` against the component's already-normalized
`normalized_purl` directly — but never runs `entry.purl` through `normalize_purl()` first.
Reproduced: a component with SBOM purl `pkg:pypi/Requests@2.31.0` normalizes to
`pkg:pypi/requests@2.31.0`; a human who copies the purl **exactly as it appeared in `scan`/
`match` table output** (`pkg:pypi/Requests@2.31.0`, unnormalized — table output shows
`normalized_purl or purl`, which for many real components *is* already normalized, but any
component whose only source is a non-normalized `purl` with no `normalized_purl` populated
yet at table-render time, or a user typing from the raw SBOM file instead of tool output,
hits this) writes a decision that **silently fails to match** — it falls through to the
automated draft and is reported as a **stale decision**, with no diagnostic connecting the
two. This quietly defeats the human-in-the-loop mechanism, the entire point of Step 3.3, in
exactly the way a real user would trigger it.

**Fix:** normalize `entry.purl` via `sbom.normalize.normalize_purl()` before both the exact
and the pattern comparison in `_matches`.

### 1.2 Document `@id` (and `version`) never change when the statements do **[verified]**

`document_id` in `cli.py`'s `vex_generate` is `f"urn:euvd-watch:vex:{_inventory_digest
(inventory)}"` — a function of the **SBOM alone**. `version` is a hardcoded `1`. Reproduced:
building two documents for the *same* inventory with genuinely different statements (e.g.
the EUVD exploited catalog changed between two `vex generate` runs — exactly the project's
core "watch" scenario) produces **identical `@id` and `version`** despite materially
different content. Per OpenVEX's own convention (and CRA auditability generally), `@id` +
`version` are how a consumer tells two assessments apart / tracks an assessment's history;
any tool that stores/deduplicates VEX documents by identity would silently treat the new
assessment as "the same document," overwriting or ignoring the old one.

**Fix:** derive `@id` from a digest of the inventory **and** the resolved statements'
content (euvd_id, component identity, status, justification, explanation per statement),
not the inventory alone. Still deterministic for identical re-runs (the existing
determinism test continues to hold); now genuinely distinct whenever content differs.

## P2 — spec-conformance debt

### 2.1 Synthetic product `@id` can contain characters invalid in an IRI **[verified]**

`vex/build.py::_product_for_component`'s fallback (`urn:euvd-watch:component:
{component.dedupe_key}`, used when a component has neither a purl nor CPE-derived
identity) embeds the raw component name verbatim. Reproduced: a component named `"My Cool
Component Name"` produces `@id: "urn:euvd-watch:component:name:my cool component
name@1.0.0"` — a URN containing literal spaces, invalid per RFC 3986/3987. Neither our own
test suite (jsonschema's default validator doesn't enforce `format: "iri"`, and even with a
`FormatChecker()` attached, no `iri` format checker is registered without the `rfc3987`
package — confirmed empirically) nor `vexctl merge` (which passed it through unvalidated)
catches this today, but it's still a real spec violation a stricter consumer could reject.

**Fix:** percent-encode the dedupe-key segment (`urllib.parse.quote`) when building the
fallback `@id`.

## P3 — consistency / forward-compat

### 3.1 `vex init-decisions`'s scaffold date uses local time, not UTC

`cli.py`'s `vex_init_decisions` uses `date.today()` (system local timezone) while every
other timestamp in the codebase uses `datetime.now(UTC)` explicitly. Low impact (a
human-facing record-keeping field, off by at most one day near midnight), but it's the one
inconsistency with the codebase's own UTC discipline — worth fixing now since M4's clock
tracking needs that discipline to be exceptionless.

**Fix:** `datetime.now(UTC).date().isoformat()`.

### 3.2 `--findings` loader never checks `schema_version`

`cli.py::_load_findings_artifact` accepts any JSON object with a `"findings"` key,
regardless of `schema_version`. Harmless today (only version 1 exists) but the findings
artifact is explicitly versioned for future evolution (Step 2.5) — a future schema bump
with no version check here would silently misparse instead of erroring clearly.

**Fix:** assert `data.get("schema_version") == 1`, error otherwise (small, cheap, no urgency).

### 3.3 Unbounded VEX summary table (not new — same as M0/M1 finding 3.7)

`_render_vex_summary_table` renders every resolved decision with no cap, same class already
tracked for the `scan` command. No new tracking needed; still deferred to M6 (dashboard).

## What held up well

- The matcher refactor (`Outcome.MATCH`/`NOT_AFFECTED`) shipped with zero regressions to
  the 234-test M2 suite, confirmed again this review by re-reading the diff against the
  original.
- The `vexctl merge` round-trip preserved every field with full fidelity — the model/writer
  layer is solid.
- The conflict-detection and stale-decision logic behaved exactly as designed under direct
  testing; the only real gap was the *matching* step feeding it (finding 1.1), not the
  logic once a match is found.
- `format: "iri"` non-enforcement (finding 2.1's root cause) is a genuine gap in the
  ecosystem's own tooling, not something we could have caught without deliberately
  investigating it — worth remembering for any future IRI-shaped field.

## Suggested sequencing

1. **Before M4:** both P1s (1.1, 1.2) — M4's CRA workflow builds an audit trail on top of
   this data; a broken document identity or a silently-ignored human decision would
   propagate straight into CRA notification drafts. P2 2.1 is cheap, fix alongside.
2. **Opportunistic:** 3.1, 3.2 — small, no urgency, easy to fold into the same commit.
