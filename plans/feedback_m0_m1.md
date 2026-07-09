# Critical review — M0 + M1 code vs. plan

> Reviewed 2026-07-09 against `plans/implementation_plan.md` and `plans/test_plan.md`,
> covering commits `19dcab8` (M0), `eec4af2` (fixture), `b24fae2` (M1).
> Every item below marked **[verified]** was reproduced empirically during the review, not
> inferred from reading. Items are ordered by severity within each section. Check items off
> as they are addressed; several are explicitly gated "before M2" because M2 builds directly
> on the flawed piece.

## How to read the priorities

- **P1 — correctness bugs.** User-visible wrong behavior today. Fix before or at the start
  of M2.
- **P2 — plan-compliance debt.** The plan or test plan requires something we don't have;
  the gap compounds if M2 starts on top of it.
- **P3 — design debt / future traps.** Not wrong today, but a known trap for a later
  milestone. Fix opportunistically; each names the milestone it will bite.

---

## P1 — correctness bugs

### 1.1 Exit-code contract violated for unexpected parse-shaped errors **[verified]**

The global rule (implementation plan, "Global engineering rules") is exit `2` = execution
error. But the parsers only wrap `json.JSONDecodeError`/`OSError` into `SbomParseError`;
anything else escapes as a raw traceback with exit **1**.

Reproduced: `{"components": [{"type": "library", "name": "x", "version": 1.5}]}` — a
numeric version, which real tools do emit — crashes with a pydantic traceback,
exit 1 (`src/euvd_watch/sbom/cyclonedx.py:70` constructs `Component` with unvalidated
`raw.get("version")`; `version: str | None` does not coerce int in pydantic v2).

**Fix:** at the parser boundary (`_parse_document` in both parsers), either coerce scalar
fields with `str(...) if ... is not None` (consistent with the "tolerant parse" philosophy)
or catch `pydantic.ValidationError` and re-raise as `SbomParseError` with the component's
`raw_ref`/index in the message. Add a fixture (`weird-types.cdx.json`) to the parser tests.
The test plan's failure taxonomy ("malformed record skipped with warning, not crash",
Step 2.2) suggests the same tolerance belongs here.

### 1.2 `read_text()` without `encoding="utf-8"` — breaks on native Windows **[verified]**

`sbom/_load.py:20`, `config.py:47` use locale-default encoding. Our own committed fixture
contains non-ASCII (author `Sebastián Ramírez` + a `0x81` byte); decoding it as cp1252 —
the default on native Windows Python — raises `UnicodeDecodeError`, which is uncaught
(→ traceback, exit 1, compounding 1.1). SBOM JSON is UTF-8 by spec. The user runs this repo
from Windows (`/mnt/c/...`), so "native Windows Python" is a realistic consumer, and the
dashboard/CI users of M5–M6 certainly are.

**Fix:** `read_text(encoding="utf-8")` in both files; also wrap the `bytes.decode("utf-8")`
branch of `load_json` so a bad byte raises `SbomParseError`, not `UnicodeDecodeError`.

### 1.3 Config silently ignores unknown keys — typos go undetected **[verified]**

Step 0.3's acceptance criterion: *"invalid config produces exit code 2 and names the bad
field."* Reproduced: `epss_treshold: 0.9` (typo) validates fine and the default 0.5 is used
silently. For a tool whose config gates a *legal reporting trigger* (`cra_trigger`,
`epss_threshold`), a typo silently reverting to defaults is exactly the "dangerous silence"
the test plan's principle #1 warns about.

**Fix:** `model_config = ConfigDict(extra="forbid")` on `Settings`/`OrganizationConfig`
(`config.py:20,28`) and a test asserting a typo'd key names itself in the error. Caveat:
`readme/readme.md`'s example config already shows a `cra_trigger:` block that `Settings`
doesn't define until M4 — either add the field now as a stub model, or accept that the
README example fails until M4 (it does say the field list grows per milestone). Decide
explicitly; don't leave `extra` at the default.

### 1.4 `~` in user-supplied `cache_dir` is not expanded **[verified]**

`config.py:34` calls `.expanduser()` on the *default* at class-definition time, but a YAML
or env-supplied `~/.cache/euvd-watch` stays literal (verified: `Settings.model_validate
({"cache_dir": "~/..."})` keeps the `~`). The shipped example config
(`examples/config/euvd-watch.yaml:1`) uses exactly that value, so any user who copies it
gets a literal `./~/` directory the moment M2's cache writes to disk.

**Fix:** a `field_validator` on `cache_dir` doing `Path(v).expanduser()`. One test with a
YAML fixture containing `~`.

### 1.5 Nameless components silently collapse in dedupe **[verified]**

`cyclonedx.py:70` defaults a missing `name` to `""`. Two nameless components with the same
version then share dedupe key `("", version)` and the second is silently dropped
(reproduced: 2 in → 1 kept, 1 "deduplicated"). A dropped component is a component that
never gets matched against the EUVD — a silently missed finding, the exact failure mode the
test plan says the suite exists to prevent.

**Fix:** treat a missing/empty `name` as a parse-level defect: skip the component *with a
warning* (consistent with Step 2.2's "malformed record skipped with warning") or raise
`SbomParseError`, but never let `""` flow into dedupe. Same check in `spdx.py:83`.

### 1.6 Summary line prints twice in table mode **[verified — visible in smoke test]**

`cli.py:83` echoes the summary to stderr unconditionally, then `cli.py:104` echoes it again
to stdout in table mode. In a terminal both streams interleave, so the user sees the line
twice (the M1 smoke test output shows the duplication). The stderr copy was justified for
JSON-mode stdout purity; in table mode it's just a duplicate.

**Fix:** echo to stderr only when `state.output is OutputFormat.JSON`.

---

## P2 — plan-compliance debt (clear before/at M2 start)

### 2.1 `live` marker exclusion not configured; markers defined but never applied **[verified]**

Test plan §2: *"Default run excludes `live`."* `pyproject.toml` defines all six markers but
`addopts` has no `-m "not live"`, and zero tests carry any of the level markers. Today it's
latent (no live tests exist); M2 introduces the nightly live job, at which point the default
run would hit the network — the test plan's hardest rule ("No network in unit or integration
tests. Ever.").

**Fix:** add `-m "not live"` to `addopts` (and an explicit `pytest -m live` invocation in
the future nightly CI job); start applying `@pytest.mark.unit/integration/e2e` when files
are next touched — the CI test topology in test plan §7 selects by marker.

### 2.2 `tests/invariants/` (§6) doesn't exist

Test plan §6 is an executable "must never happen" list, and Step 1.4's own text says the
synthesized-flag rule is *"asserted here **and** re-asserted as an invariant (§6)"*. M1
shipped the first invariant-bearing code (synthesized purls) with no invariant suite.
M2 adds the big ones (no `high` confidence from fallback comparator, etc.) — starting the
directory now with the one M1 invariant keeps §6 from becoming retroactive work.

**Fix:** create `tests/invariants/test_m1_invariants.py`: for every fixture SBOM, every
component with `normalized_purl` set and `purl is None` has `synthesized=True`, and
`normalize_component` is idempotent over every real fixture component.

### 2.3 No logging anywhere; `--verbose` is dead

`cli.py:49` accepts `--verbose`, stores it, and nothing reads it. There is no `logging`
configuration in the codebase at all. Step 2.1 requires *"structured logging of every
request (URL, status, cache hit/miss, duration)"* — if M2 starts without a logging
bootstrap, ad-hoc prints will creep in.

**Fix (small, before M2):** a `logging_setup(verbose: bool)` helper called from the
callback; parser warnings from 1.1/1.5 above get a real channel at the same time.

### 2.4 Fixture provenance/regeneration not documented in-repo

Test plan §5 is "fixture governance"; M2's plan text institutionalizes capture scripts
(`scripts/capture_fixtures.py`). M1's fixtures (Syft venv scan, GitHub SBOM export) have
their exact regeneration commands only in commit messages and session memory. Anyone
regenerating `syft-demo.cdx.json` casually will churn three golden files (the goldens are
byte-coupled to it) — including after any dev-dependency change, since the fixture is a
scan of `.venv`.

**Fix:** `tests/fixtures/README.md` documenting: source + exact command per fixture, the
warning that regenerating `syft-demo.cdx.json` invalidates `golden/*.inventory.json`, and
that GitHub's export endpoint wraps the SPDX doc in `{"sbom": ...}`.

### 2.5 PyPI name not reserved

The plan's timeline section says the first release happens *"using a project name reserved
on PyPI as early as M0."* Not done — and `euvd-watch` is exactly the kind of name that can
be squatted. This is a 15-minute action (build sdist in the Docker container, `twine upload`
a 0.0.1 placeholder or use PyPI's project-name reservation via a minimal release), but it
needs the user's PyPI account, so it's a **user-action item**, not a code change.

### 2.6 `--output json` has a snapshot test but no schema validation

Test plan Step 1.5: *"`--output json` validates against the Inventory schema and matches
golden."* Only the golden match exists. Cheap fix: validate the CLI's stdout with
`Inventory.model_validate_json` in the same test (round-trip), which also catches golden
drift that a pure string comparison can't explain.

---

## P3 — design debt / future traps (each names where it bites)

### 3.1 Synthesized purls are not canonical **[verified]** — bites M2 matching

`normalize.py:87` builds purls by f-string. Reproduced: name `My Widget`, version `v1.0.0`
→ `pkg:pypi/My Widget@v1.0.0` — contains a space (invalid purl), keeps the `v` that
`clean_version` strips elsewhere, and fails the module's own idempotence claim
(`normalize_purl(synthesized) != synthesized`). M2's matcher derives (vendor, product)
candidates from `normalized_purl`; feeding it non-canonical purls undermines the field's
one guarantee.

**Fix:** construct via `PackageURL(type=eco, name=name, version=clean_version(version))
.to_string()` (encodes/normalizes properly), and add "synthesized purls are canonical" to
the §6 invariants.

### 3.2 `cpe_parts` values keep backslash escapes — bites M2 matching

`parse_cpe` splits correctly on unescaped colons but stores field values with `\<`, `\+`
etc. intact (the test at `tests/unit/test_normalize.py:107` locks this in). M2's structured
match normalizes vendor/product "lowercase, punctuation-insensitive" — it will need decoded
values. Either unescape here (one `re.sub(r"\\(.)", r"\1", ...)` per field) or explicitly
document that `cpe_parts` is raw and the matcher owns decoding. Deciding now avoids a
silent double-unescape later.

### 3.3 Epoch stripping in `clean_version` loses ordering information — bites M2 versions.py

`1:1.0` sorts *after* `2.0` in deb semantics; the stripped `normalized_version` can't know
that. Raw `version` is retained on the model, so nothing is lost — but M2's `versions.py`
comparator must be written against **raw** versions for deb/rpm schemes, not
`normalized_version`. Record this constraint in `docs/matching.md` when it's written;
otherwise the comparator will naturally (and wrongly) reach for the normalized field.

### 3.4 `_infer_ecosystem`'s `go-`/`node-` prefixes over-match — bites M2 confidence

A pypi package whose CPE product starts with `go-` (e.g. `go-pro-utils`) would synthesize a
`pkg:golang/...` purl. M2's confidence caps (synthesized ⇒ never above `medium`) contain
the damage, which is why this is P3 not P1 — but when the M2 truth table is built, include
a case for a mis-inferred ecosystem so the cap is actually exercised.

### 3.5 `dedupe_key`'s union type (`str | tuple`) — bites M2 ergonomics

Heterogeneous key types work for set membership but make findings ordering ("by component
dedupe_key" — Step 2.3) awkward: `sorted()` over mixed str/tuple raises `TypeError`. M2's
deterministic-ordering requirement will trip on this. Consider making the property always
return `str` (e.g. `purl:<...>` / `name:<name>@<version>`) before M2 depends on it.

### 3.6 Inventory JSON output carries no schema version — bites the first release

Step 2.5 gives the *findings* artifact a `schema_version`. The `scan --output json` shape
is equally a public contract (CI consumers), and it will change (M2+ fields). Adding
`schema_version: 1` to the JSON output (not necessarily to the model) before `0.1.0`
publishes is much cheaper than after.

### 3.7 Minor code-quality notes (fix opportunistically)

- `cli.py:1` module docstring is stale ("Commands are stubs…" — `scan` isn't).
- `cyclonedx.py:59` `counter: list[int]` mutable-ref hack — an `itertools.count` passed
  down, or enumerate-after-flatten, reads better.
- `Component.licenses`/`hashes` defaults are mutable literals — safe under pydantic
  (deep-copied per instance) but the model is only shallowly frozen: `component.hashes
  ["X"] = "y"` still mutates. If deep immutability is wanted, use `tuple[str, ...]` /
  frozen mappings; otherwise fine as-is.
- Table output is unbounded — a 5 000-component SBOM prints 5 000 rows. A `--limit`/head
  behavior or "… and N more" footer is worth considering before the dashboard (M6) makes
  tables the primary surface.
- The e2e performance test (`< 2 s`) runs against `/mnt/c` (WSL cross-filesystem I/O);
  if it flakes in CI or locally, prefer moving the fixture read to tmpfs over raising the
  budget — the budget is a plan acceptance criterion.
- Plan rule "every public function has a docstring stating what it does **and why it
  exists**": the *what* is consistently there, the *why* mostly lives in module docstrings.
  Acceptable, but keep the module-docstring habit as files grow.

---

## What's genuinely solid (keep doing this)

- The parity test (`test_detect.py::test_same_logical_package_parses_equal_across_formats`)
  is exactly the right proof for the format-blind matcher contract.
- Golden files generated from *real* tool output (Syft, GitHub export) rather than
  handcrafted approximations — the test plan's "fixtures over mocks" principle, honored.
- `_load.py` extraction killed the parser boilerplate duplication before a third copy
  (detect.py) appeared.
- Byte-determinism is tested, not assumed, and `Inventory.timestamp` deliberately carries
  the *source document's* timestamp rather than generating one — the determinism rule
  survived contact with implementation.
- The messy-case table mines the real fixture instead of inventing cases, so it grows
  automatically with fixture realism.

## Suggested sequencing

1. **Before M2 step 2.1:** P1 items 1.1–1.6 (one small PR: parser hardening + encoding +
   config validators + CLI dedup of summary) and P2 items 2.1–2.3 (test-infra config +
   logging bootstrap). These all touch code M2 sits on.
2. **With M2's first steps:** 3.1, 3.2, 3.5 (normalize/dedupe-key changes are cheaper
   before the matcher consumes them), 2.4 (fixture README, extended by 2.2's capture
   scripts anyway).
3. **User action, any time:** 2.5 (PyPI name reservation).
4. **Before 0.1.0 release:** 3.6 (schema_version), 2.6.
