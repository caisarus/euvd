# Critical review — M2 (EUVD client & matching engine)

> Post-milestone review gate (mandated by `plans/implementation_plan.md` since `c207fef`),
> covering commit `5dd4a97`. Reviewed 2026-07-10 against the plan's Steps 2.1–2.5, the
> hardening rules, and TEST_PLAN.md. Every finding marked **[verified]** was reproduced
> with a running repro before being written down. P1 = correctness bugs to fix before M3;
> P2 = defensibility/compliance debt; P3 = improvement opportunities with a named payoff.

## Status (updated 2026-07-10, commit `041e346`)

**Fixed:** all P1 (1.1–1.3) and P2 2.1, each confirmed by re-running the original repro
before writing regression tests. `get_json` now raises `ApiError` on any status ≥ 400
(never returns a JSON error body as data); every CLI command is wrapped in a `cli_command`
decorator that turns escaping `OSError` into a clean exit 2; `fetch_kev_cves` raises on a
malformed feed instead of returning an empty set. 234 tests (was 226), live smoke tests and
a live `match` run both still pass. See commit `041e346` for detail.

**Still open:** P2 2.2 (`data_freshness` overstate) and 2.3 (nightly live CI job — ride
with M5), and all of P3 (3.1 comma ranges, 3.2 client-level duplicate records, 3.3
scoped-npm vendor loss, 3.4 cache growth/page caps) — none block M3, scheduled per the
sequencing section below.

## P1 — correctness bugs

### 1.1 Non-retryable HTTP errors with JSON bodies become "no findings" **[verified]**

`http.py::get_json` never checks the status code of a non-retryable response: a 403/404
with a JSON error body (`{"error": "forbidden"}`) is parsed and **returned as data**.
`EuvdClient._search_pages` then sees a dict with no `items` and returns `[]` — so
`fetch_exploited()` yields zero records, `match` prints "0 findings" and exits 0.

Reproduced: a mocked 403-with-JSON transport → `fetch_exploited()` returned 0 records with
no error raised. This is the exact failure mode the plan forbids twice over ("never
silently report 'no findings' on missing data", Step 2.5; "the dangerous direction is
silence", test plan §1) — and it is *live-plausible*: ENISA already auth-gated one endpoint
(`/vulnerability` → 403, see `docs/euvd-api.md`); if `/search` follows, every `match` run
would silently go green.

**Fix:** in `get_json`, after retries, treat any status ≥ 400 as `ApiError` (keep 204 → None
and the 304 cache path). The e2e test `test_euvd_down_with_no_cache_exits_two_loudly` only
covers 503 (retryable); add 403-with-JSON-body and 404 cases asserting exit 2, and a client
test asserting `fetch_exploited` raises rather than returning `[]`.

### 1.2 `--save-findings` to an unwritable path → traceback, exit 1 **[verified]**

`cli.py` writes the artifact with a bare `save_findings.write_text(...)`; a missing parent
directory raises `FileNotFoundError` through Typer (exit 1, stack trace). Violates the
exit-code contract and the hardening rule "no unhandled exception may escape a CLI command"
— the same defect class as M0/M1 finding 1.1, in new code written *after* that rule landed.

**Fix:** wrap in `try/except OSError` → clear stderr message + exit 2 (and consider
`save_findings.parent.mkdir(parents=True, exist_ok=True)` first). Regression test.

### 1.3 Unwritable/uncreatable `cache_dir` → traceback, exit 1 **[verified]**

`Cache.__init__` does `self._path.parent.mkdir(...)`; pointing `EUVD_WATCH_CACHE_DIR` at an
uncreatable location (reproduced with `/proc/...`) raises `FileNotFoundError` uncaught.
Same class as 1.2.

**Fix:** wrap `ApiClient` construction in the `match` command (and future commands) with
`OSError` → message + exit 2; or catch in `Cache.__init__` and re-raise as `ApiError`.

## P2 — defensibility / compliance debt

### 2.1 A malformed KEV feed asserts `in_kev=False` instead of "unknown" **[verified]**

`fetch_kev_cves` returns an **empty set** for any JSON dict without a `vulnerabilities`
key (reproduced with `{"error": "service temporarily degraded"}`), and `enrich()` then
stamps `in_kev=False` — "provably not in KEV" — from garbage data. M4's CRA trigger
(`cisa_kev == true`) consumes this field: a degraded feed could silently suppress a legally
material 24-hour notification trigger. The distinction False-vs-None exists in the model
and is even tested — but only for the transport-failure path, not the malformed-body path.

**Fix:** in `fetch_kev_cves`, treat a response without a list-valued `vulnerabilities` key
as a failure (raise `ApiError`), so `enrich()`'s existing degradation path yields `None` +
warning. Add the malformed-feed case to `test_enrich.py`.

### 2.2 `data_freshness` can overstate freshness **[verified]**

`Cache.newest_stored_at()` is a MAX over *every* cache row — including EPSS/KEV entries
and rows written by later, unrelated runs sharing the cache. Reproduced: an unrelated
fetch after the EUVD data bumps the reported freshness above the EUVD rows actually used.
The stamp exists to qualify *EUVD* data in the findings artifact (a CRA-relevant artifact),
so it should reflect the EUVD responses consulted in this run.

**Fix:** have `get_json` (or the EuvdClient layer) report the `stored_at` of each response
it actually served, and stamp the **oldest EUVD response used** (worst case, not best) —
the honest bound for "how stale could this be".

### 2.3 Nightly live job (test plan §7) not wired

`tests/live/` exists and is correctly excluded by default, but no CI schedule runs
`pytest -m live`. Until it exists, drift between `docs/euvd-api.md` and the real beta API
is only caught manually. Small addition to `.github/workflows/` (a `schedule:` workflow) —
can ride along with M5's CI work, but note it explicitly so it doesn't silently vanish.

## P3 — improvement opportunities (named payoff)

### 3.1 Comma ranges `"X, < Y"` are unparsed → AMBIGUOUS **[verified, seen live]**

The real wheel record (EUVD-2026-4133) publishes `"0.40.0, < 0.46.2"` — an
introduced-at/fixed-before shape our parser doesn't recognize. Two effects, both
conservative but real: an in-range version gets `medium` instead of `high` (weaker CRA
evidence), and a version *below* the introduced-at bound (0.39.0) still yields a medium
finding instead of none (mild false positive). Also directly weakens M3's `not_affected`
evidence quality. **Fix:** add the `"A, < B"` / `"A, <= B"` shapes to
`versions.evaluate_range` + truth-table rows from this real record.

### 3.2 `fetch_exploited` can return duplicate records **[verified]**

Pages are fetched (and cached) at different moments; if the catalog shifts, the same
`euvd_id` can appear on two pages. Reproduced at client level (150 records → 1 unique).
The CLI's `_fetch_records` dedupes today, so no user impact — but the client's contract
shouldn't depend on every caller remembering to. **Fix:** dedupe by `euvd_id` inside
`_search_pages`.

### 3.3 Scoped npm purls lose their vendor signal **[verified]**

`pkg:npm/@babel/core` normalizes to `pkg:npm/%40babel/core`, and `derive_candidates`
emits `vendor='%40babel'` — which normalizes to `40babel` and will never equal a real
EUVD vendor (`babel`). Scoped npm packages therefore always fall to the vendor-less path.
**Fix:** percent-decode purl segments and strip the leading `@` when deriving candidates;
add an npm-scoped truth-table row.

### 3.4 Smaller items

- **Cache growth is unbounded** — expired rows are never purged; tier-2 accumulates one row
  per product query. Add a purge-expired sweep on `Cache` init (cheap, keyed on TTL).
- `get_by_cve` pages the full-text search up to MAX_PAGES **only on misses** (hits return
  early); acceptable today, worth a page cap when M4 starts calling it in bulk.
- Cosmetics: yield-fixtures annotated `-> ApiClient` instead of `Iterator[ApiClient]`
  (`tests/conftest.py`, `tests/live/`); `sleep: Any` in `ApiClient.__init__` could be
  `Callable[[float], None]`.

## Carried-forward design note (not a bug)

M3's Step 3.2 `not_affected` rule needs *"version provably outside the affected range with
a high-confidence range evaluation"* — evidence the matcher currently **discards** (a
provably-outside evaluation produces no Finding at all). M3 will need a matcher mode that
also reports strong-outside evaluations, or a separate evaluation pass. Decided at M2
review time that this belongs to M3's design, not M2's scope.

## What held up well

- The live verification found real vulnerabilities in our own venv with honest confidences
  and correct explanations — including the vendor-mismatch (`python` vs `pypa`) correctly
  holding setuptools below `high`.
- Hypothesis caught a genuine crash (`int()` on non-ASCII "digits") before it shipped.
- The M0/M1 hardening rules demonstrably worked where applied: UTF-8 everywhere, identity-
  key validation (records without ids skipped loudly), config extra=forbid, invariants
  suite extended in-step, mypy hook deps updated proactively. Findings 1.2/1.3 show the
  "no unhandled exception" rule needs *mechanical* enforcement (e.g. a shared CLI error
  boundary), not just recall — the same class recurred in new code.

## Suggested sequencing

1. **Before M3:** P1 items 1.1–1.3 (one small PR: status-code check in `get_json`, an
   OSError boundary in the CLI) + P2 2.1 (KEV malformed-feed) — all four touch code M3/M4
   sit on. Consider a shared `_cli_boundary` helper so exit-code discipline stops relying
   on per-command memory.
2. **With M3:** 3.1 (comma ranges — improves the `not_affected` evidence M3 needs), the
   carried-forward matcher-mode design note, 2.2 (freshness, feeds the artifact M3
   consumes), 3.2, 3.3.
3. **With M5 CI work:** 2.3 (nightly live job).
