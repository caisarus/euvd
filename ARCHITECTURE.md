# Architecture

How euvd-watch is put together, and *why* it is put together that way. This page is the
map; the per-module documents in [`docs/`](docs/) are the territory.

If a term here is unfamiliar, [GLOSSARY.md](GLOSSARY.md) explains every one of them in
plain language.

## The shape of the thing

euvd-watch is a **pipeline of pure transformations with the I/O pushed to the edges**.
Each stage takes the previous stage's data structure and produces the next one:

```
SBOM file ─► Inventory ─► Findings ─► VEX statements
                 │            │
                 │            └─► CRA events ─► deadline clocks ─► notification draft
                 │                                    │
                 └─► watch snapshots ─► diffs         └─► audit log (hash-chained)
```

Everything above the line is deterministic: the same inputs produce byte-identical
outputs. That is not an aesthetic preference — it is what makes golden-file tests
possible, and it is what lets a CRA audit trail be re-derived and checked years later.

Network access, the filesystem, and SQLite live at the edges: `http.py`, `web/store.py`,
`cra/state.py`, `cra/audit.py`. The engines in the middle — `euvd/match.py`,
`vex/rules.py`, `cra/trigger.py`, `watch/differ.py` — do no I/O at all. That is why they
can be tested exhaustively against truth tables instead of mocks.

## Modules, by milestone

The package layout mirrors the build order, so a module's name tells you when and why it
exists.

### `models.py` — the contract (M1)

One normalized `Component`/`Inventory` shape shared by every SBOM format. The matcher
never learns whether a component came from CycloneDX or SPDX. Every later stage speaks
this vocabulary.

### `sbom/` — ingestion (M1)

`detect` → `cyclonedx`/`spdx` parse → `normalize` → dedupe, behind the single entry point
`load_inventory()`. Normalization is where purls are canonicalized and, where a purl is
absent, *synthesized* — and synthesized identifiers are permanently marked as such,
because a guessed identifier may never earn high confidence downstream.

### `euvd/` + `enrich/` — matching and signals (M2)

The hard problem of the whole tool. The SBOM side speaks purl and CPE; the EUVD side
describes affected software as **vendor / product / version-range text**. `euvd/match.py`
bridges that gap: derive candidates per component (CPE fields first — the best signal —
then purl, assisted by the curated `aliases.yaml`), run strategies in order, keep the best
result per (component, record) pair.

`euvd/versions.py` decides whether a version falls inside a range, and reports *which
scheme* it used to decide — PEP 440, semver, or a fallback tokenwise comparison. This
matters: the fallback comparator can never support a `high` confidence verdict, and an
unevaluable range is `AMBIGUOUS`, which keeps a finding alive for a human rather than
silently dropping it.

`euvd/client.py` reads the EUVD API; `enrich/` adds EPSS scores and CISA KEV membership.
See [docs/matching.md](docs/matching.md) and [docs/euvd-api.md](docs/euvd-api.md).

### `vex/` — conservative suppression (M3)

Findings become draft OpenVEX statements. The default for *every* evaluation is
`under_investigation`. `not_affected` is auto-drafted only when the matcher proved the
component's version lies outside the affected range and can explain how — and
`affected`/`fixed` come only from a human's `vex-decisions.yaml`, merged in by
`vex/merge.py`. No code path may silently suppress a finding.

### `cra/` — the reporting duty (M4)

`trigger.py` is a pure, configurable policy engine: exploited flag, KEV membership, EPSS
over threshold. It is **three-valued** — a signal whose source was unavailable is
`UNKNOWN`, never "confirmed absent", so an unreachable KEV feed produces an
*indeterminate* result and exit code `3` rather than a false all-clear.

`state.py` owns "when did we first become aware", because that timestamp must survive
re-runs even as a finding's other details change. `clock.py` turns awareness into the
24 h / 72 h / final-report deadlines; `report.py` renders the notification draft, with
`TODO-HUMAN` markers everywhere only a human can answer. `audit.py` appends every decision
to a hash-chained log.

This module contains **no URL at all** — there is nowhere for it to file anything, which
is the human-in-the-loop guarantee made structural rather than promised. See
[docs/cra.md](docs/cra.md).

### `watch/` — change over time (M5)

`differ.py` compares two `Finding` lists in memory and reports only what is new, resolved,
or changed; `sinks.py` delivers that to stdout or a webhook. The CLI owns loading and
persisting snapshots, so the differ stays pure. See [docs/watch.md](docs/watch.md).

### `web/` — the dashboard (M6, beta)

FastAPI with server-rendered Jinja2 templates. No SPA, no build step, no JavaScript
framework, no external assets: a compliance console should be readable, accessible, and
inspectable. The only script in the whole dashboard is a few lines of inline vanilla JS in
`base.html` that ticks the CRA countdowns, and it honours `prefers-reduced-motion`; every
page is fully usable with it disabled, because the server already rendered the numbers.

`store.py` is the storage layer for the whole tool, not just the web app — one WAL-mode
SQLite file with numbered migrations, applied transparently by every state-touching
command. `dashboard.py` is a view-model layer that turns domain objects into
presentation-ready data, so the templates decide *layout*, never *meaning* — no deadline
arithmetic or status derivation happens in a template. `app.py` holds the routes and
`auth.py` the PBKDF2 HTTP Basic check.

The dashboard has exactly **one** write action — marking a CRA stage complete — and it
calls the same `cra/actions.py::mark` the CLI does, so the audit trail is identical either
way. See [docs/web.md](docs/web.md) and [docs/storage.md](docs/storage.md).

### `http.py` — the only way out

Every outbound request in the entire package goes through one `ApiClient`: retry with
exponential backoff and jitter, a TTL cache, and consistent logging. Nothing else imports
`httpx`, and a test enforces that.

### `cli.py` — the surface

Typer commands, thin by design: they orchestrate the modules above and render output.
Every command supports `--output json|table` (a **global** option) and the exit-code
contract `0` clean, `1` findings above the threshold, `2` execution error — plus `3`
indeterminate for `cra check`.

## The invariants that hold it together

Ten "must never happen" rules live as executable tests in
[`tests/invariants/`](tests/invariants/). They are the architecture's load-bearing walls,
and the reason several design choices above look stricter than necessary:

| | Invariant |
|---|---|
| INV-1 | The fallback version comparator can never produce `high` confidence |
| INV-2 | A synthesized identifier can never produce `high` confidence |
| INV-3 | No `not_affected` without machine-checkable justification *and* an explanation |
| INV-4 | Missing or unreachable EUVD data can never yield a clean "no findings" exit `0` |
| INV-5 | No HTTP usage outside `http.py` |
| INV-6 | Re-running never duplicates events or resets `first_seen` |
| INV-7 | Tampering with any single audit-log entry is detected *and located* |
| INV-8 | Nothing is ever submitted or filed automatically |
| INV-9 | Identical inputs produce byte-identical outputs |
| INV-10 | Every finding carries a non-empty explanation |

INV-8 is enforced structurally, not by convention: only `GET` and `POST` reach the
transport; `post_json` has exactly one caller (the webhook sink); `cra/` holds no URL; and
no submission endpoint can be introduced through configuration.

## Why the boundaries are where they are

**The matcher is separate from the trigger.** "Is this component affected?" and "does this
oblige us to report?" are different questions with different owners — an engineer tunes
the first, a compliance decision governs the second. Keeping the trigger a small,
configurable, pure policy engine means it can be read and argued about by someone who does
not read Python well.

**State is separate from the audit log.** The SQLite database is operational state and may
be migrated, rebuilt, or backed up. The audit log is an append-only, hash-chained file
that is never rewritten. Conflating them would make the record as mutable as the cache.

**Human decisions are separate from machine conclusions.** `vex-decisions.yaml` is a
human-edited input of record; the database only caches derived statuses. A regenerated
database can never overwrite a human's judgement.

**Drafting is separate from filing — permanently.** The tool prepares and records. Legal
validation and submission remain human responsibilities, and the code is arranged so that
no bug can quietly change that.
