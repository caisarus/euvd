# Storage: the consolidated state DB (M6, Step 6.1)

All *operational* state lives in **one SQLite file**:
`state_dir/euvd-watch.sqlite` (default `state_dir`: `~/.local/share/euvd-watch`).
It runs in WAL mode, so the dashboard (Step 6.2) can read while `watch`/`cra` write.

| Table | Holds | Written by |
|---|---|---|
| `schema_migrations` | applied migration versions | the migration runner |
| `events` | CRA trigger events (the "we became aware" legal record) | `cra check` |
| `watch_snapshots` | last findings snapshot per watched SBOM | `watch` |
| `vex_status_cache` | derived VEX statuses (dashboard read model, from Step 6.2) | `web` |
| `audit_log_refs` | references to audit-log files (from Step 6.2) | `web` |

## What deliberately stays a file

Two artifacts are **not** in the DB, by design (M6 sign-off,
`docs/AUDIT_AND_REMEDIATION_PLAN.md` §17):

- **The audit log** (`state_dir/cra-audit.jsonl`) stays the append-only, hash-chained
  file — moving it into a mutable DB would gut the tamper-evidence claim. The DB holds
  references only.
- **`vex-decisions.yaml`** stays the human-edited input of record. The DB only caches
  statuses derived from it; the cache is rebuildable from the file at any time.

## Migrations

Schema changes ship as numbered SQL files in `src/euvd_watch/web/migrations/`
(`0001_initial.sql`, …). Every state-touching command applies pending migrations
transparently on first contact; `euvd-watch db migrate` runs the same step explicitly
and reports what happened (`--output json|table`; exit `0`, or `2` on error). Running
it on an up-to-date store is a no-op — run it as often as you like.

The same step imports state from the pre-0.4 layout — `cra-events.sqlite` and
`state_dir/watch/*.json` — into the consolidated DB. Imported originals are renamed
with a `.migrated-<UTC timestamp>` suffix, **never deleted**: CRA events are a legal
record. An event already present in the consolidated DB is never overwritten by a
stale legacy copy.

## Downgrading (read before you roll back)

**A `0.3.x` binary run against a migrated state directory reports "0 open event(s) of
0 total" and exits `0`.** It is not lying on purpose: it looks for `cra-events.sqlite`,
finds only the renamed `cra-events.sqlite.migrated-<timestamp>`, and creates a fresh
empty store — while your real events, deadlines and running 24-hour clocks sit in
`euvd-watch.sqlite`, untouched and invisible to it. On a CRA reporting surface that
green "nothing open" is the most expensive output this tool can produce, so treat a
downgrade as a deliberate, checked operation:

1. Stop every writer (`watch`, the dashboard, any scheduled `cra check`).
2. Rename the originals back — drop the `.migrated-<timestamp>` suffix from
   `cra-events.sqlite` and from each `watch/*.json` — and move the consolidated
   `euvd-watch.sqlite` aside rather than deleting it.
3. Know what you lose: those originals are a **point-in-time snapshot from the moment
   of migration**. Any event recorded, stage marked, or snapshot taken since then
   exists only in `euvd-watch.sqlite`, and `0.3.x` cannot read it. Reconcile against
   `cra-audit.jsonl`, which is append-only, format-stable across both versions, and
   therefore the authoritative record of what actually happened.

The audit log needs no downgrade handling: both versions append to the same
`cra-audit.jsonl` and `cra verify-log` validates the same hash chain either way.

## Corruption and backup

On corruption the DB file is quarantined by renaming (`.corrupt-<timestamp>` suffix),
never deleted, and a fresh store is created so recording new awareness is never
blocked — the same contract the standalone event store had. Keep quarantined files:
they are evidence.

Back up two things, together: `state_dir/euvd-watch.sqlite` and
`state_dir/cra-audit.jsonl`. There is no retention/expiry logic and none is planned.
When backing up a live system, prefer `sqlite3 euvd-watch.sqlite ".backup <dest>"` (or
stop writers first): a plain file copy of a WAL database can miss the not-yet-
checkpointed tail in `euvd-watch.sqlite-wal`.

The per-version fixture DBs under `tests/fixtures/db/` are the migration regression
suite and are kept forever; `scripts/make_db_fixtures.py` regenerates them when a new
schema version is added.
