# Watch mode

Re-matches an SBOM against the EUVD on a schedule and reports **only what changed** since
last time. Implemented in `src/euvd_watch/watch/` (differ, sinks); exercised end-to-end by
`tests/e2e/test_cli_watch.py`.

## The operational flow

```
euvd-watch watch sbom.cdx.json                 # one check-and-diff cycle, then exit
euvd-watch watch sbom.cdx.json --once          # same thing, spelled out explicitly
euvd-watch watch sbom.cdx.json --interval 6h   # loop forever; Ctrl+C to stop
euvd-watch watch sbom.cdx.json --webhook https://example.org/hook
```

`--interval` accepts `\d+[smhd]` (e.g. `30m`, `6h`, `1d`). `--interval` and `--once` are
mutually exclusive; omitting both behaves like `--once`.

Exit codes (`--once`/no-flag): **0** nothing changed, **1** something new/resolved/changed
(the CI-gate convention every other command uses), **2** execution error. A persistent
failure during `--interval` (EUVD unreachable, webhook down) **stops the loop with exit
2** rather than retrying silently forever - rerun once the problem is fixed (or let
cron/systemd restart it). This is a deliberate choice: silently spinning through repeated
failures is exactly the "dangerous silence" this project's test philosophy warns against.

## What counts as "new", "resolved", "changed"

Each run's findings are diffed against the *previous* run's, keyed by
`(component, EUVD record)` identity - not by memory, by a snapshot on disk (below). A
finding is:

- **new** - its key wasn't in the previous snapshot.
- **resolved** - its key was in the previous snapshot but isn't in the current findings
  (the component was removed, upgraded out of range, or the EUVD record no longer
  applies).
- **changed** - present in both, but `confidence`, `record.exploited`, `in_kev`,
  `epss_score`, or `record.cvss_score` differs. The notification names exactly which
  field(s) changed.
- **unchanged** - identical on every tracked field. Produces **zero** notifications - the
  entire point of watch mode is not re-reporting the same thing forever.

## Where the snapshot lives

One JSON snapshot per watched SBOM, in `state_dir/watch/<hash-of-resolved-path>.json`
(same durable `state_dir` the CRA workflow uses - not the purgeable HTTP cache). It reuses
the same minimal shape `match --save-findings`/`cra check --findings` already read
(`schema_version` + `findings`), so nothing new needs learning. A missing snapshot means
"first run" - every current finding reports as `new`, which is correct, not a bug.

## Sinks

Two ship today, both implementing the same small interface
(`src/euvd_watch/watch/sinks.py::NotificationSink`) so a future sink (email, Slack) is a
new class, not a rewrite:

- **stdout** (always on in table/human mode; suppressed in `--output json` mode, which
  instead prints a single structured `{"schema_version": 1, "new": [...], "resolved":
  [...], "changed": [...]}` payload to stdout, exactly like every other command's
  `--output json`).
- **webhook** (`--webhook URL`) - POSTs **one JSON payload per new/resolved/changed
  finding** through the same disciplined `ApiClient` (retry/backoff) everything else in
  this project uses. Payload shape:
  ```json
  {
    "schema_version": 1,
    "kind": "new" | "resolved" | "changed",
    "sbom": "<resolved SBOM path>",
    "generated_at": "<ISO 8601 UTC>",
    "finding": { "...": "the full Finding" },
    "changed_fields": ["epss_score"]
  }
  ```
  (`changed_fields` is present only for `kind: "changed"`.)

**Delivery is at-least-once, not exactly-once.** A transient failure is retried with the
same backoff as any other `ApiClient` call; there is no receiver-side deduplication built
in (a receiver that cares should dedupe on `(kind, finding.component, finding.record.euvd_id,
generated_at)` or similar). A persistent webhook failure stops the run with exit 2 (see
above) rather than silently dropping the notification.
