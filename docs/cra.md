# CRA Article 14 workflow

How euvd-watch supports the EU Cyber Resilience Act's reporting duties for actively
exploited vulnerabilities. Implemented in `src/euvd_watch/cra/` (trigger, state, clock,
report, audit); exercised end-to-end by scenario S3 in `tests/e2e/test_cra_commands.py`.

> **What this is — and is not.** euvd-watch is an *operational preparation and
> record-keeping aid*: it watches for trigger signals, starts countdowns, prefills
> notification drafts, and keeps a verifiable activity log. It is **not legal advice**,
> it does **not decide** whether something is legally reportable, and it **never submits
> anything** — a human validates every draft against current ENISA/CSIRT guidance and
> files it through the official channel.

## The operational flow

```
euvd-watch cra check sbom.cdx.json   # evaluate the trigger; open events; exit 1 if NEW
euvd-watch cra status                # one countdown per configured stage, all UTC
euvd-watch cra draft <event-id>      # prefilled Markdown draft (JSON with --output json)
euvd-watch cra mark <event-id> --stage early_warning --note "filed ref #123"
euvd-watch cra mark <event-id> --remediation-available
euvd-watch cra verify-log            # verify the hash-chained audit log
```

`cra check` also accepts `--findings findings.json` (from `match --save-findings`) to
evaluate a saved artifact instead of re-querying the EUVD, and `--no-enrich` (the KEV and
EPSS trigger signals then stay unknown and cannot fire).

## The trigger policy (`cra_trigger` in euvd-watch.yaml)

A finding fires the trigger when — at or above the configured confidence floor — any (or,
with `require_all: true`, every) enabled signal is present:

| Signal | Meaning | Source |
|---|---|---|
| `euvd_exploited` | ENISA's EUVD marks the vulnerability actively exploited (`exploitedSince` present) | EUVD |
| `cisa_kev` | listed in CISA's Known Exploited Vulnerabilities catalog | CISA KEV |
| `epss_over_threshold` | EPSS score ≥ `epss_threshold` — **a probability signal, not evidence of exploitation** | FIRST.org |

`min_confidence` (default `medium`) exists because low-confidence matches are for human
review, not for starting legal clocks. The tool records *which* rules fired and keeps
that record immutable (below); drafts always attribute each signal to its source and
never collapse "EPSS over threshold" into an exploitation claim.

A trigger event is a **signal that human evaluation is needed** — not a determination
that a notification is legally required. That determination is yours.

## Deadlines: configurable stages (`cra_stages`)

Deadline stages are **config, not code** — a change in law or guidance must never require
a code change. The shipped defaults reflect our reading of **Regulation (EU) 2024/2847,
Article 14** as verified on 2026-07-10 (re-verify against the current text and ENISA
guidance before relying on them):

| Stage (default) | Window | Anchor |
|---|---|---|
| `early_warning` | 24 h | `first_seen` |
| `vulnerability_notification` | 72 h | `first_seen` |
| `final_report` | 14 days | `remediation_available` |

Stages anchored on `remediation_available` show `awaiting_anchor` (no deadline at all)
until a human records availability via `cra mark --remediation-available`. Per stage, the
computed states are `pending → due_soon` (≤ 25 % of the window remaining) `→ overdue`,
plus `completed` once marked. Everything is stored and computed in UTC and rendered with
the zone explicit.

### The "awareness" caveat — read this

The clocks anchor on `first_seen`: **the moment euvd-watch first persisted the trigger
event**. That is a *proxy* for awareness — the regulation's deadlines run from when the
manufacturer becomes aware. If your team learned of the issue earlier through another
channel (a researcher e-mail, a vendor advisory), your legal clock may have started
before euvd-watch's. The tool cannot know that; the draft prints `first_seen` and its
basis so a human can correct the timeline when filing.

`first_seen` is set exactly once. Re-running `cra check` never resets it, never
duplicates the event, and never rewrites the recorded first-fire evidence
(`fired_rules`, `policy_snapshot`, the fire-time `epss_threshold`, the finding as it was
then). What later runs learn (an EPSS score moving, a KEV listing appearing) is stored
separately as `latest_finding`.

## Where the records live, and how to keep them safe

Durable records live in `state_dir` (default `~/.local/share/euvd-watch`) — deliberately
**not** in `cache_dir`, which is purgeable at will:

- `cra-events.sqlite` — the event store. On corruption it is **quarantined by renaming**
  (`.corrupt-<timestamp>` suffix), never deleted, and a fresh store is created so new
  awareness can still be recorded. Keep quarantined files: they are evidence.
- `cra-audit.jsonl` — the hash-chained audit log (below).

Back up `state_dir` like the legal record it is. There is no retention/expiry logic and
none is planned: these records must outlive the vulnerability.

## The audit log: what "tamper-evident" honestly means

Append-only JSONL; each entry carries `prev_hash` and
`entry_hash = SHA-256(prev_hash + canonical_json(entry))`, chained from a documented
genesis seed (`euvd-watch-audit-genesis-v1`). Logged: every trigger-event creation
(with its immutable first-fire policy), every draft render, and every human `cra mark`
action (actor `human`). `cra verify-log` recomputes the chain in O(n) and names the exact
first broken line, distinguishing a *truncated tail* (crash mid-write) from tampering.

**Guarantees:** any edit, insertion, deletion, or reordering by someone who cannot
rewrite the whole file is detected and located. Appending valid-looking entries after a
tamper does not hide it.

**Limits (do not overclaim):** an attacker with full write access to the file can
recompute the entire chain — this is tamper-*evident*, not tamper-*proof*. The system
clock is trusted at append time. If you need stronger guarantees, periodically anchor the
newest `entry_hash` somewhere external you trust (a ticket, a signed git commit, an
e-mail to yourself); euvd-watch does not do this for you today.

The canonical JSON form that gets hashed (sorted keys, compact separators, ASCII-only) is
frozen and fixture-tested; changing it would invalidate every existing chain, so it will
only ever change with an explicit schema-version bump and migration story.

## The draft

`cra draft <event-id>` prefills everything the tool knows: reporter identity from
`organization.*` config (missing fields produce an error naming exactly what to fill),
vulnerability identification (EUVD id, CVEs, CVSS, description, references), the affected
component and how it was matched, the awareness basis (which rules fired, attributed to
their sources), and the stage timeline. Every field requiring human judgment is a literal
**`TODO-HUMAN`** marker — impact assessment, product-specific exploitation, corrective
measures, contact person. The draft ends with the reminder that nothing has been
submitted and the current ENISA guidance must be checked before filing.
