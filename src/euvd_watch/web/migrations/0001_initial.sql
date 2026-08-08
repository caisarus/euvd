-- SPDX-License-Identifier: EUPL-1.2
-- 0001: initial consolidated schema (M6 Step 6.1).
--
-- `events` matches the table the pre-6.1 EventStore created in its own DB file, so
-- both the legacy import and EventStore's own CREATE TABLE IF NOT EXISTS agree on it.
-- `vex_status_cache` and `audit_log_refs` are the dashboard's read models (populated
-- from Step 6.2): derived VEX statuses are rebuildable from vex-decisions.yaml, and
-- the audit log itself stays an append-only hash-chained file — references only here.

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watch_snapshots (
    sbom_key TEXT PRIMARY KEY,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vex_status_cache (
    finding_key TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    justification TEXT,
    source TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log_refs (
    path TEXT PRIMARY KEY,
    recorded_at TEXT NOT NULL
);
