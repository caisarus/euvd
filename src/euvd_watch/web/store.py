# SPDX-License-Identifier: EUPL-1.2
"""Consolidated operational-state store (M6 Step 6.1).

One SQLite file per `state_dir` — `euvd-watch.sqlite` — holds all *operational* state:
CRA trigger events, watch snapshots, and (populated from Step 6.2) the dashboard's
VEX-status read model and audit-log references. Two artifacts deliberately stay files
(M6 sign-off, docs/AUDIT_AND_REMEDIATION_PLAN.md §17):

- the audit log (`cra-audit.jsonl`) is append-only and hash-chained; moving it into a
  mutable DB would gut the tamper-evidence claim. The DB stores references only.
- `vex-decisions.yaml` is the human-edited input of record; the DB only caches derived
  statuses, rebuildable from the file.

Schema changes ship as numbered SQL files in `web/migrations/`; `Store.migrate()`
applies the pending ones in order, records each in `schema_migrations`, and is a no-op
when everything is current — commands call it on every state access, so users never
need a manual step (`euvd-watch db migrate` exists to run it explicitly and see what
happened). The same call imports state from the pre-6.1 layout (`cra-events.sqlite`,
`watch/*.json`) and renames the imported files with a `.migrated-<UTC stamp>` suffix —
never deletes: CRA events are a legal record. The DB runs in WAL mode so dashboard
reads never block watch/cra writes.

Corruption of the consolidated DB follows the EventStore precedent (SEC-001): the
broken file is quarantined by renaming — never deleted — and a fresh store is created
so recording new awareness is never blocked.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from euvd_watch.cra.state import Event

logger = logging.getLogger(__name__)

DB_FILENAME = "euvd-watch.sqlite"
_LEGACY_EVENTS_FILENAME = "cra-events.sqlite"
_LEGACY_WATCH_DIRNAME = "watch"
_MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def sbom_snapshot_key(sbom: str) -> str:
    """One snapshot row per watched SBOM, keyed by its resolved path so re-runs from a
    different working directory still hit the same snapshot. Same key derivation as the
    pre-6.1 per-file layout, so migrated rows keep matching their SBOMs. Public: both
    `cli.py::watch` and `web/dashboard.py` (Step 6.2) must compute the identical key to
    find the same snapshot row."""
    return hashlib.sha256(str(Path(sbom).resolve()).encode("utf-8")).hexdigest()[:16]


class StoreError(Exception):
    """Raised when the consolidated state store cannot be read, written, or migrated."""


class VexStatusRow(BaseModel):
    """One dashboard-cached VEX status, keyed like `watch/differ.py`'s finding identity:
    `f"{component.dedupe_key}|{record.euvd_id}"`. Always rebuildable from
    vex-decisions.yaml + the current findings (web/dashboard.py) - this table is a read
    model, never the source of truth (M6 sign-off, docs/AUDIT_AND_REMEDIATION_PLAN.md
    §17)."""

    model_config = ConfigDict(frozen=True)

    finding_key: str
    status: str
    justification: str | None
    source: str  # "automated" | "human"
    updated_at: str


class MigrationReport(BaseModel):
    """What one `Store.migrate()` call did; all-empty means already up to date."""

    model_config = ConfigDict(frozen=True)

    applied_versions: list[int]
    imported_events: int
    imported_snapshots: int
    renamed_legacy: list[str]

    @property
    def is_noop(self) -> bool:
        """True when the call changed nothing (schema current, no legacy files found)."""
        return not (self.applied_versions or self.renamed_legacy)


class Store:
    """The consolidated operational-state DB: one file, WAL mode, migration-managed."""

    def __init__(self, state_dir: Path) -> None:
        self._state_dir = state_dir
        self.path = state_dir / DB_FILENAME
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connect()

    def _connect(self, *, retry_on_corruption: bool = True) -> None:
        self._conn = sqlite3.connect(self.path)
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            self._conn.commit()
        except sqlite3.DatabaseError as exc:
            if not retry_on_corruption:
                raise StoreError(f"State store at {self.path} is unusable: {exc}") from exc
            self._quarantine(exc)
            self._connect(retry_on_corruption=False)

    def _quarantine(self, cause: Exception) -> None:
        with contextlib.suppress(sqlite3.Error):
            self._conn.close()
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        quarantine = self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
        try:
            self.path.rename(quarantine)
        except OSError as exc:
            raise StoreError(
                f"State store at {self.path} is corrupted ({cause}) and could not be "
                f"quarantined to {quarantine}: {exc}. Refusing to continue - it contains "
                f"CRA events, a legal record; do not delete it."
            ) from exc
        logger.warning(
            "State store at %s is corrupted; quarantined it to %s and created a fresh "
            "store. The quarantined file is preserved for recovery - do not delete it.",
            self.path,
            quarantine,
        )

    # -- migrations ---------------------------------------------------------------

    def migrate(self) -> MigrationReport:
        """Apply pending schema migrations, then import any pre-6.1 state files."""
        applied = self._apply_pending_migrations()
        renamed: list[str] = []
        imported_events = self._import_legacy_events(renamed)
        imported_snapshots = self._import_legacy_snapshots(renamed)
        report = MigrationReport(
            applied_versions=applied,
            imported_events=imported_events,
            imported_snapshots=imported_snapshots,
            renamed_legacy=renamed,
        )
        if not report.is_noop:
            logger.info(
                "State DB %s: applied migrations %s, imported %d event(s) and %d "
                "snapshot(s) from the pre-6.1 layout (originals renamed: %s).",
                self.path,
                report.applied_versions or "none",
                report.imported_events,
                report.imported_snapshots,
                report.renamed_legacy or "none",
            )
        return report

    def _apply_pending_migrations(self) -> list[int]:
        try:
            rows = self._conn.execute("SELECT version FROM schema_migrations").fetchall()
        except sqlite3.Error as exc:
            raise StoreError(f"Could not read migration state from {self.path}: {exc}") from exc
        already = {row[0] for row in rows}
        applied: list[int] = []
        for version, sql_path in self._migration_files():
            if version in already:
                continue
            try:
                self._conn.executescript(sql_path.read_text(encoding="utf-8"))
                self._conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (version, datetime.now(UTC).isoformat()),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                raise StoreError(f"Migration {sql_path.name} failed on {self.path}: {exc}") from exc
            applied.append(version)
        return applied

    @staticmethod
    def _migration_files() -> list[tuple[int, Path]]:
        """The shipped numbered migrations, sorted; filename shape is NNNN_name.sql."""
        files: list[tuple[int, Path]] = []
        for path in sorted(_MIGRATIONS_DIR.glob("*.sql")):
            files.append((int(path.name.split("_", 1)[0]), path))
        return files

    # -- legacy (pre-6.1) import --------------------------------------------------

    def _import_legacy_events(self, renamed: list[str]) -> int:
        legacy = self._state_dir / _LEGACY_EVENTS_FILENAME
        if not legacy.exists():
            return 0
        try:
            conn = sqlite3.connect(f"file:{legacy}?mode=ro", uri=True)
            try:
                rows = conn.execute("SELECT event_id, data FROM events").fetchall()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise StoreError(
                f"Legacy CRA event store {legacy} could not be read: {exc}. It is a "
                f"legal record - do not delete it; resolve this before migrating."
            ) from exc
        imported = 0
        for event_id, data in rows:
            try:
                Event.model_validate_json(data)
            except ValidationError as exc:
                raise StoreError(
                    f"Legacy CRA event {event_id!r} in {legacy} does not match this "
                    f"build's event schema (a newer/older euvd-watch may have written "
                    f"it): {exc}"
                ) from exc
            # OR IGNORE: an event already in the consolidated DB is the newer record -
            # a stale legacy copy must never overwrite it.
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO events (event_id, data) VALUES (?, ?)",
                (event_id, data),
            )
            imported += cursor.rowcount
        self._commit_or_raise()
        self._rename_migrated(legacy, renamed)
        return imported

    def _import_legacy_snapshots(self, renamed: list[str]) -> int:
        legacy_dir = self._state_dir / _LEGACY_WATCH_DIRNAME
        if not legacy_dir.is_dir():
            return 0
        imported = 0
        for path in sorted(legacy_dir.glob("*.json")):
            try:
                text = path.read_text(encoding="utf-8")
                json.loads(text)
            except (OSError, json.JSONDecodeError) as exc:
                raise StoreError(f"Legacy watch snapshot {path} is unreadable: {exc}") from exc
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO watch_snapshots (sbom_key, data) VALUES (?, ?)",
                (path.stem, text),
            )
            imported += cursor.rowcount
            self._rename_migrated(path, renamed)
        self._commit_or_raise()
        return imported

    def _rename_migrated(self, path: Path, renamed: list[str]) -> None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        target = path.with_name(f"{path.name}.migrated-{stamp}")
        try:
            path.rename(target)
        except OSError as exc:
            raise StoreError(
                f"Imported {path} into {self.path} but could not rename the original "
                f"to {target}: {exc}. Rename or remove it manually, or the next run "
                f"will re-import it."
            ) from exc
        renamed.append(str(target))

    # -- watch snapshots ----------------------------------------------------------

    def load_watch_snapshot(self, sbom_key: str) -> str | None:
        """The stored snapshot artifact (JSON text) for one watched SBOM, if any."""
        try:
            row = self._conn.execute(
                "SELECT data FROM watch_snapshots WHERE sbom_key = ?", (sbom_key,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise StoreError(f"Could not read watch snapshot from {self.path}: {exc}") from exc
        return str(row[0]) if row else None

    def save_watch_snapshot(self, sbom_key: str, data: str) -> None:
        """Persist the snapshot artifact (JSON text) for one watched SBOM."""
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO watch_snapshots (sbom_key, data) VALUES (?, ?)",
                (sbom_key, data),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StoreError(f"Could not write watch snapshot to {self.path}: {exc}") from exc

    # -- VEX status read model (Step 6.2) ------------------------------------------

    def rebuild_vex_status_cache(self, rows: list[VexStatusRow]) -> None:
        """Replace the entire cache with `rows` in one transaction.

        A rebuild, not an incremental update - the dashboard recomputes the full set
        from vex-decisions.yaml + the current findings on every read (never trusts a
        possibly-stale cache for what it *shows*) and calls this only to keep the read
        model populated for other consumers, per the Step 6.1 sign-off.
        """
        try:
            self._conn.execute("DELETE FROM vex_status_cache")
            self._conn.executemany(
                "INSERT INTO vex_status_cache "
                "(finding_key, status, justification, source, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (row.finding_key, row.status, row.justification, row.source, row.updated_at)
                    for row in rows
                ],
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StoreError(f"Could not write VEX status cache to {self.path}: {exc}") from exc

    def list_vex_statuses(self) -> dict[str, VexStatusRow]:
        try:
            rows = self._conn.execute(
                "SELECT finding_key, status, justification, source, updated_at "
                "FROM vex_status_cache"
            ).fetchall()
        except sqlite3.Error as exc:
            raise StoreError(f"Could not read VEX status cache from {self.path}: {exc}") from exc
        return {
            finding_key: VexStatusRow(
                finding_key=finding_key,
                status=status,
                justification=justification,
                source=source,
                updated_at=updated_at,
            )
            for finding_key, status, justification, source, updated_at in rows
        }

    # -- audit log references (Step 6.2) --------------------------------------------

    def record_audit_log_ref(self, path: str, recorded_at: str) -> None:
        """Register a known audit-log file location. A reference only - the log's
        content always stays in the file (tamper-evidence carve-out, §17)."""
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO audit_log_refs (path, recorded_at) VALUES (?, ?)",
                (path, recorded_at),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StoreError(f"Could not write audit log ref to {self.path}: {exc}") from exc

    def list_audit_log_refs(self) -> list[tuple[str, str]]:
        try:
            rows = self._conn.execute(
                "SELECT path, recorded_at FROM audit_log_refs ORDER BY path"
            ).fetchall()
        except sqlite3.Error as exc:
            raise StoreError(f"Could not read audit log refs from {self.path}: {exc}") from exc
        return [(path, recorded_at) for path, recorded_at in rows]

    # -- plumbing -----------------------------------------------------------------

    def _commit_or_raise(self) -> None:
        try:
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StoreError(f"Could not write to state store {self.path}: {exc}") from exc

    def close(self) -> None:
        """Close the connection; the Store is not usable afterwards."""
        with contextlib.suppress(sqlite3.Error):
            self._conn.close()
