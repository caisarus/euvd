"""Covers implementation_plan.md Step 6.1 / test_plan.md §M6 6.1: the consolidated store.

Migration tests run from empty, from the committed legacy (pre-6.1) layout, and from
the committed v1 fixture DB — the per-version fixtures under tests/fixtures/db/ are
kept forever. WAL read-while-write and `migrate()` idempotency are asserted explicitly.
"""

import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from euvd_watch.config import CraTriggerConfig
from euvd_watch.cra.state import EventStore
from euvd_watch.euvd.match import Confidence, Finding, Strategy
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.models import Component, SourceFormat
from euvd_watch.web.store import DB_FILENAME, Store, StoreError, VexStatusRow

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "db"


def _finding(euvd_id: str = "EUVD-1") -> Finding:
    component = Component(
        name="widget", version="1.0.0", source_format=SourceFormat.CYCLONEDX, raw_ref="r"
    )
    record = EuvdRecord(euvd_id=euvd_id, exploited=True)
    return Finding(
        component=component,
        record=record,
        confidence=Confidence.HIGH,
        strategy=Strategy.STRUCTURED,
        explanation="x",
    )


def _table_names(db_path: Path) -> set[str]:
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    finally:
        conn.close()
    return {row[0] for row in rows}


def test_migrate_from_empty_applies_initial_schema(tmp_path: Path) -> None:
    store = Store(tmp_path)
    report = store.migrate()
    store.close()

    assert report.applied_versions == [1]
    assert report.imported_events == 0
    assert report.imported_snapshots == 0
    assert not report.is_noop
    assert _table_names(tmp_path / DB_FILENAME) >= {
        "schema_migrations",
        "events",
        "watch_snapshots",
        "vex_status_cache",
        "audit_log_refs",
    }


def test_migrate_is_idempotent(tmp_path: Path) -> None:
    store = Store(tmp_path)
    store.migrate()
    second = store.migrate()
    store.close()

    assert second.is_noop
    assert second.applied_versions == []
    assert second.imported_events == 0
    assert second.imported_snapshots == 0
    assert second.renamed_legacy == []


def test_migrate_from_v1_fixture_is_noop(tmp_path: Path) -> None:
    """The committed v1 DB is recognized as current — kept forever per the test plan."""
    shutil.copy(FIXTURES / "v1" / DB_FILENAME, tmp_path / DB_FILENAME)
    store = Store(tmp_path)
    report = store.migrate()
    store.close()
    assert report.is_noop


def test_migrate_imports_committed_legacy_layout(tmp_path: Path) -> None:
    """The pre-6.1 layout (cra-events.sqlite + watch/*.json) migrates in verbatim."""
    shutil.copytree(FIXTURES / "legacy-pre61", tmp_path, dirs_exist_ok=True)

    store = Store(tmp_path)
    report = store.migrate()

    assert report.imported_events == 1
    assert report.imported_snapshots == 1
    assert len(report.renamed_legacy) == 2
    # Originals are renamed, never deleted.
    assert not (tmp_path / "cra-events.sqlite").exists()
    assert all(Path(name).exists() for name in report.renamed_legacy)

    snapshot = store.load_watch_snapshot("aaaaaaaaaaaaaaaa")
    assert snapshot is not None and '"schema_version": 1' in snapshot
    store.close()

    events = EventStore(tmp_path / DB_FILENAME)
    migrated = events.list_all()
    events.close()
    assert [e.finding.record.euvd_id for e in migrated] == ["EUVD-FIXTURE-0001"]


def test_legacy_import_never_overwrites_existing_events(tmp_path: Path) -> None:
    """An event already in the consolidated DB wins over a stale legacy copy."""
    store = Store(tmp_path)
    store.migrate()
    store.close()

    events = EventStore(tmp_path / DB_FILENAME)
    current, _created = events.get_or_create(
        _finding("EUVD-FIXTURE-0001"),
        fired_rules=["cisa_kev"],
        policy_snapshot=CraTriggerConfig(),
        epss_threshold=0.9,
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    events.close()

    legacy = EventStore(tmp_path / "cra-events.sqlite")
    legacy.get_or_create(
        _finding("EUVD-FIXTURE-0001"),
        fired_rules=["euvd_exploited"],
        policy_snapshot=CraTriggerConfig(),
        epss_threshold=0.5,
        now=datetime(2020, 1, 1, tzinfo=UTC),
    )
    legacy.close()

    store = Store(tmp_path)
    report = store.migrate()
    store.close()
    assert report.imported_events == 0  # ignored, not overwritten
    assert len(report.renamed_legacy) == 1

    events = EventStore(tmp_path / DB_FILENAME)
    kept = events.list_all()
    events.close()
    assert len(kept) == 1
    assert kept[0].fired_rules == current.fired_rules
    assert kept[0].first_seen == current.first_seen


def test_wal_read_does_not_block_on_open_write_transaction(tmp_path: Path) -> None:
    """The dashboard must read while watch/cra write: WAL, not rollback journal."""
    store = Store(tmp_path)
    store.migrate()
    store.save_watch_snapshot("k1", '{"schema_version": 1, "findings": []}')

    writer = sqlite3.connect(tmp_path / DB_FILENAME)
    assert writer.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    writer.execute("BEGIN IMMEDIATE")
    writer.execute("INSERT OR REPLACE INTO watch_snapshots (sbom_key, data) VALUES ('k2', '{}')")
    try:
        # A second connection reads the pre-transaction state without "database is locked".
        assert store.load_watch_snapshot("k1") is not None
        assert store.load_watch_snapshot("k2") is None
    finally:
        writer.rollback()
        writer.close()
        store.close()


def test_corrupt_store_is_quarantined_never_deleted(tmp_path: Path) -> None:
    (tmp_path / DB_FILENAME).write_bytes(b"this is not a sqlite database at all")
    store = Store(tmp_path)
    report = store.migrate()
    store.close()

    assert report.applied_versions == [1]  # fresh store created and migrated
    quarantined = list(tmp_path.glob(f"{DB_FILENAME}.corrupt-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == b"this is not a sqlite database at all"


def test_corrupt_legacy_events_store_fails_loudly_and_keeps_the_file(tmp_path: Path) -> None:
    (tmp_path / "cra-events.sqlite").write_bytes(b"garbage, but a legal record")
    store = Store(tmp_path)
    with pytest.raises(StoreError, match="legal record"):
        store.migrate()
    store.close()
    assert (tmp_path / "cra-events.sqlite").read_bytes() == b"garbage, but a legal record"


def test_legacy_event_with_unknown_shape_fails_loudly(tmp_path: Path) -> None:
    legacy = sqlite3.connect(tmp_path / "cra-events.sqlite")
    legacy.execute("CREATE TABLE events (event_id TEXT PRIMARY KEY, data TEXT NOT NULL)")
    legacy.execute(
        "INSERT INTO events VALUES ('e1', '{\"schema_version\": 99, \"unexpected\": true}')"
    )
    legacy.commit()
    legacy.close()

    store = Store(tmp_path)
    with pytest.raises(StoreError, match="does not match this build's event schema"):
        store.migrate()
    store.close()


def test_vex_status_cache_rebuild_replaces_everything(tmp_path: Path) -> None:
    store = Store(tmp_path)
    store.migrate()

    store.rebuild_vex_status_cache(
        [
            VexStatusRow(
                finding_key="purl:pkg:pypi/jinja2@3.1.6|EUVD-1",
                status="under_investigation",
                justification=None,
                source="automated",
                updated_at="2026-08-08T12:00:00+00:00",
            )
        ]
    )
    assert set(store.list_vex_statuses()) == {"purl:pkg:pypi/jinja2@3.1.6|EUVD-1"}

    # A second rebuild with different content REPLACES, never appends.
    store.rebuild_vex_status_cache(
        [
            VexStatusRow(
                finding_key="purl:pkg:pypi/requests@2.31.0|EUVD-2",
                status="not_affected",
                justification="component_not_present",
                source="automated",
                updated_at="2026-08-08T13:00:00+00:00",
            )
        ]
    )
    statuses = store.list_vex_statuses()
    assert set(statuses) == {"purl:pkg:pypi/requests@2.31.0|EUVD-2"}
    row = statuses["purl:pkg:pypi/requests@2.31.0|EUVD-2"]
    assert row.status == "not_affected"
    assert row.justification == "component_not_present"
    store.close()


def test_vex_status_cache_empty_rebuild_clears(tmp_path: Path) -> None:
    store = Store(tmp_path)
    store.migrate()
    store.rebuild_vex_status_cache(
        [
            VexStatusRow(
                finding_key="k",
                status="affected",
                justification=None,
                source="human",
                updated_at="2026-08-08T12:00:00+00:00",
            )
        ]
    )
    store.rebuild_vex_status_cache([])
    assert store.list_vex_statuses() == {}
    store.close()


def test_audit_log_refs_upsert_and_list(tmp_path: Path) -> None:
    store = Store(tmp_path)
    store.migrate()
    store.record_audit_log_ref("/state/cra-audit.jsonl", "2026-08-08T12:00:00+00:00")
    assert store.list_audit_log_refs() == [("/state/cra-audit.jsonl", "2026-08-08T12:00:00+00:00")]

    # Re-registering the same path updates recorded_at, never duplicates the row.
    store.record_audit_log_ref("/state/cra-audit.jsonl", "2026-08-08T13:00:00+00:00")
    assert store.list_audit_log_refs() == [("/state/cra-audit.jsonl", "2026-08-08T13:00:00+00:00")]
    store.close()
