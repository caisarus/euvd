"""Covers implementation_plan.md Step 4.1: the CRA event state store.

Acceptance criterion: re-running match/cra never duplicates events or resets first_seen
(also re-asserted as INV-6 in tests/invariants/test_m4_invariants.py).
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from euvd_watch.config import CraTriggerConfig
from euvd_watch.cra.state import Event, EventStore, StateError
from euvd_watch.euvd.match import Confidence, Finding, Strategy
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.models import Component, SourceFormat

pytestmark = pytest.mark.unit


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


def test_event_id_is_component_and_euvd_id() -> None:
    finding = _finding()
    assert Event.make_id(finding.component.dedupe_key, finding.record.euvd_id) == (
        f"{finding.component.dedupe_key}|{finding.record.euvd_id}"
    )


def test_get_or_create_first_call_creates(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "cra-state.sqlite")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    event, created = store.get_or_create(
        _finding(), ["euvd_exploited"], CraTriggerConfig(), 0.5, now
    )
    assert created is True
    assert event.first_seen == now
    store.close()


def test_get_or_create_second_call_does_not_duplicate_or_reset_first_seen(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "cra-state.sqlite")
    first_seen = datetime(2026, 1, 1, tzinfo=UTC)
    later = first_seen + timedelta(hours=5)

    event1, created1 = store.get_or_create(
        _finding(), ["euvd_exploited"], CraTriggerConfig(), 0.5, first_seen
    )
    event2, created2 = store.get_or_create(
        _finding(), ["euvd_exploited", "cisa_kev"], CraTriggerConfig(), 0.5, later
    )

    assert created1 is True
    assert created2 is False
    assert event1.first_seen == event2.first_seen == first_seen  # never reset
    assert len(store.list_all()) == 1  # never duplicated
    store.close()


def test_get_or_create_never_overwrites_the_first_fire_record(tmp_path: Path) -> None:
    # Audit finding SEC-003: fired_rules and policy_snapshot are the defensibility record
    # of WHAT fired and UNDER WHICH policy - later evaluations must not rewrite them.
    store = EventStore(tmp_path / "cra-state.sqlite")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    original_policy = CraTriggerConfig(min_confidence="medium")
    changed_policy = CraTriggerConfig(min_confidence="low", require_all=True)

    store.get_or_create(_finding(), ["euvd_exploited"], original_policy, 0.5, now)
    store.get_or_create(_finding(), ["euvd_exploited", "cisa_kev"], changed_policy, 0.9, now)

    event = store.get(Event.make_id(_finding().component.dedupe_key, "EUVD-1"))
    assert event is not None
    assert event.fired_rules == ["euvd_exploited"]  # first-fire basis, immutable
    assert event.policy_snapshot == original_policy  # the policy that actually fired
    store.close()


def test_get_or_create_refreshes_latest_finding_only(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "cra-state.sqlite")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    first = _finding()
    updated = first.model_copy(update={"epss_score": 0.99, "in_kev": True})

    store.get_or_create(first, ["euvd_exploited"], CraTriggerConfig(), 0.5, now)
    store.get_or_create(updated, ["euvd_exploited", "cisa_kev"], CraTriggerConfig(), 0.5, now)

    event = store.get(Event.make_id(first.component.dedupe_key, "EUVD-1"))
    assert event is not None
    assert event.finding == first  # first-fire evaluation preserved verbatim
    assert event.latest_finding == updated  # what the most recent run knew
    assert event.current_finding == updated
    store.close()


def test_set_remediation_available(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "cra-state.sqlite")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    event, _ = store.get_or_create(_finding(), ["euvd_exploited"], CraTriggerConfig(), 0.5, now)
    assert event.remediation_available_at is None

    remediated_at = now + timedelta(days=5)
    updated = store.set_remediation_available(event.event_id, remediated_at)
    assert updated.remediation_available_at == remediated_at
    assert store.get(event.event_id).remediation_available_at == remediated_at
    store.close()


def test_set_remediation_available_unknown_event_raises(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "cra-state.sqlite")
    with pytest.raises(KeyError):
        store.set_remediation_available("no-such-event", datetime(2026, 1, 1, tzinfo=UTC))
    store.close()


def test_mark_stage_completed(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "cra-state.sqlite")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    event, _ = store.get_or_create(_finding(), ["euvd_exploited"], CraTriggerConfig(), 0.5, now)

    completed_at = now + timedelta(hours=10)
    updated = store.mark_stage_completed(
        event.event_id, "early_warning", completed_at, "Filed via the platform."
    )
    assert updated.stage_completions["early_warning"].completed_at == completed_at
    assert updated.stage_completions["early_warning"].note == "Filed via the platform."
    store.close()


def test_list_all_returns_every_event_sorted(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "cra-state.sqlite")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store.get_or_create(_finding("EUVD-2"), ["euvd_exploited"], CraTriggerConfig(), 0.5, now)
    store.get_or_create(_finding("EUVD-1"), ["euvd_exploited"], CraTriggerConfig(), 0.5, now)
    events = store.list_all()
    assert [e.finding.record.euvd_id for e in events] == ["EUVD-1", "EUVD-2"]
    store.close()


def test_corrupted_store_is_quarantined_never_deleted(tmp_path: Path) -> None:
    # Audit finding SEC-001: this file is a legal record - corruption must preserve the
    # original bytes on disk (renamed aside), not unlink them.
    path = tmp_path / "cra-state.sqlite"
    garbage = b"not a sqlite database" * 50
    path.write_bytes(garbage)

    store = EventStore(path)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    event, created = store.get_or_create(
        _finding(), ["euvd_exploited"], CraTriggerConfig(), 0.5, now
    )
    assert created is True  # a fresh store works after quarantine

    quarantined = list(tmp_path.glob("cra-state.sqlite.corrupt-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == garbage  # original bytes preserved verbatim
    store.close()


def test_row_from_an_incompatible_schema_raises_state_error(tmp_path: Path) -> None:
    # TECH-002: a row written by a different euvd-watch build must fail loudly with a
    # typed error naming the event, never escape as a raw pydantic traceback.
    import sqlite3

    path = tmp_path / "cra-state.sqlite"
    store = EventStore(path)
    store.close()
    conn = sqlite3.connect(path)
    conn.execute(
        "INSERT INTO events (event_id, data) VALUES (?, ?)",
        ("future-event", '{"schema_version": 99, "unrecognizable": true}'),
    )
    conn.commit()
    conn.close()

    store = EventStore(path)
    with pytest.raises(StateError, match="future-event"):
        store.get("future-event")
    with pytest.raises(StateError, match="future-event"):
        store.list_all()
    store.close()


def test_events_persist_across_store_instances(tmp_path: Path) -> None:
    path = tmp_path / "cra-state.sqlite"
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store1 = EventStore(path)
    store1.get_or_create(_finding(), ["euvd_exploited"], CraTriggerConfig(), 0.5, now)
    store1.close()

    store2 = EventStore(path)
    assert len(store2.list_all()) == 1
    _, created = store2.get_or_create(_finding(), ["euvd_exploited"], CraTriggerConfig(), 0.5, now)
    assert created is False  # still recognized as existing
    store2.close()
