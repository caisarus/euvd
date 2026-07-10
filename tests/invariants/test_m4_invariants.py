"""Executable "must never happen" list for M4 (test_plan.md §6, INV-6 and INV-7).

INV-6: re-running match/cra never duplicates events or resets first_seen.
INV-7: audit-log tampering of any single entry is detected and located.
"""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from euvd_watch.config import Settings
from euvd_watch.cra.audit import AuditLog, verify
from euvd_watch.cra.state import EventStore
from euvd_watch.cra.trigger import evaluate_all
from euvd_watch.euvd.match import Confidence, Finding, Strategy
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.models import Component, SourceFormat

pytestmark = pytest.mark.invariant


def _findings() -> list[Finding]:
    def finding(name: str, euvd_id: str, epss: float | None) -> Finding:
        return Finding(
            component=Component(
                name=name, version="1.0.0", source_format=SourceFormat.CYCLONEDX, raw_ref="r"
            ),
            record=EuvdRecord(euvd_id=euvd_id, exploited=True),
            confidence=Confidence.HIGH,
            strategy=Strategy.STRUCTURED,
            explanation="x",
            epss_score=epss,
            in_kev=None,
        )

    return [finding("alpha", "EUVD-1", 0.9), finding("beta", "EUVD-2", None)]


def test_inv6_double_run_never_duplicates_events_or_resets_first_seen(tmp_path: Path) -> None:
    settings = Settings()
    findings = _findings()
    store = EventStore(tmp_path / "events.sqlite")

    first_run = datetime(2026, 1, 1, tzinfo=UTC)
    second_run = first_run + timedelta(hours=6)
    for now in (first_run, second_run):
        for result in evaluate_all(findings, settings):
            store.get_or_create(
                result.finding,
                result.fired_rules,
                result.policy_snapshot,
                result.epss_threshold,
                now,
            )

    events = store.list_all()
    assert len(events) == 2  # one per (component, euvd_id): never duplicated
    assert all(e.first_seen == first_run for e in events)  # never reset
    assert all(e.fired_rules and e.policy_snapshot for e in events)  # first-fire kept
    store.close()


def test_inv7_tampering_any_single_entry_is_detected_and_located(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    total = 20
    for i in range(total):
        log.append("action", {"i": i, "text": f"payload-{i}"})
    original = path.read_text(encoding="utf-8")

    for target in range(total):  # every single entry, exhaustively
        lines = original.splitlines()
        lines[target] = lines[target].replace(f"payload-{target}", f"tampered-{target}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify(path)
        assert not result.ok, f"tamper at entry {target} went undetected"
        assert result.bad_line == target + 1, f"tamper at {target} located at {result.bad_line}"

    path.write_text(original, encoding="utf-8")
    assert verify(path).ok  # sanity: the untampered chain still verifies


def test_inv7_entries_are_valid_json_lines(tmp_path: Path) -> None:
    # The chain is only auditable if every line is independently parseable.
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("a", {"x": 1})
    log.append("b", {"y": "Țesătorie"})
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        assert entry["schema_version"] == 1
        assert set(entry) >= {"ts", "actor", "action", "payload", "prev_hash", "entry_hash"}
