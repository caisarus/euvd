"""Covers implementation_plan.md Step 4.2: the 24h/72h/14-day clock transition matrix."""

from datetime import UTC, datetime, timedelta

import pytest

from euvd_watch.config import CraStageConfig, CraTriggerConfig
from euvd_watch.cra.clock import ClockState, compute_all, compute_stage_status, is_event_open
from euvd_watch.cra.state import Event
from euvd_watch.euvd.match import Confidence, Finding, Strategy
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.models import Component, SourceFormat

pytestmark = pytest.mark.unit

FIRST_SEEN = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
EARLY_WARNING = CraStageConfig(name="early_warning", hours=24, anchor="first_seen")
VULN_NOTIFICATION = CraStageConfig(name="vulnerability_notification", hours=72, anchor="first_seen")
FINAL_REPORT = CraStageConfig(name="final_report", hours=14 * 24, anchor="remediation_available")


def _event(**overrides: object) -> Event:
    component = Component(
        name="widget", version="1.0.0", source_format=SourceFormat.CYCLONEDX, raw_ref="r"
    )
    record = EuvdRecord(euvd_id="EUVD-1", exploited=True)
    finding = Finding(
        component=component,
        record=record,
        confidence=Confidence.HIGH,
        strategy=Strategy.STRUCTURED,
        explanation="x",
    )
    defaults: dict[str, object] = {
        "event_id": Event.make_id(component.dedupe_key, record.euvd_id),
        "finding": finding,
        "fired_rules": ["euvd_exploited"],
        "first_seen": FIRST_SEEN,
        "policy_snapshot": CraTriggerConfig(),
        "epss_threshold": 0.5,
    }
    defaults.update(overrides)
    return Event.model_validate(defaults)


# --- early_warning (24h, first_seen-anchored): pending -> due_soon -> overdue -> completed ---


def test_early_warning_pending_far_from_deadline() -> None:
    status = compute_stage_status(_event(), EARLY_WARNING, FIRST_SEEN + timedelta(hours=1))
    assert status.state is ClockState.PENDING


def test_early_warning_due_soon_boundary_exact() -> None:
    # 25% of 24h = 6h remaining -> deadline - 6h = 18h after first_seen.
    at_boundary = FIRST_SEEN + timedelta(hours=18)
    status = compute_stage_status(_event(), EARLY_WARNING, at_boundary)
    assert status.state is ClockState.DUE_SOON  # exactly 25% remaining counts as due_soon


def test_early_warning_pending_just_before_due_soon_boundary() -> None:
    just_before = FIRST_SEEN + timedelta(hours=18) - timedelta(seconds=1)
    status = compute_stage_status(_event(), EARLY_WARNING, just_before)
    assert status.state is ClockState.PENDING


def test_early_warning_overdue_at_exact_deadline() -> None:
    at_deadline = FIRST_SEEN + timedelta(hours=24)
    status = compute_stage_status(_event(), EARLY_WARNING, at_deadline)
    assert status.state is ClockState.OVERDUE


def test_early_warning_overdue_one_second_after_deadline() -> None:
    after = FIRST_SEEN + timedelta(hours=24, seconds=1)
    status = compute_stage_status(_event(), EARLY_WARNING, after)
    assert status.state is ClockState.OVERDUE


def test_early_warning_due_soon_one_second_before_deadline() -> None:
    just_before = FIRST_SEEN + timedelta(hours=24) - timedelta(seconds=1)
    status = compute_stage_status(_event(), EARLY_WARNING, just_before)
    assert status.state is ClockState.DUE_SOON


def test_completed_stage_stays_completed_regardless_of_time() -> None:
    completed_event = _event(
        stage_completions={
            "early_warning": {"completed_at": FIRST_SEEN + timedelta(hours=10), "note": "filed"}
        }
    )
    # Even long after the deadline, a completed stage reports completed, not overdue.
    status = compute_stage_status(completed_event, EARLY_WARNING, FIRST_SEEN + timedelta(days=30))
    assert status.state is ClockState.COMPLETED
    assert status.completed_at == FIRST_SEEN + timedelta(hours=10)


# --- vulnerability_notification (72h): independent countdown from early_warning ---


def test_vulnerability_notification_pending_while_early_warning_is_overdue() -> None:
    # 30h after first_seen: early_warning (24h) is overdue, but vuln_notification (72h)
    # still has 42h remaining (>25% of 72h=18h) -> independently pending.
    now = FIRST_SEEN + timedelta(hours=30)
    ew = compute_stage_status(_event(), EARLY_WARNING, now)
    vn = compute_stage_status(_event(), VULN_NOTIFICATION, now)
    assert ew.state is ClockState.OVERDUE
    assert vn.state is ClockState.PENDING


def test_vulnerability_notification_due_soon_boundary() -> None:
    # 25% of 72h = 18h remaining -> 54h after first_seen.
    status = compute_stage_status(_event(), VULN_NOTIFICATION, FIRST_SEEN + timedelta(hours=54))
    assert status.state is ClockState.DUE_SOON


def test_vulnerability_notification_overdue() -> None:
    just_past = FIRST_SEEN + timedelta(hours=72, seconds=1)
    status = compute_stage_status(_event(), VULN_NOTIFICATION, just_past)
    assert status.state is ClockState.OVERDUE


# --- final_report (14 days, remediation-anchored): awaiting_anchor until marked ---


def test_final_report_awaiting_anchor_when_remediation_not_marked() -> None:
    status = compute_stage_status(_event(), FINAL_REPORT, FIRST_SEEN + timedelta(days=100))
    assert status.state is ClockState.AWAITING_ANCHOR
    assert status.deadline is None


def test_final_report_pending_once_remediation_marked() -> None:
    remediated_at = FIRST_SEEN + timedelta(days=10)
    event = _event(remediation_available_at=remediated_at)
    status = compute_stage_status(event, FINAL_REPORT, remediated_at + timedelta(hours=1))
    assert status.state is ClockState.PENDING
    assert status.deadline == remediated_at + timedelta(days=14)


def test_final_report_due_soon_and_overdue_after_remediation() -> None:
    remediated_at = FIRST_SEEN + timedelta(days=10)
    event = _event(remediation_available_at=remediated_at)
    # 25% of 336h = 84h = 3.5 days remaining
    due_soon_boundary = remediated_at + timedelta(hours=336 - 84)
    assert compute_stage_status(event, FINAL_REPORT, due_soon_boundary).state is ClockState.DUE_SOON
    overdue_at = remediated_at + timedelta(hours=336, seconds=1)
    assert compute_stage_status(event, FINAL_REPORT, overdue_at).state is ClockState.OVERDUE


def test_final_report_completed_after_remediation_and_mark() -> None:
    remediated_at = FIRST_SEEN + timedelta(days=10)
    event = _event(
        remediation_available_at=remediated_at,
        stage_completions={
            "final_report": {"completed_at": remediated_at + timedelta(days=5), "note": None}
        },
    )
    status = compute_stage_status(event, FINAL_REPORT, remediated_at + timedelta(days=100))
    assert status.state is ClockState.COMPLETED


# --- custom stage config is honored ---


def test_custom_stage_config_honored() -> None:
    custom = CraStageConfig(name="custom", hours=48, anchor="first_seen")
    status = compute_stage_status(_event(), custom, FIRST_SEEN + timedelta(hours=1))
    assert status.state is ClockState.PENDING
    assert status.deadline == FIRST_SEEN + timedelta(hours=48)


# --- compute_all / is_event_open ---


def test_compute_all_returns_independent_countdowns_in_config_order() -> None:
    statuses = compute_all(_event(), [EARLY_WARNING, VULN_NOTIFICATION, FINAL_REPORT], FIRST_SEEN)
    assert [s.stage.name for s in statuses] == [
        "early_warning",
        "vulnerability_notification",
        "final_report",
    ]
    assert statuses[2].state is ClockState.AWAITING_ANCHOR


def test_is_event_open_true_until_all_stages_completed() -> None:
    stages = [EARLY_WARNING, VULN_NOTIFICATION]
    open_event = _event()
    assert is_event_open(open_event, stages) is True

    fully_completed = _event(
        stage_completions={
            "early_warning": {"completed_at": FIRST_SEEN, "note": None},
            "vulnerability_notification": {"completed_at": FIRST_SEEN, "note": None},
        }
    )
    assert is_event_open(fully_completed, stages) is False


def test_all_times_are_utc() -> None:
    status = compute_stage_status(_event(), EARLY_WARNING, FIRST_SEEN)
    assert status.anchor_at is not None and status.anchor_at.tzinfo == UTC
    assert status.deadline is not None and status.deadline.tzinfo == UTC
