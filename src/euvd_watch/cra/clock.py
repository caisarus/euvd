"""24h / 72h / 14-day clock tracking (Step 4.2).

Stages are config (`Settings.cra_stages`), not code, so a legal-text change never requires
a code change. Two of the three default stages (early_warning, vulnerability_notification)
anchor on `first_seen`, which exists the instant a CRA event is created - always counting
down. The third (final_report) anchors on `remediation_available_at`, which doesn't exist
until a human marks it (`cra mark --remediation-available`): before that, the stage has no
deadline at all, hence the fifth state below (a deliberate addition beyond the plan's
literal 4-state list, justified by the real Article 14 text - see docs/cra.md).

All timestamps UTC in, UTC out; the CLI is responsible for rendering with an explicit zone.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from euvd_watch.config import CraStageConfig
from euvd_watch.cra.state import Event

# A stage counts as "due soon" once 25% or less of its total duration remains.
DUE_SOON_FRACTION = 0.25


class ClockState(StrEnum):
    AWAITING_ANCHOR = "awaiting_anchor"  # anchor event hasn't happened yet - no deadline
    PENDING = "pending"
    DUE_SOON = "due_soon"
    OVERDUE = "overdue"
    COMPLETED = "completed"


class StageStatus(BaseModel):
    """The computed state of one stage for one event, at a point in time."""

    model_config = ConfigDict(frozen=True)

    stage: CraStageConfig
    state: ClockState
    anchor_at: datetime | None
    deadline: datetime | None
    completed_at: datetime | None = None


def _anchor_timestamp(event: Event, stage: CraStageConfig) -> datetime | None:
    if stage.anchor == "first_seen":
        return event.first_seen
    return event.remediation_available_at


def compute_stage_status(event: Event, stage: CraStageConfig, now: datetime) -> StageStatus:
    """The stage's state as of `now` (pass a real UTC-aware datetime; tests freeze it)."""
    anchor_at = _anchor_timestamp(event, stage)
    deadline = anchor_at + timedelta(hours=stage.hours) if anchor_at is not None else None
    completion = event.stage_completions.get(stage.name)

    if completion is not None:
        return StageStatus(
            stage=stage,
            state=ClockState.COMPLETED,
            anchor_at=anchor_at,
            deadline=deadline,
            completed_at=completion.completed_at,
        )

    if anchor_at is None or deadline is None:
        return StageStatus(
            stage=stage, state=ClockState.AWAITING_ANCHOR, anchor_at=None, deadline=None
        )

    remaining = deadline - now
    total = timedelta(hours=stage.hours)
    if remaining <= timedelta(0):
        state = ClockState.OVERDUE
    elif remaining <= total * DUE_SOON_FRACTION:
        state = ClockState.DUE_SOON
    else:
        state = ClockState.PENDING
    return StageStatus(stage=stage, state=state, anchor_at=anchor_at, deadline=deadline)


def compute_all(
    event: Event, stages: list[CraStageConfig], now: datetime | None = None
) -> list[StageStatus]:
    """Every configured stage's status for one event, in config order."""
    current = now or datetime.now(UTC)
    return [compute_stage_status(event, stage, current) for stage in stages]


def is_event_open(event: Event, stages: list[CraStageConfig]) -> bool:
    """An event is open until every configured stage has been marked completed."""
    return any(stage.name not in event.stage_completions for stage in stages)
