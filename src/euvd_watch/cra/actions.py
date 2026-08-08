# SPDX-License-Identifier: EUPL-1.2
"""Human write actions on a CRA event (Step 4.5, shared with the dashboard's Step 6.2
"Mark stage complete" control).

Extracted so the CLI (`cra mark`) and the web dashboard's one write route record
*exactly* the same audit-log entries for the same action, regardless of which surface a
human used - the audit trail must never depend on which door someone walked through.
"""

from __future__ import annotations

from datetime import datetime

from euvd_watch.config import CraStageConfig
from euvd_watch.cra.audit import AuditLog
from euvd_watch.cra.state import EventStore


class UnknownStageError(Exception):
    """Raised when `stage` isn't one of the configured `cra_stages` names."""


def validate_stage_name(stage: str, cra_stages: list[CraStageConfig]) -> None:
    valid = [s.name for s in cra_stages]
    if stage not in valid:
        raise UnknownStageError(f"Unknown stage {stage!r}. Configured stages: {', '.join(valid)}")


def mark(
    store: EventStore,
    log: AuditLog,
    event_id: str,
    *,
    stage: str | None,
    note: str | None,
    remediation_available: bool,
    now: datetime,
) -> None:
    """Record human action(s) on one event: stage completion and/or remediation
    availability, in that order. Raises KeyError if the event doesn't exist (from the
    store), or StateError/AuditError on I/O failure - callers translate these to their
    own exit code / HTTP status.
    """
    if remediation_available:
        store.set_remediation_available(event_id, now)
        log.append(
            "remediation_marked",
            {"event_id": event_id, "at": now.isoformat(), "note": note},
            actor="human",
        )
    if stage is not None:
        store.mark_stage_completed(event_id, stage, now, note)
        log.append(
            "stage_marked",
            {"event_id": event_id, "stage": stage, "at": now.isoformat(), "note": note},
            actor="human",
        )
