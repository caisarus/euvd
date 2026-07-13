# SPDX-License-Identifier: EUPL-1.2
"""Durable CRA event state (Step 4.1).

A separate SQLite store from http.py's response Cache, deliberately: CRA events are a
legal record, not a cache — they must never expire, be purged, or reset once created. One
row per event, keyed by (component.dedupe_key, euvd_id), storing the full event as JSON
(the event's nested structures - Finding, EuvdRecord, Component - are already well-suited
pydantic models; a single JSON blob avoids a wide, brittle column schema).

Immutability contract (audit 2026-07-10, finding SEC-003): everything recorded at first
fire — `finding`, `fired_rules`, `policy_snapshot`, `first_seen` — is never overwritten by
later evaluations. "What did we know and under which policy did it fire" must stay
answerable verbatim. What we learn later (an EPSS score moving, a KEV listing appearing)
is recorded on `latest_finding` instead.

Corruption handling (audit finding SEC-001): a corrupted store file is quarantined by
renaming — never deleted — and a fresh store is created so new awareness can still be
recorded. Read/write failures surface as a typed StateError at this module's boundary
(audit finding TECH-002); nothing here ever lets a raw sqlite3/pydantic exception escape
to the CLI.
"""

from __future__ import annotations

import contextlib
import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from euvd_watch.config import CraTriggerConfig
from euvd_watch.euvd.match import Finding

logger = logging.getLogger(__name__)


class StateError(Exception):
    """Raised when the CRA event store cannot be read or written safely."""


class StageCompletion(BaseModel):
    model_config = ConfigDict(frozen=True)

    completed_at: datetime
    note: str | None = None


class Event(BaseModel):
    """A persisted CRA trigger event: the durable record of 'we became aware'.

    `finding`/`fired_rules`/`policy_snapshot` are the first-fire record and never change;
    `latest_finding` carries what the most recent evaluation knew (may differ in EPSS
    score, KEV membership, confidence). `schema_version` guards future shape changes:
    a newer row shape must fail loudly, never misparse (TECH-002).
    """

    model_config = ConfigDict(frozen=True)

    schema_version: int = 1
    event_id: str
    finding: Finding  # as evaluated when the trigger first fired; immutable
    fired_rules: list[str]  # the first-fire awareness basis; immutable
    first_seen: datetime  # UTC; set once, never changed by later evaluations
    policy_snapshot: CraTriggerConfig  # the exact policy that fired; immutable
    # Settings.epss_threshold at fire time (not part of CraTriggerConfig); immutable.
    epss_threshold: float
    latest_finding: Finding | None = None  # refreshed by later evaluations
    remediation_available_at: datetime | None = None
    stage_completions: dict[str, StageCompletion] = {}

    @property
    def current_finding(self) -> Finding:
        """The most recent evaluation of this event's finding (first-fire one if none)."""
        return self.latest_finding or self.finding

    @staticmethod
    def make_id(component_dedupe_key: str, euvd_id: str) -> str:
        return f"{component_dedupe_key}|{euvd_id}"


class EventStore:
    """SQLite-backed, no-TTL store of CRA events.

    Unlike http.py's Cache, corruption here never deletes data: the broken file is
    quarantined (renamed with a .corrupt-<UTC timestamp> suffix) and a fresh store is
    created, so recording new awareness is never blocked while the old bytes stay on disk
    for recovery.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._connect()

    def _connect(self, *, retry_on_corruption: bool = True) -> None:
        self._conn = sqlite3.connect(self._path)
        try:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, data TEXT NOT NULL)"
            )
            self._conn.commit()
        except sqlite3.DatabaseError as exc:
            if not retry_on_corruption:
                raise StateError(f"CRA event store at {self._path} is unusable: {exc}") from exc
            self._quarantine(exc)
            self._connect(retry_on_corruption=False)

    def _quarantine(self, cause: Exception) -> None:
        with contextlib.suppress(sqlite3.Error):
            self._conn.close()
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        quarantine = self._path.with_name(f"{self._path.name}.corrupt-{stamp}")
        try:
            self._path.rename(quarantine)
        except OSError as exc:
            raise StateError(
                f"CRA event store at {self._path} is corrupted ({cause}) and could not be "
                f"quarantined to {quarantine}: {exc}. Refusing to continue - this file is "
                f"a legal record; do not delete it."
            ) from exc
        logger.warning(
            "CRA event store at %s is corrupted; quarantined it to %s and created a fresh "
            "store. The quarantined file is preserved for recovery - do not delete it.",
            self._path,
            quarantine,
        )

    def _load_event(self, event_id: str, data: str) -> Event:
        try:
            return Event.model_validate_json(data)
        except ValidationError as exc:
            raise StateError(
                f"CRA event {event_id!r} in {self._path} does not match this build's "
                f"event schema (a newer/older euvd-watch may have written it): {exc}"
            ) from exc

    def get(self, event_id: str) -> Event | None:
        try:
            row = self._conn.execute(
                "SELECT data FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise StateError(f"Could not read CRA event store {self._path}: {exc}") from exc
        return self._load_event(event_id, row[0]) if row else None

    def get_or_create(
        self,
        finding: Finding,
        fired_rules: list[str],
        policy_snapshot: CraTriggerConfig,
        epss_threshold: float,
        now: datetime,
    ) -> tuple[Event, bool]:
        """Return (event, was_newly_created).

        Re-runs for the same (component, euvd_id) key never reset `first_seen`, and never
        overwrite the first-fire `finding`/`fired_rules`/`policy_snapshot` (SEC-003) -
        only `latest_finding` refreshes, because what changes across runs is what we know
        now, not what we knew when the clock started.
        """
        event_id = Event.make_id(finding.component.dedupe_key, finding.record.euvd_id)
        existing = self.get(event_id)
        if existing is not None:
            refreshed = existing.model_copy(update={"latest_finding": finding})
            self._save(refreshed)
            return refreshed, False

        event = Event(
            event_id=event_id,
            finding=finding,
            fired_rules=fired_rules,
            first_seen=now,
            policy_snapshot=policy_snapshot,
            epss_threshold=epss_threshold,
        )
        self._save(event)
        return event, True

    def set_remediation_available(self, event_id: str, at: datetime) -> Event:
        event = self.get(event_id)
        if event is None:
            raise KeyError(f"No CRA event with id {event_id!r}")
        updated = event.model_copy(update={"remediation_available_at": at})
        self._save(updated)
        return updated

    def mark_stage_completed(
        self, event_id: str, stage_name: str, at: datetime, note: str | None
    ) -> Event:
        event = self.get(event_id)
        if event is None:
            raise KeyError(f"No CRA event with id {event_id!r}")
        completions = dict(event.stage_completions)
        completions[stage_name] = StageCompletion(completed_at=at, note=note)
        updated = event.model_copy(update={"stage_completions": completions})
        self._save(updated)
        return updated

    def list_all(self) -> list[Event]:
        try:
            rows = self._conn.execute("SELECT event_id, data FROM events ORDER BY event_id")
            fetched = rows.fetchall()
        except sqlite3.Error as exc:
            raise StateError(f"Could not read CRA event store {self._path}: {exc}") from exc
        return [self._load_event(row[0], row[1]) for row in fetched]

    def _save(self, event: Event) -> None:
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO events (event_id, data) VALUES (?, ?)",
                (event.event_id, event.model_dump_json()),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StateError(f"Could not write CRA event store {self._path}: {exc}") from exc

    def close(self) -> None:
        with contextlib.suppress(sqlite3.Error):
            self._conn.close()
