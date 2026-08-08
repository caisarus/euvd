#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Regenerate the committed state-DB fixtures under tests/fixtures/db/.

Run manually from the repo root (never in CI). The fixtures are the "migrations from
every prior schema version" regression memory (plans/test_plan.md §M6 6.1) and are
kept forever:

- `legacy-pre61/` — the pre-6.1 layout: `cra-events.sqlite` with one event plus one
  `watch/<key>.json` snapshot, both with fixed timestamps so regeneration is stable.
- `v1/euvd-watch.sqlite` — a consolidated store at schema version 1.

A new schema version N means: ship migration `000N_*.sql`, regenerate `vN/` here, and
add a migration test from every committed older version to N.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from euvd_watch.config import CraTriggerConfig
from euvd_watch.cra.state import EventStore
from euvd_watch.euvd.match import Confidence, Finding, Strategy
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.models import Component, SourceFormat
from euvd_watch.web.store import Store

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "db"
FIXED_NOW = datetime(2026, 8, 8, 12, 0, 0, tzinfo=UTC)


def _finding() -> Finding:
    component = Component(
        name="widget", version="1.0.0", source_format=SourceFormat.CYCLONEDX, raw_ref="r"
    )
    record = EuvdRecord(euvd_id="EUVD-FIXTURE-0001", exploited=True)
    return Finding(
        component=component,
        record=record,
        confidence=Confidence.HIGH,
        strategy=Strategy.STRUCTURED,
        explanation="fixture event for state-DB migration tests",
    )


def make_legacy_pre61() -> None:
    root = FIXTURES / "legacy-pre61"
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)

    events = EventStore(root / "cra-events.sqlite")
    events.get_or_create(
        _finding(),
        fired_rules=["euvd_exploited"],
        policy_snapshot=CraTriggerConfig(),
        epss_threshold=0.5,
        now=FIXED_NOW,
    )
    events.close()

    watch_dir = root / "watch"
    watch_dir.mkdir()
    (watch_dir / "aaaaaaaaaaaaaaaa.json").write_text(
        '{\n  "schema_version": 1,\n  "generated_at": "2026-08-08T12:00:00+00:00",\n'
        '  "findings": []\n}\n',
        encoding="utf-8",
    )


def make_v1() -> None:
    root = FIXTURES / "v1"
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    store = Store(root)
    report = store.migrate()
    store.close()
    assert report.applied_versions == [1], report
    # Drop the WAL sidecars: the fixture is the .sqlite file alone.
    for sidecar in root.glob("euvd-watch.sqlite-*"):
        sidecar.unlink()


if __name__ == "__main__":
    make_legacy_pre61()
    make_v1()
    print(f"Fixtures written under {FIXTURES}")
