"""Covers implementation_plan.md Step 6.2: the dashboard view-model layer.

Pure(ish) functions in web/dashboard.py, exercised without HTTP - the FastAPI route
contract (401s, 200s, no-inline-handler sweep) lives in tests/e2e/test_web_dashboard.py.
"""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from euvd_watch.config import CraStageConfig, CraTriggerConfig, Settings
from euvd_watch.cra.clock import ClockState, StageStatus
from euvd_watch.cra.state import Event, EventStore, StageCompletion
from euvd_watch.euvd.match import Confidence, Finding, Strategy
from euvd_watch.euvd.models import AffectedProduct, EuvdRecord
from euvd_watch.models import Component, SourceFormat
from euvd_watch.vex.decisions import DecisionEntry, DecisionsFile
from euvd_watch.vex.model import Justification, Status
from euvd_watch.watch.differ import finding_identity
from euvd_watch.web import dashboard as dash
from euvd_watch.web.store import Store, sbom_snapshot_key

pytestmark = pytest.mark.unit

SBOM = "examples/sboms/demo.cdx.json"


def _component(name: str = "jinja2", version: str = "3.1.6", purl: str | None = None) -> Component:
    return Component(
        name=name,
        version=version,
        purl=purl or f"pkg:pypi/{name}@{version}",
        source_format=SourceFormat.CYCLONEDX,
        raw_ref="r",
    )


def _finding(
    euvd_id: str = "EUVD-1",
    exploited: bool = True,
    confidence: Confidence = Confidence.MEDIUM,
    component: Component | None = None,
) -> Finding:
    record = EuvdRecord(
        euvd_id=euvd_id,
        exploited=exploited,
        exploited_since="Jan 1, 2026" if exploited else None,
        aliases=["CVE-2099-0001"],
        description="a test vulnerability",
        affected_products=[AffectedProduct(vendor=None, product="jinja2", version_range="<3.1.7")],
    )
    return Finding(
        component=component or _component(),
        record=record,
        confidence=confidence,
        strategy=Strategy.STRUCTURED,
        explanation="matched via structured evidence",
        epss_score=0.91,
        in_kev=True,
    )


def _seed_snapshot(store: Store, findings: list[Finding], sbom: str = SBOM) -> None:
    key = sbom_snapshot_key(sbom)
    artifact = {
        "schema_version": 1,
        "generated_at": datetime(2026, 8, 8, 12, 0, tzinfo=UTC).isoformat(),
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    store.save_watch_snapshot(key, json.dumps(artifact))


def _settings(tmp_path: Path) -> Settings:
    settings = Settings(state_dir=tmp_path / "state")
    settings.organization.name = "Test Org"
    settings.organization.contact_email = "sec@test.org"
    settings.organization.product_name = "Test Product"
    return settings


# -- pill_for --------------------------------------------------------------------


def test_pill_for_confidence_never_borrows_semantic_colors() -> None:
    for level in Confidence:
        pill = dash.pill_for(level)
        assert "pill--neutral" in pill.css_class
        assert "pill--filled" not in pill.css_class


def test_pill_for_exploited_status_is_outline_never_filled() -> None:
    """Only overdue/exploited may use a filled crit pill - VEX 'affected' does not."""
    pill = dash.pill_for(Status.AFFECTED)
    assert "pill--crit" in pill.css_class
    assert "pill--filled" not in pill.css_class


def test_pill_for_overdue_is_filled_crit() -> None:
    pill = dash.pill_for(ClockState.OVERDUE)
    assert pill.css_class == "pill--crit pill--filled"


def test_pill_for_unknown_type_raises() -> None:
    with pytest.raises(TypeError):
        dash.pill_for("not-an-enum")  # type: ignore[arg-type]


# -- comp_hash / event_url_id / finding identity ----------------------------------


def test_comp_hash_is_url_safe_even_for_slash_heavy_purls() -> None:
    h = dash.comp_hash("purl:pkg:pypi/jinja2@3.1.6")
    assert "/" not in h and "@" not in h and ":" not in h
    assert len(h) == 12


def test_event_url_id_is_url_safe_for_purl_derived_ids() -> None:
    event_id = Event.make_id("purl:pkg:pypi/jinja2@3.1.6", "EUVD-1")
    url_id = dash.event_url_id(event_id)
    assert "/" not in url_id and "|" not in url_id


def test_default_sort_key_orders_exploited_then_confidence_then_name() -> None:
    a = _finding(
        euvd_id="A", exploited=False, confidence=Confidence.HIGH, component=_component("zeta")
    )
    b = _finding(
        euvd_id="B", exploited=True, confidence=Confidence.LOW, component=_component("alpha")
    )
    c = _finding(
        euvd_id="C", exploited=True, confidence=Confidence.HIGH, component=_component("beta")
    )
    ordered = sorted([a, b, c], key=dash.default_sort_key)
    assert [f.record.euvd_id for f in ordered] == ["C", "B", "A"]


# -- load_findings -----------------------------------------------------------------


def test_load_findings_raises_when_no_snapshot(tmp_path: Path) -> None:
    store = Store(tmp_path / "state")
    store.migrate()
    with pytest.raises(dash.NoSnapshotError, match="watch"):
        dash.load_findings(store, SBOM)
    store.close()


def test_load_findings_returns_snapshot_and_timestamp(tmp_path: Path) -> None:
    store = Store(tmp_path / "state")
    store.migrate()
    _seed_snapshot(store, [_finding()])
    findings, generated_at = dash.load_findings(store, SBOM)
    assert len(findings) == 1
    assert findings[0].record.euvd_id == "EUVD-1"
    assert generated_at == "2026-08-08T12:00:00+00:00"
    store.close()


# -- VEX status computation ---------------------------------------------------------


def test_compute_vex_statuses_defaults_to_under_investigation() -> None:
    """Watch-snapshot findings are MATCH-only, so with no human decisions every
    status is under_investigation - mirrors `vex generate --findings`."""
    finding = _finding()
    statuses = dash.compute_vex_statuses([finding], DecisionsFile(decisions=[]))
    key = finding_identity(finding)
    assert statuses[key].decision.status is Status.UNDER_INVESTIGATION
    assert statuses[key].is_human is False


def test_compute_vex_statuses_applies_human_decision() -> None:
    finding = _finding()
    entry = DecisionEntry(
        euvd_id="EUVD-1",
        purl="pkg:pypi/jinja2@3.1.6",
        status=Status.NOT_AFFECTED,
        justification=Justification.COMPONENT_NOT_PRESENT,
        statement="reviewed manually",
        author="me",
        date="2026-08-08",
    )
    statuses = dash.compute_vex_statuses([finding], DecisionsFile(decisions=[entry]))
    key = finding_identity(finding)
    assert statuses[key].decision.status is Status.NOT_AFFECTED
    assert statuses[key].is_human is True


def test_compute_and_cache_vex_statuses_populates_the_read_model(tmp_path: Path) -> None:
    store = Store(tmp_path / "state")
    store.migrate()
    finding = _finding()
    dash.compute_and_cache_vex_statuses(store, [finding], DecisionsFile(decisions=[]))
    cached = store.list_vex_statuses()
    assert len(cached) == 1
    row = next(iter(cached.values()))
    assert row.status == "under_investigation"
    assert row.source == "automated"
    store.close()


def test_vex_decision_hint_never_prescribes_a_status() -> None:
    """The UI shows how to record a decision; it must never silently choose one."""
    finding = _finding()
    snippet, cli_hint = dash.vex_decision_hint(finding, SBOM)
    assert "your call" in snippet  # the human must decide, not the tool
    assert "CVE-2099-0001" in snippet or "EUVD-1" in snippet
    assert SBOM in cli_hint
    assert "vex generate" in cli_hint


def test_vex_decision_hint_falls_back_to_euvd_id_without_a_cve() -> None:
    record = EuvdRecord(euvd_id="EUVD-9", exploited=False)
    finding = Finding(
        component=_component(),
        record=record,
        confidence=Confidence.LOW,
        strategy=Strategy.FUZZY,
        explanation="x",
    )
    snippet, _cli = dash.vex_decision_hint(finding, SBOM)
    assert "EUVD-9" in snippet


# -- deadline bars -------------------------------------------------------------------


def _stage_status(
    state: ClockState,
    hours: float = 24,
    anchor_at: datetime | None = None,
    deadline: datetime | None = None,
    completed_at: datetime | None = None,
) -> StageStatus:
    stage = CraStageConfig(name="early_warning", hours=hours, anchor="first_seen")
    return StageStatus(
        stage=stage, state=state, anchor_at=anchor_at, deadline=deadline, completed_at=completed_at
    )


def test_deadline_bar_awaiting_anchor_has_no_progress_bar() -> None:
    event = Event(
        event_id="e1",
        finding=_finding(),
        fired_rules=["euvd_exploited"],
        first_seen=datetime.now(UTC),
        policy_snapshot=CraTriggerConfig(),
        epss_threshold=0.5,
    )
    status = _stage_status(ClockState.AWAITING_ANCHOR)
    bar = dash.deadline_bar(status, datetime.now(UTC), event)
    assert bar.has_bar is False
    assert bar.remaining_seconds is None
    assert "Awaiting" in bar.remaining_text


def test_deadline_bar_pending_shows_positive_countdown() -> None:
    now = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)
    anchor = now - timedelta(hours=1)
    deadline = anchor + timedelta(hours=24)
    event = Event(
        event_id="e1",
        finding=_finding(),
        fired_rules=["euvd_exploited"],
        first_seen=anchor,
        policy_snapshot=CraTriggerConfig(),
        epss_threshold=0.5,
    )
    status = _stage_status(ClockState.PENDING, anchor_at=anchor, deadline=deadline)
    bar = dash.deadline_bar(status, now, event)
    assert bar.has_bar is True
    assert bar.remaining_seconds is not None and bar.remaining_seconds > 0
    assert not bar.remaining_text.startswith("+")


def test_deadline_bar_overdue_shows_signed_overrun() -> None:
    now = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)
    anchor = now - timedelta(hours=30)
    deadline = anchor + timedelta(hours=24)
    event = Event(
        event_id="e1",
        finding=_finding(),
        fired_rules=["euvd_exploited"],
        first_seen=anchor,
        policy_snapshot=CraTriggerConfig(),
        epss_threshold=0.5,
    )
    status = _stage_status(ClockState.OVERDUE, anchor_at=anchor, deadline=deadline)
    bar = dash.deadline_bar(status, now, event)
    assert bar.remaining_seconds is not None and bar.remaining_seconds < 0
    assert bar.remaining_text.startswith("+")
    assert bar.progress_value == bar.progress_max  # clamped full, not overflowing


def test_deadline_bar_completed_shows_note() -> None:
    now = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)
    finding = _finding()
    event = Event(
        event_id="e1",
        finding=finding,
        fired_rules=["euvd_exploited"],
        first_seen=now - timedelta(hours=10),
        policy_snapshot=CraTriggerConfig(),
        epss_threshold=0.5,
    )
    event = event.model_copy(
        update={
            "stage_completions": {
                "early_warning": StageCompletion(completed_at=now, note="filed via portal")
            }
        }
    )
    status = _stage_status(ClockState.COMPLETED, completed_at=now)
    bar = dash.deadline_bar(status, now, event)
    assert bar.has_bar is False
    assert bar.completed_note == "filed via portal"


# -- build_findings: filter, sort, paginate -----------------------------------------


def test_build_findings_filters_by_exploited(tmp_path: Path) -> None:
    store = Store(tmp_path / "state")
    store.migrate()
    exploited = _finding(euvd_id="E1", exploited=True, component=_component("a"))
    quiet = _finding(euvd_id="E2", exploited=False, component=_component("b"))
    _seed_snapshot(store, [exploited, quiet])

    view = dash.build_findings(_settings(tmp_path), store, SBOM, exploited="yes")
    assert [r.euvd_id for r in view.rows] == ["E1"]
    store.close()


def test_build_findings_filters_by_confidence_floor(tmp_path: Path) -> None:
    store = Store(tmp_path / "state")
    store.migrate()
    low = _finding(euvd_id="E1", confidence=Confidence.LOW, component=_component("a"))
    high = _finding(euvd_id="E2", confidence=Confidence.HIGH, component=_component("b"))
    _seed_snapshot(store, [low, high])

    view = dash.build_findings(_settings(tmp_path), store, SBOM, confidence="high")
    assert [r.euvd_id for r in view.rows] == ["E2"]
    store.close()


def test_build_findings_filters_by_vex_status(tmp_path: Path) -> None:
    store = Store(tmp_path / "state")
    store.migrate()
    finding = _finding(euvd_id="E1")
    _seed_snapshot(store, [finding])

    view = dash.build_findings(_settings(tmp_path), store, SBOM, vex_status="not_affected")
    assert view.rows == []
    view_any = dash.build_findings(
        _settings(tmp_path), store, SBOM, vex_status="under_investigation"
    )
    assert len(view_any.rows) == 1
    store.close()


def test_build_findings_paginates_deterministically(tmp_path: Path) -> None:
    store = Store(tmp_path / "state")
    store.migrate()
    findings = [
        _finding(euvd_id=f"E{i:03d}", component=_component(f"pkg{i:03d}")) for i in range(120)
    ]
    _seed_snapshot(store, findings)

    page1 = dash.build_findings(_settings(tmp_path), store, SBOM, page=1)
    page2 = dash.build_findings(_settings(tmp_path), store, SBOM, page=2)
    page3 = dash.build_findings(_settings(tmp_path), store, SBOM, page=3)
    assert page1.total == 120
    assert page1.page_count == 3
    assert len(page1.rows) == 50
    assert len(page2.rows) == 50
    assert len(page3.rows) == 20
    # No overlap, no gaps.
    seen = {r.euvd_id for p in (page1, page2, page3) for r in p.rows}
    assert len(seen) == 120
    store.close()


def test_build_findings_out_of_range_page_clamps(tmp_path: Path) -> None:
    store = Store(tmp_path / "state")
    store.migrate()
    _seed_snapshot(store, [_finding()])
    view = dash.build_findings(_settings(tmp_path), store, SBOM, page=999)
    assert view.page == 1  # only one page exists; clamped, not out of range
    store.close()


# -- build_finding_detail ------------------------------------------------------------


def test_build_finding_detail_returns_none_for_unknown_pair(tmp_path: Path) -> None:
    store = Store(tmp_path / "state")
    store.migrate()
    _seed_snapshot(store, [_finding()])
    view = dash.build_finding_detail(_settings(tmp_path), store, SBOM, "deadbeef0000", "EUVD-NOPE")
    assert view is None
    store.close()


def test_build_finding_detail_shows_explanation_verbatim(tmp_path: Path) -> None:
    store = Store(tmp_path / "state")
    store.migrate()
    finding = _finding()
    _seed_snapshot(store, [finding])
    h, euvd_id = dash.finding_url_parts(finding)
    view = dash.build_finding_detail(_settings(tmp_path), store, SBOM, h, euvd_id)
    assert view is not None
    assert view.explanation == "matched via structured evidence"
    assert view.affected_products[0].product == "jinja2"
    store.close()


def test_build_finding_detail_links_to_its_cra_event(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = Store(tmp_path / "state")
    store.migrate()
    finding = _finding()
    _seed_snapshot(store, [finding])

    events = EventStore(store.path)
    events.get_or_create(finding, ["euvd_exploited"], CraTriggerConfig(), 0.5, datetime.now(UTC))
    events.close()

    h, euvd_id = dash.finding_url_parts(finding)
    view = dash.build_finding_detail(settings, store, SBOM, h, euvd_id)
    assert view is not None
    assert view.cra_event_url_id is not None
    store.close()


# -- build_overview -------------------------------------------------------------


def test_build_overview_no_open_clocks_when_nothing_due_soon(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = Store(tmp_path / "state")
    store.migrate()
    finding = _finding()
    _seed_snapshot(store, [finding])

    now = datetime.now(UTC)
    events = EventStore(store.path)
    events.get_or_create(finding, ["euvd_exploited"], CraTriggerConfig(), 0.5, now)
    events.close()

    view = dash.build_overview(settings, store, SBOM, now=now)
    assert view.findings_count == 1
    assert view.exploited_count == 1
    # early_warning has 24h; just-created means ~24h left, well outside due_soon (25%).
    assert view.open_clock_count == 0
    store.close()


def test_build_overview_surfaces_due_soon_clock(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = Store(tmp_path / "state")
    store.migrate()
    finding = _finding()
    _seed_snapshot(store, [finding])

    first_seen = datetime.now(UTC) - timedelta(hours=23)  # 1h left of 24h -> due_soon
    events = EventStore(store.path)
    events.get_or_create(finding, ["euvd_exploited"], CraTriggerConfig(), 0.5, first_seen)
    events.close()

    view = dash.build_overview(settings, store, SBOM, now=datetime.now(UTC))
    assert view.open_clock_count == 1
    assert view.worst_open_state in (ClockState.DUE_SOON, ClockState.OVERDUE)
    store.close()


def test_build_overview_raises_no_snapshot_when_never_watched(tmp_path: Path) -> None:
    store = Store(tmp_path / "state")
    store.migrate()
    with pytest.raises(dash.NoSnapshotError):
        dash.build_overview(_settings(tmp_path), store, SBOM)
    store.close()


# -- CRA events / resolve_event_id ----------------------------------------------


def test_resolve_event_id_round_trips(tmp_path: Path) -> None:
    store = Store(tmp_path / "state")
    store.migrate()
    finding = _finding()
    events = EventStore(store.path)
    event, _created = events.get_or_create(
        finding, ["euvd_exploited"], CraTriggerConfig(), 0.5, datetime.now(UTC)
    )
    events.close()

    url_id = dash.event_url_id(event.event_id)
    resolved = dash.resolve_event_id(store, url_id)
    assert resolved == event.event_id
    store.close()


def test_resolve_event_id_unknown_returns_none(tmp_path: Path) -> None:
    store = Store(tmp_path / "state")
    store.migrate()
    assert dash.resolve_event_id(store, "0000000000000000") is None
    store.close()


def test_build_cra_events_open_events_sorted_first(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = Store(tmp_path / "state")
    store.migrate()

    open_finding = _finding(euvd_id="OPEN", component=_component("open-pkg"))
    closed_finding = _finding(euvd_id="CLOSED", component=_component("closed-pkg"))

    events = EventStore(store.path)
    events.get_or_create(
        open_finding, ["euvd_exploited"], CraTriggerConfig(), 0.5, datetime.now(UTC)
    )
    closed_event, _c = events.get_or_create(
        closed_finding, ["euvd_exploited"], CraTriggerConfig(), 0.5, datetime.now(UTC)
    )
    for stage in settings.cra_stages:
        if stage.anchor == "first_seen":
            events.mark_stage_completed(closed_event.event_id, stage.name, datetime.now(UTC), None)
    events.set_remediation_available(closed_event.event_id, datetime.now(UTC))
    for stage in settings.cra_stages:
        if stage.anchor == "remediation_available":
            events.mark_stage_completed(closed_event.event_id, stage.name, datetime.now(UTC), None)
    events.close()

    rows = dash.build_cra_events(settings, store)
    assert rows[0].euvd_id == "OPEN"
    assert rows[0].open is True
    closed_row = next(r for r in rows if r.euvd_id == "CLOSED")
    assert closed_row.open is False
    store.close()


def test_build_cra_event_detail_none_for_unknown_event(tmp_path: Path) -> None:
    view = dash.build_cra_event_detail(_settings(tmp_path), Store(tmp_path / "state"), "nope")
    assert view is None


# -- audit log --------------------------------------------------------------------


def test_build_audit_log_empty_is_ok(tmp_path: Path) -> None:
    view = dash.build_audit_log(_settings(tmp_path))
    assert view.ok is True
    assert view.entries == []


def test_build_audit_log_shows_entries_newest_first(tmp_path: Path) -> None:
    from euvd_watch.cra.audit import AuditLog

    settings = _settings(tmp_path)
    log = AuditLog(settings.state_dir / "cra-audit.jsonl")
    log.append(
        "trigger_event_created",
        {"event_id": "e1", "euvd_id": "EUVD-1", "fired_rules": ["euvd_exploited"]},
    )
    log.append(
        "stage_marked",
        {"event_id": "e1", "stage": "early_warning", "note": "done"},
        actor="human",
    )

    view = dash.build_audit_log(settings)
    assert view.ok is True
    assert view.entries_count == 2
    assert view.entries[0].action == "stage_marked"  # newest first
    assert view.entries[1].is_genesis is True


def test_build_audit_log_only_shows_verified_entries(tmp_path: Path) -> None:
    """A corrupted tail must never render as if it were legitimate."""
    settings = _settings(tmp_path)
    audit_path = settings.state_dir / "cra-audit.jsonl"
    audit_path.parent.mkdir(parents=True)
    audit_path.write_text('{"not": "a valid entry"}\n', encoding="utf-8")

    view = dash.build_audit_log(settings)
    assert view.ok is False
    assert view.entries == []
