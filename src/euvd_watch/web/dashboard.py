# SPDX-License-Identifier: EUPL-1.2
"""View-model layer for the dashboard (Step 6.2).

Pure(ish) functions turning Store + Settings + on-disk artifacts into plain data the
Jinja templates render directly - templates stay dumb (no business logic in HTML),
and this is the *only* place that reads the state DB for display, per
docs/dashboard-design.md §9 ("all display values come through web/store.py ... never a
second query path").

Enum -> (label, pill CSS class) mapping lives in one place here (`pill_for`) and is
registered as a single Jinja filter by web/app.py, matching the design spec's
"a single Jinja filter... so the vocabulary lives in one place."
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from euvd_watch.config import Settings
from euvd_watch.cra.actions import validate_stage_name
from euvd_watch.cra.audit import GENESIS_SEED, read_entries
from euvd_watch.cra.audit import verify as verify_audit_log
from euvd_watch.cra.clock import ClockState, StageStatus, compute_all, is_event_open
from euvd_watch.cra.state import Event, EventStore
from euvd_watch.euvd.match import Confidence, Evaluation, Finding, finding_to_evaluation
from euvd_watch.findings_artifact import parse_findings_artifact
from euvd_watch.vex.decisions import DecisionsFile, load_decisions
from euvd_watch.vex.merge import ResolvedDecision, merge
from euvd_watch.vex.model import Status
from euvd_watch.watch.differ import finding_identity
from euvd_watch.web.store import Store, VexStatusRow, sbom_snapshot_key

_DEFAULT_DECISIONS_PATH = Path("vex-decisions.yaml")
_PAGE_SIZE = 50

# Every confidence/status/state that can appear anywhere on the dashboard maps to
# exactly one (label, css class) pair, defined once (docs/dashboard-design.md §2/§5.2).
# Confidence deliberately does NOT borrow the ok/warn/crit/neutral/done scale: it is an
# epistemic signal (how sure the matcher is), not a compliance-state signal, and
# overloading the same five colors for both would let a colorblind operator conflate
# "high confidence" with "urgent" - text label carries confidence, not color.
_CONFIDENCE_LABEL = {Confidence.LOW: "low", Confidence.MEDIUM: "medium", Confidence.HIGH: "high"}
_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}

_VEX_LABEL = {
    Status.NOT_AFFECTED: "not affected",
    Status.AFFECTED: "affected",
    Status.FIXED: "fixed",
    Status.UNDER_INVESTIGATION: "under investigation",
}
_VEX_CLASS = {
    Status.NOT_AFFECTED: "pill--ok pill--outline",
    Status.AFFECTED: "pill--crit pill--outline",  # outline: filled crit is exploited-only
    Status.FIXED: "pill--done pill--outline",
    Status.UNDER_INVESTIGATION: "pill--neutral pill--outline",
}

_CLOCK_LABEL = {
    ClockState.AWAITING_ANCHOR: "awaiting anchor",
    ClockState.PENDING: "on track",
    ClockState.DUE_SOON: "due soon",
    ClockState.OVERDUE: "overdue",
    ClockState.COMPLETED: "completed",
}
_CLOCK_CLASS = {
    ClockState.AWAITING_ANCHOR: "pill--neutral pill--outline",
    ClockState.PENDING: "pill--ok pill--outline",
    ClockState.DUE_SOON: "pill--warn pill--outline",
    ClockState.OVERDUE: "pill--crit pill--filled",  # the other reserved filled-crit use
    ClockState.COMPLETED: "pill--done pill--outline",
}


class PillView(BaseModel):
    """One status rendered as text + a CSS class - never color alone (WCAG 1.4.1)."""

    model_config = ConfigDict(frozen=True)

    label: str
    css_class: str


def pill_for(value: Confidence | Status | ClockState) -> PillView:
    """The single enum -> pill mapping every template goes through (Jinja filter `pill`)."""
    if isinstance(value, Confidence):
        return PillView(label=_CONFIDENCE_LABEL[value], css_class="pill--neutral pill--outline")
    if isinstance(value, Status):
        return PillView(label=_VEX_LABEL[value], css_class=_VEX_CLASS[value])
    if isinstance(value, ClockState):
        return PillView(label=_CLOCK_LABEL[value], css_class=_CLOCK_CLASS[value])
    raise TypeError(f"No pill mapping for {type(value).__name__}")


EXPLOITED_PILL = PillView(label="exploited", css_class="pill--crit pill--filled")


def humanize_stage_name(name: str) -> str:
    """`early_warning` -> `Early warning` - stage names are config, never hardcoded copy."""
    return name.replace("_", " ").capitalize()


def comp_hash(dedupe_key: str) -> str:
    """A short, URL-safe id for a component (dedupe_keys often contain '/', '@', ':').

    Not a security boundary - just a stable path segment. Findings-page links use this
    plus the EUVD id as the two-segment finding URL.
    """
    return hashlib.sha256(dedupe_key.encode("utf-8")).hexdigest()[:12]


def finding_url_parts(finding: Finding) -> tuple[str, str]:
    return comp_hash(finding.component.dedupe_key), finding.record.euvd_id


def default_sort_key(finding: Finding) -> tuple[bool, int, str]:
    """Deterministic default order everywhere findings are listed: exploited desc,
    confidence desc, component name asc - mirrors the tool's determinism invariant."""
    return (
        not finding.record.exploited,
        -_CONFIDENCE_RANK[finding.confidence],
        finding.component.name.lower(),
    )


# -- findings loading -----------------------------------------------------------------


class NoSnapshotError(Exception):
    """Raised when the requested SBOM has never been watched (no stored snapshot)."""


def load_findings(store: Store, sbom_path: str) -> tuple[list[Finding], str | None]:
    """The current findings for `sbom_path`'s most recent watch snapshot, and its
    `generated_at` timestamp. Raises NoSnapshotError if `watch <sbom>` has never run -
    the dashboard has no live-matching path of its own (docs/dashboard-design.md
    principle 6: read-mostly, one query path, through the state store)."""
    raw = store.load_watch_snapshot(sbom_snapshot_key(sbom_path))
    if raw is None:
        raise NoSnapshotError(
            f"No findings snapshot yet for {sbom_path!r}. Run "
            f"'euvd-watch watch {sbom_path} --once' first, then reload."
        )
    findings = parse_findings_artifact(raw, f"watch snapshot for {sbom_path}")
    generated_at = json.loads(raw).get("generated_at")
    return findings, generated_at


# -- VEX status -------------------------------------------------------------------


def _evaluation_key(evaluation: Evaluation) -> str:
    # Must stay byte-identical to watch/differ.py::finding_identity's format - both key
    # the same (component, record) identity space across the dashboard.
    return f"{evaluation.component.dedupe_key}|{evaluation.record.euvd_id}"


def load_optional_decisions(path: Path | None) -> DecisionsFile:
    """Same precedence as `load_settings`'s config file: explicit path is required to
    exist; the implicit default is silently skipped when absent."""
    if path is not None:
        return load_decisions(path)
    if _DEFAULT_DECISIONS_PATH.exists():
        return load_decisions(_DEFAULT_DECISIONS_PATH)
    return DecisionsFile(decisions=[])


def compute_vex_statuses(
    findings: list[Finding], decisions_file: DecisionsFile
) -> dict[str, ResolvedDecision]:
    """VEX status per finding, keyed like `finding_identity`.

    Findings from a watch snapshot are MATCH-only (schema_version 1 never stores
    NOT_AFFECTED evidence - see `finding_to_evaluation`'s docstring), so this always
    behaves like `vex generate --findings`: conservative, auto-not_affected-blind,
    human decisions still apply and still win.
    """
    evaluations = [finding_to_evaluation(f) for f in findings]
    result = merge(evaluations, decisions_file)
    return {_evaluation_key(rd.evaluation): rd for rd in result.decisions}


def compute_and_cache_vex_statuses(
    store: Store, findings: list[Finding], decisions_file: DecisionsFile
) -> dict[str, ResolvedDecision]:
    """`compute_vex_statuses`, plus persisting the result into `vex_status_cache`
    (Step 6.1's read model). The UI always renders the freshly-computed dict returned
    here, never a re-read of the cache - the cache is populated for other consumers,
    never a source the dashboard itself trusts (it is explicitly rebuildable/lossless
    per the Step 6.1 sign-off, so treating it as authoritative here would just be a
    second, riskier query path)."""
    statuses = compute_vex_statuses(findings, decisions_file)
    now = datetime.now(UTC).isoformat()

    def _justification(resolved: ResolvedDecision) -> str | None:
        return resolved.decision.justification.value if resolved.decision.justification else None

    store.rebuild_vex_status_cache(
        [
            VexStatusRow(
                finding_key=key,
                status=resolved.decision.status.value,
                justification=_justification(resolved),
                source="human" if resolved.is_human else "automated",
                updated_at=now,
            )
            for key, resolved in statuses.items()
        ]
    )
    return statuses


def vex_decision_hint(finding: Finding, sbom_path: str) -> tuple[str, str]:
    """(yaml_snippet, cli_command) shown on the Finding detail page - the UI shows a
    human exactly what to type; it never sets affected/fixed itself (those are human
    calls, VEX invariant)."""
    component = finding.component
    purl = component.normalized_purl or component.purl or f"pkg:generic/{component.name}"
    cve = next((a for a in finding.record.aliases if a.startswith("CVE-")), None)
    id_line = f'cve: "{cve}"' if cve else f'euvd_id: "{finding.record.euvd_id}"'
    today = datetime.now(UTC).date().isoformat()
    snippet = (
        "decisions:\n"
        f"  - {id_line}\n"
        f'    purl: "{purl}"\n'
        "    status: not_affected  # or affected / fixed - your call, with evidence\n"
        "    justification: component_not_present  # only needed for not_affected\n"
        '    statement: "Explain your evidence here."\n'
        f'    author: "you@example.com"\n'
        f'    date: "{today}"\n'
    )
    cli_command = (
        f"euvd-watch vex generate {sbom_path} --decisions vex-decisions.yaml -o openvex.json"
    )
    return snippet, cli_command


# -- deadline bars ------------------------------------------------------------------


class DeadlineBarView(BaseModel):
    model_config = ConfigDict(frozen=True)

    stage_name: str
    stage_label: str
    pill: PillView
    has_bar: bool
    progress_value: int
    progress_max: int
    remaining_seconds: int | None  # signed: negative = overdue overrun; None = n/a
    remaining_text: str
    deadline_iso: str | None
    completed_at_iso: str | None
    completed_note: str | None


def _format_remaining(seconds: int) -> str:
    sign = "+" if seconds < 0 else ""
    total = abs(seconds)
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{sign}{hours:02d}:{minutes:02d}:{secs:02d}"


def deadline_bar(status: StageStatus, now: datetime, event: Event) -> DeadlineBarView:
    pill = pill_for(status.state)
    if status.state is ClockState.AWAITING_ANCHOR:
        return DeadlineBarView(
            stage_name=status.stage.name,
            stage_label=humanize_stage_name(status.stage.name),
            pill=pill,
            has_bar=False,
            progress_value=0,
            progress_max=1,
            remaining_seconds=None,
            remaining_text="Awaiting remediation date",
            deadline_iso=None,
            completed_at_iso=None,
            completed_note=None,
        )
    if status.state is ClockState.COMPLETED:
        completion = event.stage_completions.get(status.stage.name)
        completed_at_iso = status.completed_at.isoformat() if status.completed_at else None
        return DeadlineBarView(
            stage_name=status.stage.name,
            stage_label=humanize_stage_name(status.stage.name),
            pill=pill,
            has_bar=False,
            progress_value=1,
            progress_max=1,
            remaining_seconds=None,
            remaining_text=f"Completed {completed_at_iso or ''}",
            deadline_iso=status.deadline.isoformat() if status.deadline else None,
            completed_at_iso=completed_at_iso,
            completed_note=completion.note if completion else None,
        )
    assert status.anchor_at is not None and status.deadline is not None  # not AWAITING_ANCHOR
    total_seconds = int(status.stage.hours * 3600)
    elapsed = int((now - status.anchor_at).total_seconds())
    remaining = int((status.deadline - now).total_seconds())
    return DeadlineBarView(
        stage_name=status.stage.name,
        stage_label=humanize_stage_name(status.stage.name),
        pill=pill,
        has_bar=True,
        progress_value=max(0, min(elapsed, total_seconds)),
        progress_max=total_seconds,
        remaining_seconds=remaining,
        remaining_text=_format_remaining(remaining),
        deadline_iso=status.deadline.isoformat(),
        completed_at_iso=None,
        completed_note=None,
    )


# -- Overview ------------------------------------------------------------------------


class FindingRowView(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding_key: str
    comp_hash: str
    euvd_id: str
    component_name: str
    component_version: str | None
    aliases: list[str]
    exploited: bool
    confidence: PillView
    vex_status: PillView
    epss_text: str
    in_kev_text: str
    stripe_class: str


def _stripe_for(finding: Finding, vex_status: Status) -> str:
    if finding.record.exploited:
        return "s-crit"
    if vex_status is Status.FIXED:
        return "s-done"
    if vex_status is Status.NOT_AFFECTED:
        return "s-ok"
    return "s-neutral"


def _finding_row(finding: Finding, vex_status: Status) -> FindingRowView:
    fkey = finding_identity(finding)
    h, euvd_id = finding_url_parts(finding)
    return FindingRowView(
        finding_key=fkey,
        comp_hash=h,
        euvd_id=euvd_id,
        component_name=finding.component.name,
        component_version=finding.component.version,
        aliases=finding.record.aliases,
        exploited=finding.record.exploited,
        confidence=pill_for(finding.confidence),
        vex_status=pill_for(vex_status),
        epss_text=f"{finding.epss_score:.3f}" if finding.epss_score is not None else "—",
        in_kev_text={True: "✓", False: "—", None: "?"}[finding.in_kev],
        stripe_class=_stripe_for(finding, vex_status),
    )


class ClockSummaryView(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str
    url_id: str
    euvd_id: str
    component_name: str
    component_version: str | None
    exploited: bool
    stages: list[DeadlineBarView]


class OverviewView(BaseModel):
    model_config = ConfigDict(frozen=True)

    sbom_path: str
    generated_at_iso: str | None
    findings_count: int
    exploited_count: int
    exploited_component_names: list[str]
    open_clock_count: int
    worst_open_state: ClockState | None
    audit_ok: bool
    audit_entries: int
    audit_bad_line: int | None
    open_clocks: list[ClockSummaryView]
    recent_findings: list[FindingRowView]


def build_overview(
    settings: Settings, store: Store, sbom_path: str, now: datetime | None = None
) -> OverviewView:
    now = now or datetime.now(UTC)
    findings, generated_at = load_findings(store, sbom_path)
    decisions = load_optional_decisions(None)
    vex = compute_and_cache_vex_statuses(store, findings, decisions)

    ordered = sorted(findings, key=default_sort_key)
    rows = [_finding_row(f, vex[finding_identity(f)].decision.status) for f in ordered]

    exploited = [f for f in findings if f.record.exploited]

    event_store = EventStore(store.path)
    try:
        events = event_store.list_all()
    finally:
        event_store.close()

    open_clocks: list[ClockSummaryView] = []
    worst_states: list[ClockState] = []
    for event in events:
        statuses = compute_all(event, settings.cra_stages, now)
        live = [s for s in statuses if s.state in (ClockState.DUE_SOON, ClockState.OVERDUE)]
        if not live:
            continue
        worst_states.extend(s.state for s in live)
        open_clocks.append(
            ClockSummaryView(
                event_id=event.event_id,
                url_id=event_url_id(event.event_id),
                euvd_id=event.finding.record.euvd_id,
                component_name=event.finding.component.name,
                component_version=event.finding.component.version,
                exploited=event.current_finding.record.exploited,
                stages=[deadline_bar(s, now, event) for s in statuses],
            )
        )
    worst_open_state = (
        ClockState.OVERDUE
        if ClockState.OVERDUE in worst_states
        else (ClockState.DUE_SOON if worst_states else None)
    )

    audit_path = settings.state_dir / "cra-audit.jsonl"
    audit_result = verify_audit_log(audit_path)

    return OverviewView(
        sbom_path=sbom_path,
        generated_at_iso=generated_at,
        findings_count=len(findings),
        exploited_count=len(exploited),
        exploited_component_names=[f.component.name for f in exploited],
        open_clock_count=len(open_clocks),
        worst_open_state=worst_open_state,
        audit_ok=audit_result.ok,
        audit_entries=audit_result.entries,
        audit_bad_line=audit_result.bad_line,
        open_clocks=open_clocks,
        recent_findings=rows[:8],
    )


# -- Findings page ---------------------------------------------------------------


class FindingsPageView(BaseModel):
    model_config = ConfigDict(frozen=True)

    rows: list[FindingRowView]
    total: int
    page: int
    page_count: int
    confidence_filter: str
    exploited_filter: str
    vex_filter: str


_CONFIDENCE_FLOOR = {
    "any": None,
    "low": Confidence.LOW,
    "medium": Confidence.MEDIUM,
    "high": Confidence.HIGH,
}


def build_findings(
    settings: Settings,
    store: Store,
    sbom_path: str,
    *,
    confidence: str = "any",
    exploited: str = "any",
    vex_status: str = "any",
    page: int = 1,
) -> FindingsPageView:
    findings, _generated_at = load_findings(store, sbom_path)
    decisions = load_optional_decisions(None)
    vex = compute_and_cache_vex_statuses(store, findings, decisions)

    floor = _CONFIDENCE_FLOOR.get(confidence)
    filtered = []
    for f in findings:
        if floor is not None and _CONFIDENCE_RANK[f.confidence] < _CONFIDENCE_RANK[floor]:
            continue
        if exploited == "yes" and not f.record.exploited:
            continue
        status = vex[finding_identity(f)].decision.status
        if vex_status != "any" and status.value != vex_status:
            continue
        filtered.append((f, status))

    filtered.sort(key=lambda pair: default_sort_key(pair[0]))
    rows = [_finding_row(f, status) for f, status in filtered]

    total = len(rows)
    page_size = _PAGE_SIZE
    page_count = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(page, page_count))
    start = (page - 1) * page_size
    page_rows = rows[start : start + page_size]

    return FindingsPageView(
        rows=page_rows,
        total=total,
        page=page,
        page_count=page_count,
        confidence_filter=confidence,
        exploited_filter=exploited,
        vex_filter=vex_status,
    )


# -- Finding detail ----------------------------------------------------------------


class AffectedProductView(BaseModel):
    model_config = ConfigDict(frozen=True)

    vendor: str | None
    product: str
    version_range: str | None


class FindingDetailView(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding_key: str
    comp_hash: str
    component_name: str
    component_version: str | None
    component_purl: str | None
    euvd_id: str
    exploited: bool
    exploited_since: str | None
    confidence: PillView
    strategy: str
    explanation: str
    euvd_description: str
    affected_products: list[AffectedProductView]
    epss_text: str
    in_kev_text: str
    aliases: list[str]
    references: list[str]
    vex_status: PillView
    vex_justification: str | None
    vex_explanation: str
    vex_is_human: bool
    vex_snippet: str
    vex_cli_hint: str
    cra_event_url_id: str | None


def build_finding_detail(
    settings: Settings, store: Store, sbom_path: str, comp_hash_value: str, euvd_id: str
) -> FindingDetailView | None:
    findings, _generated_at = load_findings(store, sbom_path)
    finding = next(
        (
            f
            for f in findings
            if comp_hash(f.component.dedupe_key) == comp_hash_value and f.record.euvd_id == euvd_id
        ),
        None,
    )
    if finding is None:
        return None

    decisions = load_optional_decisions(None)
    vex = compute_and_cache_vex_statuses(store, findings, decisions)
    resolved = vex[finding_identity(finding)]
    snippet, cli_hint = vex_decision_hint(finding, sbom_path)

    event_store = EventStore(store.path)
    try:
        event_id = Event.make_id(finding.component.dedupe_key, finding.record.euvd_id)
        event = event_store.get(event_id)
    finally:
        event_store.close()

    return FindingDetailView(
        finding_key=finding_identity(finding),
        comp_hash=comp_hash_value,
        component_name=finding.component.name,
        component_version=finding.component.version,
        component_purl=finding.component.normalized_purl or finding.component.purl,
        euvd_id=finding.record.euvd_id,
        exploited=finding.record.exploited,
        exploited_since=finding.record.exploited_since,
        confidence=pill_for(finding.confidence),
        strategy=finding.strategy.value,
        explanation=finding.explanation,
        euvd_description=finding.record.description,
        affected_products=[
            AffectedProductView(vendor=p.vendor, product=p.product, version_range=p.version_range)
            for p in finding.record.affected_products
        ],
        epss_text=f"{finding.epss_score:.3f}" if finding.epss_score is not None else "—",
        in_kev_text={True: "✓", False: "—", None: "unknown"}[finding.in_kev],
        aliases=finding.record.aliases,
        references=finding.record.references,
        vex_status=pill_for(resolved.decision.status),
        vex_justification=resolved.decision.justification.value
        if resolved.decision.justification
        else None,
        vex_explanation=resolved.decision.explanation,
        vex_is_human=resolved.is_human,
        vex_snippet=snippet,
        vex_cli_hint=cli_hint,
        cra_event_url_id=event_url_id(event.event_id) if event is not None else None,
    )


# -- CRA events ----------------------------------------------------------------------


def event_url_id(event_id: str) -> str:
    """A URL-safe id for a CRA event.

    `Event.make_id` is `f"{component.dedupe_key}|{euvd_id}"`, and `dedupe_key` is
    purl-derived (`purl:pkg:pypi/jinja2@3.1.6`) - it routinely contains '/', which
    breaks a plain `{event_id}` path segment. This hash is what URLs carry; the real
    event_id is still shown as text and resolved server-side via `resolve_event_id`.
    """
    return hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:16]


def resolve_event_id(store: Store, url_id: str) -> str | None:
    """The real event_id for a `event_url_id` value, or None if no event matches."""
    event_store = EventStore(store.path)
    try:
        for event in event_store.list_all():
            if event_url_id(event.event_id) == url_id:
                return event.event_id
    finally:
        event_store.close()
    return None


class CraEventRowView(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str
    url_id: str
    euvd_id: str
    component_name: str
    component_version: str | None
    first_seen_iso: str
    fired_rules: list[str]
    worst: PillView
    open: bool


_WORST_FIRST = [
    ClockState.OVERDUE,
    ClockState.DUE_SOON,
    ClockState.AWAITING_ANCHOR,
    ClockState.PENDING,
]


def _worst_state(statuses: list[StageStatus]) -> ClockState:
    """The most urgent stage state across an event's stages; COMPLETED only when every
    stage is - one still-open stage always outranks "all done"."""
    non_completed = {s.state for s in statuses if s.state is not ClockState.COMPLETED}
    if not non_completed:
        return ClockState.COMPLETED
    for state in _WORST_FIRST:
        if state in non_completed:
            return state
    return next(iter(non_completed))


def build_cra_events(
    settings: Settings, store: Store, now: datetime | None = None
) -> list[CraEventRowView]:
    now = now or datetime.now(UTC)
    event_store = EventStore(store.path)
    try:
        events = event_store.list_all()
    finally:
        event_store.close()

    rows = []
    for event in events:
        statuses = compute_all(event, settings.cra_stages, now)
        rows.append(
            CraEventRowView(
                event_id=event.event_id,
                url_id=event_url_id(event.event_id),
                euvd_id=event.finding.record.euvd_id,
                component_name=event.finding.component.name,
                component_version=event.finding.component.version,
                first_seen_iso=event.first_seen.isoformat(),
                fired_rules=list(event.fired_rules),
                worst=pill_for(_worst_state(statuses)),
                open=is_event_open(event, settings.cra_stages),
            )
        )
    rows.sort(key=lambda r: (not r.open, r.first_seen_iso), reverse=False)
    return rows


class CraEventDetailView(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str
    url_id: str
    euvd_id: str
    component_name: str
    component_version: str | None
    first_seen_iso: str
    fired_rules: list[str]
    stages: list[DeadlineBarView]
    valid_stage_names: list[str]
    open: bool


def build_cra_event_detail(
    settings: Settings, store: Store, event_id: str, now: datetime | None = None
) -> CraEventDetailView | None:
    """`event_id` here is the REAL event id (already resolved from a url_id by the
    caller - app.py resolves once per request via `resolve_event_id`)."""
    now = now or datetime.now(UTC)
    event_store = EventStore(store.path)
    try:
        event = event_store.get(event_id)
    finally:
        event_store.close()
    if event is None:
        return None

    statuses = compute_all(event, settings.cra_stages, now)
    return CraEventDetailView(
        event_id=event.event_id,
        url_id=event_url_id(event.event_id),
        euvd_id=event.finding.record.euvd_id,
        component_name=event.finding.component.name,
        component_version=event.finding.component.version,
        first_seen_iso=event.first_seen.isoformat(),
        fired_rules=list(event.fired_rules),
        stages=[deadline_bar(s, now, event) for s in statuses],
        valid_stage_names=[s.name for s in settings.cra_stages],
        open=is_event_open(event, settings.cra_stages),
    )


def validate_mark_stage(stage: str, settings: Settings) -> None:
    """Re-exported so app.py doesn't need a second import for one call."""
    validate_stage_name(stage, settings.cra_stages)


# -- Audit log -------------------------------------------------------------------


class AuditEntryView(BaseModel):
    model_config = ConfigDict(frozen=True)

    action: str
    actor: str
    ts_iso: str
    summary: str
    entry_hash: str
    prev_hash: str
    is_genesis: bool


def _summarize_payload(action: str, payload: dict[str, Any]) -> str:
    if action == "trigger_event_created":
        rules = ", ".join(payload.get("fired_rules", []))
        return f"CRA event opened for {payload.get('euvd_id', '?')} ({rules})"
    if action == "draft_rendered":
        return f"Notification draft rendered ({payload.get('format', '?')})"
    if action == "stage_marked":
        note = f" — {payload['note']}" if payload.get("note") else ""
        return f"Stage '{payload.get('stage', '?')}' marked complete{note}"
    if action == "remediation_marked":
        note = f" — {payload['note']}" if payload.get("note") else ""
        return f"Remediation availability recorded{note}"
    return f"Action: {action}"  # a future action type is still shown, never dropped


class AuditLogView(BaseModel):
    model_config = ConfigDict(frozen=True)

    ok: bool
    entries_count: int
    bad_line: int | None
    reason: str | None
    truncated_tail: bool
    entries: list[AuditEntryView]  # newest first


def build_audit_log(settings: Settings) -> AuditLogView:
    path = settings.state_dir / "cra-audit.jsonl"
    result = verify_audit_log(path)
    raw_entries = read_entries(path)[: result.entries]  # only ever show verified lines

    views = [
        AuditEntryView(
            action=str(entry.get("action", "?")),
            actor=str(entry.get("actor", "?")),
            ts_iso=str(entry.get("ts", "")),
            summary=_summarize_payload(str(entry.get("action", "")), entry.get("payload", {})),
            entry_hash=str(entry.get("entry_hash", "")),
            prev_hash=str(entry.get("prev_hash", "")),
            is_genesis=entry.get("prev_hash") == GENESIS_SEED,
        )
        for entry in raw_entries
    ]
    views.reverse()  # newest first for display

    return AuditLogView(
        ok=result.ok,
        entries_count=result.entries,
        bad_line=result.bad_line,
        reason=result.reason,
        truncated_tail=result.truncated_tail,
        entries=views,
    )
