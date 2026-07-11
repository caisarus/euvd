"""Covers implementation_plan.md Step 5.4: the watch differ.

test_plan.md 5.4's exit criterion: two consecutive identical runs produce zero
notifications - asserted directly here on the pure differ, with no CLI/IO involved.
"""

import pytest

from euvd_watch.euvd.match import Confidence, Finding, Strategy
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.models import Component, SourceFormat
from euvd_watch.watch.differ import diff_findings

pytestmark = pytest.mark.unit


def _finding(
    name: str = "widget",
    euvd_id: str = "EUVD-1",
    *,
    confidence: Confidence = Confidence.HIGH,
    exploited: bool = True,
    in_kev: bool | None = None,
    epss_score: float | None = None,
    cvss_score: float | None = None,
) -> Finding:
    component = Component(
        name=name, version="1.0.0", source_format=SourceFormat.CYCLONEDX, raw_ref="r"
    )
    record = EuvdRecord(euvd_id=euvd_id, exploited=exploited, cvss_score=cvss_score)
    return Finding(
        component=component,
        record=record,
        confidence=confidence,
        strategy=Strategy.STRUCTURED,
        explanation="x",
        epss_score=epss_score,
        in_kev=in_kev,
    )


def test_new_finding_is_reported_new() -> None:
    diff = diff_findings(previous=[], current=[_finding()])
    assert [f.record.euvd_id for f in diff.new] == ["EUVD-1"]
    assert diff.resolved == []
    assert diff.changed == []
    assert not diff.is_empty


def test_resolved_finding_is_reported_resolved() -> None:
    diff = diff_findings(previous=[_finding()], current=[])
    assert diff.new == []
    assert [f.record.euvd_id for f in diff.resolved] == ["EUVD-1"]
    assert diff.changed == []
    assert not diff.is_empty


def test_unchanged_finding_produces_zero_notifications() -> None:
    finding = _finding()
    diff = diff_findings(previous=[finding], current=[finding.model_copy()])
    assert diff.new == diff.resolved == diff.changed == []
    assert diff.is_empty  # explicit, per test_plan.md 5.4


@pytest.mark.parametrize(
    ("field", "previous_kwargs", "current_kwargs"),
    [
        ("confidence", {"confidence": Confidence.MEDIUM}, {"confidence": Confidence.HIGH}),
        ("exploited", {"exploited": False}, {"exploited": True}),
        ("in_kev", {"in_kev": False}, {"in_kev": True}),
        ("epss_score", {"epss_score": 0.1}, {"epss_score": 0.9}),
        ("cvss_score", {"cvss_score": 5.0}, {"cvss_score": 9.8}),
    ],
)
def test_changed_field_is_reported_changed(
    field: str, previous_kwargs: dict[str, object], current_kwargs: dict[str, object]
) -> None:
    previous = _finding(**previous_kwargs)
    current = _finding(**current_kwargs)
    diff = diff_findings(previous=[previous], current=[current])
    assert diff.new == diff.resolved == []
    assert len(diff.changed) == 1
    assert diff.changed[0].changed_fields == [field]
    assert diff.changed[0].previous == previous
    assert diff.changed[0].current == current
    assert not diff.is_empty


def test_two_consecutive_identical_runs_produce_zero_notifications() -> None:
    # The literal test_plan.md 5.4 acceptance criterion.
    findings = [_finding("widget", "EUVD-1"), _finding("gadget", "EUVD-2", exploited=False)]
    first = diff_findings(previous=[], current=findings)
    assert not first.is_empty  # first run: everything is new

    second = diff_findings(previous=findings, current=[f.model_copy() for f in findings])
    assert second.is_empty


def test_different_components_are_never_confused_with_different_records() -> None:
    # Same euvd_id, different component - and vice versa - must both be distinct keys.
    a = _finding("widget", "EUVD-1")
    b = _finding("gadget", "EUVD-1")
    c = _finding("widget", "EUVD-2")
    diff = diff_findings(previous=[a], current=[a, b, c])
    assert {f.component.name for f in diff.new} == {"gadget", "widget"}
    assert {f.record.euvd_id for f in diff.new} == {"EUVD-1", "EUVD-2"}


def test_new_and_resolved_and_changed_sort_deterministically() -> None:
    findings_before = [_finding("z", "EUVD-9"), _finding("a", "EUVD-1", confidence=Confidence.LOW)]
    findings_after = [
        _finding("a", "EUVD-1", confidence=Confidence.HIGH),  # changed
        _finding("m", "EUVD-5"),  # new
    ]
    diff = diff_findings(previous=findings_before, current=findings_after)
    assert [f.component.name for f in diff.new] == ["m"]
    assert [f.component.name for f in diff.resolved] == ["z"]
    assert [c.current.component.name for c in diff.changed] == ["a"]
