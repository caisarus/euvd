"""Covers implementation_plan.md Step 3.3: decisions merge matrix."""

from typing import Any

import pytest

from euvd_watch.euvd.match import Confidence, Evaluation, Outcome, Strategy, evaluate_component
from euvd_watch.euvd.models import AffectedProduct, EuvdRecord
from euvd_watch.models import Component, SourceFormat
from euvd_watch.sbom.normalize import normalize_component
from euvd_watch.vex.decisions import DecisionEntry, DecisionsFile
from euvd_watch.vex.merge import merge
from euvd_watch.vex.model import Justification, Status

pytestmark = pytest.mark.unit


def _component(**kwargs: Any) -> Component:
    raw = Component(source_format=SourceFormat.CYCLONEDX, raw_ref="r", **kwargs)
    return normalize_component(raw)


def _match_evaluation() -> Any:
    # A real, unresolved MATCH (inside range) - stays under_investigation absent a decision.
    component = _component(
        name="openssl",
        version="3.0.2",
        cpe="cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*",
        purl="pkg:generic/openssl@3.0.2",
    )
    record = EuvdRecord(
        euvd_id="EUVD-1",
        aliases=["CVE-2026-1"],
        exploited=True,
        affected_products=[
            AffectedProduct(vendor="openssl", product="openssl", version_range="<3.0.8")
        ],
    )
    return evaluate_component(component, [record])[0]


def _not_affected_evaluation() -> Any:
    component = _component(
        name="widget",
        version="1.5.0",
        cpe="cpe:2.3:a:acme:widget:1.5.0:*:*:*:*:*:*:*",
        purl="pkg:generic/widget@1.5.0",
    )
    record = EuvdRecord(
        euvd_id="EUVD-2",
        affected_products=[
            AffectedProduct(vendor="acme", product="widget", version_range="<1.0.0")
        ],
    )
    return evaluate_component(component, [record])[0]


def test_no_matching_decision_falls_back_to_automated_draft() -> None:
    result = merge([_match_evaluation()], DecisionsFile(decisions=[]))
    assert len(result.decisions) == 1
    decision = result.decisions[0].decision
    assert decision.status is Status.UNDER_INVESTIGATION
    assert result.stale == []


def test_decision_overrides_automated_draft_exact_purl() -> None:
    evaluation = _match_evaluation()
    entry = DecisionEntry(
        euvd_id="EUVD-1",
        purl="pkg:generic/openssl@3.0.2",
        status=Status.AFFECTED,
        statement="Confirmed in our deployment.",
        author="a@example.com",
        date="2026-01-01",
    )
    result = merge([evaluation], DecisionsFile(decisions=[entry]))
    decision = result.decisions[0].decision
    assert decision.status is Status.AFFECTED
    assert decision.explanation == "Confirmed in our deployment."


def test_decision_matches_by_cve_alias() -> None:
    evaluation = _match_evaluation()
    entry = DecisionEntry(
        cve="CVE-2026-1",
        purl="pkg:generic/openssl@3.0.2",
        status=Status.FIXED,
        statement="Patched upstream.",
        author="a@example.com",
        date="2026-01-01",
    )
    result = merge([evaluation], DecisionsFile(decisions=[entry]))
    assert result.decisions[0][1].status is Status.FIXED


def test_versionless_purl_pattern_matches_any_version() -> None:
    evaluation = _match_evaluation()  # component purl is pkg:generic/openssl@3.0.2
    entry = DecisionEntry(
        euvd_id="EUVD-1",
        purl="pkg:generic/openssl",  # no @version -> pattern
        status=Status.NOT_AFFECTED,
        justification=Justification.VULNERABLE_CODE_NOT_PRESENT,
        statement="Not used in our build.",
        author="a@example.com",
        date="2026-01-01",
    )
    result = merge([evaluation], DecisionsFile(decisions=[entry]))
    assert result.decisions[0][1].status is Status.NOT_AFFECTED


def test_versionless_pattern_with_qualifiers_still_matches() -> None:
    # Audit finding TECH-001 sibling: a versionless entry purl carrying qualifiers used to
    # fail the pattern compare (split("@") mistook the qualifiers for a version slot).
    evaluation = _match_evaluation()  # component purl is pkg:generic/openssl@3.0.2
    entry = DecisionEntry(
        euvd_id="EUVD-1",
        purl="pkg:generic/openssl?os=linux",  # no @version -> pattern; qualifiers ignored
        status=Status.NOT_AFFECTED,
        justification=Justification.VULNERABLE_CODE_NOT_PRESENT,
        statement="Not used in our build.",
        author="a@example.com",
        date="2026-01-01",
    )
    result = merge([evaluation], DecisionsFile(decisions=[entry]))
    assert result.decisions[0][1].status is Status.NOT_AFFECTED


def test_stale_decision_is_reported() -> None:
    entry = DecisionEntry(
        euvd_id="EUVD-NO-SUCH-RECORD",
        purl="pkg:generic/nothing@1.0.0",
        status=Status.NOT_AFFECTED,
        justification=Justification.COMPONENT_NOT_PRESENT,
        statement="doesn't apply to anything current",
        author="a@example.com",
        date="2026-01-01",
    )
    result = merge([_match_evaluation()], DecisionsFile(decisions=[entry]))
    assert result.stale == [entry]


def test_conflict_human_downgrades_stronger_automated_match_still_wins_but_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    evaluation = _match_evaluation()  # exploited=True, MATCH outcome
    entry = DecisionEntry(
        euvd_id="EUVD-1",
        purl="pkg:generic/openssl@3.0.2",
        status=Status.NOT_AFFECTED,
        justification=Justification.VULNERABLE_CODE_NOT_PRESENT,
        statement="We believe this isn't exploitable in our context.",
        author="a@example.com",
        date="2026-01-01",
    )
    with caplog.at_level("WARNING"):
        result = merge([evaluation], DecisionsFile(decisions=[entry]))
    # Human decision wins regardless...
    assert result.decisions[0][1].status is Status.NOT_AFFECTED
    # ...but the conflict is flagged, not silently applied.
    assert len(result.conflicts) == 1
    assert "automation independently found" in result.conflicts[0]
    assert any("automation independently found" in r.message for r in caplog.records)


def test_no_conflict_when_decision_agrees_with_automated_not_affected() -> None:
    evaluation = _not_affected_evaluation()
    entry = DecisionEntry(
        euvd_id="EUVD-2",
        purl="pkg:generic/widget@1.5.0",
        status=Status.NOT_AFFECTED,
        justification=Justification.VULNERABLE_CODE_NOT_PRESENT,
        statement="Confirmed independently.",
        author="a@example.com",
        date="2026-01-01",
    )
    result = merge([evaluation], DecisionsFile(decisions=[entry]))
    assert result.conflicts == []


def test_no_conflict_when_downgrading_a_not_affected_evaluation() -> None:
    # The evaluation itself is already NOT_AFFECTED (matcher's own outcome, not a MATCH),
    # so a human decision affirming/adjusting it isn't a "downgrade against a real finding".
    evaluation = _not_affected_evaluation()
    entry = DecisionEntry(
        euvd_id="EUVD-2",
        purl="pkg:generic/widget@1.5.0",
        status=Status.FIXED,
        statement="Actually already fixed upstream.",
        author="a@example.com",
        date="2026-01-01",
    )
    result = merge([evaluation], DecisionsFile(decisions=[entry]))
    assert result.conflicts == []


def test_decision_matches_purl_typed_unnormalized() -> None:
    # feedback_m3.md finding 1.1: a human plausibly copies the purl exactly as it appears
    # in the SBOM/tool output, which may not already be normalized. This used to silently
    # never match, falling through to the automated draft and getting reported as stale.
    component = _component(
        name="Requests",
        version="2.31.0",
        purl="pkg:pypi/Requests@2.31.0",  # mixed-case, un-normalized
    )
    assert component.normalized_purl == "pkg:pypi/requests@2.31.0"
    record = EuvdRecord(euvd_id="EUVD-3")
    evaluation = Evaluation(
        component=component,
        record=record,
        outcome=Outcome.MATCH,
        confidence=Confidence.LOW,
        strategy=Strategy.FUZZY,
        explanation="x",
    )
    entry = DecisionEntry(
        euvd_id="EUVD-3",
        purl="pkg:pypi/Requests@2.31.0",  # exact SBOM casing, not normalized
        status=Status.FIXED,
        statement="Patched.",
        author="a@example.com",
        date="2026-01-01",
    )
    result = merge([evaluation], DecisionsFile(decisions=[entry]))
    assert result.decisions[0].decision.status is Status.FIXED
    assert result.decisions[0].is_human is True
    assert result.stale == []


def test_decision_purl_pattern_also_normalizes() -> None:
    # The no-version "pattern" branch must normalize too, not just the exact-match branch.
    component = _component(name="Requests", version="2.31.0", purl="pkg:pypi/Requests@2.31.0")
    record = EuvdRecord(euvd_id="EUVD-4")
    evaluation = Evaluation(
        component=component,
        record=record,
        outcome=Outcome.MATCH,
        confidence=Confidence.LOW,
        strategy=Strategy.FUZZY,
        explanation="x",
    )
    entry = DecisionEntry(
        euvd_id="EUVD-4",
        purl="pkg:pypi/Requests",  # un-normalized, no version -> pattern match
        status=Status.NOT_AFFECTED,
        justification=Justification.VULNERABLE_CODE_NOT_PRESENT,
        statement="Not used.",
        author="a@example.com",
        date="2026-01-01",
    )
    result = merge([evaluation], DecisionsFile(decisions=[entry]))
    assert result.decisions[0].decision.status is Status.NOT_AFFECTED
    assert result.stale == []
