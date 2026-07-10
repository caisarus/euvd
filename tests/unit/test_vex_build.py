"""Covers implementation_plan.md Step 3.4's assembly layer: (Evaluation, Decision) -> Statement."""

import pytest

from euvd_watch.euvd.match import Confidence, Evaluation, Outcome, Strategy, evaluate_component
from euvd_watch.euvd.models import AffectedProduct, EuvdRecord
from euvd_watch.models import Component, SourceFormat
from euvd_watch.sbom.normalize import normalize_component
from euvd_watch.vex.build import build_document, build_statement
from euvd_watch.vex.merge import ResolvedDecision
from euvd_watch.vex.model import Status
from euvd_watch.vex.rules import Decision, decide

pytestmark = pytest.mark.unit


def _not_affected_evaluation() -> Evaluation:
    component = normalize_component(
        Component(
            name="openssl",
            version="3.0.8",
            cpe="cpe:2.3:a:openssl:openssl:3.0.8:*:*:*:*:*:*:*",
            purl="pkg:generic/openssl@3.0.8",
            source_format=SourceFormat.CYCLONEDX,
            raw_ref="r",
        )
    )
    record = EuvdRecord(
        euvd_id="EUVD-1",
        aliases=["CVE-2026-1", "GHSA-x"],
        affected_products=[
            AffectedProduct(vendor="openssl", product="openssl", version_range="<3.0.8")
        ],
    )
    return evaluate_component(component, [record])[0]


def _synthetic_evaluation(component: Component, record: EuvdRecord) -> Evaluation:
    return Evaluation(
        component=component,
        record=record,
        outcome=Outcome.MATCH,
        confidence=Confidence.LOW,
        strategy=Strategy.FUZZY,
        explanation="synthetic test evaluation",
    )


def test_not_affected_statement_gets_justification_and_impact_statement() -> None:
    evaluation = _not_affected_evaluation()
    decision = decide(evaluation)
    statement = build_statement(evaluation, decision)
    assert statement.status is Status.NOT_AFFECTED
    assert statement.justification is not None
    assert statement.impact_statement == decision.explanation
    assert statement.action_statement is None


def test_affected_statement_gets_action_statement_not_impact_statement() -> None:
    evaluation = _not_affected_evaluation()
    decision = Decision(status=Status.AFFECTED, explanation="Confirmed exploitable.")
    statement = build_statement(evaluation, decision)
    assert statement.status is Status.AFFECTED
    assert statement.action_statement == "Confirmed exploitable."
    assert statement.impact_statement is None


def test_under_investigation_statement_needs_no_extra_fields_but_carries_context() -> None:
    evaluation = _not_affected_evaluation()
    decision = Decision(status=Status.UNDER_INVESTIGATION, explanation="No automated rule fired.")
    statement = build_statement(evaluation, decision)
    assert statement.status is Status.UNDER_INVESTIGATION
    assert statement.impact_statement == "No automated rule fired."


def test_vulnerability_name_prefers_cve_alias_over_euvd_id() -> None:
    evaluation = _not_affected_evaluation()
    decision = decide(evaluation)
    statement = build_statement(evaluation, decision)
    assert statement.vulnerability.name == "CVE-2026-1"
    assert "EUVD-1" in statement.vulnerability.aliases
    assert "GHSA-x" in statement.vulnerability.aliases
    assert "CVE-2026-1" not in statement.vulnerability.aliases  # not duplicated as its own alias


def test_vulnerability_name_falls_back_to_euvd_id_without_cve() -> None:
    component = normalize_component(
        Component(name="x", version="1.0", source_format=SourceFormat.CYCLONEDX, raw_ref="r")
    )
    record = EuvdRecord(euvd_id="EUVD-9", aliases=["GHSA-only"])
    evaluation = _synthetic_evaluation(component, record)
    decision = decide(evaluation)
    statement = build_statement(evaluation, decision)
    assert statement.vulnerability.name == "EUVD-9"
    assert "GHSA-only" in statement.vulnerability.aliases


def test_product_uses_component_purl() -> None:
    evaluation = _not_affected_evaluation()
    decision = decide(evaluation)
    statement = build_statement(evaluation, decision)
    assert statement.products[0].identifiers is not None
    assert statement.products[0].identifiers.purl == "pkg:generic/openssl@3.0.8"


def test_product_falls_back_to_synthetic_id_without_a_purl() -> None:
    component = normalize_component(
        Component(name="no-purl-component", source_format=SourceFormat.CYCLONEDX, raw_ref="r")
    )
    assert component.purl is None and component.normalized_purl is None
    record = EuvdRecord(euvd_id="EUVD-10")
    evaluation = _synthetic_evaluation(component, record)
    decision = decide(evaluation)
    statement = build_statement(evaluation, decision)
    assert statement.products[0].identifiers is None
    assert statement.products[0].id == f"urn:euvd-watch:component:{component.dedupe_key}"


def test_synthetic_id_percent_encodes_unsafe_characters() -> None:
    # feedback_m3.md finding 2.1: a component name with spaces (or other characters
    # invalid in an IRI per RFC 3986/3987) must not leak them into the @id verbatim.
    component = normalize_component(
        Component(
            name="My Cool Component Name",
            version="1.0.0",
            source_format=SourceFormat.CYCLONEDX,
            raw_ref="r",
        )
    )
    assert component.purl is None and component.normalized_purl is None
    record = EuvdRecord(euvd_id="EUVD-11")
    evaluation = _synthetic_evaluation(component, record)
    decision = decide(evaluation)
    statement = build_statement(evaluation, decision)
    assert statement.products[0].id is not None
    assert " " not in statement.products[0].id
    assert "my%20cool%20component%20name" in statement.products[0].id


def test_build_document_assembles_all_statements() -> None:
    evaluation = _not_affected_evaluation()
    decision = decide(evaluation)
    document = build_document(
        [ResolvedDecision(evaluation, decision, False)],
        document_id="urn:euvd-watch:vex:test",
        author="euvd-watch",
        timestamp="2026-01-01T00:00:00Z",
    )
    assert document.id == "urn:euvd-watch:vex:test"
    assert len(document.statements) == 1
    assert document.statements[0].status is Status.NOT_AFFECTED
