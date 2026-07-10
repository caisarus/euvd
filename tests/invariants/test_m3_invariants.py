"""Executable "must never happen" list for M3 (test_plan.md §6).

The VEX rule engine's credibility guarantees, asserted over the M2/M3 truth tables, real
fixture data, and randomized inputs - not just the single values the unit tests use.
"""

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from euvd_watch.euvd.match import Confidence, Evaluation, Outcome, Strategy, evaluate_component
from euvd_watch.euvd.models import AffectedProduct, EuvdRecord
from euvd_watch.models import Component, SourceFormat
from euvd_watch.sbom import load_inventory
from euvd_watch.sbom.normalize import normalize_component
from euvd_watch.vex.build import build_document
from euvd_watch.vex.merge import ResolvedDecision
from euvd_watch.vex.model import Status
from euvd_watch.vex.rules import decide
from euvd_watch.vex.write import render

pytestmark = pytest.mark.invariant

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
SCHEMA = json.loads((FIXTURES / "openvex" / "schema.json").read_text(encoding="utf-8"))

MATCH_CASES: list[dict[str, Any]] = yaml.safe_load(
    (FIXTURES / "matching" / "cases.yaml").read_text(encoding="utf-8")
)
RULES_CASES: list[dict[str, Any]] = yaml.safe_load(
    (FIXTURES / "vex" / "rules-cases.yaml").read_text(encoding="utf-8")
)


def _component(spec: dict[str, Any]) -> Component:
    raw = Component(
        name=spec["name"],
        version=spec.get("version"),
        purl=spec.get("purl"),
        cpe=spec.get("cpe"),
        source_format=SourceFormat.CYCLONEDX,
        raw_ref="invariant-check",
    )
    return normalize_component(raw)


def _record(affected: list[dict[str, Any]], euvd_id: str = "EUVD-INV-1") -> EuvdRecord:
    return EuvdRecord(
        euvd_id=euvd_id,
        affected_products=[
            AffectedProduct(
                vendor=e.get("vendor"), product=e["product"], version_range=e.get("version_range")
            )
            for e in affected
        ],
    )


def _all_case_evaluations() -> list[Evaluation]:
    # Each case gets a distinct euvd_id derived from its own id: real usage never produces
    # two byte-identical statements (each evaluation has a genuinely distinct EuvdRecord),
    # and the OpenVEX schema enforces uniqueItems on the statements array.
    evaluations: list[Evaluation] = []
    for case in MATCH_CASES + RULES_CASES:
        component = _component(case["component"])
        record = _record(case["affected"], euvd_id=f"EUVD-INV-{case['id']}")
        evaluations.extend(evaluate_component(component, [record]))
    return evaluations


def _real_fixture_evaluations() -> list[Evaluation]:
    inventory = load_inventory(FIXTURES / "sboms" / "syft-demo.cdx.json")
    exploited = json.loads(
        (FIXTURES / "euvd" / "search-exploited-page0.json").read_text(encoding="utf-8")
    )
    from euvd_watch.euvd.match import evaluate_inventory
    from euvd_watch.euvd.models import parse_records

    records = parse_records(exploited["items"])
    return evaluate_inventory(inventory, records)


def test_invariant_no_not_affected_without_justification_or_impact_statement() -> None:
    for evaluation in _all_case_evaluations() + _real_fixture_evaluations():
        decision = decide(evaluation)
        if decision.status is Status.NOT_AFFECTED:
            assert decision.justification is not None or decision.explanation.strip()


def test_invariant_not_affected_only_from_not_affected_outcome() -> None:
    # The rule must never assert not_affected for a MATCH outcome (an actual finding).
    for evaluation in _all_case_evaluations() + _real_fixture_evaluations():
        decision = decide(evaluation)
        if decision.status is Status.NOT_AFFECTED:
            assert evaluation.outcome is Outcome.NOT_AFFECTED


def test_invariant_every_statement_in_a_built_document_validates() -> None:
    resolved = [
        ResolvedDecision(evaluation, decide(evaluation), False)
        for evaluation in _all_case_evaluations()
    ]
    document = build_document(
        resolved,
        document_id="urn:euvd-watch:vex:invariant-test",
        author="euvd-watch",
        timestamp="2026-01-01T00:00:00Z",
    )
    jsonschema.validate(json.loads(render(document)), SCHEMA)


def test_invariant_conservation_every_evaluation_becomes_exactly_one_statement() -> None:
    # No finding/evaluation vanishes or duplicates across the VEX pipeline.
    evaluations = _real_fixture_evaluations()
    resolved = [ResolvedDecision(e, decide(e), False) for e in evaluations]
    document = build_document(
        resolved,
        document_id="urn:euvd-watch:vex:conservation-test",
        author="euvd-watch",
        timestamp="2026-01-01T00:00:00Z",
    )
    assert len(document.statements) == len(evaluations)


@given(
    st.sampled_from([Outcome.MATCH, Outcome.NOT_AFFECTED]),
    st.sampled_from(list(Confidence)),
    st.sampled_from(list(Strategy)),
    st.text(min_size=1, max_size=200),
)
def test_invariant_randomized_not_affected_always_has_evidence(
    outcome: Outcome, confidence: Confidence, strategy: Strategy, explanation: str
) -> None:
    component = _component({"name": "hypothesis-widget", "version": "1.0.0"})
    record = _record([{"vendor": "acme", "product": "widget", "version_range": "<9.9.9"}])
    evaluation = Evaluation(
        component=component,
        record=record,
        outcome=outcome,
        confidence=confidence,
        strategy=strategy,
        explanation=explanation,
    )
    decision = decide(evaluation)
    if decision.status is Status.NOT_AFFECTED:
        assert evaluation.outcome is Outcome.NOT_AFFECTED
        assert decision.justification is not None
