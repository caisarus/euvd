"""Covers implementation_plan.md Step 3.2: conservative VEX statement rules."""

from pathlib import Path
from typing import Any

import pytest
import yaml

from euvd_watch.euvd.match import Evaluation, Outcome, evaluate_component
from euvd_watch.euvd.models import AffectedProduct, EuvdRecord
from euvd_watch.models import Component, SourceFormat
from euvd_watch.sbom.normalize import normalize_component
from euvd_watch.vex.model import Justification, Status
from euvd_watch.vex.rules import (
    UNDER_INVESTIGATION,
    Decision,
    ProvablyOutsideRule,
    Rule,
    decide,
    decide_all,
)

pytestmark = pytest.mark.unit

CASES_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "vex" / "rules-cases.yaml"
CASES: list[dict[str, Any]] = yaml.safe_load(CASES_PATH.read_text(encoding="utf-8"))


def _component(spec: dict[str, Any]) -> Component:
    raw = Component(
        name=spec["name"],
        version=spec.get("version"),
        purl=spec.get("purl"),
        cpe=spec.get("cpe"),
        source_format=SourceFormat.CYCLONEDX,
        raw_ref="rules-truth-table",
    )
    return normalize_component(raw)


def _record(affected: list[dict[str, Any]]) -> EuvdRecord:
    return EuvdRecord(
        euvd_id="EUVD-RULES-TEST",
        affected_products=[
            AffectedProduct(
                vendor=entry.get("vendor"),
                product=entry["product"],
                version_range=entry.get("version_range"),
            )
            for entry in affected
        ],
    )


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_rules_truth_table(case: dict[str, Any]) -> None:
    component = _component(case["component"])
    record = _record(case["affected"])
    evaluations = evaluate_component(component, [record])
    expect = case["expect"]

    if expect.get("no_evaluation"):
        assert evaluations == [], f"{case['id']}: expected no evaluation at all"
        return

    assert len(evaluations) == 1, f"{case['id']}: expected exactly one evaluation"
    decision = decide(evaluations[0])
    assert decision.status == Status(expect["status"]), case["id"]
    if "justification" in expect:
        assert decision.justification == Justification(expect["justification"]), case["id"]
    assert decision.explanation.strip(), f"{case['id']}: explanation must never be empty"


def test_truth_table_has_positive_and_adversarial_cases() -> None:
    statuses = {c["expect"].get("status") for c in CASES}
    assert "not_affected" in statuses
    assert "under_investigation" in statuses
    assert any(c["expect"].get("no_evaluation") for c in CASES)


def _not_affected_evaluation() -> Evaluation:
    component = _component(
        {
            "name": "openssl",
            "version": "3.0.8",
            "cpe": "cpe:2.3:a:openssl:openssl:3.0.8:*:*:*:*:*:*:*",
            "purl": "pkg:generic/openssl@3.0.8",
        }
    )
    record = _record([{"vendor": "openssl", "product": "openssl", "version_range": "<3.0.8"}])
    evaluations = evaluate_component(component, [record])
    assert evaluations[0].outcome is Outcome.NOT_AFFECTED
    return evaluations[0]


def test_default_is_under_investigation_when_no_rule_fires() -> None:
    component = _component({"name": "totally-unrelated", "version": "1.0.0"})
    record = _record([{"vendor": "acme", "product": "widget", "version_range": "<2.0.0"}])
    # No signal at all -> no evaluation to decide on in the real pipeline, but decide()
    # itself must still default safely given an evaluation with no applicable rule.
    evaluations = evaluate_component(component, [record])
    assert evaluations == []
    # Directly exercise decide() with a MATCH-outcome evaluation the rule doesn't touch.
    match_component = _component(
        {
            "name": "openssl",
            "version": "3.0.2",
            "cpe": "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*",
            "purl": "pkg:generic/openssl@3.0.2",
        }
    )
    match_record = _record([{"vendor": "openssl", "product": "openssl", "version_range": "<3.0.8"}])
    match_eval = evaluate_component(match_component, [match_record])[0]
    assert decide(match_eval).status is Status.UNDER_INVESTIGATION


def test_disagreeing_rules_fall_back_to_under_investigation_and_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class AlwaysAffected:
        name = "always_affected_test_rule"

        def applies(self, evaluation: Evaluation) -> Decision | None:
            return Decision(status=Status.AFFECTED, explanation="synthetic disagreement")

    evaluation = _not_affected_evaluation()  # ProvablyOutsideRule would say not_affected
    rules: list[Rule] = [ProvablyOutsideRule(), AlwaysAffected()]
    with caplog.at_level("WARNING"):
        decision = decide(evaluation, rules)
    assert decision == UNDER_INVESTIGATION
    assert any("disagree" in r.message for r in caplog.records)


def test_agreeing_rules_do_not_trigger_fallback() -> None:
    class AlsoNotAffected:
        name = "also_not_affected_test_rule"

        def applies(self, evaluation: Evaluation) -> Decision | None:
            return Decision(status=Status.NOT_AFFECTED, explanation="agrees")

    evaluation = _not_affected_evaluation()
    rules: list[Rule] = [ProvablyOutsideRule(), AlsoNotAffected()]
    decision = decide(evaluation, rules)
    assert decision.status is Status.NOT_AFFECTED  # first fired decision, not a fallback


def test_decide_all_preserves_order() -> None:
    evaluation = _not_affected_evaluation()
    results = decide_all([evaluation, evaluation])
    assert len(results) == 2
    assert all(d.status is Status.NOT_AFFECTED for _, d in results)


def test_no_code_path_produces_not_affected_without_justification() -> None:
    # Grep-able invariant per the plan's acceptance criterion, re-asserted directly here.
    for case in CASES:
        component = _component(case["component"])
        record = _record(case["affected"])
        for evaluation in evaluate_component(component, [record]):
            decision = decide(evaluation)
            if decision.status is Status.NOT_AFFECTED:
                assert decision.justification is not None
                assert decision.explanation.strip()
