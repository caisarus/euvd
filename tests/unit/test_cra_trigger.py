"""Covers implementation_plan.md Step 4.1: the trigger policy engine truth table."""

from pathlib import Path
from typing import Any

import pytest
import yaml

from euvd_watch.config import CraTriggerConfig, Settings
from euvd_watch.cra.trigger import evaluate_trigger
from euvd_watch.euvd.match import Confidence, Finding, Strategy
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.models import Component, SourceFormat

pytestmark = pytest.mark.unit

CASES_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "cra" / "trigger-cases.yaml"
CASES: list[dict[str, Any]] = yaml.safe_load(CASES_PATH.read_text(encoding="utf-8"))


def _finding(spec: dict[str, Any]) -> Finding:
    component = Component(
        name="widget", version="1.0.0", source_format=SourceFormat.CYCLONEDX, raw_ref="r"
    )
    record = EuvdRecord(euvd_id="EUVD-TRIGGER-TEST", exploited=spec["exploited"])
    return Finding(
        component=component,
        record=record,
        confidence=Confidence(spec["confidence"]),
        strategy=Strategy.STRUCTURED,
        explanation="x",
        epss_score=spec["epss_score"],
        in_kev=spec["in_kev"],
    )


def _settings(config_spec: dict[str, Any], epss_threshold: float) -> Settings:
    return Settings(
        cra_trigger=CraTriggerConfig(**config_spec), epss_threshold=epss_threshold
    )


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_trigger_truth_table(case: dict[str, Any]) -> None:
    finding = _finding(case["finding"])
    settings = _settings(case["config"], case["settings_epss_threshold"])
    result = evaluate_trigger(finding, settings)
    expect = case["expect"]

    if not expect["fires"]:
        assert result is None, f"{case['id']}: expected no trigger"
        return

    assert result is not None, f"{case['id']}: expected a trigger"
    assert set(result.fired_rules) == set(expect["fired_rules"]), case["id"]
    assert result.policy_snapshot == settings.cra_trigger, case["id"]


def test_truth_table_has_at_least_15_cases() -> None:
    assert len(CASES) >= 15
