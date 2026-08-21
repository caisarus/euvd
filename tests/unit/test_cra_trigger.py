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
    return Settings(cra_trigger=CraTriggerConfig(**config_spec), epss_threshold=epss_threshold)


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


# -- three-valued run evaluation (audit follow-up): indeterminate vs clear vs triggered --

from euvd_watch.cra.trigger import evaluate_run  # noqa: E402


def _run_finding(
    euvd_id: str,
    *,
    exploited: bool,
    in_kev: bool | None,
    epss: float | None,
    confidence: str = "high",
    name: str = "widget",
) -> Finding:
    component = Component(
        name=name, version="1.0.0", source_format=SourceFormat.CYCLONEDX, raw_ref="r"
    )
    record = EuvdRecord(euvd_id=euvd_id, exploited=exploited)
    return Finding(
        component=component,
        record=record,
        confidence=Confidence(confidence),
        strategy=Strategy.STRUCTURED,
        explanation="x",
        epss_score=epss,
        in_kev=in_kev,
    )


_DEFAULT = {
    "euvd_exploited": True,
    "cisa_kev": True,
    "epss_over_threshold": True,
    "min_confidence": "medium",
}


def test_run_exploited_fires_even_when_kev_and_epss_unavailable() -> None:
    """A signal we CAN evaluate (euvd_exploited, from the record) still fires - the
    unavailability of other signals must not suppress a real, determinate trigger."""
    findings = [_run_finding("E1", exploited=True, in_kev=None, epss=None)]
    run = evaluate_run(findings, _settings(_DEFAULT | {"require_all": False}, 0.5))
    assert [t.finding.record.euvd_id for t in run.triggered] == ["E1"]
    assert run.indeterminate == []  # it fired; not indeterminate


def test_run_unavailable_signal_makes_a_nonfiring_finding_indeterminate() -> None:
    """Disjunction: a finding that didn't fire on the signals we could check, but whose
    remaining enabled signals were UNAVAILABLE, is indeterminate - never a clean 'no'."""
    findings = [_run_finding("E1", exploited=False, in_kev=None, epss=None)]
    run = evaluate_run(findings, _settings(_DEFAULT | {"require_all": False}, 0.5))
    assert run.triggered == []
    assert [i.finding.record.euvd_id for i in run.indeterminate] == ["E1"]
    assert set(run.indeterminate[0].unknown_signals) == {"cisa_kev", "epss_over_threshold"}
    assert set(run.unavailable_signals) == {"cisa_kev", "epss_over_threshold"}


def test_run_all_signals_confirmed_absent_is_clear_not_indeterminate() -> None:
    """When every enabled signal's source WAS available and confirmed the condition
    absent, the finding is a clean 'no' - not indeterminate. (KEV available because
    in_kev is a real bool; EPSS available because a score is present, just below.)"""
    findings = [_run_finding("E1", exploited=False, in_kev=False, epss=0.1)]
    run = evaluate_run(findings, _settings(_DEFAULT | {"require_all": False}, 0.5))
    assert run.triggered == []
    assert run.indeterminate == []
    assert run.unavailable_signals == []


def test_run_epss_available_but_scoreless_finding_is_absent_not_indeterminate() -> None:
    """A CVE with no EPSS score, when the EPSS source WAS available for the run (another
    finding carries a score), is a determinate ABSENT - not an unavailability UNKNOWN."""
    findings = [
        _run_finding("E1", exploited=False, in_kev=False, epss=None, name="a"),  # scoreless
        _run_finding("E2", exploited=False, in_kev=False, epss=0.1, name="b"),  # source is up
    ]
    run = evaluate_run(findings, _settings(_DEFAULT | {"require_all": False}, 0.5))
    assert run.triggered == []
    assert run.indeterminate == []  # E1 scoreless != indeterminate; EPSS was available
    assert run.unavailable_signals == []


def test_run_require_all_unavailable_required_signal_is_indeterminate() -> None:
    """require_all conjunction: a required signal whose source is down blocks the
    conjunction as INDETERMINATE, not a silent clean 'no'. euvd_exploited fired, KEV
    unavailable, epss disabled -> can't confirm the conjunction -> indeterminate."""
    config = {
        "euvd_exploited": True,
        "cisa_kev": True,
        "epss_over_threshold": False,
        "min_confidence": "medium",
        "require_all": True,
    }
    findings = [_run_finding("E1", exploited=True, in_kev=None, epss=None)]
    run = evaluate_run(findings, _settings(config, 0.5))
    assert run.triggered == []
    assert [i.finding.record.euvd_id for i in run.indeterminate] == ["E1"]
    assert run.indeterminate[0].unknown_signals == ["cisa_kev"]


def test_run_require_all_confirmed_absent_signal_is_clear_not_indeterminate() -> None:
    """require_all: a CONFIRMED-absent required signal sinks the conjunction definitively
    -> clear, even if another signal is unknown. Here KEV is available (E2 sets it), E1's
    in_kev is False (absent) -> E1 clear; E2 fires both -> triggered."""
    config = {
        "euvd_exploited": True,
        "cisa_kev": True,
        "epss_over_threshold": False,
        "min_confidence": "medium",
        "require_all": True,
    }
    findings = [
        _run_finding("E1", exploited=True, in_kev=False, epss=None, name="a"),  # kev absent
        _run_finding("E2", exploited=True, in_kev=True, epss=None, name="b"),  # kev present
    ]
    run = evaluate_run(findings, _settings(config, 0.5))
    assert [t.finding.record.euvd_id for t in run.triggered] == ["E2"]
    assert run.indeterminate == []  # E1 is a clean no (confirmed absent), not indeterminate


def test_run_below_confidence_is_clear_not_indeterminate() -> None:
    """A below-min-confidence finding is deliberately excluded and can never start a
    clock, so signal availability is irrelevant - it is clear, never indeterminate."""
    findings = [_run_finding("E1", exploited=False, in_kev=None, epss=None, confidence="low")]
    run = evaluate_run(findings, _settings(_DEFAULT | {"require_all": False}, 0.5))
    assert run.triggered == []
    assert run.indeterminate == []
