"""Covers implementation_plan.md Step 2.3: the matcher truth table + engine behavior."""

from pathlib import Path
from typing import Any

import pytest
import yaml

from euvd_watch.euvd.match import (
    Confidence,
    Strategy,
    confidence_at_least,
    derive_candidates,
    match_component,
    match_inventory,
    normalize_text,
)
from euvd_watch.euvd.models import AffectedProduct, EuvdRecord
from euvd_watch.models import Component, Inventory, SourceFormat
from euvd_watch.sbom.normalize import normalize_component

pytestmark = pytest.mark.unit

CASES_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "matching" / "cases.yaml"
CASES: list[dict[str, Any]] = yaml.safe_load(CASES_PATH.read_text(encoding="utf-8"))


def _component(spec: dict[str, Any]) -> Component:
    raw = Component(
        name=spec["name"],
        version=spec.get("version"),
        purl=spec.get("purl"),
        cpe=spec.get("cpe"),
        source_format=SourceFormat.CYCLONEDX,
        raw_ref="truth-table",
    )
    return normalize_component(raw)


def _record(affected: list[dict[str, Any]], euvd_id: str = "EUVD-TEST-1") -> EuvdRecord:
    return EuvdRecord(
        euvd_id=euvd_id,
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
def test_truth_table(case: dict[str, Any]) -> None:
    component = _component(case["component"])
    record = _record(case["affected"])
    findings = match_component(component, [record])
    expect = case["expect"]

    if not expect["matched"]:
        assert findings == [], f"{case['id']}: expected no finding, got {findings}"
        return

    assert len(findings) == 1, f"{case['id']}: expected exactly one finding"
    finding = findings[0]
    assert finding.confidence == Confidence(expect["confidence"]), case["id"]
    assert finding.strategy == Strategy(expect["strategy"]), case["id"]
    assert finding.explanation.strip(), f"{case['id']}: explanation must never be empty"


def test_truth_table_has_at_least_25_cases() -> None:
    assert len(CASES) >= 25


def test_match_inventory_orders_deterministically() -> None:
    record_a = _record([{"vendor": "acme", "product": "widget", "version_range": "<9"}], "EUVD-1-2")
    record_b = _record([{"vendor": "acme", "product": "widget", "version_range": "<9"}], "EUVD-1-1")
    zed = _component({"name": "zed-widget", "version": "1.0"})
    widget = _component(
        {"name": "widget", "version": "1.0", "cpe": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}
    )
    inventory = Inventory(components=[zed, widget])
    findings = match_inventory(inventory, [record_a, record_b])
    keys = [(f.component.dedupe_key, f.record.euvd_id) for f in findings]
    assert keys == sorted(keys), "findings must be ordered by (dedupe_key, euvd_id)"
    assert len(findings) >= 2


def test_match_inventory_same_inputs_same_output() -> None:
    record = _record([{"vendor": "acme", "product": "widget", "version_range": "<9"}])
    component = _component(
        {"name": "widget", "version": "1.0", "cpe": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}
    )
    inventory = Inventory(components=[component])
    first = match_inventory(inventory, [record])
    second = match_inventory(inventory, [record])
    assert [f.model_dump() for f in first] == [f.model_dump() for f in second]


def test_best_confidence_wins_across_multiple_product_entries() -> None:
    # One record lists the product twice: once ambiguously, once with an evaluable range.
    component = _component(
        {"name": "widget", "version": "1.0", "cpe": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}
    )
    record = _record(
        [
            {"vendor": "acme", "product": "widget", "version_range": "unspecified"},
            {"vendor": "acme", "product": "widget", "version_range": "<2.0"},
        ]
    )
    findings = match_component(component, [record])
    assert len(findings) == 1
    assert findings[0].confidence is Confidence.HIGH


def test_derive_candidates_prefers_cpe_then_alias_then_purl_then_name() -> None:
    component = _component(
        {
            "name": "displayname",
            "version": "9.0.0",
            "purl": "pkg:pypi/pillow@9.0.0",
            "cpe": "cpe:2.3:a:cpevendor:cpeproduct:9.0.0:*:*:*:*:*:*:*",
        }
    )
    candidates = derive_candidates(component)
    sources = [c.source for c in candidates]
    assert sources[0] == "cpe"
    assert "alias" in sources  # pkg:pypi/pillow is in the curated table
    assert sources[-1] == "name"


def test_normalize_text_is_punctuation_and_case_insensitive() -> None:
    assert normalize_text("Spring-Framework") == normalize_text("spring framework")
    assert normalize_text("Node.js") == normalize_text("nodejs")


def test_confidence_at_least() -> None:
    assert confidence_at_least(Confidence.HIGH, Confidence.MEDIUM)
    assert confidence_at_least(Confidence.MEDIUM, Confidence.MEDIUM)
    assert not confidence_at_least(Confidence.LOW, Confidence.MEDIUM)
