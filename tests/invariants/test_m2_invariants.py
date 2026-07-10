"""Executable "must never happen" list for M2 (test_plan.md §6).

The matcher's honesty guarantees, asserted over the truth-table corpus and real EUVD
fixture data — not just over the single values the unit tests use.
"""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from euvd_watch.euvd.match import Confidence, match_component, match_inventory
from euvd_watch.euvd.models import AffectedProduct, EuvdRecord, parse_records
from euvd_watch.models import Component, SourceFormat
from euvd_watch.sbom import load_inventory
from euvd_watch.sbom.normalize import normalize_component

pytestmark = pytest.mark.invariant

REPO_SRC = Path(__file__).resolve().parents[2] / "src" / "euvd_watch"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

CASES: list[dict[str, Any]] = yaml.safe_load(
    (FIXTURES / "matching" / "cases.yaml").read_text(encoding="utf-8")
)


def _truth_table_findings() -> list[Any]:
    findings = []
    for case in CASES:
        component = normalize_component(
            Component(
                name=case["component"]["name"],
                version=case["component"].get("version"),
                purl=case["component"].get("purl"),
                cpe=case["component"].get("cpe"),
                source_format=SourceFormat.CYCLONEDX,
                raw_ref=case["id"],
            )
        )
        record = EuvdRecord(
            euvd_id=f"EUVD-INV-{case['id']}",
            affected_products=[
                AffectedProduct(
                    vendor=e.get("vendor"),
                    product=e["product"],
                    version_range=e.get("version_range"),
                )
                for e in case["affected"]
            ],
        )
        findings.extend(match_component(component, [record]))
    return findings


def _real_data_findings() -> list[Any]:
    import json

    inventory = load_inventory(FIXTURES / "sboms" / "syft-demo.cdx.json")
    exploited = json.loads(
        (FIXTURES / "euvd" / "search-exploited-page0.json").read_text(encoding="utf-8")
    )
    records = parse_records(exploited["items"])
    return match_inventory(inventory, records)


def test_invariant_every_explanation_is_non_empty() -> None:
    for finding in _truth_table_findings() + _real_data_findings():
        assert finding.explanation and finding.explanation.strip()


def test_invariant_synthesized_identifier_never_exceeds_medium() -> None:
    for finding in _truth_table_findings() + _real_data_findings():
        if finding.component.synthesized:
            assert finding.confidence is not Confidence.HIGH, (
                f"{finding.component.name}: high confidence from a synthesized identifier"
            )


def test_invariant_high_confidence_requires_real_version_evidence() -> None:
    # Every high finding's explanation must cite the range and a non-fallback scheme;
    # the matcher encodes the tokenwise cap, this asserts it end-to-end.
    for finding in _truth_table_findings() + _real_data_findings():
        if finding.confidence is Confidence.HIGH:
            assert "inside affected range" in finding.explanation
            assert "fallback" not in finding.explanation


def test_invariant_findings_are_deterministically_ordered() -> None:
    findings = _real_data_findings()
    keys = [(f.component.dedupe_key, f.record.euvd_id) for f in findings]
    assert keys == sorted(keys)


def test_invariant_no_httpx_import_outside_http_module() -> None:
    # Step 2.1 acceptance criterion: all HTTP goes through the single ApiClient.
    pattern = re.compile(r"^\s*(import httpx|from httpx)", re.MULTILINE)
    offenders = [
        path
        for path in REPO_SRC.rglob("*.py")
        if path.name != "http.py" and pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"httpx imported outside http.py: {offenders}"
