"""Covers the M3 matcher extension: evaluate_component/evaluate_inventory expose
NOT_AFFECTED outcomes that match_component/match_inventory (M2's public contract) filter
out. See plans/feedback_m2.md's carried-forward design note and the M3 plan.
"""

from typing import Any

import pytest

from euvd_watch.euvd.match import (
    Confidence,
    Outcome,
    evaluate_component,
    evaluate_inventory,
    match_component,
    match_inventory,
)
from euvd_watch.euvd.models import AffectedProduct, EuvdRecord
from euvd_watch.models import Component, Inventory, SourceFormat
from euvd_watch.sbom.normalize import normalize_component

pytestmark = pytest.mark.unit


def _component(**kwargs: Any) -> Component:
    raw = Component(source_format=SourceFormat.CYCLONEDX, raw_ref="r", **kwargs)
    return normalize_component(raw)


def _record(**kwargs: Any) -> EuvdRecord:
    kwargs.setdefault("euvd_id", "EUVD-TEST-1")
    return EuvdRecord(**kwargs)


def test_vendor_and_product_exact_match_provably_outside_is_not_affected_high() -> None:
    component = _component(
        name="openssl",
        version="3.0.8",
        cpe="cpe:2.3:a:openssl:openssl:3.0.8:*:*:*:*:*:*:*",
        purl="pkg:generic/openssl@3.0.8",
    )
    record = _record(
        affected_products=[
            AffectedProduct(vendor="openssl", product="openssl", version_range="<3.0.8")
        ]
    )
    evaluations = evaluate_component(component, [record])
    assert len(evaluations) == 1
    assert evaluations[0].outcome is Outcome.NOT_AFFECTED
    assert evaluations[0].confidence is Confidence.HIGH
    assert "outside affected range" in evaluations[0].explanation


def test_product_equal_vendor_unknown_provably_outside_is_not_affected_medium() -> None:
    component = _component(name="widget", version="1.5.0")
    record = _record(
        affected_products=[AffectedProduct(vendor="acme", product="widget", version_range="<1.0.0")]
    )
    evaluations = evaluate_component(component, [record])
    assert len(evaluations) == 1
    assert evaluations[0].outcome is Outcome.NOT_AFFECTED
    assert evaluations[0].confidence is Confidence.MEDIUM


def test_vendor_mismatch_provably_outside_is_no_signal_at_all() -> None:
    # Too weak an identity signal to auto-assert not_affected on.
    component = _component(
        name="widget",
        version="3.0.0",
        cpe="cpe:2.3:a:evilcorp:widget:3.0.0:*:*:*:*:*:*:*",
        purl="pkg:generic/widget@3.0.0",
    )
    record = _record(
        affected_products=[AffectedProduct(vendor="acme", product="widget", version_range="<2.0.0")]
    )
    assert evaluate_component(component, [record]) == []


def test_synthesized_identifier_provably_outside_is_no_signal_at_all() -> None:
    component = _component(
        name="widget",
        version="1.0.0",
        cpe="cpe:2.3:a:python-widget:widget:1.0.0:*:*:*:*:*:*:*",
    )
    assert component.synthesized is True
    record = _record(
        affected_products=[
            AffectedProduct(vendor="python-widget", product="widget", version_range="<0.5.0")
        ]
    )
    assert evaluate_component(component, [record]) == []


def test_fuzzy_only_provably_outside_is_no_signal_at_all() -> None:
    component = _component(name="page builder", version="9.0.0")
    record = _record(
        affected_products=[
            AffectedProduct(vendor="joomshaper", product="Page Builder CK", version_range="<2.0.0")
        ]
    )
    assert evaluate_component(component, [record]) == []


def test_not_affected_never_appears_in_match_component() -> None:
    component = _component(
        name="openssl",
        version="3.0.8",
        cpe="cpe:2.3:a:openssl:openssl:3.0.8:*:*:*:*:*:*:*",
        purl="pkg:generic/openssl@3.0.8",
    )
    record = _record(
        affected_products=[
            AffectedProduct(vendor="openssl", product="openssl", version_range="<3.0.8")
        ]
    )
    assert evaluate_component(component, [record])  # evaluation exists
    assert match_component(component, [record]) == []  # but M2's Finding view sees nothing


def test_match_outranks_not_affected_across_affected_product_entries() -> None:
    # One record with two affected entries for the same product: one where the version is
    # outside, one where it's inside. The real match must win.
    component = _component(
        name="widget",
        version="1.5.0",
        cpe="cpe:2.3:a:acme:widget:1.5.0:*:*:*:*:*:*:*",
        purl="pkg:generic/widget@1.5.0",
    )
    record = _record(
        affected_products=[
            AffectedProduct(vendor="acme", product="widget", version_range="<1.0.0"),
            AffectedProduct(vendor="acme", product="widget", version_range="<2.0.0"),
        ]
    )
    evaluations = evaluate_component(component, [record])
    assert len(evaluations) == 1
    assert evaluations[0].outcome is Outcome.MATCH
    assert evaluations[0].confidence is Confidence.HIGH


def test_evaluate_inventory_ordering_matches_match_inventory_ordering() -> None:
    not_affected_record = _record(
        euvd_id="EUVD-1",
        affected_products=[
            AffectedProduct(vendor="openssl", product="openssl", version_range="<3.0.8")
        ],
    )
    match_record = _record(
        euvd_id="EUVD-2",
        affected_products=[
            AffectedProduct(vendor="acme", product="widget", version_range="<9.0.0")
        ],
    )
    openssl = _component(
        name="openssl",
        version="3.0.8",
        cpe="cpe:2.3:a:openssl:openssl:3.0.8:*:*:*:*:*:*:*",
        purl="pkg:generic/openssl@3.0.8",
    )
    widget = _component(
        name="widget",
        version="1.0.0",
        cpe="cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*",
        purl="pkg:generic/widget@1.0.0",
    )
    inventory = Inventory(components=[openssl, widget])
    records = [not_affected_record, match_record]

    evaluations = evaluate_inventory(inventory, records)
    findings = match_inventory(inventory, records)

    assert {e.outcome for e in evaluations} == {Outcome.NOT_AFFECTED, Outcome.MATCH}
    assert len(findings) == 1
    assert findings[0].record.euvd_id == "EUVD-2"
    keys = [(e.component.dedupe_key, e.record.euvd_id) for e in evaluations]
    assert keys == sorted(keys)
