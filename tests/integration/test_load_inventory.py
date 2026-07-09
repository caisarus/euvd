"""Covers implementation_plan.md Step 1.5: load_inventory (detect -> parse -> normalize -> dedupe).

load_inventory() itself is the exact function M2's matcher is meant to reuse, so it gets a
direct test here rather than only being exercised indirectly through the CLI.
"""

from pathlib import Path

from euvd_watch.sbom import load_inventory, load_inventory_with_stats

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sboms"


def test_load_inventory_dedupes_by_normalized_purl() -> None:
    inventory = load_inventory(FIXTURES / "duplicates.cdx.json")
    names = sorted(c.name for c in inventory.components)
    assert names == ["other-lib", "widget"]


def test_load_inventory_with_stats_reports_dropped_count() -> None:
    inventory, dropped = load_inventory_with_stats(FIXTURES / "duplicates.cdx.json")
    assert dropped == 1
    assert len(inventory.components) == 2


def test_load_inventory_keeps_first_occurrence() -> None:
    inventory = load_inventory(FIXTURES / "duplicates.cdx.json")
    widget = next(c for c in inventory.components if c.name == "widget")
    assert widget.raw_ref == "widget-a"


def test_load_inventory_normalizes_components() -> None:
    inventory = load_inventory(FIXTURES / "syft-demo.cdx.json")
    assert all(c.normalized_purl is not None for c in inventory.components if c.purl)


def test_load_inventory_works_for_spdx_too() -> None:
    inventory = load_inventory(FIXTURES / "github-export.spdx.json")
    assert len(inventory.components) == 105
