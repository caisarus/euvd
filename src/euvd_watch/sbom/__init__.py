"""SBOM ingestion: format detection, parsing, and normalization into Inventory.

`load_inventory` is the single entry point M2's matcher (and the `scan` command) build on:
detect -> parse -> normalize -> dedupe, format-blind.
"""

from __future__ import annotations

from pathlib import Path

from euvd_watch.models import Component, Inventory
from euvd_watch.sbom.detect import parse_any
from euvd_watch.sbom.normalize import normalize_component


def _dedupe(components: list[Component]) -> tuple[list[Component], int]:
    """First-occurrence-wins dedup by dedupe_key. Returns (kept, count dropped)."""
    seen: set[object] = set()
    kept: list[Component] = []
    dropped = 0
    for component in components:
        key = component.dedupe_key
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        kept.append(component)
    return kept, dropped


def load_inventory_with_stats(path_or_bytes: str | Path | bytes) -> tuple[Inventory, int]:
    """Like load_inventory, but also returns the count of components dropped as duplicates."""
    inventory = parse_any(path_or_bytes)
    normalized = [normalize_component(c) for c in inventory.components]
    deduped, dropped = _dedupe(normalized)
    return inventory.model_copy(update={"components": deduped}), dropped


def load_inventory(path_or_bytes: str | Path | bytes) -> Inventory:
    """Parse and normalize an SBOM into a deduplicated Inventory, any supported format."""
    inventory, _dropped = load_inventory_with_stats(path_or_bytes)
    return inventory
