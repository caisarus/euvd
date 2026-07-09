"""Executable "must never happen" list for M1 (test_plan.md §6).

These re-assert, over every real and handcrafted fixture, the invariants that individual
unit tests assert over single values. M2 adds its own entries (confidence caps, etc.).
"""

from pathlib import Path

import pytest

from euvd_watch.models import Component
from euvd_watch.sbom.detect import parse_any
from euvd_watch.sbom.normalize import normalize_component, normalize_purl

pytestmark = pytest.mark.invariant

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sboms"

# Every fixture that is a well-formed SBOM (the malformed/garbage ones are covered by the
# parser error tests).
PARSEABLE_FIXTURES = [
    "syft-demo.cdx.json",
    "github-export.spdx.json",
    "minimal.cdx.json",
    "minimal.spdx.json",
    "nested-licenses.cdx.json",
    "cpe-ref.spdx.json",
    "parity.cdx.json",
    "parity.spdx.json",
    "duplicates.cdx.json",
]


def _all_normalized_components() -> list[Component]:
    components: list[Component] = []
    for fixture in PARSEABLE_FIXTURES:
        inventory = parse_any(FIXTURES / fixture)
        components.extend(normalize_component(c) for c in inventory.components)
    assert components, "fixture set must not be empty"
    return components


def test_invariant_synthesized_flag_is_set_iff_purl_was_synthesized() -> None:
    for c in _all_normalized_components():
        if c.normalized_purl is not None and c.purl is None:
            assert c.synthesized, f"{c.name}: synthesized purl without synthesized=True"
        if c.synthesized:
            assert c.purl is None, f"{c.name}: synthesized=True despite an original purl"


def test_invariant_normalized_purls_are_canonical() -> None:
    for c in _all_normalized_components():
        if c.normalized_purl is not None:
            assert c.normalized_purl == normalize_purl(c.normalized_purl), (
                f"{c.name}: normalized_purl is not a fixed point of normalize_purl"
            )


def test_invariant_normalization_is_idempotent() -> None:
    for c in _all_normalized_components():
        again = normalize_component(c)
        assert again.model_dump() == c.model_dump(), f"{c.name}: normalization not idempotent"


def test_invariant_no_component_has_an_empty_name() -> None:
    # The parsers must skip nameless components (loudly); an empty name here would collide
    # in dedup and silently drop components from matching.
    for c in _all_normalized_components():
        assert c.name.strip(), "component with empty name escaped the parsers"
