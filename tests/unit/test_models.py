"""Covers implementation_plan.md Step 1.1: the pipeline's core contract."""

import pytest
from pydantic import ValidationError

from euvd_watch.models import Component, ComponentType, Inventory, SourceFormat

pytestmark = pytest.mark.unit


def _component(**overrides: object) -> Component:
    defaults: dict[str, object] = {
        "name": "requests",
        "version": "2.31.0",
        "source_format": SourceFormat.CYCLONEDX,
        "raw_ref": "bom-ref-1",
    }
    defaults.update(overrides)
    return Component.model_validate(defaults)


def test_construction_with_minimal_fields() -> None:
    c = _component()
    assert c.name == "requests"
    assert c.purl is None
    assert c.licenses == []
    assert c.hashes == {}
    assert c.type == ComponentType.LIBRARY
    assert c.synthesized is False


def test_construction_with_maximal_fields() -> None:
    c = _component(
        purl="pkg:pypi/requests@2.31.0",
        cpe="cpe:2.3:a:python-requests:requests:2.31.0:*:*:*:*:*:*:*",
        licenses=["Apache-2.0"],
        hashes={"SHA-256": "deadbeef"},
        type=ComponentType.APPLICATION,
        normalized_purl="pkg:pypi/requests@2.31.0",
        normalized_version="2.31.0",
        cpe_parts={"vendor": "python-requests", "product": "requests"},
        synthesized=True,
    )
    assert c.purl == "pkg:pypi/requests@2.31.0"
    assert c.synthesized is True


def test_missing_required_field_raises() -> None:
    with pytest.raises(ValidationError):
        Component.model_validate({"version": "1.0", "source_format": "cyclonedx"})


def test_component_is_frozen() -> None:
    c = _component()
    with pytest.raises(ValidationError):
        c.name = "other"  # type: ignore[misc]


def test_dedupe_key_purl_beats_name_version() -> None:
    a = _component(purl="pkg:pypi/requests@2.31.0", name="requests", version="2.31.0")
    b = _component(purl="pkg:pypi/requests@2.31.0", name="Requests", version="2.30.0")
    assert a.dedupe_key == b.dedupe_key


def test_dedupe_key_normalized_purl_beats_raw_purl() -> None:
    c = _component(purl="pkg:pypi/Requests@2.31.0", normalized_purl="pkg:pypi/requests@2.31.0")
    assert c.dedupe_key == "purl:pkg:pypi/requests@2.31.0"


def test_dedupe_key_falls_back_to_case_insensitive_name_and_version() -> None:
    a = _component(name="Requests", version="2.31.0")
    b = _component(name="requests", version="2.31.0")
    assert a.dedupe_key == b.dedupe_key == "name:requests@2.31.0"


def test_dedupe_keys_are_always_strings_and_sortable() -> None:
    # M2 sorts findings by dedupe_key; mixed key types would make sorted() raise TypeError.
    with_purl = _component(purl="pkg:pypi/requests@2.31.0")
    without_purl = _component(name="zlib", version=None)
    keys = sorted([with_purl.dedupe_key, without_purl.dedupe_key])
    assert all(isinstance(k, str) for k in keys)


def test_dedupe_key_same_purl_different_raw_ref_is_same_key() -> None:
    a = _component(purl="pkg:pypi/requests@2.31.0", raw_ref="bom-ref-1")
    b = _component(purl="pkg:pypi/requests@2.31.0", raw_ref="bom-ref-2")
    assert a.dedupe_key == b.dedupe_key


def test_inventory_holds_components_and_metadata() -> None:
    inv = Inventory(
        components=[_component()],
        document_name="demo.cdx.json",
        tool="syft",
        timestamp="2026-01-01T00:00:00Z",
        format_version="1.5",
    )
    assert len(inv.components) == 1
    assert inv.tool == "syft"
    assert inv.schema_version == 1  # the JSON output contract version
