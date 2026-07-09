"""Covers implementation_plan.md Step 1.2: CycloneDX real-world messiness."""

import json
from pathlib import Path

import pytest

from euvd_watch.sbom import cyclonedx
from euvd_watch.sbom.errors import SbomParseError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sboms"
GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "golden" / "syft-demo.inventory.json"


def test_real_syft_fixture_matches_golden_byte_for_byte() -> None:
    inventory = cyclonedx.parse(FIXTURES / "syft-demo.cdx.json")
    golden = GOLDEN.read_text().rstrip("\n")
    assert inventory.model_dump_json(indent=2) == golden


def test_parsing_is_deterministic_across_runs() -> None:
    first = cyclonedx.parse(FIXTURES / "syft-demo.cdx.json")
    second = cyclonedx.parse(FIXTURES / "syft-demo.cdx.json")
    assert first.model_dump_json() == second.model_dump_json()


def test_minimal_fixture_parses() -> None:
    inventory = cyclonedx.parse(FIXTURES / "minimal.cdx.json")
    assert len(inventory.components) == 1
    assert inventory.components[0].name == "leftpad"
    assert inventory.components[0].version is None


def test_nested_components_are_flattened() -> None:
    inventory = cyclonedx.parse(FIXTURES / "nested-licenses.cdx.json")
    names = {c.name for c in inventory.components}
    assert names == {"outer", "inner-a", "inner-b", "innermost"}


def test_license_id_name_and_expression_all_extracted() -> None:
    inventory = cyclonedx.parse(FIXTURES / "nested-licenses.cdx.json")
    by_name = {c.name: c for c in inventory.components}
    assert by_name["outer"].licenses == ["MIT"]
    assert by_name["inner-a"].licenses == ["Custom Proprietary License"]
    assert by_name["inner-b"].licenses == ["MIT OR Apache-2.0"]
    assert by_name["innermost"].licenses == []


def test_document_metadata_extracted() -> None:
    inventory = cyclonedx.parse(FIXTURES / "nested-licenses.cdx.json")
    assert inventory.document_name == "demo-app"
    assert inventory.tool == "cdxgen/10.0.0"
    assert inventory.timestamp == "2026-01-01T00:00:00Z"
    assert inventory.format_version == "1.5"


def test_malformed_json_raises_sbom_parse_error_with_context() -> None:
    with pytest.raises(SbomParseError, match="line"):
        cyclonedx.parse(FIXTURES / "malformed.cdx.json")


def test_missing_file_raises_sbom_parse_error() -> None:
    with pytest.raises(SbomParseError):
        cyclonedx.parse(FIXTURES / "does-not-exist.cdx.json")


def test_unknown_top_level_fields_are_ignored(tmp_path: Path) -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "somethingFromTheFuture": {"nested": True},
        "components": [{"type": "library", "name": "ok", "extraneousField": 1}],
    }
    path = tmp_path / "future.cdx.json"
    path.write_text(json.dumps(doc))
    inventory = cyclonedx.parse(path)
    assert inventory.components[0].name == "ok"


@pytest.mark.parametrize("spec_version", ["1.4", "1.5", "1.6"])
def test_supported_spec_versions_all_parse(tmp_path: Path, spec_version: str) -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "components": [{"type": "library", "name": "widget", "version": "1.0.0"}],
    }
    path = tmp_path / "versioned.cdx.json"
    path.write_text(json.dumps(doc))
    inventory = cyclonedx.parse(path)
    assert inventory.format_version == spec_version
    assert inventory.components[0].name == "widget"


def test_bytes_input_is_accepted() -> None:
    raw = (FIXTURES / "minimal.cdx.json").read_bytes()
    inventory = cyclonedx.parse(raw)
    assert inventory.components[0].name == "leftpad"


def test_component_type_mapping(tmp_path: Path) -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"type": "library", "name": "a"},
            {"type": "application", "name": "b"},
            {"type": "operating-system", "name": "c"},
            {"type": "container", "name": "d"},
            {"type": "firmware", "name": "e"},
        ],
    }
    path = tmp_path / "types.cdx.json"
    path.write_text(json.dumps(doc))
    inventory = cyclonedx.parse(path)
    types = {c.name: c.type.value for c in inventory.components}
    assert types == {
        "a": "library",
        "b": "application",
        "c": "os",
        "d": "container",
        "e": "other",
    }
