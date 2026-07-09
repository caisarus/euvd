"""Covers implementation_plan.md Step 1.3: format detection matrix + cross-format parity.

The parity test is the proof the M2 matcher can be format-blind: the same logical package,
described in CycloneDX and in SPDX, must parse to equal Components (minus the two fields that
are inherently format-specific: source_format and raw_ref).
"""

from pathlib import Path

import pytest

from euvd_watch.models import SourceFormat
from euvd_watch.sbom import cyclonedx, spdx
from euvd_watch.sbom._load import load_json
from euvd_watch.sbom.detect import detect_format, parse_any
from euvd_watch.sbom.errors import SbomParseError, UnsupportedFormatError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sboms"


def test_detects_cyclonedx() -> None:
    data, _ = load_json(FIXTURES / "minimal.cdx.json")
    assert detect_format(data) is SourceFormat.CYCLONEDX


def test_detects_spdx() -> None:
    data, _ = load_json(FIXTURES / "minimal.spdx.json")
    assert detect_format(data) is SourceFormat.SPDX


def test_garbage_raises_sbom_parse_error() -> None:
    with pytest.raises(SbomParseError):
        parse_any(FIXTURES / "garbage.json")


def test_empty_file_raises_sbom_parse_error() -> None:
    with pytest.raises(SbomParseError):
        parse_any(FIXTURES / "empty.json")


def test_valid_json_but_neither_format_raises_unsupported_format_error() -> None:
    with pytest.raises(UnsupportedFormatError):
        parse_any(FIXTURES / "valid-json-not-sbom.json")


def test_parse_any_routes_cyclonedx_correctly() -> None:
    via_detect = parse_any(FIXTURES / "minimal.cdx.json")
    via_direct = cyclonedx.parse(FIXTURES / "minimal.cdx.json")
    assert via_detect.model_dump_json() == via_direct.model_dump_json()


def test_parse_any_routes_spdx_correctly() -> None:
    via_detect = parse_any(FIXTURES / "minimal.spdx.json")
    via_direct = spdx.parse(FIXTURES / "minimal.spdx.json")
    assert via_detect.model_dump_json() == via_direct.model_dump_json()


def test_same_logical_package_parses_equal_across_formats() -> None:
    cdx_inventory = cyclonedx.parse(FIXTURES / "parity.cdx.json")
    spdx_inventory = spdx.parse(FIXTURES / "parity.spdx.json")

    assert len(cdx_inventory.components) == len(spdx_inventory.components) == 1
    cdx_component = cdx_inventory.components[0]
    spdx_component = spdx_inventory.components[0]

    format_agnostic_fields = {"source_format", "raw_ref"}
    cdx_dump = cdx_component.model_dump(exclude=format_agnostic_fields)
    spdx_dump = spdx_component.model_dump(exclude=format_agnostic_fields)
    assert cdx_dump == spdx_dump
