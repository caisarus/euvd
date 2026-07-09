"""Covers implementation_plan.md Step 1.3: SPDX format routing and semantic parity."""

from pathlib import Path

import pytest

from euvd_watch.sbom import spdx
from euvd_watch.sbom.errors import SbomParseError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sboms"
GOLDEN = (
    Path(__file__).resolve().parents[1] / "fixtures" / "golden" / "github-export.inventory.json"
)


def test_real_github_export_fixture_matches_golden_byte_for_byte() -> None:
    inventory = spdx.parse(FIXTURES / "github-export.spdx.json")
    golden = GOLDEN.read_text().rstrip("\n")
    assert inventory.model_dump_json(indent=2) == golden


def test_parsing_is_deterministic_across_runs() -> None:
    first = spdx.parse(FIXTURES / "github-export.spdx.json")
    second = spdx.parse(FIXTURES / "github-export.spdx.json")
    assert first.model_dump_json() == second.model_dump_json()


def test_minimal_fixture_parses() -> None:
    inventory = spdx.parse(FIXTURES / "minimal.spdx.json")
    assert len(inventory.components) == 1
    assert inventory.components[0].name == "leftpad"
    assert inventory.components[0].licenses == []  # NOASSERTION is skipped


def test_purl_and_cpe23type_external_refs_extracted() -> None:
    inventory = spdx.parse(FIXTURES / "cpe-ref.spdx.json")
    component = inventory.components[0]
    assert component.name == "openssl"
    assert component.cpe == "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"


def test_document_metadata_extracted() -> None:
    inventory = spdx.parse(FIXTURES / "minimal.spdx.json")
    assert inventory.document_name == "minimal-doc"
    assert inventory.tool == "example-tool-1.0.0"
    assert inventory.timestamp == "2026-01-01T00:00:00Z"
    assert inventory.format_version == "SPDX-2.3"


def test_malformed_json_raises_sbom_parse_error_with_context() -> None:
    with pytest.raises(SbomParseError, match="line"):
        spdx.parse(FIXTURES / "malformed.spdx.json")


def test_missing_file_raises_sbom_parse_error() -> None:
    with pytest.raises(SbomParseError):
        spdx.parse(FIXTURES / "does-not-exist.spdx.json")
