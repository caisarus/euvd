"""Covers implementation_plan.md Step 1.5: the first user-visible promise.

Also covers the README quickstart's `euvd-watch scan <sbom>` line running verbatim.
"""

import time
from pathlib import Path

from typer.testing import CliRunner

from euvd_watch.cli import app

runner = CliRunner()
DEMO = Path(__file__).resolve().parents[2] / "examples" / "sboms" / "demo.cdx.json"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sboms"
GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "golden" / "scan-demo.inventory.json"


def test_readme_quickstart_scan_line_runs_verbatim() -> None:
    # README quickstart: `euvd-watch scan sbom.json`
    result = runner.invoke(app, ["scan", str(DEMO)])
    assert result.exit_code == 0


def test_table_output_contains_expected_component_rows() -> None:
    result = runner.invoke(app, ["scan", str(DEMO)])
    assert result.exit_code == 0
    assert "annotated-doc" in result.output
    assert "euvd-watch" in result.output
    assert "pydantic" in result.output


def test_json_output_matches_golden_and_is_pure_json_on_stdout() -> None:
    result = runner.invoke(app, ["--output", "json", "scan", str(DEMO)])
    assert result.exit_code == 0
    golden = GOLDEN.read_text().rstrip("\n")
    assert result.stdout.rstrip("\n") == golden


def test_summary_line_counts_are_exact() -> None:
    result = runner.invoke(app, ["scan", str(DEMO)])
    assert "70 components (0 deduplicated, 0 with synthesized identifiers)" in result.output


def test_malformed_sbom_exits_two() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "malformed.cdx.json")])
    assert result.exit_code == 2


def test_missing_file_exits_two() -> None:
    result = runner.invoke(app, ["scan", "/no/such/file.json"])
    assert result.exit_code == 2


def test_valid_json_but_unsupported_format_exits_two() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "valid-json-not-sbom.json")])
    assert result.exit_code == 2


def test_spdx_input_also_works() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "github-export.spdx.json")])
    assert result.exit_code == 0
    assert "105 components" in result.output


def test_scan_completes_within_performance_budget() -> None:
    start = time.monotonic()
    result = runner.invoke(app, ["scan", str(DEMO)])
    elapsed = time.monotonic() - start
    assert result.exit_code == 0
    assert elapsed < 2.0
