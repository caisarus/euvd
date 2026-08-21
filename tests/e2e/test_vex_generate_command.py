"""Covers implementation_plan.md Step 3.4: the `vex generate`/`vex init-decisions` commands."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import yaml
from typer.testing import CliRunner

from euvd_watch.cli import app

pytestmark = pytest.mark.e2e

runner = CliRunner()
DEMO = Path(__file__).resolve().parents[2] / "examples" / "sboms" / "demo.cdx.json"
BASE = "https://euvdservices.enisa.europa.eu/api"
TIMESTAMP = "2026-01-01T00:00:00Z"

# jinja2 3.1.6 is real in the demo SBOM. This record's range excludes it -> NOT_AFFECTED.
NOT_AFFECTED_RECORD = {
    "id": "EUVD-TEST-0001",
    "aliases": "CVE-2099-0001\n",
    "enisaIdProduct": [{"product": {"name": "jinja2"}, "product_version": "<3.1.6"}],
}
# This record's range includes jinja2 3.1.6 -> MATCH -> stays under_investigation.
MATCH_RECORD = {
    "id": "EUVD-TEST-0002",
    "aliases": "CVE-2099-0002\n",
    "enisaIdProduct": [{"product": {"name": "jinja2"}, "product_version": "<3.9.9"}],
}


def _mock_search(items: list[dict[str, Any]]) -> None:
    respx.get(f"{BASE}/search").mock(
        return_value=httpx.Response(200, json={"items": items, "total": len(items)})
    )


def _generate(tmp_path: Path, *args: str) -> Any:
    return runner.invoke(
        app,
        ["vex", "generate", str(DEMO), *args],
        env={"EUVD_WATCH_CACHE_DIR": str(tmp_path), "COLUMNS": "300"},
    )


@respx.mock
def test_full_pipeline_drafts_not_affected_with_evidence(
    tmp_path: Path, validate_openvex: Any
) -> None:
    _mock_search([NOT_AFFECTED_RECORD])
    result = _generate(tmp_path, "--timestamp", TIMESTAMP)
    assert result.exit_code == 0
    assert "1 auto-drafted not_affected" in result.output


@respx.mock
def test_json_output_is_pure_and_schema_valid(tmp_path: Path, validate_openvex: Any) -> None:
    _mock_search([NOT_AFFECTED_RECORD])
    result = runner.invoke(
        app,
        ["--output", "json", "vex", "generate", str(DEMO), "--timestamp", TIMESTAMP],
        env={"EUVD_WATCH_CACHE_DIR": str(tmp_path)},
    )
    assert result.exit_code == 0
    document = json.loads(result.stdout)  # stdout must be pure JSON
    validate_openvex(document)
    assert document["timestamp"] == TIMESTAMP
    assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
    statuses = {s["status"] for s in document["statements"]}
    assert "not_affected" in statuses


@respx.mock
def test_match_outcome_stays_under_investigation(tmp_path: Path, validate_openvex: Any) -> None:
    _mock_search([MATCH_RECORD])
    result = runner.invoke(
        app,
        ["--output", "json", "vex", "generate", str(DEMO), "--timestamp", TIMESTAMP],
        env={"EUVD_WATCH_CACHE_DIR": str(tmp_path)},
    )
    document = json.loads(result.stdout)
    validate_openvex(document)
    statuses = {s["status"] for s in document["statements"]}
    assert statuses == {"under_investigation"}


@respx.mock
def test_out_writes_file_and_stdout_stays_clean(tmp_path: Path, validate_openvex: Any) -> None:
    _mock_search([NOT_AFFECTED_RECORD])
    out = tmp_path / "doc.json"
    result = _generate(tmp_path, "--timestamp", TIMESTAMP, "--out", str(out))
    assert result.exit_code == 0
    assert out.exists()
    validate_openvex(out.read_text(encoding="utf-8"))


@respx.mock
def test_determinism_two_runs_identical_bytes_given_pinned_timestamp(tmp_path: Path) -> None:
    _mock_search([NOT_AFFECTED_RECORD, MATCH_RECORD])
    out1, out2 = tmp_path / "a.json", tmp_path / "b.json"
    r1 = _generate(tmp_path, "--timestamp", TIMESTAMP, "--out", str(out1))
    r2 = _generate(tmp_path, "--timestamp", TIMESTAMP, "--out", str(out2))
    assert r1.exit_code == r2.exit_code == 0
    assert out1.read_text(encoding="utf-8") == out2.read_text(encoding="utf-8")


@respx.mock
def test_decisions_file_overrides_and_reports_counts(tmp_path: Path) -> None:
    _mock_search([MATCH_RECORD])
    decisions_path = tmp_path / "vex-decisions.yaml"
    decisions_path.write_text(
        yaml.safe_dump(
            {
                "decisions": [
                    {
                        "euvd_id": "EUVD-TEST-0002",
                        "purl": "pkg:pypi/jinja2",
                        "status": "affected",
                        "statement": "Confirmed exploitable here.",
                        "author": "a@example.com",
                        "date": "2026-01-01",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = _generate(tmp_path, "--timestamp", TIMESTAMP, "--decisions", str(decisions_path))
    assert result.exit_code == 0
    assert "'affected': 1" in result.output


def _conflicting_decisions_file(tmp_path: Path) -> Path:
    # Human says not_affected while automation independently finds a MATCH -> conflict.
    decisions_path = tmp_path / "vex-decisions.yaml"
    decisions_path.write_text(
        yaml.safe_dump(
            {
                "decisions": [
                    {
                        "euvd_id": "EUVD-TEST-0002",
                        "purl": "pkg:pypi/jinja2",
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_in_execute_path",
                        "statement": "We never render untrusted templates.",
                        "author": "a@example.com",
                        "date": "2026-01-01",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return decisions_path


@respx.mock
def test_conflict_without_flag_still_exits_zero(tmp_path: Path) -> None:
    _mock_search([MATCH_RECORD])
    decisions_path = _conflicting_decisions_file(tmp_path)
    result = _generate(tmp_path, "--timestamp", TIMESTAMP, "--decisions", str(decisions_path))
    assert result.exit_code == 0
    assert "1 conflicts" in result.output


@respx.mock
def test_fail_on_conflict_exits_one_but_still_writes_the_document(
    tmp_path: Path, validate_openvex: Any
) -> None:
    # Owner decision 2026-07-10 (audit REQ-VEX-004): a CI gate for human-vs-automation
    # conflicts. The gate must never suppress the document itself.
    _mock_search([MATCH_RECORD])
    decisions_path = _conflicting_decisions_file(tmp_path)
    out = tmp_path / "doc.json"
    result = _generate(
        tmp_path,
        "--timestamp",
        TIMESTAMP,
        "--decisions",
        str(decisions_path),
        "--out",
        str(out),
        "--fail-on-conflict",
    )
    assert result.exit_code == 1
    assert out.exists()
    validate_openvex(out.read_text(encoding="utf-8"))
    assert "1 conflicts" in result.output


@respx.mock
def test_fail_on_conflict_without_conflicts_exits_zero(tmp_path: Path) -> None:
    _mock_search([MATCH_RECORD])
    result = _generate(tmp_path, "--timestamp", TIMESTAMP, "--fail-on-conflict")
    assert result.exit_code == 0


@respx.mock
def test_stale_decision_is_reported_in_summary(tmp_path: Path) -> None:
    _mock_search([MATCH_RECORD])
    decisions_path = tmp_path / "vex-decisions.yaml"
    decisions_path.write_text(
        yaml.safe_dump(
            {
                "decisions": [
                    {
                        "euvd_id": "EUVD-NO-SUCH-RECORD",
                        "purl": "pkg:pypi/nothing",
                        "status": "not_affected",
                        "justification": "component_not_present",
                        "statement": "doesn't apply",
                        "author": "a@example.com",
                        "date": "2026-01-01",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = _generate(tmp_path, "--timestamp", TIMESTAMP, "--decisions", str(decisions_path))
    assert result.exit_code == 0
    assert "1 stale decisions" in result.output


@respx.mock
def test_findings_fast_path_never_auto_drafts_not_affected(
    tmp_path: Path, validate_openvex: Any
) -> None:
    # The design decision (M3 plan): a saved findings artifact carries no NOT_AFFECTED
    # evidence, so the fast path is conservative-only by construction.
    _mock_search([NOT_AFFECTED_RECORD, MATCH_RECORD])
    findings_path = tmp_path / "findings.json"
    match_result = runner.invoke(
        app,
        [
            "match",
            str(DEMO),
            "--no-enrich",
            "--fail-on",
            "none",
            "--save-findings",
            str(findings_path),
        ],
        env={"EUVD_WATCH_CACHE_DIR": str(tmp_path)},
    )
    assert match_result.exit_code == 0

    result = runner.invoke(
        app,
        [
            "--output",
            "json",
            "vex",
            "generate",
            str(DEMO),
            "--findings",
            str(findings_path),
            "--timestamp",
            TIMESTAMP,
        ],
        env={"EUVD_WATCH_CACHE_DIR": str(tmp_path)},
    )
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    validate_openvex(document)
    assert "not_affected" not in {s["status"] for s in document["statements"]}


@respx.mock
def test_findings_and_full_pipeline_are_equivalent_when_no_not_affected_evidence_exists(
    tmp_path: Path,
) -> None:
    # test_plan.md's literal "equivalence test" ask holds exactly where the sign-off-
    # approved design allows it: when nothing in the mocked catalog is eligible for
    # not_affected, --findings and the full pipeline must agree (both produce the same
    # under_investigation statements). Where not_affected evidence *does* exist, the two
    # paths intentionally diverge - see test_findings_fast_path_never_auto_drafts_not_affected
    # and docs/matching.md's design note.
    _mock_search([MATCH_RECORD])
    findings_path = tmp_path / "findings.json"
    assert (
        runner.invoke(
            app,
            [
                "match",
                str(DEMO),
                "--no-enrich",
                "--fail-on",
                "none",
                "--save-findings",
                str(findings_path),
            ],
            env={"EUVD_WATCH_CACHE_DIR": str(tmp_path)},
        ).exit_code
        == 0
    )

    full = runner.invoke(
        app,
        ["--output", "json", "vex", "generate", str(DEMO), "--timestamp", TIMESTAMP],
        env={"EUVD_WATCH_CACHE_DIR": str(tmp_path)},
    )
    fast = runner.invoke(
        app,
        [
            "--output",
            "json",
            "vex",
            "generate",
            str(DEMO),
            "--findings",
            str(findings_path),
            "--timestamp",
            TIMESTAMP,
        ],
        env={"EUVD_WATCH_CACHE_DIR": str(tmp_path)},
    )
    assert full.stdout == fast.stdout


@respx.mock
def test_init_decisions_scaffold_round_trips_through_the_validator(tmp_path: Path) -> None:
    _mock_search([NOT_AFFECTED_RECORD])
    out = tmp_path / "scaffold.yaml"
    result = runner.invoke(
        app,
        ["vex", "init-decisions", str(DEMO), "--out", str(out)],
        env={"EUVD_WATCH_CACHE_DIR": str(tmp_path)},
    )
    assert result.exit_code == 0
    from euvd_watch.vex.decisions import load_decisions

    scaffold = load_decisions(out)  # must validate cleanly
    assert len(scaffold.decisions) >= 1
    assert all(e.status.value == "under_investigation" for e in scaffold.decisions)


def test_malformed_sbom_exits_two(tmp_path: Path) -> None:
    bad = tmp_path / "bad.cdx.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(
        app,
        ["vex", "generate", str(bad), "--timestamp", TIMESTAMP],
        env={"EUVD_WATCH_CACHE_DIR": str(tmp_path)},
    )
    assert result.exit_code == 2


@respx.mock
def test_malformed_findings_artifact_exits_two(tmp_path: Path) -> None:
    bad = tmp_path / "bad-findings.json"
    bad.write_text("not json at all", encoding="utf-8")
    result = _generate(tmp_path, "--findings", str(bad))
    assert result.exit_code == 2


@respx.mock
def test_findings_artifact_wrong_schema_version_exits_two(tmp_path: Path) -> None:
    # feedback_m3.md finding 3.2: schema_version was never checked.
    bad = tmp_path / "wrong-version-findings.json"
    bad.write_text(json.dumps({"schema_version": 2, "findings": []}), encoding="utf-8")
    result = _generate(tmp_path, "--findings", str(bad))
    assert result.exit_code == 2
    assert "schema_version" in result.output


@respx.mock
def test_document_id_changes_when_underlying_data_changes(tmp_path: Path) -> None:
    # feedback_m3.md finding 1.2: two runs over the same SBOM with genuinely different
    # EUVD data must not collide on document @id. Separate cache dirs per run - same dir
    # would serve the first run's cached (empty) response to the second call, exactly the
    # cache-first behavior test_euvd_down_but_fresh_cache_proceeds (M2) relies on.
    _mock_search([])
    empty_out = tmp_path / "empty.json"
    assert (
        _generate(tmp_path / "cache1", "--timestamp", TIMESTAMP, "--out", str(empty_out)).exit_code
        == 0
    )

    respx.clear()
    _mock_search([NOT_AFFECTED_RECORD])
    with_findings_out = tmp_path / "with-findings.json"
    assert (
        _generate(
            tmp_path / "cache2", "--timestamp", TIMESTAMP, "--out", str(with_findings_out)
        ).exit_code
        == 0
    )

    empty_doc = json.loads(empty_out.read_text(encoding="utf-8"))
    filled_doc = json.loads(with_findings_out.read_text(encoding="utf-8"))
    assert empty_doc["@id"] != filled_doc["@id"]


@respx.mock
def test_malformed_decisions_file_exits_two(tmp_path: Path) -> None:
    _mock_search([])
    bad = tmp_path / "bad-decisions.yaml"
    bad.write_text("decisions:\n  - purl: pkg:pypi/x\n    status: not_affected\n", encoding="utf-8")
    result = _generate(tmp_path, "--decisions", str(bad))
    assert result.exit_code == 2


@respx.mock
def test_euvd_down_with_no_cache_exits_two(tmp_path: Path) -> None:
    respx.get(f"{BASE}/search").mock(return_value=httpx.Response(503))
    result = _generate(tmp_path)
    assert result.exit_code == 2
    assert "unreachable" in result.output
