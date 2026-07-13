"""Covers implementation_plan.md Step 2.5: the flagship `match` command, fully mocked."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from typer.testing import CliRunner

from euvd_watch.cli import app

pytestmark = pytest.mark.e2e

runner = CliRunner()
DEMO = Path(__file__).resolve().parents[2] / "examples" / "sboms" / "demo.cdx.json"
BASE = "https://euvdservices.enisa.europa.eu/api"
EPSS = "https://api.first.org/data/v1/epss"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# One synthetic exploited record that matches the demo SBOM's real jinja2 3.1.6 component
# (product-equal, vendor unknown on the record side, version in range -> medium).
JINJA_RECORD = {
    "id": "EUVD-TEST-0001",
    "description": "Test vulnerability in jinja2 sandbox.",
    "aliases": "CVE-2099-0001\n",
    "exploitedSince": "Jan 1, 2026, 12:00:00 AM",
    "epss": 42.0,
    "enisaIdProduct": [{"product": {"name": "jinja2"}, "product_version": "<3.1.7"}],
}


def _mock_euvd(exploited_items: list[dict[str, Any]]) -> None:
    def route(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("exploited") == "true":
            return httpx.Response(
                200, json={"items": exploited_items, "total": len(exploited_items)}
            )
        return httpx.Response(200, json={"items": [], "total": 0})

    respx.get(f"{BASE}/search").mock(side_effect=route)


def _mock_enrichment() -> None:
    respx.get(EPSS).mock(
        return_value=httpx.Response(200, json={"data": [{"cve": "CVE-2099-0001", "epss": "0.777"}]})
    )
    respx.get(KEV).mock(
        return_value=httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2099-0001"}]})
    )


def _invoke(tmp_path: Path, *args: str) -> Any:
    # Throwaway cache dir per test (no shared state); wide COLUMNS so rich doesn't wrap
    # table cells mid-identifier in the 80-column test terminal.
    return runner.invoke(
        app,
        ["match", str(DEMO), *args],
        env={"EUVD_WATCH_CACHE_DIR": str(tmp_path), "COLUMNS": "300"},
    )


@respx.mock
def test_match_finds_the_seeded_exploited_record(tmp_path: Path) -> None:
    _mock_euvd([JINJA_RECORD])
    _mock_enrichment()
    result = _invoke(tmp_path, "--exploited-only")
    assert result.exit_code == 1  # findings present, default --fail-on any
    assert "EUVD-TEST-0001" in result.output
    assert "1 findings (1 exploited)" in result.output


@respx.mock
def test_no_findings_exits_zero(tmp_path: Path) -> None:
    _mock_euvd([])
    _mock_enrichment()
    result = _invoke(tmp_path, "--exploited-only")
    assert result.exit_code == 0
    assert "0 findings" in result.output


@respx.mock
def test_fail_on_none_exits_zero_despite_findings(tmp_path: Path) -> None:
    _mock_euvd([JINJA_RECORD])
    _mock_enrichment()
    result = _invoke(tmp_path, "--exploited-only", "--fail-on", "none")
    assert result.exit_code == 0
    assert "1 findings" in result.output


@respx.mock
def test_fail_on_exploited(tmp_path: Path) -> None:
    _mock_euvd([JINJA_RECORD])
    _mock_enrichment()
    result = _invoke(tmp_path, "--exploited-only", "--fail-on", "exploited")
    assert result.exit_code == 1


@respx.mock
def test_min_confidence_high_filters_medium_finding(tmp_path: Path) -> None:
    _mock_euvd([JINJA_RECORD])
    _mock_enrichment()
    result = _invoke(tmp_path, "--exploited-only", "--min-confidence", "high")
    assert result.exit_code == 0
    assert "0 findings" in result.output


@respx.mock
def test_json_output_is_a_valid_versioned_artifact(tmp_path: Path) -> None:
    _mock_euvd([JINJA_RECORD])
    _mock_enrichment()
    result = runner.invoke(
        app,
        ["--output", "json", "match", str(DEMO), "--exploited-only"],
        env={"EUVD_WATCH_CACHE_DIR": str(tmp_path)},
    )
    artifact = json.loads(result.stdout)  # stdout must be pure JSON
    assert artifact["schema_version"] == 1
    assert artifact["inventory_digest"].startswith("sha256:")
    assert artifact["generated_at"]
    assert artifact["data_freshness"]
    finding = artifact["findings"][0]
    assert finding["record"]["euvd_id"] == "EUVD-TEST-0001"
    assert finding["confidence"] == "medium"  # vendor unknown on the record side
    assert finding["explanation"]
    assert finding["epss_score"] == pytest.approx(0.777)  # FIRST value, not EUVD's
    assert finding["in_kev"] is True


@respx.mock
def test_pinned_timestamp_makes_json_output_byte_identical(tmp_path: Path) -> None:
    # INV-9 for match (audit finding TECH-003): generated_at was the one uncontrolled
    # field. Same cache dir on purpose - data_freshness must also be stable across runs:
    # since the feedback_m2 2.2 fix it is the oldest EUVD response *served*, which run 2
    # replays from cache with the same stored_at (--no-enrich just keeps the test lean).
    _mock_euvd([JINJA_RECORD])
    args = [
        "--output", "json", "match", str(DEMO),
        "--exploited-only", "--no-enrich", "--fail-on", "none",
        "--timestamp", "2026-01-01T00:00:00+00:00",
    ]
    env = {"EUVD_WATCH_CACHE_DIR": str(tmp_path)}
    first = runner.invoke(app, args, env=env)
    second = runner.invoke(app, args, env=env)
    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    assert json.loads(first.stdout)["generated_at"] == "2026-01-01T00:00:00+00:00"


@respx.mock
def test_save_findings_writes_the_same_artifact(tmp_path: Path) -> None:
    _mock_euvd([JINJA_RECORD])
    _mock_enrichment()
    out = tmp_path / "findings.json"
    result = _invoke(tmp_path, "--exploited-only", "--save-findings", str(out), "--fail-on", "none")
    assert result.exit_code == 0
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert saved["schema_version"] == 1
    assert len(saved["findings"]) == 1


@respx.mock
def test_no_enrich_skips_epss_and_kev_entirely(tmp_path: Path) -> None:
    _mock_euvd([JINJA_RECORD])
    epss_route = respx.get(EPSS).mock(return_value=httpx.Response(200, json={"data": []}))
    kev_route = respx.get(KEV).mock(return_value=httpx.Response(200, json={}))
    result = _invoke(tmp_path, "--exploited-only", "--no-enrich", "--fail-on", "none")
    assert result.exit_code == 0
    assert not epss_route.called
    assert not kev_route.called


@respx.mock
def test_euvd_down_with_no_cache_exits_two_loudly(tmp_path: Path) -> None:
    respx.get(f"{BASE}/search").mock(return_value=httpx.Response(503))
    result = _invoke(tmp_path, "--exploited-only")
    assert result.exit_code == 2
    assert "unreachable" in result.output
    assert "Refusing to report 'no findings'" in result.output


@respx.mock
def test_euvd_403_with_json_body_exits_two_not_zero_findings(tmp_path: Path) -> None:
    # feedback_m2.md finding 1.1: a JSON error body must not be read as "zero results".
    # This is live-plausible - ENISA already auth-gates the /vulnerability endpoint.
    respx.get(f"{BASE}/search").mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
    result = _invoke(tmp_path, "--exploited-only")
    assert result.exit_code == 2
    assert "0 findings" not in result.output
    assert "Refusing to report 'no findings'" in result.output


def test_save_findings_to_unwritable_path_exits_two_not_one(tmp_path: Path) -> None:
    # feedback_m2.md finding 1.2: used to raise FileNotFoundError uncaught (exit 1,
    # traceback). Network isn't reached before the write, so no respx mock needed... but
    # the match pipeline runs first, so mock it anyway to isolate this from EUVD behavior.
    with respx.mock:
        respx.get(f"{BASE}/search").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )
        result = _invoke(
            tmp_path,
            "--exploited-only",
            "--no-enrich",
            "--save-findings",
            "/no/such/dir/findings.json",
        )
    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "I/O error" in result.output


def test_uncreatable_cache_dir_exits_two_not_one() -> None:
    # feedback_m2.md finding 1.3: Cache.__init__'s mkdir used to raise uncaught.
    with respx.mock:
        respx.get(f"{BASE}/search").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )
        result = runner.invoke(
            app,
            ["match", str(DEMO), "--exploited-only", "--no-enrich"],
            env={"EUVD_WATCH_CACHE_DIR": "/proc/definitely-unwritable/cache"},
        )
    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)


@respx.mock
def test_euvd_down_but_fresh_cache_proceeds(tmp_path: Path) -> None:
    # First run populates the cache; second run's network 503s but cache is TTL-fresh.
    _mock_euvd([JINJA_RECORD])
    _mock_enrichment()
    assert _invoke(tmp_path, "--exploited-only", "--fail-on", "none").exit_code == 0

    respx.clear()
    respx.get(f"{BASE}/search").mock(return_value=httpx.Response(503))
    _mock_enrichment()
    result = _invoke(tmp_path, "--exploited-only", "--fail-on", "none")
    assert result.exit_code == 0
    assert "EUVD-TEST-0001" in result.output  # served from cache


@respx.mock
def test_tier2_product_searches_run_without_exploited_only(tmp_path: Path) -> None:
    product_queries: list[str] = []

    def route(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("exploited") == "true":
            return httpx.Response(200, json={"items": [], "total": 0})
        product_queries.append(request.url.params.get("product", ""))
        return httpx.Response(200, json={"items": [], "total": 0})

    respx.get(f"{BASE}/search").mock(side_effect=route)
    _mock_enrichment()
    result = _invoke(tmp_path, "--fail-on", "none")
    assert result.exit_code == 0
    assert "jinja2" in product_queries  # per-candidate searches actually happened
    assert len(product_queries) == len(set(product_queries))  # deduplicated


@respx.mock
def test_tier2_disabled_by_config_sends_no_product_searches(tmp_path: Path) -> None:
    # Privacy toggle (audit finding SEC-004): tier2_product_search=false must mean zero
    # SBOM-derived terms leave the machine - only the tier-1 exploited sync runs.
    product_queries: list[str] = []

    def route(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("exploited") == "true":
            return httpx.Response(200, json={"items": [], "total": 0})
        product_queries.append(request.url.params.get("product", ""))
        return httpx.Response(200, json={"items": [], "total": 0})

    respx.get(f"{BASE}/search").mock(side_effect=route)
    _mock_enrichment()
    result = runner.invoke(
        app,
        ["match", str(DEMO), "--fail-on", "none"],
        env={
            "EUVD_WATCH_CACHE_DIR": str(tmp_path),
            "EUVD_WATCH_TIER2_PRODUCT_SEARCH": "false",
            "COLUMNS": "300",
        },
    )
    assert result.exit_code == 0
    assert product_queries == []
