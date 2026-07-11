"""Covers implementation_plan.md Step 5.4: watch mode end-to-end.

Scenario: first `watch --once` against the demo SBOM reports the known exploited
component as new (exit 1) and persists a snapshot; an identical second run reports zero
notifications (exit 0, test_plan.md 5.4's literal acceptance criterion); a mutated mock
record between two runs is reported as changed, with a webhook receiving exactly one POST.
"""

import json
import shutil
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

JINJA_RECORD = {
    "id": "EUVD-TEST-0001",
    "description": "Test vulnerability in jinja2 sandbox.",
    "aliases": "CVE-2099-0001\n",
    "exploitedSince": "Jan 1, 2026, 12:00:00 AM",
    "enisaIdProduct": [{"product": {"name": "jinja2"}, "product_version": "<3.1.7"}],
}


def _mock_apis(*, epss: str = "0.9") -> None:
    def route(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("exploited") == "true":
            return httpx.Response(200, json={"items": [JINJA_RECORD], "total": 1})
        return httpx.Response(200, json={"items": [], "total": 0})

    respx.get(f"{BASE}/search").mock(side_effect=route)
    respx.get(EPSS).mock(
        return_value=httpx.Response(200, json={"data": [{"cve": "CVE-2099-0001", "epss": epss}]})
    )
    respx.get(KEV).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))


def _env(tmp_path: Path) -> dict[str, str]:
    return {
        "EUVD_WATCH_CACHE_DIR": str(tmp_path / "cache"),
        "EUVD_WATCH_STATE_DIR": str(tmp_path / "state"),
        # A test run of 'two runs of watch, second one sees fresh data' must never
        # cache-hit the first run's HTTP responses (real deployments accept the 24h
        # default staleness window; these tests exercise the differ, not the cache).
        "EUVD_WATCH_CACHE_TTL_HOURS": "0",
        "COLUMNS": "300",
    }


def _watch_json(tmp_path: Path, *extra_args: str) -> Any:
    result = runner.invoke(
        app, ["--output", "json", "watch", str(DEMO), "--once", *extra_args], env=_env(tmp_path)
    )
    return result, (json.loads(result.stdout) if result.stdout else None)


@respx.mock
def test_first_run_reports_new_second_identical_run_reports_nothing(tmp_path: Path) -> None:
    _mock_apis()

    result1, payload1 = _watch_json(tmp_path)
    assert result1.exit_code == 1  # something changed - the CI-gate convention
    assert len(payload1["new"]) == 1
    assert payload1["new"][0]["record"]["euvd_id"] == "EUVD-TEST-0001"
    assert payload1["resolved"] == []
    assert payload1["changed"] == []

    result2, payload2 = _watch_json(tmp_path)
    assert result2.exit_code == 0  # literal test_plan.md 5.4 acceptance criterion
    assert payload2 == {"schema_version": 1, "new": [], "resolved": [], "changed": []}


@respx.mock
def test_changed_epss_between_runs_is_reported_changed(tmp_path: Path) -> None:
    _mock_apis(epss="0.1")
    result1, _ = _watch_json(tmp_path)
    assert result1.exit_code == 1

    # EPSS enrichment caches for a fixed 24h regardless of cache_ttl_hours (by design,
    # separate freshness knob - see enrich/epss.py); drop the cache so the second run's
    # mocked EPSS score is actually re-fetched instead of served from the first run's cache.
    shutil.rmtree(tmp_path / "cache")
    respx.clear()
    _mock_apis(epss="0.95")
    result2, payload2 = _watch_json(tmp_path)
    assert result2.exit_code == 1
    assert payload2["new"] == []
    assert payload2["resolved"] == []
    assert len(payload2["changed"]) == 1
    assert "epss_score" in payload2["changed"][0]["changed_fields"]


@respx.mock
def test_once_and_interval_are_mutually_exclusive(tmp_path: Path) -> None:
    _mock_apis()
    result = runner.invoke(
        app, ["watch", str(DEMO), "--once", "--interval", "1h"], env=_env(tmp_path)
    )
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


@respx.mock
def test_invalid_interval_exits_two(tmp_path: Path) -> None:
    result = runner.invoke(app, ["watch", str(DEMO), "--interval", "bogus"], env=_env(tmp_path))
    assert result.exit_code == 2
    assert "Invalid --interval" in result.output


@respx.mock
def test_webhook_receives_one_post_for_the_new_finding(tmp_path: Path) -> None:
    _mock_apis()
    posts: list[dict[str, Any]] = []
    respx.get(f"{BASE}/search").mock(
        side_effect=lambda r: (
            httpx.Response(200, json={"items": [JINJA_RECORD], "total": 1})
            if r.url.params.get("exploited") == "true"
            else httpx.Response(200, json={"items": [], "total": 0})
        )
    )
    respx.post("https://hooks.example/x").mock(
        side_effect=lambda r: (posts.append(json.loads(r.content)), httpx.Response(200))[1]
    )

    result = runner.invoke(
        app,
        ["watch", str(DEMO), "--once", "--webhook", "https://hooks.example/x"],
        env=_env(tmp_path),
    )
    assert result.exit_code == 1
    assert len(posts) == 1
    assert posts[0]["kind"] == "new"
    assert posts[0]["finding"]["record"]["euvd_id"] == "EUVD-TEST-0001"


@respx.mock
def test_table_output_prints_human_readable_new_marker(tmp_path: Path) -> None:
    _mock_apis()
    result = runner.invoke(app, ["watch", str(DEMO), "--once"], env=_env(tmp_path))
    assert result.exit_code == 1
    assert "[NEW]" in result.output
    assert "EUVD-TEST-0001" in result.output


@respx.mock
def test_interval_loop_runs_one_cycle_then_stops_cleanly_on_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import euvd_watch.cli as cli_module

    _mock_apis()
    calls = {"n": 0}

    def fake_sleep(_seconds: float) -> None:
        calls["n"] += 1
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module.time, "sleep", fake_sleep)
    result = runner.invoke(app, ["watch", str(DEMO), "--interval", "1h"], env=_env(tmp_path))

    assert result.exit_code == 0
    assert calls["n"] == 1  # exactly one cycle ran before the (simulated) Ctrl+C
    assert "Interrupted." in result.output
    assert "[NEW]" in result.output  # the one cycle's notification did fire


@respx.mock
def test_webhook_failure_exits_two_with_a_clear_message(tmp_path: Path) -> None:
    _mock_apis()
    # 403 (not in RETRYABLE_STATUSES) fails immediately - keeps this test fast instead of
    # riding out ApiClient's real exponential backoff for a retryable status.
    respx.post("https://hooks.example/x").mock(return_value=httpx.Response(403))

    result = runner.invoke(
        app,
        ["watch", str(DEMO), "--once", "--webhook", "https://hooks.example/x"],
        env=_env(tmp_path),
    )
    assert result.exit_code == 2
    assert "hooks.example" in result.output
