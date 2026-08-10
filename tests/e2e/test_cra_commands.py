"""Covers implementation_plan.md Step 4.5 and TEST_PLAN scenario S3: the 24-hour story.

seeded exploited finding -> cra check fires exactly one event -> status shows countdowns ->
draft renders with TODO-HUMAN markers -> mark completes -> verify-log passes -> second
cra check is a no-op.
"""

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

# Matches the demo SBOM's real jinja2 3.1.6 component (medium confidence: vendor unknown
# on the record side) and is exploited -> fires the default trigger policy.
JINJA_RECORD = {
    "id": "EUVD-TEST-0001",
    "description": "Test vulnerability in jinja2 sandbox.",
    "aliases": "CVE-2099-0001\n",
    "exploitedSince": "Jan 1, 2026, 12:00:00 AM",
    "enisaIdProduct": [{"product": {"name": "jinja2"}, "product_version": "<3.1.7"}],
}


def _mock_apis() -> None:
    def route(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("exploited") == "true":
            return httpx.Response(200, json={"items": [JINJA_RECORD], "total": 1})
        return httpx.Response(200, json={"items": [], "total": 0})

    respx.get(f"{BASE}/search").mock(side_effect=route)
    respx.get(EPSS).mock(
        return_value=httpx.Response(200, json={"data": [{"cve": "CVE-2099-0001", "epss": "0.9"}]})
    )
    respx.get(KEV).mock(
        return_value=httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2099-0001"}]})
    )


def _env(tmp_path: Path, *, with_org: bool = True) -> dict[str, str]:
    env = {
        "EUVD_WATCH_CACHE_DIR": str(tmp_path / "cache"),
        "EUVD_WATCH_STATE_DIR": str(tmp_path / "state"),
        "COLUMNS": "300",
    }
    if with_org:
        env.update(
            {
                "EUVD_WATCH_ORGANIZATION__NAME": "Exemplu S.R.L.",
                "EUVD_WATCH_ORGANIZATION__CONTACT_EMAIL": "sec@exemplu.ro",
                "EUVD_WATCH_ORGANIZATION__PRODUCT_NAME": "Produsul",
            }
        )
    return env


def _check_json(tmp_path: Path) -> Any:
    result = runner.invoke(
        app, ["--output", "json", "cra", "check", str(DEMO)], env=_env(tmp_path)
    )
    return result, (json.loads(result.stdout) if result.stdout else None)


@respx.mock
def test_scenario_s3_the_24_hour_story(tmp_path: Path) -> None:
    _mock_apis()
    env = _env(tmp_path)

    # 1. check fires exactly one NEW event -> exit 1 (the CI gate for "something opened").
    result, payload = _check_json(tmp_path)
    assert result.exit_code == 1
    assert payload["new_events"] == 1
    assert len(payload["events"]) == 1
    event = payload["events"][0]
    event_id = event["event_id"]
    assert event["fired_rules"] == ["euvd_exploited", "cisa_kev", "epss_over_threshold"]
    first_seen = event["first_seen"]

    # 2. second check is idempotent: same event, nothing new, exit 0, first_seen unchanged.
    result2, payload2 = _check_json(tmp_path)
    assert result2.exit_code == 0
    assert payload2["new_events"] == 0
    assert payload2["events"][0]["event_id"] == event_id
    assert payload2["events"][0]["first_seen"] == first_seen

    # 3. status shows one open event with a countdown per configured stage.
    status = runner.invoke(app, ["cra", "status"], env=env)
    assert status.exit_code == 0
    assert "1 open event(s)" in status.output
    for stage in ("early_warning", "vulnerability_notification", "final_report"):
        assert stage in status.output
    assert "awaiting anchor" in status.output  # final_report has no deadline yet

    # 4. draft renders prefilled, with unmissable human-judgment markers.
    draft = runner.invoke(app, ["cra", "draft", event_id], env=env)
    assert draft.exit_code == 0
    assert "TODO-HUMAN" in draft.output
    assert "EUVD-TEST-0001" in draft.output
    assert "has NOT submitted anything" in draft.output

    # 5. human marks: remediation available, then every stage completed.
    mark = runner.invoke(
        app,
        ["cra", "mark", event_id, "--remediation-available", "--note", "fix shipped"],
        env=env,
    )
    assert mark.exit_code == 0
    for stage in ("early_warning", "vulnerability_notification", "final_report"):
        done = runner.invoke(
            app, ["cra", "mark", event_id, "--stage", stage, "--note", "filed"], env=env
        )
        assert done.exit_code == 0

    closed = runner.invoke(app, ["cra", "status"], env=env)
    assert "0 open event(s) of 1 total" in closed.output

    # 6. the audit trail of all of the above verifies end-to-end.
    verify = runner.invoke(app, ["cra", "verify-log"], env=env)
    assert verify.exit_code == 0
    assert "chain intact" in verify.output
    log_path = tmp_path / "state" / "cra-audit.jsonl"
    actions = [json.loads(line)["action"] for line in log_path.read_text("utf-8").splitlines()]
    assert actions[0] == "trigger_event_created"
    assert "draft_rendered" in actions
    assert "remediation_marked" in actions
    assert actions.count("stage_marked") == 3


@respx.mock
def test_tampered_audit_log_fails_verify_log_with_exit_one(tmp_path: Path) -> None:
    _mock_apis()
    _check_json(tmp_path)  # creates one event + one audit entry
    log_path = tmp_path / "state" / "cra-audit.jsonl"
    tampered = log_path.read_text("utf-8").replace("euvd_exploited", "euvd_EXPLOITED")
    log_path.write_text(tampered, encoding="utf-8")

    result = runner.invoke(app, ["cra", "verify-log"], env=_env(tmp_path))
    assert result.exit_code == 1
    assert "line 1" in result.output


@respx.mock
def test_check_with_saved_findings_artifact_is_equivalent(tmp_path: Path) -> None:
    _mock_apis()
    artifact = tmp_path / "findings.json"
    matched = runner.invoke(
        app,
        ["match", str(DEMO), "--save-findings", str(artifact), "--fail-on", "none"],
        env=_env(tmp_path),
    )
    assert matched.exit_code == 0

    result = runner.invoke(
        app,
        ["--output", "json", "cra", "check", str(DEMO), "--findings", str(artifact)],
        env=_env(tmp_path),
    )
    assert result.exit_code == 1  # same event fires from the replayed artifact
    payload = json.loads(result.stdout)
    assert payload["new_events"] == 1
    assert payload["events"][0]["fired_rules"] == [
        "euvd_exploited",
        "cisa_kev",
        "epss_over_threshold",
    ]


@respx.mock
def test_draft_without_org_config_exits_two_naming_the_fields(tmp_path: Path) -> None:
    _mock_apis()
    env_no_org = _env(tmp_path, with_org=False)
    result = runner.invoke(
        app, ["--output", "json", "cra", "check", str(DEMO)], env=env_no_org
    )
    event_id = json.loads(result.stdout)["events"][0]["event_id"]

    draft = runner.invoke(app, ["cra", "draft", event_id], env=env_no_org)
    assert draft.exit_code == 2
    assert "organization.name" in draft.output


@respx.mock
def test_mark_and_draft_argument_errors_exit_two(tmp_path: Path) -> None:
    _mock_apis()
    env = _env(tmp_path)
    assert runner.invoke(app, ["cra", "draft", "no-such-event"], env=env).exit_code == 2
    assert runner.invoke(app, ["cra", "mark", "x"], env=env).exit_code == 2  # nothing to record
    result = runner.invoke(app, ["cra", "mark", "x", "--stage", "bogus"], env=env)
    assert result.exit_code == 2
    assert "early_warning" in result.output  # lists the valid stage names


# A NON-exploited jinja2 record (no exploitedSince) returned by product search (tier 2),
# used to exercise the trigger without euvd_exploited firing.
NONEXPLOITED_JINJA = {
    "id": "EUVD-TEST-0002",
    "description": "Non-exploited jinja2 finding for indeterminacy tests.",
    "aliases": "CVE-2099-0002\n",
    "enisaIdProduct": [{"product": {"name": "jinja2"}, "product_version": "<3.1.7"}],
}


def _mock_apis_kev_unavailable() -> None:
    """No exploited catalog; product search returns a non-exploited jinja2 record; EPSS
    below threshold; KEV feed returns a malformed body -> ApiError -> KEV unavailable
    (fast: a 200 body is not retried)."""

    def route(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("exploited") == "true":
            return httpx.Response(200, json={"items": [], "total": 0})
        return httpx.Response(200, json={"items": [NONEXPLOITED_JINJA], "total": 1})

    respx.get(f"{BASE}/search").mock(side_effect=route)
    respx.get(EPSS).mock(
        return_value=httpx.Response(200, json={"data": [{"cve": "CVE-2099-0002", "epss": "0.10"}]})
    )
    respx.get(KEV).mock(return_value=httpx.Response(200, json={"broken": "not a kev catalog"}))


@respx.mock
def test_cra_check_exits_indeterminate_when_a_required_signal_source_is_unavailable(
    tmp_path: Path,
) -> None:
    """Audit follow-up: a required trigger signal (KEV) being UNAVAILABLE must not read as
    a clean all-clear. The finding didn't fire euvd_exploited (not exploited) or EPSS
    (below threshold), and KEV couldn't be checked -> indeterminate -> exit 3, loudly."""
    _mock_apis_kev_unavailable()
    result = runner.invoke(
        app, ["--output", "json", "cra", "check", str(DEMO)], env=_env(tmp_path)
    )
    assert result.exit_code == 3, result.output
    assert "INDETERMINATE" in result.stderr
    assert "cisa_kev" in result.stderr
    payload = json.loads(result.stdout)
    assert payload["new_events"] == 0
    assert payload["unavailable_signals"] == ["cisa_kev"]
    assert len(payload["indeterminate"]) >= 1
    assert payload["indeterminate"][0]["unknown_signals"] == ["cisa_kev"]


def _findings_artifact(tmp_path: Path) -> Path:
    """A crafted findings artifact with one exploited finding (will fire euvd_exploited)
    and one non-exploited finding carrying no KEV/EPSS data (in_kev/epss null -> those
    sources read as unavailable -> that finding is indeterminate). Deterministic: it
    doesn't depend on live matching or the demo SBOM's contents."""
    from euvd_watch.euvd.match import Confidence, Finding, Strategy
    from euvd_watch.euvd.models import EuvdRecord
    from euvd_watch.models import Component, SourceFormat

    def _finding(name: str, euvd_id: str, exploited: bool) -> Finding:
        return Finding(
            component=Component(
                name=name, version="1.0.0", source_format=SourceFormat.CYCLONEDX, raw_ref="r"
            ),
            record=EuvdRecord(euvd_id=euvd_id, exploited=exploited),
            confidence=Confidence.HIGH,
            strategy=Strategy.STRUCTURED,
            explanation="x",
        )

    artifact = tmp_path / "findings.json"
    artifact.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "findings": [
                    _finding("exploited-pkg", "EUVD-A", True).model_dump(mode="json"),
                    _finding("quiet-pkg", "EUVD-B", False).model_dump(mode="json"),
                ],
            }
        ),
        encoding="utf-8",
    )
    return artifact


def test_cra_check_new_event_takes_precedence_over_indeterminate(tmp_path: Path) -> None:
    """When a real event fires AND other findings are indeterminate, the confirmed new
    event (exit 1) dominates the indeterminate exit (3) - but the indeterminacy is still
    surfaced loudly on stderr so it is never silently lost."""
    artifact = _findings_artifact(tmp_path)
    result = runner.invoke(
        app,
        ["--output", "json", "cra", "check", str(DEMO), "--findings", str(artifact)],
        env=_env(tmp_path),
    )
    assert result.exit_code == 1, result.output  # new event dominates
    assert "INDETERMINATE" in result.stderr  # but the indeterminacy is still surfaced
    payload = json.loads(result.stdout)
    assert payload["new_events"] == 1
    assert len(payload["indeterminate"]) >= 1
