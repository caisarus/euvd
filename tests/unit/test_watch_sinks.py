"""Covers implementation_plan.md Step 5.4: notification sinks.

test_plan.md 5.4: webhook payload schema (snapshotted below) and "respx-intercepted
webhook receives exactly one POST per changed finding".
"""

import json
from pathlib import Path

import httpx
import pytest

from euvd_watch.euvd.match import Confidence, Finding, Strategy
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.http import ApiClient
from euvd_watch.models import Component, SourceFormat
from euvd_watch.watch.differ import ChangedFinding, DiffResult
from euvd_watch.watch.sinks import StdoutSink, WebhookSink

pytestmark = pytest.mark.unit


def _finding(name: str = "widget", euvd_id: str = "EUVD-1") -> Finding:
    component = Component(
        name=name, version="1.0.0", source_format=SourceFormat.CYCLONEDX, raw_ref="r"
    )
    record = EuvdRecord(euvd_id=euvd_id, exploited=True)
    return Finding(
        component=component,
        record=record,
        confidence=Confidence.HIGH,
        strategy=Strategy.STRUCTURED,
        explanation="x",
    )


def _client(handler, tmp_path: Path) -> ApiClient:  # type: ignore[no-untyped-def]
    return ApiClient(
        cache_dir=tmp_path, transport=httpx.MockTransport(handler), sleep=lambda _s: None
    )


def test_stdout_sink_prints_one_line_per_new_resolved_changed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    new = _finding("widget", "EUVD-1")
    resolved = _finding("gadget", "EUVD-2")
    changed = ChangedFinding(
        previous=_finding("thing", "EUVD-3"),
        current=_finding("thing", "EUVD-3"),
        changed_fields=["confidence"],
    )
    diff = DiffResult(new=[new], resolved=[resolved], changed=[changed])

    StdoutSink().notify(diff, sbom="/sboms/demo.json", generated_at="2026-01-01T00:00:00+00:00")

    out = capsys.readouterr().out
    assert "[NEW] widget 1.0.0 - EUVD-1 (high)" in out
    assert "[RESOLVED] gadget 1.0.0 - EUVD-2" in out
    assert "[CHANGED] thing 1.0.0 - EUVD-3 (confidence)" in out


def test_stdout_sink_prints_nothing_for_an_empty_diff(
    capsys: pytest.CaptureFixture[str],
) -> None:
    StdoutSink().notify(
        DiffResult(new=[], resolved=[], changed=[]),
        sbom="x",
        generated_at="2026-01-01T00:00:00+00:00",
    )
    assert capsys.readouterr().out == ""


def test_webhook_sink_posts_exactly_one_request_per_changed_finding(tmp_path: Path) -> None:
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200)

    api = _client(handler, tmp_path)
    diff = DiffResult(
        new=[_finding("widget", "EUVD-1")],
        resolved=[_finding("gadget", "EUVD-2")],
        changed=[
            ChangedFinding(
                previous=_finding("thing", "EUVD-3"),
                current=_finding("thing", "EUVD-3"),
                changed_fields=["epss_score"],
            )
        ],
    )

    WebhookSink(api, "https://hooks.example/x").notify(
        diff, sbom="/sboms/demo.json", generated_at="2026-01-01T00:00:00+00:00"
    )

    assert len(requests) == 3  # exactly one POST per new/resolved/changed finding
    kinds = {r["kind"] for r in requests}
    assert kinds == {"new", "resolved", "changed"}
    api.close()


def test_webhook_payload_schema(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(200)

    api = _client(handler, tmp_path)
    changed = ChangedFinding(
        previous=_finding("thing", "EUVD-3"), current=_finding("thing", "EUVD-3"),
        changed_fields=["epss_score"],
    )
    diff = DiffResult(new=[], resolved=[], changed=[changed])

    WebhookSink(api, "https://hooks.example/x").notify(
        diff, sbom="/sboms/demo.json", generated_at="2026-01-01T00:00:00+00:00"
    )

    assert captured["schema_version"] == 1
    assert captured["kind"] == "changed"
    assert captured["sbom"] == "/sboms/demo.json"
    assert captured["generated_at"] == "2026-01-01T00:00:00+00:00"
    assert captured["changed_fields"] == ["epss_score"]
    assert captured["finding"]["record"]["euvd_id"] == "EUVD-3"  # type: ignore[index]
    api.close()


def test_new_and_resolved_payloads_carry_no_changed_fields_key(tmp_path: Path) -> None:
    captured: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        return httpx.Response(200)

    api = _client(handler, tmp_path)
    diff = DiffResult(new=[_finding()], resolved=[], changed=[])
    WebhookSink(api, "https://hooks.example/x").notify(
        diff, sbom="x", generated_at="2026-01-01T00:00:00+00:00"
    )
    assert "changed_fields" not in captured[0]
    api.close()
