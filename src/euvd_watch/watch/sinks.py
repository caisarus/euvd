"""Notification sinks (Step 5.4): where a diff's findings get reported.

`NotificationSink` is deliberately a small `Protocol` - stdout and a generic webhook ship
today; the interface is the extension point for future sinks (email, Slack) without
touching the differ or the CLI wiring. Neither sink imports `typer`: they stay
framework-agnostic and testable with plain `capsys`/mock transports, matching how
`cra/report.py` and `cra/audit.py` keep the CLI's concerns out of their modules.
"""

from __future__ import annotations

from typing import Any, Protocol

from euvd_watch.euvd.match import Finding
from euvd_watch.http import ApiClient
from euvd_watch.watch.differ import DiffResult

SCHEMA_VERSION = 1


class NotificationSink(Protocol):
    """Reports a diff. Implementations decide how (and whether) to batch."""

    def notify(self, diff: DiffResult, *, sbom: str, generated_at: str) -> None: ...


class StdoutSink:
    """Always-on, human-readable sink: one line per new/resolved/changed finding."""

    def notify(self, diff: DiffResult, *, sbom: str, generated_at: str) -> None:
        for finding in diff.new:
            print(f"[NEW] {_label(finding)} ({finding.confidence.value})")
        for finding in diff.resolved:
            print(f"[RESOLVED] {_label(finding)}")
        for changed in diff.changed:
            fields = ", ".join(changed.changed_fields)
            print(f"[CHANGED] {_label(changed.current)} ({fields})")


def _label(finding: Finding) -> str:
    name = f"{finding.component.name} {finding.component.version or ''}".strip()
    return f"{name} - {finding.record.euvd_id}"


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return finding.model_dump(mode="json")


def _webhook_payload(
    kind: str,
    finding: Finding,
    *,
    sbom: str,
    generated_at: str,
    changed_fields: list[str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "sbom": sbom,
        "generated_at": generated_at,
        "finding": _finding_payload(finding),
    }
    if changed_fields is not None:
        payload["changed_fields"] = changed_fields
    return payload


class WebhookSink:
    """POSTs one JSON payload per new/resolved/changed finding via the shared ApiClient.

    At-least-once delivery: a POST is retried with the same backoff as any other
    `ApiClient` call, but there is no receiver-side deduplication built in. A failure
    raises `ApiError` - the caller decides whether that aborts the run or is logged and
    skipped (see `cli.py::watch`).
    """

    def __init__(self, api: ApiClient, url: str) -> None:
        self._api = api
        self._url = url

    def notify(self, diff: DiffResult, *, sbom: str, generated_at: str) -> None:
        for finding in diff.new:
            self._api.post_json(
                self._url, _webhook_payload("new", finding, sbom=sbom, generated_at=generated_at)
            )
        for finding in diff.resolved:
            self._api.post_json(
                self._url,
                _webhook_payload("resolved", finding, sbom=sbom, generated_at=generated_at),
            )
        for changed in diff.changed:
            self._api.post_json(
                self._url,
                _webhook_payload(
                    "changed",
                    changed.current,
                    sbom=sbom,
                    generated_at=generated_at,
                    changed_fields=changed.changed_fields,
                ),
            )
