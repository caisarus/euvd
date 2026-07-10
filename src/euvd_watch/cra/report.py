"""CRA Article 14 notification draft renderer (Step 4.3).

Under deadline pressure, a prefilled draft with everything the tool knows is the
difference between meeting the 24-hour early warning and chaos. Drafting only: a human
reviews, completes the `TODO-HUMAN` fields, and files the notification through the
official channel — euvd-watch never submits anything.

Two hard rules encoded here (audit REQ-CRA-004):
- The draft never upgrades a signal into a claim: "EPSS over threshold" is described as a
  probability signal, never as evidence of active exploitation; only the EUVD/KEV signals
  are described in exploitation terms, each with its concrete source.
- The awareness basis rendered is the event's *first-fire* record (`event.fired_rules`,
  `event.first_seen`); current knowledge comes from `event.current_finding` and is
  labeled as such.

The exact fields a notification legally requires may evolve with ENISA guidance — the
Markdown shape lives in a Jinja2 template (templates/early_warning.md.j2) precisely so it
stays easy to update; see docs/cra.md.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from euvd_watch.config import Settings
from euvd_watch.cra.clock import compute_all
from euvd_watch.cra.state import Event

DISCLAIMER = (
    "This is a machine-prepared DRAFT to support your own CRA Article 14 process. It is "
    "not legal advice, it has not been submitted anywhere, and euvd-watch never submits "
    "anything. A human must verify every field against current ENISA/CSIRT guidance and "
    "file the notification through the official channel."
)


class DraftError(Exception):
    """Raised when a draft cannot be rendered; names the missing config fields."""


_ENV = Environment(
    loader=PackageLoader("euvd_watch.cra", "templates"),
    autoescape=False,  # Markdown output, not HTML
    undefined=StrictUndefined,  # a missing context key must fail tests, not render blank
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


def _require_organization(settings: Settings) -> dict[str, str]:
    org = settings.organization
    missing = [
        f"organization.{field}"
        for field, value in (
            ("name", org.name),
            ("contact_email", org.contact_email),
            ("product_name", org.product_name),
        )
        if not value
    ]
    if missing:
        raise DraftError(
            "Cannot render a notification draft: the reporter identity is incomplete. "
            f"Fill in {', '.join(missing)} in euvd-watch.yaml (see examples/config/)."
        )
    return {
        "name": org.name or "",
        "contact_email": org.contact_email or "",
        "product_name": org.product_name or "",
    }


def _awareness_basis(event: Event) -> list[str]:
    """One factual sentence per first-fire rule; signals are never upgraded to claims."""
    finding = event.finding  # the first-fire evaluation: what we knew when the clock started
    sentences: list[str] = []
    for rule in event.fired_rules:
        if rule == "euvd_exploited":
            since = finding.record.exploited_since or "date not published"
            sentences.append(
                f"ENISA's EUVD marks this vulnerability as actively exploited "
                f"(exploitedSince: {since})."
            )
        elif rule == "cisa_kev":
            sentences.append(
                "The vulnerability is listed in the CISA Known Exploited Vulnerabilities "
                "(KEV) catalog."
            )
        elif rule == "epss_over_threshold":
            score = f"{finding.epss_score:.3f}" if finding.epss_score is not None else "unknown"
            sentences.append(
                f"The EPSS score ({score}) was at or above the threshold configured at "
                f"fire time ({event.epss_threshold}) - note: EPSS is a probability "
                f"signal, NOT direct evidence of active exploitation."
            )
        else:  # a future rule name we don't know how to describe: still surfaced, never dropped
            sentences.append(f"Configured trigger rule fired: {rule}.")
    return sentences


def _build_context(
    event: Event, settings: Settings, generated_at: str, now: datetime
) -> dict[str, Any]:
    current = event.current_finding
    record = current.record
    component = current.component
    cves = [a for a in record.aliases if a.startswith("CVE-")]
    stages = compute_all(event, settings.cra_stages, now)

    return {
        "disclaimer": DISCLAIMER,
        "generated_at": generated_at,
        "organization": _require_organization(settings),
        "event": {
            "event_id": event.event_id,
            "first_seen": event.first_seen.isoformat(),
            "fired_rules": list(event.fired_rules),
        },
        "vulnerability": {
            "euvd_id": record.euvd_id,
            "cves": cves,
            "description": record.description,
            "references": list(record.references),
            "exploited_since": record.exploited_since,
            "epss_score": current.epss_score,
            "in_kev": current.in_kev,
            "cvss_score": record.cvss_score,
        },
        "component": {
            "name": component.name,
            "version": component.version,
            "purl": component.normalized_purl or component.purl,
        },
        "match_explanation": current.explanation,
        "match_confidence": current.confidence.value,
        "awareness_basis": _awareness_basis(event),
        "timeline": [
            {
                "stage": status.stage.name,
                "hours": status.stage.hours,
                "state": status.state.value,
                "deadline": status.deadline.isoformat() if status.deadline else None,
            }
            for status in stages
        ],
    }


def render_markdown(
    event: Event, settings: Settings, generated_at: str, now: datetime | None = None
) -> str:
    """The human-facing early-warning draft (Markdown), with TODO-HUMAN judgment fields."""
    context = _build_context(event, settings, generated_at, now or datetime.now(UTC))
    return _ENV.get_template("early_warning.md.j2").render(**context)


def render_json(
    event: Event, settings: Settings, generated_at: str, now: datetime | None = None
) -> str:
    """The machine-readable draft artifact (versioned, deterministic serialization)."""
    context = _build_context(event, settings, generated_at, now or datetime.now(UTC))
    artifact = {"schema_version": 1, "kind": "cra_early_warning_draft", **context}
    return json.dumps(artifact, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
