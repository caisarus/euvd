# SPDX-License-Identifier: EUPL-1.2
"""Typer CLI entry point.

`version`, `scan`, `match`, `vex generate`/`vex init-decisions`, `cra ...`, and `watch`
are implemented.
"""

from __future__ import annotations

import functools
import hashlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import ParamSpec

import typer
import yaml
from rich.console import Console
from rich.table import Table

from euvd_watch import __version__
from euvd_watch.config import ConfigError, Settings, load_settings
from euvd_watch.cra.audit import AuditError, AuditLog
from euvd_watch.cra.audit import verify as verify_audit_log
from euvd_watch.cra.clock import ClockState, compute_all, is_event_open
from euvd_watch.cra.report import DraftError, render_json, render_markdown
from euvd_watch.cra.state import Event, EventStore, StateError
from euvd_watch.cra.trigger import evaluate_all
from euvd_watch.enrich import enrich
from euvd_watch.euvd.client import EuvdClient
from euvd_watch.euvd.match import (
    Confidence,
    Evaluation,
    Finding,
    confidence_at_least,
    derive_candidates,
    evaluate_inventory,
    finding_to_evaluation,
    match_inventory,
)
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.http import ApiClient, ApiError
from euvd_watch.log import setup_logging
from euvd_watch.models import Inventory
from euvd_watch.sbom import load_inventory_with_stats
from euvd_watch.sbom.errors import SbomParseError, UnsupportedFormatError
from euvd_watch.vex.build import build_document
from euvd_watch.vex.decisions import DecisionEntry, DecisionsError, DecisionsFile, load_decisions
from euvd_watch.vex.merge import ResolvedDecision, merge
from euvd_watch.vex.model import Status
from euvd_watch.vex.write import render
from euvd_watch.watch.differ import DiffResult, diff_findings
from euvd_watch.watch.sinks import NotificationSink, StdoutSink, WebhookSink
from euvd_watch.web.store import Store, StoreError

app = typer.Typer(no_args_is_help=True, add_completion=False)
vex_app = typer.Typer(no_args_is_help=True)
cra_app = typer.Typer(no_args_is_help=True)
db_app = typer.Typer(no_args_is_help=True)
app.add_typer(vex_app, name="vex", help="OpenVEX statement generation.")
app.add_typer(cra_app, name="cra", help="CRA Article 14 reporting workflow.")
app.add_typer(db_app, name="db", help="Consolidated state database maintenance.")


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"


@dataclass
class GlobalState:
    settings: Settings
    output: OutputFormat
    verbose: bool


_P = ParamSpec("_P")


def cli_command(func: Callable[_P, None]) -> Callable[_P, None]:
    """Mechanical exit-code boundary applied to every command uniformly.

    Any escaping OSError (unwritable --save-findings path, uncreatable cache_dir, etc.)
    becomes a clean stderr message + exit 2 instead of a traceback with exit 1. This is
    deliberately a decorator applied to every command rather than a per-command try/except:
    feedback_m2.md findings 1.2/1.3 were both a *recurrence* of the M1 "no unhandled
    exception escapes a CLI command" rule in new code - per-command memory demonstrably
    isn't enough, so new commands get this for free instead of needing to remember it.
    """

    @functools.wraps(func)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> None:
        try:
            func(*args, **kwargs)
        except typer.Exit:
            raise
        except StoreError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=2) from exc
        except OSError as exc:
            typer.echo(f"Unexpected I/O error: {exc}", err=True)
            raise typer.Exit(code=2) from exc

    return wrapper


@app.callback()
def main(
    ctx: typer.Context,
    config: Path | None = typer.Option(
        None, "--config", help="Path to euvd-watch.yaml (defaults to ./euvd-watch.yaml)."
    ),
    output: OutputFormat = typer.Option(OutputFormat.TABLE, "--output", help="Output format."),
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose logging."),
) -> None:
    setup_logging(verbose)
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    ctx.obj = GlobalState(settings=settings, output=output, verbose=verbose)


@app.command()
@cli_command
def version() -> None:
    """Print the euvd-watch version."""
    typer.echo(__version__)


@app.command()
@cli_command
def scan(
    ctx: typer.Context,
    sbom: str = typer.Argument(..., help="Path to a CycloneDX/SPDX SBOM file."),
) -> None:
    """Parse and normalize an SBOM into a component inventory."""
    state: GlobalState = ctx.obj
    try:
        inventory, dropped = load_inventory_with_stats(sbom)
    except (SbomParseError, UnsupportedFormatError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    synthesized_count = sum(c.synthesized for c in inventory.components)
    summary = (
        f"{len(inventory.components)} components "
        f"({dropped} deduplicated, {synthesized_count} with synthesized identifiers)"
    )

    if state.output is OutputFormat.JSON:
        # Keep stdout pure JSON; the human-readable summary goes to stderr instead.
        typer.echo(summary, err=True)
        typer.echo(inventory.model_dump_json())
        return

    table = Table(title=str(sbom))
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("PURL")
    table.add_column("Type")
    table.add_column("Flags")
    for component in inventory.components:
        table.add_row(
            component.name,
            component.version or "",
            component.normalized_purl or component.purl or "",
            component.type.value,
            "synthesized" if component.synthesized else "",
        )
    Console().print(table)
    typer.echo(summary)


class FailOn(StrEnum):
    NONE = "none"
    ANY = "any"
    EXPLOITED = "exploited"


def _inventory_digest(inventory: Inventory) -> str:
    return "sha256:" + hashlib.sha256(inventory.model_dump_json().encode("utf-8")).hexdigest()


def _vex_document_id(inventory: Inventory, resolved: list[ResolvedDecision]) -> str:
    """A document identity that changes whenever the resolved statements do, not just the
    SBOM (feedback_m3.md finding 1.2): two `vex generate` runs over the same SBOM with
    genuinely different EUVD data - the project's core "watch" scenario - must not collide
    on @id, or a consumer that tracks VEX documents by identity would silently treat the
    new assessment as the same as the old one. Still deterministic for identical re-runs.
    """
    statements_payload = json.dumps(
        [
            {
                "euvd_id": r.evaluation.record.euvd_id,
                "component": r.evaluation.component.dedupe_key,
                "status": r.decision.status.value,
                "justification": r.decision.justification.value
                if r.decision.justification
                else None,
                "explanation": r.decision.explanation,
            }
            for r in resolved
        ],
        sort_keys=True,
    )
    digest = hashlib.sha256(
        (_inventory_digest(inventory) + statements_payload).encode("utf-8")
    ).hexdigest()
    return f"urn:euvd-watch:vex:sha256:{digest}"


def _findings_artifact(
    findings: list[Finding],
    inventory: Inventory,
    data_freshness: str | None,
    generated_at: str,
) -> dict[str, object]:
    """The versioned findings artifact consumed later by `vex generate` and `cra check`.

    `generated_at` is caller-supplied so `--timestamp` can pin it: identical inputs must
    be able to produce byte-identical output (INV-9), and this field was the one
    uncontrolled piece of the match JSON (audit finding TECH-003).
    """
    return {
        "schema_version": 1,
        "generated_at": generated_at,
        "inventory_digest": _inventory_digest(inventory),
        "data_freshness": data_freshness,
        "findings": [f.model_dump(mode="json") for f in findings],
    }


def _fetch_records(
    client: EuvdClient, inventory: Inventory, *, exploited_only: bool, tier2_enabled: bool = True
) -> list[EuvdRecord]:
    """Two-tier query strategy (docs/matching.md).

    Tier 1 always syncs the full exploited catalog. Tier 2 adds per-candidate product
    searches, deduplicated across components and served from the HTTP cache — it sends
    SBOM-derived product names to the EUVD API, so `tier2_product_search: false` lets
    confidential deployments opt out (privacy note in docs/matching.md). Note the
    cache-first client means "EUVD unreachable but cache fresh" is served transparently;
    an ApiError here means both the network and the cache have nothing usable.
    """
    records: dict[str, EuvdRecord] = {}
    for record in client.fetch_exploited():
        records[record.euvd_id] = record

    if not exploited_only and tier2_enabled:
        products = {
            candidate.product.lower()
            for component in inventory.components
            for candidate in derive_candidates(component)
        }
        for product in sorted(products):
            for record in client.search_product(product):
                records.setdefault(record.euvd_id, record)

    return list(records.values())


def _render_findings_table(findings: list[Finding], title: str) -> None:
    table = Table(title=title)
    table.add_column("Component")
    table.add_column("EUVD ID")
    table.add_column("Confidence")
    table.add_column("Exploited")
    table.add_column("EPSS")
    table.add_column("KEV")
    table.add_column("Why")
    colors = {Confidence.HIGH: "red", Confidence.MEDIUM: "yellow", Confidence.LOW: "cyan"}
    for f in findings:
        table.add_row(
            f"{f.component.name} {f.component.version or ''}".strip(),
            f.record.euvd_id,
            f"[{colors[f.confidence]}]{f.confidence.value}[/{colors[f.confidence]}]",
            "yes" if f.record.exploited else "",
            f"{f.epss_score:.3f}" if f.epss_score is not None else "",
            {True: "yes", False: "no", None: "?"}[f.in_kev],
            f.explanation,
        )
    Console().print(table)


@app.command()
@cli_command
def match(
    ctx: typer.Context,
    sbom: str = typer.Argument(..., help="Path to a CycloneDX/SPDX SBOM file."),
    exploited_only: bool = typer.Option(
        False, "--exploited-only", help="Only match against actively exploited vulnerabilities."
    ),
    min_confidence: Confidence | None = typer.Option(
        None, "--min-confidence", help="Drop findings below this confidence (default: config)."
    ),
    no_enrich: bool = typer.Option(
        False, "--no-enrich", help="Skip EPSS/KEV enrichment (offline mode)."
    ),
    fail_on: FailOn = typer.Option(
        FailOn.ANY, "--fail-on", help="What makes the exit code 1 (CI gate)."
    ),
    save_findings: Path | None = typer.Option(
        None, "--save-findings", help="Also write the findings artifact to this path."
    ),
    timestamp: str | None = typer.Option(
        None,
        "--timestamp",
        help="Pin the artifact's generated_at (ISO 8601); default: now. Same contract as "
        "'vex generate --timestamp' - identical inputs then produce byte-identical output.",
    ),
) -> None:
    """Match SBOM components against the EUVD, with confidence scoring."""
    state: GlobalState = ctx.obj
    settings = state.settings

    try:
        inventory, _dropped = load_inventory_with_stats(sbom)
    except (SbomParseError, UnsupportedFormatError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    api = ApiClient(settings.cache_dir, settings.cache_ttl_hours)
    try:
        client = EuvdClient(api, settings.euvd_api_base_url)
        try:
            records = _fetch_records(
                client,
                inventory,
                exploited_only=exploited_only,
                tier2_enabled=settings.tier2_product_search,
            )
        except ApiError as exc:
            typer.echo(
                f"EUVD is unreachable and the local cache has no usable data: {exc}\n"
                f"Refusing to report 'no findings' on missing data.",
                err=True,
            )
            raise typer.Exit(code=2) from exc

        # Read before enrichment on purpose: the stamp qualifies the EUVD data in the
        # artifact, so EPSS/KEV responses must not participate (feedback_m2.md 2.2).
        oldest = api.oldest_served_stored_at()
        data_freshness = (
            datetime.fromtimestamp(oldest, UTC).isoformat() if oldest is not None else None
        )

        findings = match_inventory(inventory, records)
        if not no_enrich:
            findings = enrich(findings, api, settings.epss_api_base_url, settings.kev_feed_url)
    finally:
        api.close()

    floor = min_confidence or Confidence(settings.min_confidence)
    findings = [f for f in findings if confidence_at_least(f.confidence, floor)]
    if exploited_only:
        findings = [f for f in findings if f.record.exploited]

    exploited_count = sum(1 for f in findings if f.record.exploited)
    summary = (
        f"{len(findings)} findings ({exploited_count} exploited) across "
        f"{len(inventory.components)} components; min confidence: {floor.value}"
    )

    artifact = _findings_artifact(
        findings, inventory, data_freshness, timestamp or datetime.now(UTC).isoformat()
    )
    if save_findings is not None:
        save_findings.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

    if state.output is OutputFormat.JSON:
        typer.echo(summary, err=True)
        typer.echo(json.dumps(artifact))
    else:
        _render_findings_table(findings, title=str(sbom))
        typer.echo(summary)

    if fail_on is FailOn.ANY and findings:
        raise typer.Exit(code=1)
    if fail_on is FailOn.EXPLOITED and exploited_count:
        raise typer.Exit(code=1)


class FindingsArtifactError(Exception):
    """Raised when a saved findings artifact (--findings) can't be loaded."""


def _load_findings_artifact(path: Path) -> list[Finding]:
    raw = path.read_text(encoding="utf-8")  # OSError -> caught by the cli_command boundary
    return _parse_findings_artifact(raw, str(path))


def _parse_findings_artifact(raw: str, source: str) -> list[Finding]:
    """Parse a findings artifact from JSON text; `source` names it in error messages."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FindingsArtifactError(f"{source} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "findings" not in data:
        raise FindingsArtifactError(
            f"{source} does not look like a findings artifact (missing 'findings')."
        )
    if data.get("schema_version") != 1:
        raise FindingsArtifactError(
            f"{source} has schema_version={data.get('schema_version')!r}, expected 1. "
            f"This build of euvd-watch only understands schema_version 1."
        )
    try:
        return [Finding.model_validate(f) for f in data["findings"]]
    except Exception as exc:  # pydantic.ValidationError, kept generic to avoid a new import
        raise FindingsArtifactError(f"{source} contains invalid finding data: {exc}") from exc


def _evaluations_for(
    inventory: Inventory, settings: Settings, *, findings_path: Path | None
) -> tuple[list[Evaluation], bool]:
    """Returns (evaluations, not_affected_capable).

    The --findings fast path is auto-not_affected-blind by construction: a saved findings
    artifact (schema_version 1) only ever stored MATCH outcomes, so there is no
    NOT_AFFECTED evidence to replay (see docs/matching.md's design note). This is itself
    conservative - less certainty available defaults to under_investigation, not a guess.
    """
    if findings_path is not None:
        findings = _load_findings_artifact(findings_path)
        return [finding_to_evaluation(f) for f in findings], False

    api = ApiClient(settings.cache_dir, settings.cache_ttl_hours)
    try:
        client = EuvdClient(api, settings.euvd_api_base_url)
        try:
            records = _fetch_records(
                client,
                inventory,
                exploited_only=False,
                tier2_enabled=settings.tier2_product_search,
            )
        except ApiError as exc:
            typer.echo(
                f"EUVD is unreachable and the local cache has no usable data: {exc}\n"
                f"Refusing to draft VEX statements on missing data.",
                err=True,
            )
            raise typer.Exit(code=2) from exc
        return evaluate_inventory(inventory, records), True
    finally:
        api.close()


def _render_vex_summary_table(
    document_title: str, resolved: list[ResolvedDecision], not_affected_capable: bool
) -> None:
    table = Table(title=document_title)
    table.add_column("Component")
    table.add_column("Vulnerability")
    table.add_column("Status")
    table.add_column("Human?")
    table.add_column("Why")
    colors = {
        Status.NOT_AFFECTED: "green",
        Status.AFFECTED: "red",
        Status.FIXED: "cyan",
        Status.UNDER_INVESTIGATION: "yellow",
    }
    for r in resolved:
        color = colors[r.decision.status]
        table.add_row(
            f"{r.evaluation.component.name} {r.evaluation.component.version or ''}".strip(),
            r.evaluation.record.euvd_id,
            f"[{color}]{r.decision.status.value}[/{color}]",
            "yes" if r.is_human else "",
            r.decision.explanation,
        )
    Console().print(table)
    if not not_affected_capable:
        typer.echo(
            "Note: --findings was used, so no not_affected statements were auto-drafted "
            "(the saved artifact carries no such evidence).",
            err=True,
        )


@vex_app.command("generate")
@cli_command
def vex_generate(
    ctx: typer.Context,
    sbom: str = typer.Argument(..., help="Path to a CycloneDX/SPDX SBOM file."),
    decisions: Path | None = typer.Option(
        None, "--decisions", help="vex-decisions.yaml overriding automated drafts."
    ),
    findings: Path | None = typer.Option(
        None,
        "--findings",
        help="Reuse a saved findings artifact instead of live matching (conservative-only).",
    ),
    timestamp: str | None = typer.Option(
        None, "--timestamp", help="Pin the document timestamp (ISO 8601); default: now."
    ),
    out: Path | None = typer.Option(
        None, "--out", "-o", help="Write the OpenVEX document to this path."
    ),
    fail_on_conflict: bool = typer.Option(
        False,
        "--fail-on-conflict",
        help="Exit 1 when a human decision conflicts with automated evidence (CI gate). "
        "The document is still written; the human decision still wins.",
    ),
) -> None:
    """Draft OpenVEX statements: not_affected only with machine-checkable proof."""
    state: GlobalState = ctx.obj
    settings = state.settings

    try:
        inventory, _dropped = load_inventory_with_stats(sbom)
    except (SbomParseError, UnsupportedFormatError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    try:
        evaluations, not_affected_capable = _evaluations_for(
            inventory, settings, findings_path=findings
        )
    except FindingsArtifactError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    decisions_file = DecisionsFile(decisions=[])
    if decisions is not None:
        try:
            decisions_file = load_decisions(decisions)
        except DecisionsError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=2) from exc

    result = merge(evaluations, decisions_file)

    document = build_document(
        result.decisions,
        document_id=_vex_document_id(inventory, result.decisions),
        author=settings.organization.name or "euvd-watch",
        timestamp=timestamp or datetime.now(UTC).isoformat(),
    )
    text = render(document)

    if out is not None:
        out.write_text(text, encoding="utf-8")

    status_counts: dict[str, int] = {}
    auto_not_affected = 0
    for r in result.decisions:
        status_counts[r.decision.status.value] = status_counts.get(r.decision.status.value, 0) + 1
        if r.decision.status is Status.NOT_AFFECTED and not r.is_human:
            auto_not_affected += 1

    summary = (
        f"{len(result.decisions)} statements ({status_counts}); "
        f"{auto_not_affected} auto-drafted not_affected; "
        f"{len(result.stale)} stale decisions; {len(result.conflicts)} conflicts"
    )

    if state.output is OutputFormat.JSON:
        typer.echo(summary, err=True)
        if out is None:
            typer.echo(text, nl=False)
    else:
        _render_vex_summary_table(str(sbom), result.decisions, not_affected_capable)
        typer.echo(summary)
    if out is not None:
        typer.echo(f"Wrote {out}", err=True)

    if fail_on_conflict and result.conflicts:
        # Exit 1 = "findings above threshold" in the CLI contract: a human decision that
        # contradicts automated evidence is exactly the kind of finding a CI gate exists
        # for. Output was already produced above - the gate never suppresses the document.
        raise typer.Exit(code=1)


@vex_app.command("init-decisions")
@cli_command
def vex_init_decisions(
    ctx: typer.Context,
    sbom: str = typer.Argument(..., help="Path to a CycloneDX/SPDX SBOM file."),
    out: Path = typer.Option(
        Path("vex-decisions.yaml"), "--out", "-o", help="Where to write the scaffold."
    ),
) -> None:
    """Scaffold a vex-decisions.yaml from current findings, for a human to fill in."""
    state: GlobalState = ctx.obj
    settings = state.settings

    try:
        inventory, _dropped = load_inventory_with_stats(sbom)
    except (SbomParseError, UnsupportedFormatError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    evaluations, _ = _evaluations_for(inventory, settings, findings_path=None)
    today = datetime.now(UTC).date().isoformat()
    author = settings.organization.contact_email or settings.organization.name or "TODO"

    entries = [
        DecisionEntry(
            euvd_id=evaluation.record.euvd_id,
            purl=evaluation.component.normalized_purl or evaluation.component.purl or "TODO",
            status=Status.UNDER_INVESTIGATION,
            statement="TODO: describe your reasoning for this component/vulnerability.",
            author=author,
            date=today,
        )
        for evaluation in evaluations
    ]
    scaffold = DecisionsFile(decisions=entries)
    out.write_text(
        yaml.safe_dump(
            scaffold.model_dump(mode="json", exclude_none=True), sort_keys=False, allow_unicode=True
        ),
        encoding="utf-8",
    )
    typer.echo(f"Wrote {len(entries)} decision stub(s) to {out}", err=True)


def _state_store(settings: Settings) -> Store:
    """Open the consolidated state DB, applying pending migrations and legacy imports.

    Every state-touching command goes through here, so users on a pre-6.1 layout are
    migrated transparently on first contact - `db migrate` exists to do it explicitly.
    """
    store = Store(settings.state_dir)
    store.migrate()
    return store


def _event_store(settings: Settings) -> EventStore:
    store = _state_store(settings)
    store.close()
    return EventStore(store.path)


def _audit_log(settings: Settings) -> AuditLog:
    return AuditLog(settings.state_dir / "cra-audit.jsonl")


def _compute_findings(
    settings: Settings, sbom: str, *, no_enrich: bool, findings_path: Path | None
) -> list[Finding]:
    """Findings for a saved artifact, or a live match + enrichment - shared by `cra check`
    and `watch` (both need the same "match, then enrich, then hand me findings" pipeline)."""
    if findings_path is not None:
        return _load_findings_artifact(findings_path)

    try:
        inventory, _dropped = load_inventory_with_stats(sbom)
    except (SbomParseError, UnsupportedFormatError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    api = ApiClient(settings.cache_dir, settings.cache_ttl_hours)
    try:
        client = EuvdClient(api, settings.euvd_api_base_url)
        try:
            records = _fetch_records(
                client,
                inventory,
                exploited_only=False,
                tier2_enabled=settings.tier2_product_search,
            )
        except ApiError as exc:
            typer.echo(
                f"EUVD is unreachable and the local cache has no usable data: {exc}\n"
                f"Refusing to report on missing data.",
                err=True,
            )
            raise typer.Exit(code=2) from exc
        findings = match_inventory(inventory, records)
        if not no_enrich:
            findings = enrich(findings, api, settings.epss_api_base_url, settings.kev_feed_url)
    finally:
        api.close()
    return findings


def _event_as_json(event: Event, settings: Settings, now: datetime) -> dict[str, object]:
    stages = compute_all(event, settings.cra_stages, now)
    return {
        "event_id": event.event_id,
        "component": event.finding.component.dedupe_key,
        "euvd_id": event.finding.record.euvd_id,
        "fired_rules": list(event.fired_rules),
        "first_seen": event.first_seen.isoformat(),
        "open": is_event_open(event, settings.cra_stages),
        "stages": [
            {
                "name": status.stage.name,
                "state": status.state.value,
                "deadline": status.deadline.isoformat() if status.deadline else None,
            }
            for status in stages
        ],
    }


def _remaining_text(deadline: datetime | None, now: datetime) -> str:
    if deadline is None:
        return "-"
    remaining = deadline - now
    seconds = int(remaining.total_seconds())
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)
    return f"{sign}{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


@cra_app.command("check")
@cli_command
def cra_check(
    ctx: typer.Context,
    sbom: str = typer.Argument(..., help="Path to a CycloneDX/SPDX SBOM file."),
    findings: Path | None = typer.Option(
        None, "--findings", help="Reuse a saved findings artifact instead of live matching."
    ),
    no_enrich: bool = typer.Option(
        False, "--no-enrich", help="Skip EPSS/KEV enrichment (their trigger signals stay unknown)."
    ),
) -> None:
    """Evaluate the CRA reporting trigger; persist events; exit 1 when NEW events opened."""
    state: GlobalState = ctx.obj
    settings = state.settings
    found = _compute_findings(settings, sbom, no_enrich=no_enrich, findings_path=findings)
    results = evaluate_all(found, settings)

    now = datetime.now(UTC)
    store = _event_store(settings)
    log = _audit_log(settings)
    events: list[tuple[Event, bool]] = []
    try:
        for result in results:
            event, created = store.get_or_create(
                result.finding,
                result.fired_rules,
                result.policy_snapshot,
                result.epss_threshold,
                now,
            )
            if created:
                log.append(
                    "trigger_event_created",
                    {
                        "event_id": event.event_id,
                        "euvd_id": event.finding.record.euvd_id,
                        "component": event.finding.component.dedupe_key,
                        "fired_rules": list(event.fired_rules),
                        "first_seen": event.first_seen.isoformat(),
                        "policy_snapshot": event.policy_snapshot.model_dump(mode="json"),
                        "epss_threshold": event.epss_threshold,
                    },
                )
            events.append((event, created))
    except (StateError, AuditError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    finally:
        store.close()

    new_count = sum(1 for _, created in events if created)
    summary = (
        f"{len(events)} trigger event(s) ({new_count} new) from {len(found)} findings; "
        f"state: {settings.state_dir}"
    )

    if state.output is OutputFormat.JSON:
        typer.echo(summary, err=True)
        payload = {
            "schema_version": 1,
            "new_events": new_count,
            "events": [
                {**_event_as_json(e, settings, now), "new": created} for e, created in events
            ],
        }
        typer.echo(json.dumps(payload))
    else:
        table = Table(title="CRA trigger events")
        table.add_column("Event id")
        table.add_column("EUVD ID")
        table.add_column("Fired rules")
        table.add_column("First seen (UTC)")
        table.add_column("New")
        for event, created in events:
            table.add_row(
                event.event_id,
                event.finding.record.euvd_id,
                ", ".join(event.fired_rules),
                event.first_seen.isoformat(),
                "yes" if created else "",
            )
        Console().print(table)
        typer.echo(summary)

    if new_count:
        raise typer.Exit(code=1)


@cra_app.command("status")
@cli_command
def cra_status(ctx: typer.Context) -> None:
    """Show open CRA events with one countdown per configured stage."""
    state: GlobalState = ctx.obj
    settings = state.settings
    now = datetime.now(UTC)
    store = _event_store(settings)
    try:
        events = store.list_all()
    except StateError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    finally:
        store.close()

    open_events = [e for e in events if is_event_open(e, settings.cra_stages)]
    summary = f"{len(open_events)} open event(s) of {len(events)} total; times are UTC"

    if state.output is OutputFormat.JSON:
        typer.echo(summary, err=True)
        payload = {
            "schema_version": 1,
            "generated_at": now.isoformat(),
            "events": [_event_as_json(e, settings, now) for e in open_events],
        }
        typer.echo(json.dumps(payload))
        return

    table = Table(title="Open CRA events (all times UTC)")
    table.add_column("Event id")
    table.add_column("EUVD ID")
    table.add_column("Stage")
    table.add_column("State")
    table.add_column("Deadline (UTC)")
    table.add_column("Remaining")
    state_colors = {
        ClockState.PENDING: "green",
        ClockState.DUE_SOON: "yellow",
        ClockState.OVERDUE: "red",
        ClockState.COMPLETED: "cyan",
        ClockState.AWAITING_ANCHOR: "white",
    }
    for event in open_events:
        for status in compute_all(event, settings.cra_stages, now):
            color = state_colors[status.state]
            table.add_row(
                event.event_id,
                event.finding.record.euvd_id,
                status.stage.name,
                f"[{color}]{status.state.value}[/{color}]",
                status.deadline.isoformat() if status.deadline else "awaiting anchor",
                _remaining_text(status.deadline, now),
            )
    Console().print(table)
    typer.echo(summary)


@cra_app.command("draft")
@cli_command
def cra_draft(
    ctx: typer.Context,
    event_id: str = typer.Argument(..., help="Event id from 'cra check' / 'cra status'."),
    out: Path | None = typer.Option(
        None, "--out", "-o", help="Write the draft to this path instead of stdout."
    ),
    timestamp: str | None = typer.Option(
        None, "--timestamp", help="Pin the draft's generated_at (ISO 8601); default: now."
    ),
) -> None:
    """Render a prefilled notification draft (Markdown; JSON with --output json).

    Drafting only: complete every TODO-HUMAN field and file through the official channel.
    euvd-watch never submits anything.
    """
    state: GlobalState = ctx.obj
    settings = state.settings
    store = _event_store(settings)
    try:
        event = store.get(event_id)
    except StateError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    finally:
        store.close()
    if event is None:
        typer.echo(f"No CRA event with id {event_id!r}. See 'euvd-watch cra status'.", err=True)
        raise typer.Exit(code=2)

    generated_at = timestamp or datetime.now(UTC).isoformat()
    try:
        if state.output is OutputFormat.JSON:
            text = render_json(event, settings, generated_at)
        else:
            text = render_markdown(event, settings, generated_at)
    except DraftError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    try:
        _audit_log(settings).append(
            "draft_rendered",
            {
                "event_id": event_id,
                "format": state.output.value,
                "generated_at": generated_at,
            },
        )
    except AuditError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    if out is not None:
        out.write_text(text, encoding="utf-8")
        typer.echo(f"Wrote {out}", err=True)
    else:
        typer.echo(text, nl=False)


@cra_app.command("mark")
@cli_command
def cra_mark(
    ctx: typer.Context,
    event_id: str = typer.Argument(..., help="Event id from 'cra check' / 'cra status'."),
    stage: str | None = typer.Option(
        None, "--stage", help="Mark this configured stage as completed by a human."
    ),
    note: str | None = typer.Option(None, "--note", help="Free-text note (e.g. filing reference)."),
    remediation_available: bool = typer.Option(
        False,
        "--remediation-available",
        help="Record that a remediation is available (anchors remediation-based stages).",
    ),
) -> None:
    """Record a human action on an event: stage completion and/or remediation availability."""
    state: GlobalState = ctx.obj
    settings = state.settings
    if stage is None and not remediation_available:
        typer.echo("Nothing to record: pass --stage NAME and/or --remediation-available.", err=True)
        raise typer.Exit(code=2)

    valid_stages = [s.name for s in settings.cra_stages]
    if stage is not None and stage not in valid_stages:
        typer.echo(
            f"Unknown stage {stage!r}. Configured stages: {', '.join(valid_stages)}", err=True
        )
        raise typer.Exit(code=2)

    now = datetime.now(UTC)
    store = _event_store(settings)
    log = _audit_log(settings)
    try:
        if remediation_available:
            store.set_remediation_available(event_id, now)
            log.append(
                "remediation_marked",
                {"event_id": event_id, "at": now.isoformat(), "note": note},
                actor="human",
            )
            typer.echo(f"Recorded remediation availability for {event_id} at {now.isoformat()}.")
        if stage is not None:
            store.mark_stage_completed(event_id, stage, now, note)
            log.append(
                "stage_marked",
                {"event_id": event_id, "stage": stage, "at": now.isoformat(), "note": note},
                actor="human",
            )
            typer.echo(f"Marked stage '{stage}' completed for {event_id} at {now.isoformat()}.")
    except KeyError as exc:
        typer.echo(f"No CRA event with id {event_id!r}. See 'euvd-watch cra status'.", err=True)
        raise typer.Exit(code=2) from exc
    except (StateError, AuditError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    finally:
        store.close()


@cra_app.command("verify-log")
@cli_command
def cra_verify_log(ctx: typer.Context) -> None:
    """Verify the hash-chained audit log; exit 1 naming the first broken entry if any."""
    state: GlobalState = ctx.obj
    result = verify_audit_log(state.settings.state_dir / "cra-audit.jsonl")
    if state.output is OutputFormat.JSON:
        typer.echo(
            json.dumps(
                {
                    "schema_version": 1,
                    "ok": result.ok,
                    "entries": result.entries,
                    "bad_line": result.bad_line,
                    "reason": result.reason,
                    "truncated_tail": result.truncated_tail,
                }
            )
        )
    else:
        typer.echo(result.describe())
    if not result.ok:
        raise typer.Exit(code=1)


_INTERVAL_RE = re.compile(r"^(\d+)([smhd])$")
_INTERVAL_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_interval(text: str) -> float:
    """Parse '30m'/'6h'/'1d'-style durations into seconds."""
    match = _INTERVAL_RE.match(text.strip())
    if not match:
        raise ValueError(f"Invalid --interval {text!r}; expected e.g. '30m', '6h', '1d'.")
    value, unit = match.groups()
    return int(value) * _INTERVAL_UNITS[unit]


def _watch_snapshot_key(sbom: str) -> str:
    """One snapshot row per watched SBOM, keyed by its resolved path so re-runs from a
    different working directory still hit the same snapshot. Same key derivation as the
    pre-6.1 per-file layout, so migrated rows keep matching their SBOMs."""
    return hashlib.sha256(str(Path(sbom).resolve()).encode("utf-8")).hexdigest()[:16]


def _load_watch_snapshot(store: Store, sbom_key: str) -> list[Finding]:
    """The previous run's findings, or an empty list on the very first run."""
    raw = store.load_watch_snapshot(sbom_key)
    if raw is None:
        return []
    return _parse_findings_artifact(raw, f"watch snapshot {sbom_key!r}")


def _save_watch_snapshot(
    store: Store, sbom_key: str, findings: list[Finding], generated_at: str
) -> None:
    # Deliberately the same minimal shape `_parse_findings_artifact` already understands
    # (schema_version + findings) - a watch snapshot has no SBOM/data-freshness of its own
    # to report, unlike `match --save-findings`'s fuller artifact.
    artifact = {
        "schema_version": 1,
        "generated_at": generated_at,
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    store.save_watch_snapshot(sbom_key, json.dumps(artifact, indent=2) + "\n")


def _echo_cycle_summary(diff: DiffResult, output: OutputFormat) -> None:
    summary = f"{len(diff.new)} new, {len(diff.resolved)} resolved, {len(diff.changed)} changed."
    typer.echo(summary, err=True)
    if output is OutputFormat.JSON:
        payload = {
            "schema_version": 1,
            "new": [f.model_dump(mode="json") for f in diff.new],
            "resolved": [f.model_dump(mode="json") for f in diff.resolved],
            "changed": [
                {
                    "changed_fields": c.changed_fields,
                    "previous": c.previous.model_dump(mode="json"),
                    "current": c.current.model_dump(mode="json"),
                }
                for c in diff.changed
            ],
        }
        typer.echo(json.dumps(payload))


def _run_watch_cycle(
    settings: Settings, sbom: str, *, no_enrich: bool, sinks: list[NotificationSink]
) -> DiffResult:
    """One check-and-diff cycle: load the previous snapshot, match+enrich, diff, notify,
    persist the new snapshot - always, even when the diff is empty, so the next cycle
    compares against the latest data."""
    sbom_key = _watch_snapshot_key(sbom)
    store = _state_store(settings)
    try:
        previous = _load_watch_snapshot(store, sbom_key)
        current = _compute_findings(settings, sbom, no_enrich=no_enrich, findings_path=None)
        diff = diff_findings(previous, current)

        generated_at = datetime.now(UTC).isoformat()
        resolved_sbom = str(Path(sbom).resolve())
        for sink in sinks:
            sink.notify(diff, sbom=resolved_sbom, generated_at=generated_at)
        _save_watch_snapshot(store, sbom_key, current, generated_at)
    finally:
        store.close()
    return diff


@app.command()
@cli_command
def watch(
    ctx: typer.Context,
    sbom: str = typer.Argument(..., help="Path to a CycloneDX/SPDX SBOM file."),
    interval: str | None = typer.Option(
        None,
        "--interval",
        help="Re-check on a schedule (e.g. '30m', '6h', '1d'); runs until interrupted.",
    ),
    once: bool = typer.Option(
        False, "--once", help="Run a single check-and-diff cycle and exit (the default)."
    ),
    webhook: str | None = typer.Option(
        None,
        "--webhook",
        help="POST a JSON notification here for every new/resolved/changed finding.",
    ),
    no_enrich: bool = typer.Option(
        False, "--no-enrich", help="Skip EPSS/KEV enrichment (offline mode)."
    ),
) -> None:
    """Re-match an SBOM on a schedule; notify only new/resolved/changed findings.

    Persists a findings snapshot in `state_dir` between runs, keyed by the SBOM's resolved
    path, so the diff survives process restarts. With no `--interval`, runs one
    check-and-diff cycle and exits (0 clean, 1 if anything changed, 2 on error) - the same
    as passing `--once` explicitly. `--interval` loops the same cycle forever
    (Ctrl+C to stop); a persistent failure (EUVD unreachable, webhook down) stops the loop
    with exit 2 rather than retrying silently forever - rerun once the problem is fixed.
    """
    state: GlobalState = ctx.obj
    settings = state.settings

    if interval is not None and once:
        typer.echo("--interval and --once are mutually exclusive.", err=True)
        raise typer.Exit(code=2)

    seconds: float | None = None
    if interval is not None:
        try:
            seconds = _parse_interval(interval)
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=2) from exc

    # StdoutSink is the human ("table" mode) display; JSON mode prints a structured diff
    # instead (see _echo_cycle_summary) - both never fire together, same as every other
    # command's --output contract.
    sinks: list[NotificationSink] = [StdoutSink()] if state.output is OutputFormat.TABLE else []
    api: ApiClient | None = None
    if webhook is not None:
        api = ApiClient(settings.cache_dir, settings.cache_ttl_hours)
        sinks.append(WebhookSink(api, webhook))

    try:
        if seconds is None:
            diff = _run_watch_cycle(settings, sbom, no_enrich=no_enrich, sinks=sinks)
            _echo_cycle_summary(diff, state.output)
            if not diff.is_empty:
                raise typer.Exit(code=1)
            return

        typer.echo(f"Watching {sbom} every {interval}. Press Ctrl+C to stop.", err=True)
        try:
            while True:
                diff = _run_watch_cycle(settings, sbom, no_enrich=no_enrich, sinks=sinks)
                _echo_cycle_summary(diff, state.output)
                time.sleep(seconds)
        except KeyboardInterrupt:
            typer.echo("Interrupted.", err=True)
    except ApiError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    finally:
        if api is not None:
            api.close()


@db_app.command("migrate")
@cli_command
def db_migrate(ctx: typer.Context) -> None:
    """Apply pending schema migrations to the consolidated state DB.

    Also imports state from the pre-6.1 layout (`cra-events.sqlite`, `watch/*.json`)
    and renames the imported originals with a `.migrated-<stamp>` suffix. Safe to run
    any number of times: an up-to-date store is a no-op. Every state-touching command
    migrates transparently anyway; this command exists to do it explicitly (e.g. right
    after an upgrade) and to show what happened.
    """
    state: GlobalState = ctx.obj
    store = Store(state.settings.state_dir)
    try:
        report = store.migrate()
    finally:
        store.close()

    if state.output is OutputFormat.JSON:
        typer.echo(report.model_dump_json())
        return
    if report.is_noop:
        typer.echo(f"State DB {store.path} is up to date; nothing to migrate.")
        return
    typer.echo(f"State DB: {store.path}")
    if report.applied_versions:
        typer.echo(f"Applied migration(s): {', '.join(map(str, report.applied_versions))}")
    if report.renamed_legacy:
        typer.echo(
            f"Imported {report.imported_events} event(s) and {report.imported_snapshots} "
            f"watch snapshot(s) from the pre-6.1 layout."
        )
        for renamed in report.renamed_legacy:
            typer.echo(f"  original kept as: {renamed}")


if __name__ == "__main__":
    app()
