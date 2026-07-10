"""Typer CLI entry point.

`version` and `scan` are implemented; `match`, `watch`, `vex generate`, and `cra check`
remain stubs until their owning milestone (M2-M4) lands.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from euvd_watch import __version__
from euvd_watch.config import ConfigError, Settings, load_settings
from euvd_watch.enrich import enrich
from euvd_watch.euvd.client import EuvdClient
from euvd_watch.euvd.match import (
    Confidence,
    Finding,
    confidence_at_least,
    derive_candidates,
    match_inventory,
)
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.http import ApiClient, ApiError
from euvd_watch.log import setup_logging
from euvd_watch.models import Inventory
from euvd_watch.sbom import load_inventory_with_stats
from euvd_watch.sbom.errors import SbomParseError, UnsupportedFormatError

app = typer.Typer(no_args_is_help=True, add_completion=False)
vex_app = typer.Typer(no_args_is_help=True)
cra_app = typer.Typer(no_args_is_help=True)
app.add_typer(vex_app, name="vex", help="OpenVEX statement generation.")
app.add_typer(cra_app, name="cra", help="CRA Article 14 reporting workflow.")


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"


@dataclass
class GlobalState:
    settings: Settings
    output: OutputFormat
    verbose: bool


def _not_implemented(command: str) -> None:
    typer.echo(f"'{command}' is not implemented yet.", err=True)
    raise typer.Exit(code=2)


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
def version() -> None:
    """Print the euvd-watch version."""
    typer.echo(__version__)


@app.command()
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


def _findings_artifact(
    findings: list[Finding], inventory: Inventory, data_freshness: str | None
) -> dict[str, object]:
    """The versioned findings artifact consumed later by `vex generate` and `cra check`."""
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "inventory_digest": _inventory_digest(inventory),
        "data_freshness": data_freshness,
        "findings": [f.model_dump(mode="json") for f in findings],
    }


def _fetch_records(
    client: EuvdClient, inventory: Inventory, *, exploited_only: bool
) -> list[EuvdRecord]:
    """Two-tier query strategy (docs/matching.md).

    Tier 1 always syncs the full exploited catalog. Tier 2 adds per-candidate product
    searches, deduplicated across components and served from the HTTP cache. Note the
    cache-first client means "EUVD unreachable but cache fresh" is served transparently;
    an ApiError here means both the network and the cache have nothing usable.
    """
    records: dict[str, EuvdRecord] = {}
    for record in client.fetch_exploited():
        records[record.euvd_id] = record

    if not exploited_only:
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
            records = _fetch_records(client, inventory, exploited_only=exploited_only)
        except ApiError as exc:
            typer.echo(
                f"EUVD is unreachable and the local cache has no usable data: {exc}\n"
                f"Refusing to report 'no findings' on missing data.",
                err=True,
            )
            raise typer.Exit(code=2) from exc

        newest = api.cache.newest_stored_at()
        data_freshness = (
            datetime.fromtimestamp(newest, UTC).isoformat() if newest is not None else None
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

    artifact = _findings_artifact(findings, inventory, data_freshness)
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


@app.command()
def watch(sbom: str = typer.Argument(..., help="Path to a CycloneDX/SPDX SBOM file.")) -> None:
    """Re-match an SBOM on a schedule, reporting only new/changed findings."""
    _not_implemented("watch")


@vex_app.command("generate")
def vex_generate(
    sbom: str = typer.Argument(..., help="Path to a CycloneDX/SPDX SBOM file."),
) -> None:
    """Draft OpenVEX statements for an SBOM's findings."""
    _not_implemented("vex generate")


@cra_app.command("check")
def cra_check(sbom: str = typer.Argument(..., help="Path to a CycloneDX/SPDX SBOM file.")) -> None:
    """Evaluate the CRA reporting trigger against an SBOM's findings."""
    _not_implemented("cra check")


if __name__ == "__main__":
    app()
