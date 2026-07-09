"""Typer CLI entry point. Commands are stubs until their owning milestone lands."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from euvd_watch import __version__
from euvd_watch.config import ConfigError, Settings, load_settings
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
    typer.echo(summary, err=True)

    if state.output is OutputFormat.JSON:
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


@app.command()
def match(sbom: str = typer.Argument(..., help="Path to a CycloneDX/SPDX SBOM file.")) -> None:
    """Match SBOM components against the EUVD."""
    _not_implemented("match")


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
