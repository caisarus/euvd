"""Covers implementation_plan.md Step 0.2: CLI command surface stability."""

import pytest
from typer.testing import CliRunner

from euvd_watch import __version__
from euvd_watch.cli import app

pytestmark = pytest.mark.e2e

runner = CliRunner()


def test_version_prints_version_and_exits_zero() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


@pytest.mark.parametrize(
    "args",
    [
        ["watch", "sbom.json"],
        ["cra", "check", "sbom.json"],
    ],
)
def test_stub_commands_exit_two_and_say_not_implemented(args: list[str]) -> None:
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "not implemented yet" in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["--help"],
        ["version", "--help"],
        ["scan", "--help"],
        ["match", "--help"],
        ["watch", "--help"],
        ["vex", "--help"],
        ["vex", "generate", "--help"],
        ["cra", "--help"],
        ["cra", "check", "--help"],
    ],
)
def test_help_renders_for_every_command(args: list[str]) -> None:
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    assert "Usage" in result.output


def test_no_args_shows_help() -> None:
    # no_args_is_help=True: Typer prints full usage but treats this as a non-zero exit.
    result = runner.invoke(app, [])
    assert result.exit_code == 2
    assert "Usage" in result.output
    assert "Commands" in result.output


def test_global_output_option_accepts_json() -> None:
    result = runner.invoke(app, ["--output", "json", "version"])
    assert result.exit_code == 0


def test_missing_explicit_config_file_exits_two() -> None:
    result = runner.invoke(app, ["--config", "/no/such/file.yaml", "version"])
    assert result.exit_code == 2
