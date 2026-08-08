"""Covers implementation_plan.md Step 6.2: the `web serve` / `web hash-password`
CLI surface (not the dashboard's own HTTP routes - those are in test_web_dashboard.py).

`web serve` itself is a blocking uvicorn.run() call, so it is never invoked directly
here; these tests cover its two guard clauses (missing [web] extra, missing password
hash) and the hashing command, which are what a user actually hits before the server
would ever bind a socket.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from euvd_watch import cli
from euvd_watch.cli import app
from euvd_watch.web.auth import verify_password

pytestmark = pytest.mark.e2e

runner = CliRunner()


def _env(tmp_path: Path) -> dict[str, str]:
    return {"EUVD_WATCH_STATE_DIR": str(tmp_path / "state"), "COLUMNS": "300"}


def test_hash_password_prints_a_verifiable_hash() -> None:
    result = runner.invoke(app, ["web", "hash-password"], input="hunter2\nhunter2\n")
    assert result.exit_code == 0
    hashed = result.stdout.strip().splitlines()[-1]  # prompt echoes precede the hash
    assert hashed.startswith("pbkdf2_sha256$")
    assert verify_password("hunter2", hashed)


def test_hash_password_confirmation_mismatch_fails() -> None:
    result = runner.invoke(app, ["web", "hash-password"], input="hunter2\nsomethingelse\n")
    assert result.exit_code != 0


def test_web_serve_exits_2_when_extra_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_import() -> tuple[object, object]:
        raise cli.WebExtraMissingError()

    monkeypatch.setattr(cli, "_import_web_app", fake_import)
    result = runner.invoke(
        app, ["web", "serve", "examples/sboms/demo.cdx.json"], env=_env(tmp_path)
    )
    assert result.exit_code == 2
    assert "[web] extra" in result.output


def test_web_serve_exits_2_when_password_hash_unset(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["web", "serve", "examples/sboms/demo.cdx.json"], env=_env(tmp_path)
    )
    assert result.exit_code == 2
    assert "password hash" in result.output
    assert "hash-password" in result.output


def test_web_serve_reaches_run_server_once_both_guards_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proves the two guards above are the only things standing between `web serve`
    and actually starting a server - stub run_server so no socket is bound."""
    calls: list[dict[str, object]] = []

    def fake_import() -> tuple[object, object]:
        from euvd_watch.web.app import create_app

        def fake_run_server(application: object, *, host: str, port: int) -> None:
            calls.append({"host": host, "port": port})

        return create_app, fake_run_server

    monkeypatch.setattr(cli, "_import_web_app", fake_import)
    env = _env(tmp_path)
    env["EUVD_WATCH_WEB__PASSWORD_HASH"] = "pbkdf2_sha256$1$aa$bb"
    result = runner.invoke(
        app, ["web", "serve", "examples/sboms/demo.cdx.json", "--port", "9999"], env=env
    )
    assert result.exit_code == 0, result.output
    assert calls == [{"host": "127.0.0.1", "port": 9999}]
