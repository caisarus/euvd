"""Covers implementation_plan.md Step 6.1: the `db migrate` command surface.

The Store's own behavior (schema, legacy import, WAL, quarantine) is unit-tested in
tests/unit/test_store.py; here the contract is the CLI one — exit 0, `--output
json|table`, run-twice idempotency, and that earlier commands transparently migrate a
pre-6.1 layout on first contact (the Step 6.1 acceptance criterion).
"""

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from euvd_watch.cli import app
from euvd_watch.web.store import DB_FILENAME

pytestmark = pytest.mark.e2e

runner = CliRunner()
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "db"


def _env(tmp_path: Path) -> dict[str, str]:
    return {
        "EUVD_WATCH_CACHE_DIR": str(tmp_path / "cache"),
        "EUVD_WATCH_STATE_DIR": str(tmp_path / "state"),
        "COLUMNS": "300",
    }


def test_db_migrate_from_empty_then_noop(tmp_path: Path) -> None:
    env = _env(tmp_path)

    first = runner.invoke(app, ["db", "migrate"], env=env)
    assert first.exit_code == 0, first.output
    assert "Applied migration(s): 1" in first.output

    second = runner.invoke(app, ["db", "migrate"], env=env)
    assert second.exit_code == 0, second.output
    assert "up to date" in second.output


def test_db_migrate_json_output(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--output", "json", "db", "migrate"], env=_env(tmp_path))
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["applied_versions"] == [1]
    assert payload["imported_events"] == 0
    assert payload["imported_snapshots"] == 0


def test_db_migrate_imports_legacy_layout_and_reports_it(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    shutil.copytree(FIXTURES / "legacy-pre61", state_dir)

    result = runner.invoke(app, ["db", "migrate"], env=_env(tmp_path))
    assert result.exit_code == 0, result.output
    assert "Imported 1 event(s) and 1 watch snapshot(s)" in result.output
    assert "original kept as:" in result.output
    assert (state_dir / DB_FILENAME).exists()


def test_earlier_commands_migrate_legacy_state_transparently(tmp_path: Path) -> None:
    """`cra status` on a pre-6.1 state dir shows the migrated event with no manual step."""
    state_dir = tmp_path / "state"
    shutil.copytree(FIXTURES / "legacy-pre61", state_dir)

    result = runner.invoke(app, ["cra", "status"], env=_env(tmp_path))
    assert result.exit_code == 0, result.output
    assert "EUVD-FIXTURE-0001" in result.output
    assert not (state_dir / "cra-events.sqlite").exists()  # renamed by the import
