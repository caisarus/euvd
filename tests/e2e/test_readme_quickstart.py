"""X.1 (plans/test_plan.md): the README quickstart is executed, so docs can't drift.

Every `euvd-watch ...` line in the README's Quickstart code block runs through the real
CLI against the demo SBOM with the network mocked. A renamed command or flag makes the
line exit 2 (usage error) and fails this test. Non-euvd-watch lines (pip, syft) are
environment setup for humans and are skipped; `--interval 6h` is rewritten to `--once`
because this test must terminate — both flags belong to the same command surface, so a
drift in either still fails the run.
"""

import re
import shutil
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from typer.testing import CliRunner

from euvd_watch.cli import app

pytestmark = pytest.mark.e2e

REPO = Path(__file__).resolve().parents[2]
README = REPO / "README.md"
DEMO_SBOM = REPO / "examples" / "sboms" / "demo.cdx.json"

BASE = "https://euvdservices.enisa.europa.eu/api"
EPSS = "https://api.first.org/data/v1/epss"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

runner = CliRunner()

# The rewrites this test applies to run documentation commands in a test harness. Keys
# must keep matching the README: if a documented flag changes, the command still runs
# (and exits 2 on a genuinely wrong flag), so drift is caught either way.
REWRITES = {"--interval 6h": "--once"}


def quickstart_commands() -> list[str]:
    """The `euvd-watch ...` lines of the first fenced block after '## Quickstart'."""
    text = README.read_text(encoding="utf-8")
    section = text.split("## Quickstart", 1)[1]
    block = re.search(r"```bash\n(.*?)```", section, flags=re.DOTALL)
    assert block, "README quickstart has no bash code block"
    commands = [
        line.strip()
        for line in block.group(1).splitlines()
        if line.strip().startswith("euvd-watch ")
    ]
    assert commands, "README quickstart contains no euvd-watch commands"
    return commands


def _mock_network() -> None:
    def search(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("exploited") == "true":
            record = {
                "id": "EUVD-README-0001",
                "description": "Seeded quickstart record (matches demo SBOM jinja2).",
                "aliases": "CVE-2099-0001\n",
                "exploitedSince": "Jan 1, 2026, 12:00:00 AM",
                "enisaIdProduct": [{"product": {"name": "jinja2"}, "product_version": "<3.1.7"}],
            }
            return httpx.Response(200, json={"items": [record], "total": 1})
        return httpx.Response(200, json={"items": [], "total": 0})

    respx.get(f"{BASE}/search").mock(side_effect=search)
    respx.get(EPSS).mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(KEV).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))


@respx.mock
def test_readme_quickstart_commands_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_network()
    monkeypatch.chdir(tmp_path)
    shutil.copy(DEMO_SBOM, tmp_path / "sbom.cdx.json")
    env = {
        "EUVD_WATCH_CACHE_DIR": str(tmp_path / "cache"),
        "EUVD_WATCH_STATE_DIR": str(tmp_path / "state"),
        "COLUMNS": "300",
    }

    for command in quickstart_commands():
        for documented, harness in REWRITES.items():
            command = command.replace(documented, harness)
        args = command.split()[1:]  # drop the program name
        result: Any = runner.invoke(app, args, env=env)
        # 0 (clean) and 1 (findings/events - expected with the seeded record) are both
        # documented outcomes; 2 means the documented command line no longer exists.
        assert result.exit_code in (0, 1), (
            f"README quickstart line failed: {command!r}\nexit {result.exit_code}\n{result.output}"
        )
