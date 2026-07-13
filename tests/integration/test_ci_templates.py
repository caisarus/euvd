"""CI template lint (plans/test_plan.md 5.3).

The GitLab include template and every GitHub workflow are validated against their vendored
schemastore schemas (check-jsonschema ships them offline — no network). action.yml gets a
structural contract check: the dogfood job in ci.yml exercises its behavior for real, so
this only pins the published input/output surface.
"""

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]


def _schema_lint(builtin_schema: str, *files: Path) -> None:
    assert files, "no files matched"
    result = subprocess.run(
        [sys.executable, "-m", "check_jsonschema", "--builtin-schema", builtin_schema]
        + [str(f) for f in files],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"{builtin_schema}:\n{result.stdout}{result.stderr}"


def test_gitlab_template_passes_schema_lint() -> None:
    _schema_lint("vendor.gitlab-ci", REPO / "templates" / "euvd-watch.gitlab-ci.yml")


def test_github_workflows_pass_schema_lint() -> None:
    _schema_lint("vendor.github-workflows", *sorted((REPO / ".github" / "workflows").glob("*.yml")))


def test_action_passes_schema_lint() -> None:
    _schema_lint("vendor.github-actions", REPO / "action.yml")


def _load_action() -> dict[str, Any]:
    data = yaml.safe_load((REPO / "action.yml").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_action_is_composite_with_contracted_inputs() -> None:
    action = _load_action()
    assert action["runs"]["using"] == "composite"
    # The published input surface (implementation_plan.md 5.3) — removing one is a breaking
    # change for every consumer workflow.
    assert set(action["inputs"]) >= {"sbom-path", "fail-on", "min-confidence"}
    assert action["inputs"]["sbom-path"]["required"] is True
    assert set(action["outputs"]) == {"exit-code", "findings-file"}


def test_action_steps_are_well_formed() -> None:
    action = _load_action()
    for step in action["runs"]["steps"]:
        # Composite actions require an explicit shell on every `run` step.
        assert "uses" in step or step.get("shell") == "bash", step
