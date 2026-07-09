"""Covers implementation_plan.md Step 0.1: version is a single source of truth."""

import tomllib
from pathlib import Path

import pytest

from euvd_watch import __version__

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_version_matches_pyproject() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    assert __version__ == pyproject["project"]["version"]
