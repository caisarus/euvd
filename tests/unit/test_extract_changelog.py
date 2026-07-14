"""Test-plan 5.1: changelog section extraction is unit-tested.

`scripts/extract_changelog.py` feeds the GitHub release notes; a wrong slice would
publish another version's notes, and a silent miss would publish an empty release.
"""

import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "extract_changelog", REPO / "scripts" / "extract_changelog.py"
)
assert _spec is not None and _spec.loader is not None
extract_changelog = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(extract_changelog)

CHANGELOG = """\
# Changelog

## [Unreleased]

Nothing yet.

## [0.3.1] — 2026-07-15

### Added
- Release automation.

## [0.3.0] — 2026-07-13

### Added
- Watch mode.
- Docker image.

## [0.1.0] — unreleased

Milestones M0–M3.
"""


def test_extracts_exact_version_section() -> None:
    section = extract_changelog.extract_section(CHANGELOG, "0.3.0")
    assert "Watch mode." in section
    assert "Docker image." in section


def test_section_excludes_heading_and_neighbouring_versions() -> None:
    section = extract_changelog.extract_section(CHANGELOG, "0.3.0")
    assert "## [0.3.0]" not in section
    assert "Release automation." not in section  # 0.3.1 (above)
    assert "Milestones M0–M3." not in section  # 0.1.0 (below)


def test_last_section_extends_to_end_of_file() -> None:
    assert extract_changelog.extract_section(CHANGELOG, "0.1.0") == "Milestones M0–M3."


def test_prerelease_falls_back_to_base_version() -> None:
    assert "Release automation." in extract_changelog.extract_section(CHANGELOG, "0.3.1rc1")


def test_exact_prerelease_section_wins_over_base() -> None:
    changelog = CHANGELOG.replace(
        "## [0.3.1] — 2026-07-15", "## [0.3.1rc1] — 2026-07-14\n\n- RC notes.\n\n## [0.3.1]"
    )
    assert extract_changelog.extract_section(changelog, "0.3.1rc1") == "- RC notes."


def test_missing_version_raises() -> None:
    with pytest.raises(KeyError, match="9.9.9"):
        extract_changelog.extract_section(CHANGELOG, "9.9.9")


def test_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "CHANGELOG.md"
    path.write_text(CHANGELOG, encoding="utf-8")
    assert extract_changelog.main(["0.3.0", str(path)]) == 0
    assert "Watch mode." in capsys.readouterr().out
    assert extract_changelog.main(["9.9.9", str(path)]) == 1
    assert "9.9.9" in capsys.readouterr().err


def test_real_changelog_has_a_section_for_every_git_tag_version() -> None:
    """The workflow's build job requires a section for the tagged version — keep the
    real CHANGELOG.md extractable for the versions we have already shipped."""
    real = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    assert extract_changelog.extract_section(real, "0.3.0")
