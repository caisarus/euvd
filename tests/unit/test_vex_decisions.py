"""Covers implementation_plan.md Step 3.3: decisions file loading & validation."""

from pathlib import Path

import pytest

from euvd_watch.vex.decisions import DecisionsError, load_decisions
from euvd_watch.vex.model import Justification, Status

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "vex" / "decisions-examples"


def test_valid_decisions_file_loads() -> None:
    decisions = load_decisions(FIXTURES / "valid.yaml")
    assert len(decisions.decisions) == 2
    first = decisions.decisions[0]
    assert first.euvd_id == "EUVD-TEST-1"
    assert first.status is Status.NOT_AFFECTED
    assert first.justification is Justification.VULNERABLE_CODE_NOT_PRESENT


def test_missing_identifier_is_rejected() -> None:
    with pytest.raises(DecisionsError, match="euvd_id or cve"):
        load_decisions(FIXTURES / "invalid.yaml")


def test_typoed_key_is_rejected_and_named() -> None:
    with pytest.raises(DecisionsError, match="status"):
        load_decisions(FIXTURES / "typo.yaml")


def test_missing_file_raises_actionable_error() -> None:
    with pytest.raises(DecisionsError, match="Could not read"):
        load_decisions(FIXTURES / "does-not-exist.yaml")


def test_non_mapping_yaml_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(DecisionsError, match="mapping"):
        load_decisions(path)


def test_cve_only_identifier_is_sufficient(tmp_path: Path) -> None:
    path = tmp_path / "cve-only.yaml"
    path.write_text(
        "decisions:\n"
        "  - cve: CVE-2026-1\n"
        "    purl: pkg:pypi/widget\n"
        "    status: under_investigation\n"
        "    statement: 'still checking'\n"
        "    author: a@example.com\n"
        "    date: '2026-01-01'\n",
        encoding="utf-8",
    )
    decisions = load_decisions(path)
    assert decisions.decisions[0].cve == "CVE-2026-1"
