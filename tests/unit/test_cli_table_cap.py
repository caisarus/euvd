"""Covers M0/M1 review 3.7 (closed at M6 Step 6.2): the CLI's human-readable tables
cap unbounded output with an "... and N more" footer instead of printing everything.

`--output json` is untouched by this cap (asserted implicitly: these tests only ever
call the table-rendering helpers, never the JSON path).
"""

import pytest

from euvd_watch.cli import _TABLE_ROW_LIMIT, _echo_row_limit_note, _render_findings_table
from euvd_watch.euvd.match import Confidence, Finding, Strategy
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.models import Component, SourceFormat

pytestmark = pytest.mark.unit


def _finding(n: int) -> Finding:
    return Finding(
        component=Component(
            name=f"pkg{n:04d}",
            version="1.0.0",
            source_format=SourceFormat.CYCLONEDX,
            raw_ref="r",
        ),
        record=EuvdRecord(euvd_id=f"EUVD-{n:04d}"),
        confidence=Confidence.LOW,
        strategy=Strategy.FUZZY,
        explanation="x",
    )


def test_row_limit_note_silent_when_under_the_cap(capsys: pytest.CaptureFixture[str]) -> None:
    _echo_row_limit_note(_TABLE_ROW_LIMIT)
    captured = capsys.readouterr()
    assert captured.err == ""


def test_row_limit_note_reports_the_overflow(capsys: pytest.CaptureFixture[str]) -> None:
    _echo_row_limit_note(_TABLE_ROW_LIMIT + 7)
    captured = capsys.readouterr()
    assert "7 more" in captured.err
    assert "--output json" in captured.err


def test_findings_table_caps_rows_and_reports_overflow(capsys: pytest.CaptureFixture[str]) -> None:
    findings = [_finding(i) for i in range(_TABLE_ROW_LIMIT + 5)]
    _render_findings_table(findings, title="test")
    captured = capsys.readouterr()
    # The table (rich, stdout) shows only the capped rows; the footer note (stderr)
    # names the overflow.
    assert captured.out.count("EUVD-") == _TABLE_ROW_LIMIT
    assert "5 more" in captured.err


def test_findings_table_under_the_cap_shows_every_row(capsys: pytest.CaptureFixture[str]) -> None:
    findings = [_finding(i) for i in range(10)]
    _render_findings_table(findings, title="test")
    captured = capsys.readouterr()
    assert captured.out.count("EUVD-") == 10
    assert captured.err == ""
