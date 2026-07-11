"""Covers implementation_plan.md Step 4.4: tamper evidence is only as good as its tests."""

import json
from pathlib import Path

import pytest

from euvd_watch.cra.audit import (
    GENESIS_SEED,
    AuditError,
    AuditLog,
    canonical_json,
    verify,
)

pytestmark = pytest.mark.unit


def _build_log(path: Path, entries: int) -> AuditLog:
    log = AuditLog(path)
    for i in range(entries):
        log.append(
            "trigger_event_created",
            {"event_id": f"purl:pkg:pypi/demo@{i}|EUVD-{i}", "index": i},
            ts=f"2026-01-01T00:00:{i % 60:02d}+00:00",
        )
    return log


def test_intact_chain_of_100_entries_verifies(tmp_path: Path) -> None:
    _build_log(tmp_path / "audit.jsonl", 100)
    result = verify(tmp_path / "audit.jsonl")
    assert result.ok
    assert result.entries == 100


def test_missing_log_verifies_as_empty(tmp_path: Path) -> None:
    result = verify(tmp_path / "absent.jsonl")
    assert result.ok
    assert result.entries == 0


def test_genesis_seed_is_the_documented_constant(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _build_log(path, 1)
    first = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert GENESIS_SEED == "euvd-watch-audit-genesis-v1"  # documented; changing it breaks chains
    assert first["prev_hash"] == GENESIS_SEED


@pytest.mark.parametrize("target", [0, 5, 9], ids=["first", "middle", "last"])
def test_tampering_any_single_entry_is_located_exactly(tmp_path: Path, target: int) -> None:
    path = tmp_path / "audit.jsonl"
    _build_log(path, 10)
    lines = path.read_text(encoding="utf-8").splitlines()
    # Flip payload content inside the JSON string - the line stays parseable, the digest
    # must catch it.
    lines[target] = lines[target].replace(f'"index":{target}', f'"index":{target + 100}')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify(path)
    assert not result.ok
    assert result.bad_line == target + 1  # 1-based, named exactly
    assert not result.truncated_tail


def test_deleting_an_entry_is_detected_at_the_gap(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _build_log(path, 10)
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[4]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify(path)
    assert not result.ok
    assert result.bad_line == 5  # the entry now sitting where the deleted one was
    assert "chain link mismatch" in (result.reason or "")


def test_reordering_entries_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _build_log(path, 10)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[2], lines[3] = lines[3], lines[2]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert verify(path).bad_line == 3


def test_valid_appends_after_a_tamper_do_not_hide_it(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = _build_log(path, 5)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"index":1', '"index":999')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log.append("later_action", {"looks": "legitimate"})  # extends the (tampered) chain

    result = verify(path)
    assert not result.ok
    assert result.bad_line == 2  # still located at the original tamper point


def test_truncated_tail_is_distinguished_from_tampering(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _build_log(path, 3)
    text = path.read_text(encoding="utf-8")
    path.write_text(text[:-25], encoding="utf-8")  # chop mid-way through the last entry

    result = verify(path)
    assert not result.ok
    assert result.bad_line == 3
    assert result.truncated_tail  # crash-mid-write, reported distinctly from tamper


def test_append_refuses_to_extend_a_damaged_log(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = _build_log(path, 3)
    path.write_text(path.read_text(encoding="utf-8")[:-25], encoding="utf-8")
    with pytest.raises(AuditError, match="verify-log"):
        log.append("more", {"x": 1})


def test_append_repairs_a_missing_final_newline(tmp_path: Path) -> None:
    # The one benign tail state: complete final entry, newline lost.
    path = tmp_path / "audit.jsonl"
    log = _build_log(path, 2)
    path.write_text(path.read_text(encoding="utf-8").rstrip("\n"), encoding="utf-8")
    log.append("more", {"x": 1})
    result = verify(path)
    assert result.ok
    assert result.entries == 3


def test_canonicalization_ignores_key_order_and_whitespace(tmp_path: Path) -> None:
    a = canonical_json({"b": 1, "a": {"y": 2, "x": [1, 2]}})
    b = canonical_json({"a": {"x": [1, 2], "y": 2}, "b": 1})
    assert a == b == '{"a":{"x":[1,2],"y":2},"b":1}'


def test_canonical_form_is_ascii_only(tmp_path: Path) -> None:
    # Frozen canonicalization: unicode always escapes identically regardless of platform.
    assert canonical_json({"org": "Țesătorie"}) == '{"org":"\\u021aes\\u0103torie"}'


def test_zero_byte_file_appends_from_genesis_and_verifies_empty(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    assert verify(path).ok
    assert verify(path).entries == 0
    log = AuditLog(path)
    assert log.path == path
    entry = log.append("first", {"x": 1})
    assert entry["prev_hash"] == GENESIS_SEED
    assert verify(path).ok


def test_mid_file_garbage_line_is_a_tamper_not_a_truncation(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _build_log(path, 4)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = "this is not json at all"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = verify(path)
    assert not result.ok
    assert result.bad_line == 2
    assert not result.truncated_tail


def test_entry_that_is_not_an_object_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _build_log(path, 2)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines.append('["an", "array"]')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = verify(path)
    assert not result.ok
    assert result.bad_line == 3
    assert "not an object" in (result.reason or "")


def test_append_refuses_when_last_entry_is_not_an_object(tmp_path: Path) -> None:
    # Review finding: a last line that is valid JSON but not a dict (e.g. an array, a
    # bare number) must raise the documented AuditError, not an uncaught TypeError from
    # indexing a non-dict with "entry_hash" - that would escape cli_command's OSError-only
    # boundary as a raw traceback instead of the clean "run verify-log" message.
    path = tmp_path / "audit.jsonl"
    path.write_text("[1,2,3]\n", encoding="utf-8")
    with pytest.raises(AuditError, match="verify-log"):
        AuditLog(path).append("more", {"x": 1})


def test_unicode_payload_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("draft_rendered", {"organization": "Exemplu Țesătorie S.R.L."})
    assert verify(path).ok
    entry = json.loads(path.read_text(encoding="utf-8"))
    assert entry["payload"]["organization"] == "Exemplu Țesătorie S.R.L."
