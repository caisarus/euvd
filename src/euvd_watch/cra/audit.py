"""Tamper-evident audit log (Step 4.4): the evidence trail behind "when did you know
and what did you do".

Append-only JSONL. Each line is one entry:

    {"schema_version": 1, "ts": ..., "actor": "tool"|"human", "action": ...,
     "payload": {...}, "payload_digest": sha256(canonical_json(payload)),
     "prev_hash": <previous entry_hash or GENESIS_SEED>,
     "entry_hash": sha256(prev_hash + canonical_json(entry sans entry_hash))}

Canonicalization is FROZEN (asserted by fixture tests, never change silently): JSON with
sorted keys, separators (",", ":"), ensure_ascii=True. Changing any of this invalidates
every existing chain — a canonicalization change requires a new schema_version and an
explicit migration story.

Honest threat model (also documented in docs/cra.md): this chain detects accidental
corruption and any edit, insertion, deletion, or reordering by an actor who cannot
rewrite the whole file. An attacker with full write access to the file can recompute the
entire chain — "tamper-evident" is not "tamper-proof". The system clock is trusted at
append time. For stronger guarantees, periodically anchor the newest entry_hash somewhere
external (a ticket, a signed commit, an e-mail).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# The documented genesis: the first entry's prev_hash. A constant string (not a hash of
# anything) so it is trivially recognizable in the raw file.
GENESIS_SEED = "euvd-watch-audit-genesis-v1"


class AuditError(Exception):
    """Raised when the audit log cannot be safely appended to."""


def canonical_json(obj: Any) -> str:
    """The frozen canonical form hashed by the chain. Do not change (see module docstring)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _entry_hash(prev_hash: str, entry_sans_hash: dict[str, Any]) -> str:
    return _sha256(prev_hash + canonical_json(entry_sans_hash))


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of a full-chain verification pass."""

    ok: bool
    entries: int  # entries verified successfully (all of them when ok)
    bad_line: int | None = None  # 1-based line number of the first failure
    reason: str | None = None
    truncated_tail: bool = False  # last line incomplete: crash-mid-write, not proof of tamper

    def describe(self) -> str:
        if self.ok:
            return f"audit log OK: {self.entries} entries, chain intact"
        kind = "truncated tail (crash mid-write?)" if self.truncated_tail else "chain broken"
        return f"audit log FAILED at line {self.bad_line}: {kind} - {self.reason}"


class AuditLog:
    """Append-only hash-chained JSONL log."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def _last_hash(self) -> tuple[str, bool]:
        """(newest entry_hash or genesis seed, whether a repair newline is needed).

        Refuses to append after damage: extending a log whose tail cannot be parsed would
        bury the evidence under valid-looking entries. Run `cra verify-log` first. The one
        benign tail state — a complete final entry merely missing its newline — is
        repaired by prefixing the next append with a newline.
        """
        if not self._path.exists():
            return GENESIS_SEED, False
        text = self._path.read_text(encoding="utf-8")
        lines = text.splitlines()
        if not lines:
            return GENESIS_SEED, False
        try:
            last = json.loads(lines[-1])
            if not isinstance(last, dict):
                raise TypeError(f"entry is a {type(last).__name__}, not an object")
            return str(last["entry_hash"]), not text.endswith("\n")
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AuditError(
                f"Audit log {self._path} has an unreadable last entry (crash during a "
                f"previous write, or damage): {exc}. Refusing to append; run "
                f"'euvd-watch cra verify-log' and resolve first."
            ) from exc

    def append(
        self,
        action: str,
        payload: dict[str, Any],
        *,
        actor: str = "tool",
        ts: str | None = None,
    ) -> dict[str, Any]:
        """Append one entry and return it. `ts` is pinnable for deterministic tests."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        prev_hash, needs_repair_newline = self._last_hash()
        entry: dict[str, Any] = {
            "schema_version": 1,
            "ts": ts or datetime.now(UTC).isoformat(),
            "actor": actor,
            "action": action,
            "payload": payload,
            "payload_digest": _sha256(canonical_json(payload)),
            "prev_hash": prev_hash,
        }
        entry["entry_hash"] = _entry_hash(prev_hash, entry)
        with self._path.open("a", encoding="utf-8") as handle:
            prefix = "\n" if needs_repair_newline else ""
            handle.write(prefix + canonical_json(entry) + "\n")
        return entry


def verify(path: Path) -> VerificationResult:
    """Recompute the whole chain; O(n), reports the FIRST broken entry precisely."""
    if not path.exists():
        return VerificationResult(ok=True, entries=0)
    text = path.read_text(encoding="utf-8")
    if not text:
        return VerificationResult(ok=True, entries=0)

    lines = text.split("\n")
    incomplete_tail = lines[-1] != ""  # a complete log ends with a newline
    if lines[-1] == "":
        lines = lines[:-1]

    prev_hash = GENESIS_SEED
    for index, line in enumerate(lines, start=1):
        is_last = index == len(lines)
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            if is_last and incomplete_tail:
                return VerificationResult(
                    ok=False,
                    entries=index - 1,
                    bad_line=index,
                    reason=f"incomplete final entry: {exc}",
                    truncated_tail=True,
                )
            return VerificationResult(
                ok=False, entries=index - 1, bad_line=index, reason=f"not valid JSON: {exc}"
            )
        if not isinstance(entry, dict):
            return VerificationResult(
                ok=False, entries=index - 1, bad_line=index, reason="entry is not an object"
            )
        if entry.get("prev_hash") != prev_hash:
            return VerificationResult(
                ok=False,
                entries=index - 1,
                bad_line=index,
                reason=(
                    f"chain link mismatch: prev_hash={entry.get('prev_hash')!r} but the "
                    f"previous entry's hash is {prev_hash!r} (edit, deletion, insertion, "
                    f"or reordering upstream of this line)"
                ),
            )
        recorded_hash = entry.get("entry_hash")
        sans_hash = {k: v for k, v in entry.items() if k != "entry_hash"}
        expected_digest = _sha256(canonical_json(entry.get("payload")))
        if entry.get("payload_digest") != expected_digest:
            return VerificationResult(
                ok=False,
                entries=index - 1,
                bad_line=index,
                reason="payload does not match its digest",
            )
        if recorded_hash != _entry_hash(prev_hash, sans_hash):
            return VerificationResult(
                ok=False,
                entries=index - 1,
                bad_line=index,
                reason="entry_hash does not match entry content",
            )
        prev_hash = str(recorded_hash)

    return VerificationResult(ok=True, entries=len(lines))
