"""The watch differ (Step 5.4): what changed since the last run, and nothing else.

Pure evaluation - no I/O, no persistence (mirrors `cra/trigger.py`'s shape). The caller
(`cli.py::watch`) is responsible for loading the previous snapshot and persisting the
current one; this module only ever compares two `Finding` lists in memory.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from euvd_watch.euvd.match import Finding

# Fields whose change makes an otherwise-still-matched finding worth re-notifying about.
_TRACKED_FIELDS = ("confidence", "exploited", "in_kev", "epss_score", "cvss_score")


def _key(finding: Finding) -> str:
    """Stable identity across runs: (component, EUVD record) pair.

    Deliberately not `cra/state.py::Event.make_id` - watch mode must work whether or not
    the CRA trigger is configured/used at all, so `watch/` does not depend on `cra/`.
    """
    return f"{finding.component.dedupe_key}|{finding.record.euvd_id}"


def _tracked_values(finding: Finding) -> dict[str, object]:
    return {
        "confidence": finding.confidence,
        "exploited": finding.record.exploited,
        "in_kev": finding.in_kev,
        "epss_score": finding.epss_score,
        "cvss_score": finding.record.cvss_score,
    }


def _changed_fields(previous: Finding, current: Finding) -> list[str]:
    before = _tracked_values(previous)
    after = _tracked_values(current)
    return [field for field in _TRACKED_FIELDS if before[field] != after[field]]


class ChangedFinding(BaseModel):
    """One (component, record) pair whose tracked fields differ from the last run."""

    model_config = ConfigDict(frozen=True)

    previous: Finding
    current: Finding
    changed_fields: list[str]


class DiffResult(BaseModel):
    """Everything that changed between two findings snapshots, sorted deterministically."""

    model_config = ConfigDict(frozen=True)

    new: list[Finding]
    resolved: list[Finding]
    changed: list[ChangedFinding]

    @property
    def is_empty(self) -> bool:
        return not (self.new or self.resolved or self.changed)


def diff_findings(previous: list[Finding], current: list[Finding]) -> DiffResult:
    """Compare two findings snapshots. Unchanged findings produce no output at all."""
    previous_by_key = {_key(f): f for f in previous}
    current_by_key = {_key(f): f for f in current}

    new = [current_by_key[key] for key in current_by_key if key not in previous_by_key]
    resolved = [previous_by_key[key] for key in previous_by_key if key not in current_by_key]
    changed = [
        ChangedFinding(
            previous=previous_by_key[key], current=current_by_key[key], changed_fields=fields
        )
        for key in current_by_key
        if key in previous_by_key
        and (fields := _changed_fields(previous_by_key[key], current_by_key[key]))
    ]

    new.sort(key=_key)
    resolved.sort(key=_key)
    changed.sort(key=lambda c: _key(c.current))
    return DiffResult(new=new, resolved=resolved, changed=changed)
