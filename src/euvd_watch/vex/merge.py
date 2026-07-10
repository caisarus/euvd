"""Decisions merge (Step 3.3): human decisions override automated drafts.

Precedence is absolute: a matching human decision always wins, even against stronger
automated evidence - but that specific case (human downgrades to not_affected/fixed while
the matcher independently found an actionable MATCH) is a conflict worth a loud warning,
since it's the direction that could hide real risk. Decisions matching nothing current are
reported as stale, so a decisions file doesn't quietly accumulate dead entries.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import NamedTuple

from packageurl import PackageURL

from euvd_watch.euvd.match import Evaluation, Outcome
from euvd_watch.sbom.normalize import normalize_purl, strip_purl_version
from euvd_watch.vex.decisions import DecisionEntry, DecisionsFile
from euvd_watch.vex.model import Status
from euvd_watch.vex.rules import Decision, Rule, decide

logger = logging.getLogger(__name__)

_DOWNGRADE_STATUSES = {Status.NOT_AFFECTED, Status.FIXED}


def _matches(entry: DecisionEntry, evaluation: Evaluation) -> bool:
    id_match = (entry.euvd_id is not None and entry.euvd_id == evaluation.record.euvd_id) or (
        entry.cve is not None and entry.cve in evaluation.record.aliases
    )
    if not id_match:
        return False

    component_purl = evaluation.component.normalized_purl or evaluation.component.purl
    if component_purl is None:
        return False
    # A human typing a decision plausibly copies the purl as it appears in the source SBOM
    # or in `scan`/`match` table output, not necessarily already normalized (feedback_m3.md
    # finding 1.1: an un-normalized entry.purl used to silently never match, defeating the
    # human-in-the-loop mechanism and reporting the decision as "stale" with no diagnostic).
    entry_purl = normalize_purl(entry.purl)
    if entry_purl == component_purl:
        return True
    # A purl with no version acts as a pattern matching any version of that package.
    # Version presence and package identity both come from PackageURL, never string
    # splitting: qualifiers on a versionless purl sit where split("@") expects the version.
    try:
        entry_parsed = PackageURL.from_string(entry_purl)
    except ValueError:
        return False  # unparseable entry purl: only the exact string compare above applies
    if entry_parsed.version is not None:
        return False
    return strip_purl_version(entry_purl) == strip_purl_version(component_purl)


def _is_conflict(entry_status: Status, evaluation: Evaluation) -> bool:
    return entry_status in _DOWNGRADE_STATUSES and evaluation.outcome is Outcome.MATCH


class ResolvedDecision(NamedTuple):
    evaluation: Evaluation
    decision: Decision
    is_human: bool


@dataclass(frozen=True)
class MergeResult:
    decisions: list[ResolvedDecision] = field(default_factory=list)
    stale: list[DecisionEntry] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)


def merge(
    evaluations: list[Evaluation],
    decisions_file: DecisionsFile,
    rules: list[Rule] | None = None,
) -> MergeResult:
    """Resolve every evaluation to a final Decision: human override, else automated draft."""
    matched_entries: set[int] = set()
    resolved: list[ResolvedDecision] = []
    conflicts: list[str] = []

    for evaluation in evaluations:
        entry = next((e for e in decisions_file.decisions if _matches(e, evaluation)), None)
        if entry is None:
            resolved.append(ResolvedDecision(evaluation, decide(evaluation, rules), False))
            continue

        matched_entries.add(id(entry))
        if _is_conflict(entry.status, evaluation):
            message = (
                f"Decision for {evaluation.record.euvd_id} on component "
                f"'{evaluation.component.name}' sets status={entry.status.value}, but "
                f"automation independently found this component matches "
                f"(confidence={evaluation.confidence.value}, "
                f"exploited={evaluation.record.exploited}). The human decision is applied "
                f"regardless, but this conflict is flagged for review."
            )
            logger.warning(message)
            conflicts.append(message)

        human_decision = Decision(
            status=entry.status,
            justification=entry.justification,
            explanation=entry.statement,
        )
        resolved.append(ResolvedDecision(evaluation, human_decision, True))

    stale = [e for e in decisions_file.decisions if id(e) not in matched_entries]
    if stale:
        for entry in stale:
            logger.warning(
                "Stale decision (matches no current evaluation): euvd_id=%s cve=%s purl=%s",
                entry.euvd_id,
                entry.cve,
                entry.purl,
            )

    return MergeResult(decisions=resolved, stale=stale, conflicts=conflicts)
