"""Conservative statement rules (Step 3.2): findings -> draft VEX statements.

The credibility of the tool: it must never auto-suppress real risk. Automation only
asserts safety when it can prove and explain it. Default for every evaluation -
Outcome.MATCH (a real finding) or Outcome.NOT_AFFECTED alike - is under_investigation.
`not_affected` is auto-drafted only by ProvablyOutsideRule, and only for Evaluations the
matcher already classified as Outcome.NOT_AFFECTED - which itself requires product+vendor
identity at least as strong as a real match, a non-tokenwise version scheme, and a
non-synthesized component identifier (euvd/match.py). `affected`/`fixed` are never
auto-asserted; they come only from human decisions (vex/decisions.py, Step 3.3).

Rules are small classes with `applies(evaluation) -> Decision | None`, run through a
registry: first-match-wins is forbidden. If more than one rule fires on the same
evaluation and they disagree on status, the conflict is logged and the result falls back
to under_investigation - defensive scaffolding for when a second rule is added later, even
though only one rule ships today.
"""

from __future__ import annotations

import logging
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from euvd_watch.euvd.match import Evaluation, Outcome
from euvd_watch.vex.model import Justification, Status

logger = logging.getLogger(__name__)


class Decision(BaseModel):
    """A drafted (or default) VEX status for one evaluation, with its own explanation."""

    model_config = ConfigDict(frozen=True)

    status: Status
    justification: Justification | None = None
    explanation: str


UNDER_INVESTIGATION = Decision(
    status=Status.UNDER_INVESTIGATION,
    explanation="No automated rule could establish safety; awaiting human review.",
)


class Rule(Protocol):
    """A pure function from one Evaluation to an optional Decision."""

    name: str

    def applies(self, evaluation: Evaluation) -> Decision | None: ...


class ProvablyOutsideRule:
    """The one real rule: version provably outside the affected range.

    Fires only on Outcome.NOT_AFFECTED, which the matcher already restricts to strong
    identity evidence, a trustworthy version scheme, and a non-synthesized identifier -
    this rule adds no further conditions, it just translates that outcome into VEX terms.

    Justification is `component_not_present` (owner decision, 2026-07-10): the proof is
    that the *component at an affected version* is not present in the product. We have not
    inspected any code, so `vulnerable_code_not_present` would claim more than the
    evidence supports. Humans remain free to use any justification in vex-decisions.yaml.
    """

    name = "provably_outside"

    def applies(self, evaluation: Evaluation) -> Decision | None:
        if evaluation.outcome is not Outcome.NOT_AFFECTED:
            return None
        return Decision(
            status=Status.NOT_AFFECTED,
            justification=Justification.COMPONENT_NOT_PRESENT,
            explanation=evaluation.explanation,
        )


DEFAULT_RULES: list[Rule] = [ProvablyOutsideRule()]


def decide(evaluation: Evaluation, rules: list[Rule] | None = None) -> Decision:
    """Apply every rule to one evaluation; under_investigation by default or on disagreement."""
    active_rules = DEFAULT_RULES if rules is None else rules
    fired = [(r, d) for r in active_rules if (d := r.applies(evaluation)) is not None]
    if not fired:
        return UNDER_INVESTIGATION

    statuses = {d.status for _, d in fired}
    if len(statuses) > 1:
        names = ", ".join(r.name for r, _ in fired)
        logger.warning(
            "Rules disagree on status for %s vs %s (rules: %s) - falling back to "
            "under_investigation.",
            evaluation.component.name,
            evaluation.record.euvd_id,
            names,
        )
        return UNDER_INVESTIGATION
    return fired[0][1]


def decide_all(
    evaluations: list[Evaluation], rules: list[Rule] | None = None
) -> list[tuple[Evaluation, Decision]]:
    """Batch form of `decide`, preserving the input evaluation order."""
    return [(evaluation, decide(evaluation, rules)) for evaluation in evaluations]
