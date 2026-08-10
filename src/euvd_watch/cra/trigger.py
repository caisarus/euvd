# SPDX-License-Identifier: EUPL-1.2
"""Trigger policy engine (Step 4.1): one configurable, defensible definition of "this
crossed the line" for CRA Article 14 purposes.

Pure evaluation - no I/O, no persistence. `first_seen` is deliberately not decided here:
that's the state store's job (cra/state.py), since "when did we first become aware" must
survive across re-runs even as the finding's other details (confidence, EPSS score) change.

Three-valued signal logic (audit follow-up 2026-08-09). Each enabled signal is FIRED,
ABSENT, or UNKNOWN, where UNKNOWN means "this signal's data source was unavailable this
run" - distinct from "confirmed absent". For a compliance gate, "we could not check KEV
because the feed was down" must NOT read the same as "confirmed not in KEV": treating them
alike is a false-negative-by-omission that turns a CI run green when it should be
indeterminate. So a finding evaluates to TRIGGERED, CLEAR, or INDETERMINATE, and
`cra check` refuses to report a clean all-clear (exit 0) when any finding is INDETERMINATE.

Signal availability is derived from the findings themselves, so it works identically for a
live match+enrich run and for a replayed `--findings` artifact: enrichment sets `in_kev`
on *every* finding when the KEV feed succeeds (so `in_kev is None` on any finding ⟺ KEV
was unavailable/skipped this run), and sets `epss_score` on the findings whose CVE has a
score (so at least one non-None `epss_score` ⟺ EPSS was consulted). A source that was up
but simply had no score for a given CVE yields ABSENT (a determinate "not over threshold"),
never UNKNOWN - UNKNOWN is reserved for genuine unavailability.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from euvd_watch.config import CraTriggerConfig, Settings
from euvd_watch.euvd.match import Confidence, Finding, confidence_at_least


class SignalState(StrEnum):
    FIRED = "fired"  # the signal's condition is met
    ABSENT = "absent"  # the source was available and the condition is confirmed not met
    UNKNOWN = "unknown"  # the source was unavailable this run - genuinely couldn't check


class Outcome(StrEnum):
    TRIGGERED = "triggered"  # the policy fired
    CLEAR = "clear"  # the policy definitively did not fire (all relevant signals determinate)
    INDETERMINATE = "indeterminate"  # could not decide - an enabled signal's source was down


class TriggerResult(BaseModel):
    """A pure evaluation outcome: this finding crossed the configured trigger threshold."""

    model_config = ConfigDict(frozen=True)

    finding: Finding
    fired_rules: list[str]
    policy_snapshot: CraTriggerConfig
    # The EPSS threshold lives on Settings, not inside CraTriggerConfig - captured here so
    # the fire-time policy is reconstructible verbatim even after the config changes.
    epss_threshold: float


@dataclass(frozen=True)
class SignalAvailability:
    """Whether each enrichment-backed signal's data source was available this run."""

    epss: bool
    kev: bool


@dataclass(frozen=True)
class IndeterminateFinding:
    """A finding whose trigger outcome could not be decided because a required signal's
    data source was unavailable. `unknown_signals` names the enabled signals we couldn't
    check (e.g. `cisa_kev`)."""

    finding: Finding
    unknown_signals: list[str]


@dataclass(frozen=True)
class RunEvaluation:
    """The outcome of evaluating a whole findings list against the trigger policy."""

    triggered: list[TriggerResult]
    indeterminate: list[IndeterminateFinding]
    # Enabled signals whose data source was unavailable this run (for a loud warning).
    unavailable_signals: list[str]


def signal_availability(findings: list[Finding]) -> SignalAvailability:
    """Infer, from the findings' enrichment fields, which signal sources were available.

    See the module docstring for why these field-presence checks are exact: enrichment
    populates `in_kev` on all findings when KEV succeeds, and `epss_score` where a score
    exists. Empty findings list -> both unavailable (there is nothing to gate on anyway).
    """
    return SignalAvailability(
        epss=any(f.epss_score is not None for f in findings),
        kev=any(f.in_kev is not None for f in findings),
    )


def _signal_states(
    finding: Finding, config: CraTriggerConfig, epss_threshold: float, avail: SignalAvailability
) -> dict[str, SignalState]:
    """Per-enabled-signal state for one finding. Disabled signals are omitted entirely."""
    states: dict[str, SignalState] = {}
    if config.euvd_exploited:
        # Always determinate: `exploited` is a property of the EUVD record itself.
        states["euvd_exploited"] = (
            SignalState.FIRED if finding.record.exploited else SignalState.ABSENT
        )
    if config.cisa_kev:
        if not avail.kev:
            states["cisa_kev"] = SignalState.UNKNOWN
        else:
            states["cisa_kev"] = SignalState.FIRED if finding.in_kev else SignalState.ABSENT
    if config.epss_over_threshold:
        if not avail.epss:
            states["epss_over_threshold"] = SignalState.UNKNOWN
        elif finding.epss_score is not None and finding.epss_score >= epss_threshold:
            states["epss_over_threshold"] = SignalState.FIRED
        else:
            # Source available but no score, or a score below threshold: determinately absent.
            states["epss_over_threshold"] = SignalState.ABSENT
    return states


@dataclass(frozen=True)
class _Classification:
    outcome: Outcome
    fired_rules: list[str]
    unknown_signals: list[str]


def _classify(finding: Finding, settings: Settings, avail: SignalAvailability) -> _Classification:
    """Classify one finding as TRIGGERED / CLEAR / INDETERMINATE under the policy."""
    config = settings.cra_trigger
    if not confidence_at_least(finding.confidence, Confidence(config.min_confidence)):
        # Below the confidence bar: deliberately excluded from triggering, and NOT
        # indeterminate - low-confidence matches exist for human review, and their signal
        # availability is irrelevant because they can never start a legal clock.
        return _Classification(Outcome.CLEAR, [], [])

    states = _signal_states(finding, config, settings.epss_threshold, avail)
    if not states:
        return _Classification(Outcome.CLEAR, [], [])  # no signals enabled: can never fire

    fired = [name for name, state in states.items() if state is SignalState.FIRED]
    unknown = [name for name, state in states.items() if state is SignalState.UNKNOWN]

    if config.require_all:
        # Conjunction: every enabled signal must fire.
        if all(state is SignalState.FIRED for state in states.values()):
            return _Classification(Outcome.TRIGGERED, fired, [])
        # A confirmed-ABSENT signal makes the conjunction definitively impossible -> clear,
        # regardless of any unknowns (the absent one alone sinks it).
        if any(state is SignalState.ABSENT for state in states.values()):
            return _Classification(Outcome.CLEAR, [], [])
        # No absent signal, but not all fired: only unknowns are blocking -> indeterminate.
        return _Classification(Outcome.INDETERMINATE, fired, unknown)

    # Disjunction: any enabled signal firing triggers.
    if fired:
        return _Classification(Outcome.TRIGGERED, fired, [])
    if unknown:
        # Nothing fired, but a signal we couldn't check might have -> indeterminate.
        return _Classification(Outcome.INDETERMINATE, [], unknown)
    return _Classification(Outcome.CLEAR, [], [])


def _trigger_result(finding: Finding, settings: Settings, fired_rules: list[str]) -> TriggerResult:
    return TriggerResult(
        finding=finding,
        fired_rules=fired_rules,
        policy_snapshot=settings.cra_trigger,
        epss_threshold=settings.epss_threshold,
    )


def evaluate_trigger(finding: Finding, settings: Settings) -> TriggerResult | None:
    """Evaluate one finding against the configured CRA trigger policy.

    Returns a TriggerResult iff the finding definitively TRIGGERED; None otherwise (CLEAR
    *or* INDETERMINATE). This TRIGGERED/None contract is unchanged from before the
    three-valued refactor - a signal can only FIRE when its data is present, so a
    finding's TRIGGERED verdict never depends on run-level availability. Use
    `evaluate_run` when the indeterminate distinction matters (i.e. in `cra check`).
    """
    avail = signal_availability([finding])
    classification = _classify(finding, settings, avail)
    if classification.outcome is Outcome.TRIGGERED:
        return _trigger_result(finding, settings, classification.fired_rules)
    return None


def evaluate_all(findings: list[Finding], settings: Settings) -> list[TriggerResult]:
    """Every finding that TRIGGERED; deterministic ordering by the finding's own dedupe_key."""
    return evaluate_run(findings, settings).triggered


def evaluate_run(findings: list[Finding], settings: Settings) -> RunEvaluation:
    """Evaluate a whole findings list: which triggered, which are indeterminate, and which
    enabled signals had unavailable sources this run.

    Availability is computed once across all findings, so a finding with no EPSS score is
    treated as ABSENT when *some* finding in the run carries EPSS data (the source was up),
    and only UNKNOWN when the source was genuinely unavailable for the whole run.
    """
    avail = signal_availability(findings)
    config = settings.cra_trigger

    triggered: list[TriggerResult] = []
    indeterminate: list[IndeterminateFinding] = []
    for finding in findings:
        classification = _classify(finding, settings, avail)
        if classification.outcome is Outcome.TRIGGERED:
            triggered.append(_trigger_result(finding, settings, classification.fired_rules))
        elif classification.outcome is Outcome.INDETERMINATE:
            indeterminate.append(
                IndeterminateFinding(
                    finding=finding, unknown_signals=classification.unknown_signals
                )
            )

    triggered.sort(key=lambda r: (r.finding.component.dedupe_key, r.finding.record.euvd_id))
    indeterminate.sort(
        key=lambda i: (i.finding.component.dedupe_key, i.finding.record.euvd_id)
    )

    unavailable: list[str] = []
    if config.cisa_kev and not avail.kev:
        unavailable.append("cisa_kev")
    if config.epss_over_threshold and not avail.epss:
        unavailable.append("epss_over_threshold")

    return RunEvaluation(
        triggered=triggered, indeterminate=indeterminate, unavailable_signals=unavailable
    )
