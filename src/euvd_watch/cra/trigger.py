"""Trigger policy engine (Step 4.1): one configurable, defensible definition of "this
crossed the line" for CRA Article 14 purposes.

Pure evaluation - no I/O, no persistence. `first_seen` is deliberately not decided here:
that's the state store's job (cra/state.py), since "when did we first become aware" must
survive across re-runs even as the finding's other details (confidence, EPSS score) change.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from euvd_watch.config import CraTriggerConfig, Settings
from euvd_watch.euvd.match import Confidence, Finding, confidence_at_least

_SIGNAL_NAMES = ("euvd_exploited", "cisa_kev", "epss_over_threshold")


class TriggerResult(BaseModel):
    """A pure evaluation outcome: this finding crossed the configured trigger threshold."""

    model_config = ConfigDict(frozen=True)

    finding: Finding
    fired_rules: list[str]
    policy_snapshot: CraTriggerConfig


def _fired_signals(finding: Finding, config: CraTriggerConfig, epss_threshold: float) -> list[str]:
    fired = []
    if config.euvd_exploited and finding.record.exploited:
        fired.append("euvd_exploited")
    if config.cisa_kev and finding.in_kev:
        fired.append("cisa_kev")
    if (
        config.epss_over_threshold
        and finding.epss_score is not None
        and finding.epss_score >= epss_threshold
    ):
        fired.append("epss_over_threshold")
    return fired


def evaluate_trigger(finding: Finding, settings: Settings) -> TriggerResult | None:
    """Evaluate one finding against the configured CRA trigger policy."""
    config = settings.cra_trigger
    if not confidence_at_least(finding.confidence, Confidence(config.min_confidence)):
        return None

    fired = _fired_signals(finding, config, settings.epss_threshold)
    if not fired:
        return None

    if config.require_all:
        enabled = {
            name
            for name, on in zip(
                _SIGNAL_NAMES,
                (config.euvd_exploited, config.cisa_kev, config.epss_over_threshold),
                strict=True,
            )
            if on
        }
        if set(fired) != enabled:
            return None

    return TriggerResult(finding=finding, fired_rules=fired, policy_snapshot=config)


def evaluate_all(findings: list[Finding], settings: Settings) -> list[TriggerResult]:
    """Evaluate every finding; deterministic ordering by the finding's own dedupe_key."""
    results = [
        result
        for finding in findings
        if (result := evaluate_trigger(finding, settings)) is not None
    ]
    results.sort(key=lambda r: (r.finding.component.dedupe_key, r.finding.record.euvd_id))
    return results
