# SPDX-License-Identifier: EUPL-1.2
"""Enrichment (Step 2.4): independent exploitation-likelihood signals for the CRA trigger.

EUVD carries some signals; independent FIRST.org EPSS scores and CISA KEV membership make
the M4 reporting trigger defensible. Enrichment failures degrade gracefully — a warning and
None fields, never a failed run.
"""

from __future__ import annotations

import logging

from euvd_watch.enrich.epss import fetch_epss_scores
from euvd_watch.enrich.kev import fetch_kev_cves
from euvd_watch.euvd.match import Finding
from euvd_watch.http import ApiClient, ApiError

logger = logging.getLogger(__name__)


def _cves_of(finding: Finding) -> list[str]:
    return [alias for alias in finding.record.aliases if alias.startswith("CVE-")]


def enrich(findings: list[Finding], api: ApiClient, epss_url: str, kev_url: str) -> list[Finding]:
    """Fill epss_score and in_kev on each finding. Never raises; never mutates matches."""
    all_cves = sorted({cve for finding in findings for cve in _cves_of(finding)})

    epss_scores: dict[str, float] = {}
    try:
        epss_scores = fetch_epss_scores(api, epss_url, all_cves)
    except ApiError as exc:
        logger.warning("EPSS enrichment unavailable, leaving scores empty: %s", exc)

    kev_cves: set[str] | None = None
    try:
        kev_cves = fetch_kev_cves(api, kev_url)
    except ApiError as exc:
        logger.warning("KEV enrichment unavailable, leaving membership unknown: %s", exc)

    enriched: list[Finding] = []
    for finding in findings:
        cves = _cves_of(finding)
        scores = [epss_scores[cve] for cve in cves if cve in epss_scores]
        updates: dict[str, object] = {}
        if scores:
            updates["epss_score"] = max(scores)
        if kev_cves is not None:
            updates["in_kev"] = any(cve in kev_cves for cve in cves)
        enriched.append(finding.model_copy(update=updates) if updates else finding)
    return enriched
