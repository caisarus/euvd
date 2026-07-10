"""FIRST.org EPSS scores, batched by CVE (Step 2.4). 24 h cache TTL."""

from __future__ import annotations

import logging

from euvd_watch.http import ApiClient

logger = logging.getLogger(__name__)

BATCH_SIZE = 100
TTL_SECONDS = 24 * 3600


def fetch_epss_scores(api: ApiClient, base_url: str, cves: list[str]) -> dict[str, float]:
    """EPSS score (0-1) per CVE. Unknown CVEs are simply absent from the result."""
    scores: dict[str, float] = {}
    for start in range(0, len(cves), BATCH_SIZE):
        batch = cves[start : start + BATCH_SIZE]
        data = api.get_json(base_url, {"cve": ",".join(batch)}, ttl_seconds=TTL_SECONDS)
        if not isinstance(data, dict):
            continue
        for row in data.get("data") or []:
            if not isinstance(row, dict):
                continue
            cve = row.get("cve")
            try:
                score = float(row.get("epss", ""))
            except (TypeError, ValueError):
                continue
            if cve:
                scores[str(cve)] = score
    return scores
