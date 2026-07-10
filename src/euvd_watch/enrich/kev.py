"""CISA Known Exploited Vulnerabilities catalog membership (Step 2.4). 24 h cache TTL."""

from __future__ import annotations

import logging

from euvd_watch.http import ApiClient

logger = logging.getLogger(__name__)

TTL_SECONDS = 24 * 3600


def fetch_kev_cves(api: ApiClient, feed_url: str) -> set[str]:
    """The set of CVE ids in the KEV catalog (one cached download)."""
    data = api.get_json(feed_url, ttl_seconds=TTL_SECONDS)
    if not isinstance(data, dict):
        return set()
    cves: set[str] = set()
    for entry in data.get("vulnerabilities") or []:
        if isinstance(entry, dict) and entry.get("cveID"):
            cves.add(str(entry["cveID"]))
    return cves
