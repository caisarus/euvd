"""CISA Known Exploited Vulnerabilities catalog membership (Step 2.4). 24 h cache TTL."""

from __future__ import annotations

import logging

from euvd_watch.http import ApiClient, ApiError

logger = logging.getLogger(__name__)

TTL_SECONDS = 24 * 3600


def fetch_kev_cves(api: ApiClient, feed_url: str) -> set[str]:
    """The set of CVE ids in the KEV catalog (one cached download).

    Raises ApiError if the feed isn't shaped like a KEV catalog. This is deliberate
    (feedback_m2.md finding 2.1): a malformed body must not be read as "an empty catalog"
    - enrich() would then stamp in_kev=False (provably not in KEV) from garbage data,
    which M4's CRA trigger (cisa_kev == true) could act on. Raising here routes through
    enrich()'s existing degrade-to-None path instead.
    """
    data = api.get_json(feed_url, ttl_seconds=TTL_SECONDS)
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ApiError(f"KEV feed at {feed_url} is not shaped like a catalog: {data!r:.200}")
    cves: set[str] = set()
    for entry in data["vulnerabilities"]:
        if isinstance(entry, dict) and entry.get("cveID"):
            cves.add(str(entry["cveID"]))
    return cves
