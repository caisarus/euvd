# SPDX-License-Identifier: EUPL-1.2
"""EUVD API access patterns (plans/implementation_plan.md Step 2.2).

Endpoints and quirks verified live on 2026-07-10 and documented in docs/euvd-api.md.
Notably: the dedicated CVE-lookup endpoint (`/vulnerability?id=CVE-...`) returns HTTP 403
for every CVE (dead or auth-gated), so `get_by_cve` goes through search + exact alias
filtering instead. The search endpoint caps `size` at 100 and paginates 0-based.
"""

from __future__ import annotations

import logging
from typing import Any

from euvd_watch.euvd.models import EuvdRecord, parse_record, parse_records
from euvd_watch.http import ApiClient, ApiError

logger = logging.getLogger(__name__)

PAGE_SIZE = 100
# Safety valve for pagination: 200 pages x 100 = 20k records, far above today's exploited
# catalog (~1.6k). Prevents an API bug (bad `total`) from turning into an infinite loop.
MAX_PAGES = 200


class EuvdClient:
    """Typed access to the EUVD API. All HTTP goes through the shared ApiClient."""

    def __init__(self, api: ApiClient, base_url: str) -> None:
        self._api = api
        self._base = base_url.rstrip("/")

    def _search_pages(self, params: dict[str, Any]) -> list[EuvdRecord]:
        """Fetch every page of a /search query, tolerating a shrinking/buggy `total`.

        Records are deduplicated by euvd_id (first occurrence wins): pages are fetched —
        and cached — at different moments, so a catalog shift can surface the same record
        on two pages (M2 review 3.2). Unique records are part of this method's contract.
        """
        records: list[EuvdRecord] = []
        seen: set[str] = set()
        page = 0
        while page < MAX_PAGES:
            data = self._api.get_json(
                f"{self._base}/search", {**params, "page": page, "size": PAGE_SIZE}
            )
            # An unreadable page is missing data, never "no results". This used to `break`
            # and return whatever had accumulated, so a beta-API envelope change (or a 204)
            # surfaced as a confident "0 findings", exit 0 - a green CI gate built on
            # nothing. Same rule as a 4xx body (feedback_m2.md finding 1.1): fail loudly and
            # let the caller decide. The legitimately-empty shape is {"items": [], ...}.
            if not isinstance(data, dict) or not isinstance(data.get("items"), list):
                raise ApiError(
                    f"unexpected shape from {self._base}/search (page {page}, params "
                    f"{params!r}): expected an object with an 'items' list, got "
                    f"{type(data).__name__}"
                    + (f" with keys {sorted(data)!r}" if isinstance(data, dict) else "")
                )
            items = data["items"]
            for record in parse_records(items):
                if record.euvd_id not in seen:
                    seen.add(record.euvd_id)
                    records.append(record)
            total = data.get("total")
            page += 1
            if len(items) < PAGE_SIZE:
                break
            if isinstance(total, int) and page * PAGE_SIZE >= total:
                break
        else:
            logger.warning("Pagination stopped at the %d-page safety limit: %r", MAX_PAGES, params)
        return records

    def fetch_exploited(self) -> list[EuvdRecord]:
        """The full actively-exploited catalog (tier 1 of the match query strategy).

        Uses search?exploited=true: the dedicated /exploitedvulnerabilities endpoint only
        returns the latest few records, not the catalog.
        """
        return self._search_pages({"exploited": "true"})

    def fetch_latest(self) -> list[EuvdRecord]:
        """The most recently published records (small feed)."""
        data = self._api.get_json(f"{self._base}/lastvulnerabilities")
        return parse_records(data if isinstance(data, list) else [])

    def search_product(self, product: str) -> list[EuvdRecord]:
        """Keyword search by product name (tier 2 of the match query strategy)."""
        return self._search_pages({"product": product})

    def search_vendor(self, vendor: str) -> list[EuvdRecord]:
        """Keyword search by vendor name."""
        return self._search_pages({"vendor": vendor})

    def get_by_euvd_id(self, euvd_id: str) -> EuvdRecord | None:
        """Lookup by EUVD id. The API answers a missing id with HTTP 204 (empty body)."""
        data = self._api.get_json(f"{self._base}/enisaid", {"id": euvd_id})
        if not isinstance(data, dict):
            return None
        return parse_record(data)

    def get_by_cve(self, cve: str) -> EuvdRecord | None:
        """Lookup by CVE alias.

        The dedicated /vulnerability endpoint 403s for every CVE, so this searches the
        full-text index and filters for an exact alias match client-side.
        """
        for record in self._search_pages({"text": cve}):
            if cve in record.aliases:
                return record
        return None
