# SPDX-License-Identifier: EUPL-1.2
"""The single disciplined HTTP layer (plans/implementation_plan.md Step 2.1).

The EUVD API is beta with unknown rate limits; one client with retry/backoff and an
on-disk cache protects both the user and ENISA's service, and makes everything testable.
Every other module receives an ApiClient instance — nothing else may import httpx
(enforced by an invariant test).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import random
import sqlite3
import time
from pathlib import Path
from typing import Any

import httpx

from euvd_watch import __version__

logger = logging.getLogger(__name__)

USER_AGENT = f"euvd-watch/{__version__} (+https://github.com/euvd-watch/euvd-watch)"
MAX_RETRIES = 5
RETRYABLE_STATUSES = {429, 500, 502, 503, 504}


class ApiError(Exception):
    """Raised when a request ultimately fails (after retries) or returns unusable data."""


class Cache:
    """Small SQLite-backed response cache: key -> (body, etag, stored_at).

    A corrupted database self-heals: the file is dropped and recreated with a warning,
    because a broken cache must never break a scan.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._connect()

    def _connect(self, *, retry_on_corruption: bool = True) -> None:
        self._conn = sqlite3.connect(self._path)
        try:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS responses ("
                "  key TEXT PRIMARY KEY,"
                "  body TEXT NOT NULL,"
                "  etag TEXT,"
                "  stored_at REAL NOT NULL"
                ")"
            )
            self._conn.commit()
        except sqlite3.DatabaseError:
            # Pre-existing garbage at the cache path; a broken cache must never break a run.
            if not retry_on_corruption:
                raise
            self._self_heal(reconnect_retry=False)

    def _self_heal(self, *, reconnect_retry: bool = True) -> None:
        logger.warning("Cache at %s is corrupted; dropping and recreating it.", self._path)
        with contextlib.suppress(sqlite3.Error):
            self._conn.close()
        self._path.unlink(missing_ok=True)
        self._connect(retry_on_corruption=reconnect_retry)

    def get(self, key: str) -> tuple[str, str | None, float] | None:
        """Return (body, etag, stored_at) or None. Never raises on a broken cache."""
        try:
            row = self._conn.execute(
                "SELECT body, etag, stored_at FROM responses WHERE key = ?", (key,)
            ).fetchone()
        except sqlite3.Error:
            self._self_heal()
            return None
        if row is None:
            return None
        return (row[0], row[1], row[2])

    def set(self, key: str, body: str, etag: str | None, stored_at: float) -> None:
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO responses (key, body, etag, stored_at) VALUES (?, ?, ?, ?)",
                (key, body, etag, stored_at),
            )
            self._conn.commit()
        except sqlite3.Error:
            self._self_heal()

    def purge(self) -> None:
        try:
            self._conn.execute("DELETE FROM responses")
            self._conn.commit()
        except sqlite3.Error:
            self._self_heal()

    def newest_stored_at(self) -> float | None:
        """Timestamp of the freshest cached entry (diagnostics only — data_freshness
        stamping uses ApiClient.oldest_served_stored_at, the responses actually used)."""
        try:
            row = self._conn.execute("SELECT MAX(stored_at) FROM responses").fetchone()
        except sqlite3.Error:
            self._self_heal()
            return None
        return row[0] if row and row[0] is not None else None

    def close(self) -> None:
        with contextlib.suppress(sqlite3.Error):
            self._conn.close()


def _cache_key(url: str, params: dict[str, Any] | None) -> str:
    canonical = url + "?" + json.dumps(params or {}, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApiClient:
    """httpx.Client wrapper: retry with exponential backoff + jitter, TTL cache, logging."""

    def __init__(
        self,
        cache_dir: Path,
        cache_ttl_hours: int = 24,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Any = time.sleep,
    ) -> None:
        self._client = httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={"User-Agent": USER_AGENT},
            transport=transport,
        )
        self.cache = Cache(cache_dir / "euvd-cache.sqlite")
        self._ttl_seconds = cache_ttl_hours * 3600
        self._sleep = sleep
        # stored_at of every response actually served by this client instance, whether
        # from cache or the network — feeds oldest_served_stored_at().
        self._served_stored_at: list[float] = []

    def get_json(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        *,
        use_cache: bool = True,
        ttl_seconds: int | None = None,
    ) -> Any:
        """GET a JSON document, cache-first. HTTP 204 returns None.

        Raises ApiError after MAX_RETRIES failures or on undecodable payloads.
        """
        key = _cache_key(url, params)
        ttl = self._ttl_seconds if ttl_seconds is None else ttl_seconds
        cached = self.cache.get(key) if use_cache else None
        etag: str | None = None
        if cached is not None:
            body, etag, stored_at = cached
            if time.time() - stored_at < ttl:
                logger.debug("cache hit url=%s", url)
                self._served_stored_at.append(stored_at)
                return json.loads(body)

        response = self._request_with_retries("GET", url, params=params, etag=etag)

        if response.status_code == 304 and cached is not None:
            # Server confirmed our stale copy is still current; refresh its timestamp.
            body, etag, _ = cached
            revalidated_at = time.time()
            self.cache.set(key, body, etag, revalidated_at)
            self._served_stored_at.append(revalidated_at)
            return json.loads(body)
        if response.status_code == 204:
            return None
        if response.status_code >= 400:
            # Any error status (including non-retryable 4xx like 403) must fail loudly,
            # even when the body happens to be valid JSON - a {"error": "forbidden"} body
            # must never be mistaken for real data (feedback_m2.md finding 1.1).
            raise ApiError(f"HTTP {response.status_code} from {url}: {response.text[:200]!r}")

        text = response.text
        try:
            data = json.loads(text) if text.strip() else None
        except json.JSONDecodeError as exc:
            raise ApiError(f"Non-JSON response from {url}: {text[:200]!r}") from exc
        # One timestamp for both the cache row and the served-response tracker: a later
        # run replaying this row from cache must report the identical stored_at, or
        # byte-identical output (INV-9) breaks on microsecond skew.
        fetched_at = time.time()
        if use_cache and data is not None:
            self.cache.set(key, text, response.headers.get("ETag"), fetched_at)
        if data is not None:
            self._served_stored_at.append(fetched_at)
        return data

    def oldest_served_stored_at(self) -> float | None:
        """Worst-case age of the responses this client actually served so far.

        The honest `data_freshness` bound (feedback_m2.md 2.2): the oldest response used
        in this run — not the newest row anywhere in the shared on-disk cache, which
        EPSS/KEV entries and rows written by unrelated later runs would inflate.
        """
        return min(self._served_stored_at, default=None)

    def post_json(self, url: str, payload: dict[str, Any]) -> None:
        """POST a JSON payload with the same retry/backoff as GET. Raises ApiError on
        failure. Never cached - a POST (e.g. a webhook delivery) is not an idempotent GET.
        """
        response = self._request_with_retries("POST", url, json_body=payload)
        if response.status_code >= 400:
            raise ApiError(
                f"POST to {url} failed: HTTP {response.status_code}: {response.text[:200]!r}"
            )

    def _request_with_retries(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        etag: str | None = None,
    ) -> httpx.Response:
        headers = {"If-None-Match": etag} if etag else {}
        last_error: str = "unknown"
        for attempt in range(MAX_RETRIES):
            started = time.monotonic()
            try:
                response = self._client.request(
                    method, url, params=params, json=json_body, headers=headers
                )
            except httpx.HTTPError as exc:
                last_error = str(exc)
                logger.warning("request error url=%s attempt=%d error=%s", url, attempt + 1, exc)
            else:
                duration_ms = (time.monotonic() - started) * 1000
                logger.debug(
                    "request url=%s status=%d cache=miss duration_ms=%.0f",
                    url,
                    response.status_code,
                    duration_ms,
                )
                if response.status_code not in RETRYABLE_STATUSES:
                    return response
                last_error = f"HTTP {response.status_code}"
                logger.warning(
                    "retryable status url=%s attempt=%d status=%d",
                    url,
                    attempt + 1,
                    response.status_code,
                )
            if attempt < MAX_RETRIES - 1:
                backoff = (2**attempt) + random.uniform(0, 1)
                self._sleep(backoff)
        raise ApiError(f"Request to {url} failed after {MAX_RETRIES} attempts: {last_error}")

    def close(self) -> None:
        self._client.close()
        self.cache.close()
