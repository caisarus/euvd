"""Covers implementation_plan.md Step 2.1: politeness and resilience of the HTTP layer."""

import json
import time
from pathlib import Path

import httpx
import pytest

from euvd_watch.http import MAX_RETRIES, USER_AGENT, ApiClient, ApiError, Cache

pytestmark = pytest.mark.unit


def _client_with(handler, tmp_path: Path, **kwargs) -> ApiClient:  # type: ignore[no-untyped-def]
    return ApiClient(
        cache_dir=tmp_path, transport=httpx.MockTransport(handler), sleep=lambda _s: None, **kwargs
    )


def test_success_returns_json_and_caches(tmp_path: Path) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"ok": True})

    client = _client_with(handler, tmp_path)
    assert client.get_json("https://api.example/x") == {"ok": True}
    assert client.get_json("https://api.example/x") == {"ok": True}
    assert len(calls) == 1  # second call served from cache, no network


def test_user_agent_sent_on_every_request(tmp_path: Path) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["User-Agent"])
        return httpx.Response(200, json={})

    client = _client_with(handler, tmp_path)
    client.get_json("https://api.example/x", use_cache=False)
    assert seen == [USER_AGENT]
    assert "euvd-watch/" in USER_AGENT


def test_retry_on_429_then_success(tmp_path: Path) -> None:
    attempts = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) < 3:
            return httpx.Response(429)
        return httpx.Response(200, json={"after": "retries"})

    client = _client_with(handler, tmp_path)
    assert client.get_json("https://api.example/x") == {"after": "retries"}
    assert len(attempts) == 3


def test_persistent_failure_raises_api_error_after_max_retries(tmp_path: Path) -> None:
    attempts = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(503)

    client = _client_with(handler, tmp_path)
    with pytest.raises(ApiError, match="failed after"):
        client.get_json("https://api.example/x")
    assert len(attempts) == MAX_RETRIES


def test_non_retryable_4xx_is_returned_not_retried(tmp_path: Path) -> None:
    attempts = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(403, text="forbidden")

    client = _client_with(handler, tmp_path)
    with pytest.raises(ApiError, match="Non-JSON"):
        client.get_json("https://api.example/x")
    assert len(attempts) == 1


def test_http_204_returns_none(tmp_path: Path) -> None:
    client = _client_with(lambda r: httpx.Response(204), tmp_path)
    assert client.get_json("https://api.example/missing") is None


def test_ttl_expiry_refetches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200, json={"n": len(calls)})

    client = _client_with(handler, tmp_path, cache_ttl_hours=1)
    now = time.time()
    assert client.get_json("https://api.example/x") == {"n": 1}
    monkeypatch.setattr(time, "time", lambda: now + 2 * 3600)  # 2h later, TTL is 1h
    assert client.get_json("https://api.example/x") == {"n": 2}
    assert len(calls) == 2


def test_etag_304_refreshes_cached_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.headers.get("If-None-Match") == "v1":
            return httpx.Response(304)
        return httpx.Response(200, json={"body": 1}, headers={"ETag": "v1"})

    client = _client_with(handler, tmp_path, cache_ttl_hours=1)
    now = time.time()
    assert client.get_json("https://api.example/x") == {"body": 1}
    monkeypatch.setattr(time, "time", lambda: now + 2 * 3600)
    assert client.get_json("https://api.example/x") == {"body": 1}
    assert len(calls) == 2
    assert calls[1].headers.get("If-None-Match") == "v1"


def test_corrupted_cache_self_heals(tmp_path: Path) -> None:
    cache_file = tmp_path / "euvd-cache.sqlite"
    cache_file.write_bytes(b"this is not a sqlite database at all" * 100)
    client = _client_with(lambda r: httpx.Response(200, json={"ok": 1}), tmp_path)
    assert client.get_json("https://api.example/x") == {"ok": 1}  # heals, then works


def test_cache_purge_and_newest_stored_at(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "c.sqlite")
    assert cache.newest_stored_at() is None
    cache.set("k", json.dumps({"a": 1}), None, 123.0)
    cache.set("k2", json.dumps({"a": 2}), None, 456.0)
    assert cache.newest_stored_at() == 456.0
    cache.purge()
    assert cache.get("k") is None


def test_connection_error_retries_then_raises(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    client = _client_with(handler, tmp_path)
    with pytest.raises(ApiError, match="boom"):
        client.get_json("https://api.example/x")
