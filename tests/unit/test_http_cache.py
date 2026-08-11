"""Covers implementation_plan.md Step 2.1: politeness and resilience of the HTTP layer."""

import json
import logging
import time
from pathlib import Path

import httpx
import pytest

from euvd_watch.http import MAX_RETRIES, USER_AGENT, ApiClient, ApiError, Cache, _cache_key

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
    with pytest.raises(ApiError, match="HTTP 403"):
        client.get_json("https://api.example/x")
    assert len(attempts) == 1


def test_4xx_with_valid_json_body_still_raises(tmp_path: Path) -> None:
    # A JSON error body must never be mistaken for real data (feedback_m2.md finding 1.1):
    # this used to silently return {"error": "forbidden"} as if it were a real payload.
    client = _client_with(lambda r: httpx.Response(403, json={"error": "forbidden"}), tmp_path)
    with pytest.raises(ApiError, match="HTTP 403"):
        client.get_json("https://api.example/x")


def test_404_with_json_body_raises(tmp_path: Path) -> None:
    client = _client_with(lambda r: httpx.Response(404, json={"message": "not found"}), tmp_path)
    with pytest.raises(ApiError, match="HTTP 404"):
        client.get_json("https://api.example/x")


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


def test_oldest_served_stored_at_tracks_responses_actually_used(tmp_path: Path) -> None:
    # feedback_m2.md 2.2: data_freshness must reflect the OLDEST response actually served
    # in this run (worst case), not the newest row anywhere in the shared cache — EPSS/KEV
    # entries and rows written by unrelated later runs must not inflate the stamp.
    client = _client_with(lambda r: httpx.Response(200, json={"ok": True}), tmp_path)
    assert client.oldest_served_stored_at() is None  # nothing served yet

    # Seed an hour-old (but within-TTL) cached response and serve it from cache.
    old = time.time() - 3600
    client.cache.set(_cache_key("https://api.example/old", None), '{"v": 1}', None, old)
    assert client.get_json("https://api.example/old") == {"v": 1}

    # A newer network fetch and a newer never-served cache row must not mask the old one.
    assert client.get_json("https://api.example/new") == {"ok": True}
    client.cache.set("unrelated-newer-row", "{}", None, time.time() + 999)

    oldest = client.oldest_served_stored_at()
    assert oldest == pytest.approx(old, abs=1.0)


def test_connection_error_retries_then_raises(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    client = _client_with(handler, tmp_path)
    with pytest.raises(ApiError, match="boom"):
        client.get_json("https://api.example/x")


def test_post_json_sends_the_payload_and_succeeds(tmp_path: Path) -> None:
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})

    client = _client_with(handler, tmp_path)
    client.post_json("https://hooks.example/x", {"kind": "new", "x": 1})
    assert seen == [{"kind": "new", "x": 1}]


def test_post_json_retries_on_429_then_succeeds(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429)
        return httpx.Response(200)

    client = _client_with(handler, tmp_path)
    client.post_json("https://hooks.example/x", {"a": 1})  # must not raise
    assert calls["n"] == 2


def test_post_json_persistent_failure_raises_api_error(tmp_path: Path) -> None:
    client = _client_with(lambda r: httpx.Response(500), tmp_path)
    with pytest.raises(ApiError, match="500"):
        client.post_json("https://hooks.example/x", {"a": 1})


def test_post_json_non_retryable_4xx_raises_immediately(tmp_path: Path) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(403)

    client = _client_with(handler, tmp_path)
    with pytest.raises(ApiError, match="403"):
        client.post_json("https://hooks.example/x", {"a": 1})
    assert len(calls) == 1  # not retried - 403 isn't in RETRYABLE_STATUSES


def test_webhook_url_is_redacted_in_logs_and_errors(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """1.0-audit: a webhook URL IS the credential - it must never reach a log line.

    Slack/Discord/Teams put the secret in the URL path, so the retry warnings and the
    final ApiError used to print it in full. Six lines carrying a live token, straight
    into CI output that is public for most open-source projects, on nothing worse than a
    transient delivery failure.
    """
    secret = "https://hooks.slack.com/services/T00000000/B00000000/SUPERSECRETTOKEN123"
    transport = httpx.MockTransport(lambda request: httpx.Response(500))
    client = ApiClient(tmp_path, transport=transport, sleep=lambda _: None)
    with caplog.at_level(logging.WARNING), pytest.raises(ApiError) as excinfo:
        client.post_json(secret, {"a": 1})

    assert "SUPERSECRETTOKEN123" not in str(excinfo.value)
    assert "T00000000" not in str(excinfo.value)
    for record in caplog.records:
        assert "SUPERSECRETTOKEN123" not in record.getMessage()
        assert "T00000000" not in record.getMessage()
    # Still useful for debugging: the operator must be able to tell WHICH service failed.
    assert "hooks.slack.com" in str(excinfo.value)


def test_non_webhook_urls_keep_their_path_in_logs(tmp_path: Path) -> None:
    """The EUVD path is not a secret and stays readable - redaction is POST-scoped."""
    transport = httpx.MockTransport(lambda request: httpx.Response(500))
    client = ApiClient(tmp_path, transport=transport, sleep=lambda _: None)
    with pytest.raises(ApiError) as excinfo:
        client.get_json("https://euvdservices.enisa.europa.eu/api/search", {"exploited": "true"})
    assert "/api/search" in str(excinfo.value)
