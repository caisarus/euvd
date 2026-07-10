"""Covers implementation_plan.md Step 2.2: EUVD client over captured real fixtures (respx)."""

from typing import Any

import httpx
import pytest
import respx

from euvd_watch.euvd.client import EuvdClient
from euvd_watch.euvd.models import parse_record, parse_records
from euvd_watch.http import ApiClient

pytestmark = pytest.mark.integration

BASE = "https://euvdservices.enisa.europa.eu/api"


def _client(api_client: ApiClient) -> EuvdClient:
    return EuvdClient(api_client, BASE)


# --- record parsing over real captured data ---


def test_parse_real_exploited_page(euvd_fixture: Any) -> None:
    records = parse_records(euvd_fixture("search-exploited-page0")["items"])
    assert len(records) == 100
    first = records[0]
    assert first.euvd_id.startswith("EUVD-")
    assert first.exploited is True  # exploitedSince present on every exploited record
    assert first.exploited_since is not None
    # newline-joined aliases split into a list of CVE/GHSA ids
    assert any(a.startswith("CVE-") for a in first.aliases)
    # 0-100 scale normalized to 0-1
    assert first.epss is not None and 0.0 <= first.epss <= 1.0
    assert first.affected_products, "exploited records carry affected products"
    assert first.affected_products[0].product


def test_parse_real_enisaid_record(euvd_fixture: Any) -> None:
    record = parse_record(euvd_fixture("enisaid-hit"))
    assert record is not None
    assert record.euvd_id == "EUVD-2026-38110"


def test_record_without_id_is_skipped_with_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        records = parse_records([{"description": "no id at all"}, {"id": "EUVD-1-1"}])
    assert [r.euvd_id for r in records] == ["EUVD-1-1"]
    assert any("without an id" in r.message for r in caplog.records)


def test_non_dict_entries_are_skipped(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        records = parse_records(["garbage", 42, {"id": "EUVD-1-2"}])
    assert [r.euvd_id for r in records] == ["EUVD-1-2"]


def test_epss_normalization_is_0_to_1() -> None:
    record = parse_record({"id": "EUVD-1-3", "epss": 87.06})
    assert record is not None
    assert record.epss == pytest.approx(0.8706)


def test_non_exploited_record_has_exploited_false() -> None:
    record = parse_record({"id": "EUVD-1-4"})
    assert record is not None
    assert record.exploited is False
    assert record.exploited_since is None


# --- client behavior over mocked transport ---


@respx.mock
def test_fetch_exploited_paginates_to_total(api_client: ApiClient, euvd_fixture: Any) -> None:
    page0 = euvd_fixture("search-exploited-page0")
    page1 = euvd_fixture("search-exploited-page1")
    # Pretend the catalog is exactly these two pages.
    page0["total"] = 150
    page1["total"] = 150
    page1["items"] = page1["items"][:50]

    def route(request: httpx.Request) -> httpx.Response:
        page = request.url.params.get("page")
        return httpx.Response(200, json=page0 if page == "0" else page1)

    respx.get(f"{BASE}/search").mock(side_effect=route)
    records = _client(api_client).fetch_exploited()
    assert len(records) == 150


@respx.mock
def test_search_product_single_page(api_client: ApiClient, euvd_fixture: Any) -> None:
    respx.get(f"{BASE}/search").mock(
        return_value=httpx.Response(200, json=euvd_fixture("search-product-jinja2"))
    )
    records = _client(api_client).search_product("jinja2")
    assert len(records) == 1


@respx.mock
def test_search_empty_results(api_client: ApiClient) -> None:
    respx.get(f"{BASE}/search").mock(
        return_value=httpx.Response(200, json={"items": [], "total": 0})
    )
    assert _client(api_client).search_product("no-such-product") == []


@respx.mock
def test_get_by_euvd_id_hit(api_client: ApiClient, euvd_fixture: Any) -> None:
    respx.get(f"{BASE}/enisaid").mock(
        return_value=httpx.Response(200, json=euvd_fixture("enisaid-hit"))
    )
    record = _client(api_client).get_by_euvd_id("EUVD-2026-38110")
    assert record is not None and record.euvd_id == "EUVD-2026-38110"


@respx.mock
def test_get_by_euvd_id_miss_is_204_none(api_client: ApiClient) -> None:
    # Verified live: a missing id answers HTTP 204 with an empty body, not 404.
    respx.get(f"{BASE}/enisaid").mock(return_value=httpx.Response(204))
    assert _client(api_client).get_by_euvd_id("EUVD-1999-99999") is None


@respx.mock
def test_get_by_cve_filters_for_exact_alias(api_client: ApiClient) -> None:
    # Full-text search matches descriptions too; only an exact alias match counts.
    items = [
        {"id": "EUVD-1-10", "aliases": "CVE-2024-99999\n", "description": "mentions CVE-2024-3094"},
        {"id": "EUVD-1-11", "aliases": "CVE-2024-3094\nGHSA-x\n"},
    ]
    respx.get(f"{BASE}/search").mock(
        return_value=httpx.Response(200, json={"items": items, "total": 2})
    )
    record = _client(api_client).get_by_cve("CVE-2024-3094")
    assert record is not None and record.euvd_id == "EUVD-1-11"


@respx.mock
def test_get_by_cve_no_exact_alias_returns_none(api_client: ApiClient) -> None:
    items = [{"id": "EUVD-1-12", "aliases": "CVE-2020-1234\n", "description": "text mention only"}]
    respx.get(f"{BASE}/search").mock(
        return_value=httpx.Response(200, json={"items": items, "total": 1})
    )
    assert _client(api_client).get_by_cve("CVE-2024-3094") is None


@respx.mock
def test_fetch_latest_parses_array(api_client: ApiClient, euvd_fixture: Any) -> None:
    respx.get(f"{BASE}/lastvulnerabilities").mock(
        return_value=httpx.Response(200, json=euvd_fixture("lastvulnerabilities"))
    )
    records = _client(api_client).fetch_latest()
    assert len(records) == 4
