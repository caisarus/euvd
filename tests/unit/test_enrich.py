"""Covers implementation_plan.md Step 2.4: EPSS/KEV enrichment and graceful degradation."""

import httpx
import pytest
import respx

from euvd_watch.enrich import enrich
from euvd_watch.enrich.epss import fetch_epss_scores
from euvd_watch.enrich.kev import fetch_kev_cves
from euvd_watch.euvd.match import Confidence, Finding, Strategy
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.http import ApiClient, ApiError
from euvd_watch.models import Component, SourceFormat

pytestmark = pytest.mark.unit

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://kev.example/feed.json"


def _finding(aliases: list[str]) -> Finding:
    return Finding(
        component=Component(
            name="widget", version="1.0", source_format=SourceFormat.CYCLONEDX, raw_ref="r"
        ),
        record=EuvdRecord(euvd_id="EUVD-1-1", aliases=aliases),
        confidence=Confidence.HIGH,
        strategy=Strategy.STRUCTURED,
        explanation="test finding",
    )


@respx.mock
def test_epss_batch_parses_scores(api_client: ApiClient) -> None:
    respx.get(EPSS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"cve": "CVE-1", "epss": "0.85974"}, {"cve": "CVE-2", "epss": "0.01"}]},
        )
    )
    scores = fetch_epss_scores(api_client, EPSS_URL, ["CVE-1", "CVE-2"])
    assert scores == {"CVE-1": pytest.approx(0.85974), "CVE-2": pytest.approx(0.01)}


@respx.mock
def test_epss_batches_by_100(api_client: ApiClient) -> None:
    calls: list[str] = []

    def route(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.params.get("cve", ""))
        return httpx.Response(200, json={"data": []})

    respx.get(EPSS_URL).mock(side_effect=route)
    fetch_epss_scores(api_client, EPSS_URL, [f"CVE-{i}" for i in range(150)])
    assert len(calls) == 2
    assert len(calls[0].split(",")) == 100


@respx.mock
def test_kev_membership_set(api_client: ApiClient) -> None:
    respx.get(KEV_URL).mock(
        return_value=httpx.Response(
            200, json={"vulnerabilities": [{"cveID": "CVE-1"}, {"cveID": "CVE-2"}]}
        )
    )
    assert fetch_kev_cves(api_client, KEV_URL) == {"CVE-1", "CVE-2"}


@respx.mock
def test_kev_malformed_feed_raises_instead_of_empty_set(api_client: ApiClient) -> None:
    # feedback_m2.md finding 2.1: a body without a `vulnerabilities` list must not be read
    # as "an empty catalog" (which would make every CVE look provably not-in-KEV).
    respx.get(KEV_URL).mock(
        return_value=httpx.Response(200, json={"error": "service temporarily degraded"})
    )
    with pytest.raises(ApiError, match="not shaped like a catalog"):
        fetch_kev_cves(api_client, KEV_URL)


@respx.mock
def test_enrich_malformed_kev_feed_yields_unknown_not_false(api_client: ApiClient) -> None:
    respx.get(EPSS_URL).mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(KEV_URL).mock(
        return_value=httpx.Response(200, json={"error": "service temporarily degraded"})
    )
    findings = enrich([_finding(["CVE-1"])], api_client, EPSS_URL, KEV_URL)
    assert findings[0].in_kev is None  # unknown, never a false "provably not in KEV"


@respx.mock
def test_enrich_fills_epss_and_kev(api_client: ApiClient) -> None:
    respx.get(EPSS_URL).mock(
        return_value=httpx.Response(200, json={"data": [{"cve": "CVE-1", "epss": "0.9"}]})
    )
    respx.get(KEV_URL).mock(
        return_value=httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-1"}]})
    )
    findings = enrich([_finding(["CVE-1", "GHSA-x"])], api_client, EPSS_URL, KEV_URL)
    assert findings[0].epss_score == pytest.approx(0.9)
    assert findings[0].in_kev is True


@respx.mock
def test_enrich_does_not_mutate_match_fields(api_client: ApiClient) -> None:
    respx.get(EPSS_URL).mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))
    original = _finding(["CVE-1"])
    enriched = enrich([original], api_client, EPSS_URL, KEV_URL)[0]
    assert enriched.confidence == original.confidence
    assert enriched.explanation == original.explanation
    assert enriched.in_kev is False  # KEV catalog fetched fine, CVE just not in it


@respx.mock
def test_enrichment_apis_down_degrades_gracefully(
    api_client: ApiClient, caplog: pytest.LogCaptureFixture
) -> None:
    respx.get(EPSS_URL).mock(return_value=httpx.Response(500))
    respx.get(KEV_URL).mock(return_value=httpx.Response(500))
    with caplog.at_level("WARNING"):
        findings = enrich([_finding(["CVE-1"])], api_client, EPSS_URL, KEV_URL)
    assert findings[0].epss_score is None
    assert findings[0].in_kev is None  # unknown, not False: the catalog was unreachable
    assert any("EPSS enrichment unavailable" in r.message for r in caplog.records)
    assert any("KEV enrichment unavailable" in r.message for r in caplog.records)


@respx.mock
def test_finding_without_cve_aliases_left_untouched(api_client: ApiClient) -> None:
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))
    findings = enrich([_finding(["GHSA-only"])], api_client, EPSS_URL, KEV_URL)
    assert findings[0].epss_score is None
    assert findings[0].in_kev is False
