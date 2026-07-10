"""Live smoke tests against the real EUVD/EPSS/KEV services (test_plan.md §7).

Excluded from every default run (`-m 'not live'` in addopts); intended for the nightly
job and for manual re-verification of docs/euvd-api.md when the beta API changes:

    pytest -m live --no-cov tests/live/
"""

from pathlib import Path

import pytest

from euvd_watch.config import Settings
from euvd_watch.enrich.epss import fetch_epss_scores
from euvd_watch.enrich.kev import fetch_kev_cves
from euvd_watch.euvd.client import EuvdClient
from euvd_watch.http import ApiClient

pytestmark = pytest.mark.live


@pytest.fixture
def live_client(tmp_path: Path) -> ApiClient:
    client = ApiClient(cache_dir=tmp_path)
    yield client
    client.close()


def test_exploited_catalog_is_syncable(live_client: ApiClient) -> None:
    settings = Settings()
    records = EuvdClient(live_client, settings.euvd_api_base_url).fetch_exploited()
    assert len(records) > 500, "exploited catalog shrank dramatically - API change?"
    assert all(r.euvd_id.startswith("EUVD-") for r in records[:20])
    assert all(r.exploited for r in records[:20])


def test_enisaid_miss_still_answers_204_none(live_client: ApiClient) -> None:
    settings = Settings()
    client = EuvdClient(live_client, settings.euvd_api_base_url)
    assert client.get_by_euvd_id("EUVD-1999-99999") is None


def test_epss_and_kev_reachable(live_client: ApiClient) -> None:
    settings = Settings()
    scores = fetch_epss_scores(live_client, settings.epss_api_base_url, ["CVE-2024-3094"])
    assert 0.0 < scores.get("CVE-2024-3094", 0.0) <= 1.0
    kev = fetch_kev_cves(live_client, settings.kev_feed_url)
    assert len(kev) > 1000
