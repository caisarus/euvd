"""Prime the euvd-watch HTTP cache from a committed fixture (network-free CI dogfood).

The dogfood CI job (plans/test_plan.md §7) exercises the real CLI end-to-end through the
GitHub Action, and blocking CI jobs must never hit the network. The ApiClient is
cache-first: a fresh cache entry short-circuits the HTTP request entirely, so seeding the
cache with one exploited-search page makes `match --exploited-only --no-enrich` fully
offline. This script stores the fixture body under the exact cache key the client computes
for `/search?exploited=true` page 0, with `total` rewritten to the item count so pagination
stops after that single page.

Usage: python scripts/prime_cache.py [FIXTURE]
Defaults to tests/fixtures/euvd/dogfood-seeded-exploited.json (a SEEDED record, not a real
vulnerability). Honors EUVD_WATCH_CACHE_DIR / EUVD_WATCH_EUVD_API_BASE_URL exactly like
the CLI does, so the primed cache lands where the subsequent `match` run will look.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from euvd_watch.config import load_settings
from euvd_watch.euvd.client import PAGE_SIZE
from euvd_watch.http import Cache, _cache_key

DEFAULT_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "euvd"
    / "dogfood-seeded-exploited.json"
)


def main(argv: list[str]) -> int:
    """Insert the fixture as a fresh exploited-search page-0 cache entry."""
    fixture = Path(argv[1]) if len(argv) > 1 else DEFAULT_FIXTURE
    page = json.loads(fixture.read_text(encoding="utf-8"))
    items = page["items"]
    if len(items) > PAGE_SIZE:
        print(f"fixture has {len(items)} items; a single page holds {PAGE_SIZE}", file=sys.stderr)
        return 1

    settings = load_settings(None)
    url = settings.euvd_api_base_url.rstrip("/") + "/search"
    params = {"exploited": "true", "page": 0, "size": PAGE_SIZE}
    body = json.dumps({"items": items, "total": len(items)})

    settings.cache_dir.mkdir(parents=True, exist_ok=True)
    cache = Cache(settings.cache_dir / "euvd-cache.sqlite")
    cache.set(_cache_key(url, params), body, None, time.time())
    cache.close()
    print(f"primed {url}?exploited=true (page 0, {len(items)} records) -> {settings.cache_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
