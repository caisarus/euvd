"""Capture real EUVD API responses into tests/fixtures/euvd/ (run manually, once).

Fixtures are committed; tests replay them through respx and never hit the network
(TEST_PLAN.md §1 principle 2). Re-running this script refreshes the fixtures from the live
API — do that deliberately: record contents change over time and tests assert on them.

Usage: python scripts/capture_fixtures.py
"""

from __future__ import annotations

import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "https://euvdservices.enisa.europa.eu/api"
OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "euvd"

CAPTURES: list[tuple[str, str, dict[str, str]]] = [
    # (output filename, endpoint path, params)
    ("search-exploited-page0.json", "/search", {"exploited": "true", "page": "0", "size": "100"}),
    ("search-exploited-page1.json", "/search", {"exploited": "true", "page": "1", "size": "100"}),
    ("search-product-openssl.json", "/search", {"product": "openssl", "page": "0", "size": "100"}),
    ("search-product-jinja2.json", "/search", {"product": "jinja2", "page": "0", "size": "100"}),
    ("search-product-pillow.json", "/search", {"product": "pillow", "page": "0", "size": "100"}),
    ("lastvulnerabilities.json", "/lastvulnerabilities", {}),
    ("exploitedvulnerabilities-latest.json", "/exploitedvulnerabilities", {}),
]


def fetch(path: str, params: dict[str, str]) -> tuple[int, str]:
    query = ("?" + urllib.parse.urlencode(params)) if params else ""
    request = urllib.request.Request(
        BASE + path + query, headers={"User-Agent": "euvd-watch-fixture-capture/1"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.status, response.read().decode("utf-8")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for filename, path, params in CAPTURES:
        status, body = fetch(path, params)
        if status != 200:
            print(f"FAILED {path} -> HTTP {status}", file=sys.stderr)
            return 1
        # Re-serialize for stable, reviewable formatting.
        (OUT / filename).write_text(
            json.dumps(json.loads(body), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"captured {filename} ({len(body)} bytes)")
        time.sleep(1.5)  # be polite to the beta API

    # One enisaid hit: take the first record id from the exploited page.
    first = json.loads((OUT / "search-exploited-page0.json").read_text(encoding="utf-8"))
    record_id = first["items"][0]["id"]
    status, body = fetch("/enisaid", {"id": record_id})
    (OUT / "enisaid-hit.json").write_text(
        json.dumps(json.loads(body), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"captured enisaid-hit.json (id={record_id})")

    # The documented 204 miss needs no capture (empty body); tests mock it directly.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
