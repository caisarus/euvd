"""Shared test fixtures (TEST_PLAN.md §2): ApiClient with no real sleeping, fixture loaders."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from euvd_watch.http import ApiClient

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_OPENVEX_SCHEMA = json.loads((FIXTURES / "openvex" / "schema.json").read_text(encoding="utf-8"))


@pytest.fixture
def api_client(tmp_path: Path) -> ApiClient:
    """An ApiClient with a throwaway cache and no real backoff sleeping (respx-friendly)."""
    client = ApiClient(cache_dir=tmp_path, sleep=lambda _s: None)
    yield client
    client.close()


@pytest.fixture
def euvd_fixture() -> Any:
    """Loader for captured EUVD API responses: euvd_fixture('search-exploited-page0')."""

    def load(name: str) -> Any:
        return json.loads((FIXTURES / "euvd" / f"{name}.json").read_text(encoding="utf-8"))

    return load


@pytest.fixture
def validate_openvex() -> Any:
    """Assert a JSON string or dict is a valid OpenVEX document (implementation_plan.md
    Step 3.1: schema validation wired into every later VEX test via this shared helper)."""

    def check(document: str | dict[str, Any]) -> None:
        data = json.loads(document) if isinstance(document, str) else document
        jsonschema.validate(data, _OPENVEX_SCHEMA)

    return check
