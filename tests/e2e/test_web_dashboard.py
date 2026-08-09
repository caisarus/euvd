"""Covers implementation_plan.md Step 6.2 / test_plan.md §M6 6.2: the dashboard's
HTTP contract.

Per the test plan: every route 200 with demo data; 401 without credentials on all
routes; write endpoints (mark) reject unauthenticated; HTML has no inline event
handlers (CSP-friendliness); finding detail shows explanation + confidence verbatim
from the store.
"""

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from euvd_watch.config import Settings, WebConfig
from euvd_watch.cra.state import EventStore
from euvd_watch.cra.trigger import evaluate_all
from euvd_watch.euvd.match import Confidence, Finding, Strategy
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.models import Component, SourceFormat
from euvd_watch.web.app import create_app
from euvd_watch.web.auth import hash_password
from euvd_watch.web.store import Store, sbom_snapshot_key

pytestmark = pytest.mark.e2e

SBOM = "examples/sboms/demo.cdx.json"
PASSWORD = "correct horse battery staple"
AUTH = ("admin", PASSWORD)

ALL_GET_ROUTES = ["/", "/findings", "/cra", "/audit"]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings(
        state_dir=tmp_path / "state", web=WebConfig(password_hash=hash_password(PASSWORD))
    )
    s.organization.name = "Test Org"
    s.organization.contact_email = "sec@test.org"
    s.organization.product_name = "Test Product"
    return s


def _finding() -> Finding:
    component = Component(
        name="jinja2",
        version="3.1.6",
        purl="pkg:pypi/jinja2@3.1.6",
        source_format=SourceFormat.CYCLONEDX,
        raw_ref="r",
    )
    record = EuvdRecord(
        euvd_id="EUVD-DOGFOOD-0001",
        exploited=True,
        exploited_since="Jan 1, 2026",
        aliases=["CVE-2099-0001"],
        description="a seeded demo vulnerability",
    )
    return Finding(
        component=component,
        record=record,
        confidence=Confidence.MEDIUM,
        strategy=Strategy.STRUCTURED,
        explanation="matched via structured evidence, deterministic and verbatim",
        epss_score=0.91,
        in_kev=True,
    )


def _seed_demo_scenario(settings: Settings) -> Finding:
    """The demo narrative docs/dashboard-design.md uses everywhere: jinja2 3.1.6
    matches an exploited record, which fires one CRA event."""
    store = Store(settings.state_dir)
    store.migrate()
    finding = _finding()
    key = sbom_snapshot_key(SBOM)
    artifact = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "findings": [finding.model_dump(mode="json")],
    }
    store.save_watch_snapshot(key, json.dumps(artifact))
    store.close()

    events = EventStore(settings.state_dir / "euvd-watch.sqlite")
    for result in evaluate_all([finding], settings):
        events.get_or_create(
            result.finding,
            result.fired_rules,
            result.policy_snapshot,
            result.epss_threshold,
            datetime.now(UTC),
        )
    events.close()
    return finding


def _client(settings: Settings) -> TestClient:
    app = create_app(settings, sbom_path=SBOM, host="127.0.0.1", port=8642)
    return TestClient(app)


# -- auth: every route requires it ------------------------------------------------


@pytest.mark.parametrize("path", ALL_GET_ROUTES)
def test_routes_401_without_credentials(settings: Settings, path: str) -> None:
    _seed_demo_scenario(settings)
    client = _client(settings)
    response = client.get(path)
    assert response.status_code == 401
    assert "Basic" in response.headers.get("www-authenticate", "")


@pytest.mark.parametrize("path", ALL_GET_ROUTES)
def test_routes_401_with_wrong_password(settings: Settings, path: str) -> None:
    _seed_demo_scenario(settings)
    client = _client(settings)
    response = client.get(path, auth=("admin", "wrong password"))
    assert response.status_code == 401


def test_routes_401_with_wrong_username(settings: Settings) -> None:
    _seed_demo_scenario(settings)
    client = _client(settings)
    response = client.get("/", auth=("someone-else", PASSWORD))
    assert response.status_code == 401


def test_static_css_does_not_require_auth(settings: Settings) -> None:
    """Static assets aren't secrets; requiring auth for them would break the login
    prompt's own page render in some browsers and buys nothing."""
    client = _client(settings)
    response = client.get("/static/dashboard.css")
    assert response.status_code == 200
    assert "text/css" in response.headers["content-type"]


def test_mark_write_endpoint_rejects_unauthenticated(settings: Settings) -> None:
    finding = _seed_demo_scenario(settings)
    client = _client(settings)
    event_store = EventStore(settings.state_dir / "euvd-watch.sqlite")
    from euvd_watch.cra.state import Event

    event_id = Event.make_id(finding.component.dedupe_key, finding.record.euvd_id)
    event_store.close()
    from euvd_watch.web.dashboard import event_url_id

    response = client.post(f"/cra/{event_url_id(event_id)}/mark", data={"stage": "early_warning"})
    assert response.status_code == 401


# -- every route 200 with demo data ------------------------------------------------


def test_overview_200_with_demo_data(settings: Settings) -> None:
    _seed_demo_scenario(settings)
    client = _client(settings)
    response = client.get("/", auth=AUTH)
    assert response.status_code == 200
    assert "jinja2" in response.text
    assert "EUVD-DOGFOOD-0001" in response.text


def test_findings_200_with_demo_data(settings: Settings) -> None:
    _seed_demo_scenario(settings)
    client = _client(settings)
    response = client.get("/findings", auth=AUTH)
    assert response.status_code == 200
    assert "EUVD-DOGFOOD-0001" in response.text


def test_finding_detail_200_and_shows_explanation_and_confidence_verbatim(
    settings: Settings,
) -> None:
    from euvd_watch.web.dashboard import comp_hash

    finding = _seed_demo_scenario(settings)
    client = _client(settings)
    h = comp_hash(finding.component.dedupe_key)
    response = client.get(f"/findings/{h}/{finding.record.euvd_id}", auth=AUTH)
    assert response.status_code == 200
    assert "matched via structured evidence, deterministic and verbatim" in response.text
    assert "medium" in response.text  # confidence label, verbatim


def test_finding_detail_404_for_unknown_pair(settings: Settings) -> None:
    _seed_demo_scenario(settings)
    client = _client(settings)
    response = client.get("/findings/000000000000/EUVD-NOPE", auth=AUTH)
    assert response.status_code == 404


def test_cra_events_200_with_demo_data(settings: Settings) -> None:
    _seed_demo_scenario(settings)
    client = _client(settings)
    response = client.get("/cra", auth=AUTH)
    assert response.status_code == 200
    assert "EUVD-DOGFOOD-0001" in response.text


def test_cra_event_detail_200_and_disclaimer_present(settings: Settings) -> None:
    finding = _seed_demo_scenario(settings)
    client = _client(settings)
    from euvd_watch.cra.state import Event
    from euvd_watch.web.dashboard import event_url_id

    event_id = Event.make_id(finding.component.dedupe_key, finding.record.euvd_id)
    response = client.get(f"/cra/{event_url_id(event_id)}", auth=AUTH)
    assert response.status_code == 200
    assert "never files anything" in response.text


def test_cra_event_detail_404_for_unknown_id(settings: Settings) -> None:
    _seed_demo_scenario(settings)
    client = _client(settings)
    response = client.get("/cra/0000000000000000", auth=AUTH)
    assert response.status_code == 404


def test_cra_event_draft_200_and_disclaimer(settings: Settings) -> None:
    finding = _seed_demo_scenario(settings)
    client = _client(settings)
    from euvd_watch.cra.state import Event
    from euvd_watch.web.dashboard import event_url_id

    event_id = Event.make_id(finding.component.dedupe_key, finding.record.euvd_id)
    response = client.get(f"/cra/{event_url_id(event_id)}/draft", auth=AUTH)
    assert response.status_code == 200
    assert "not been submitted anywhere" in response.text
    assert "TODO-HUMAN" in response.text


def test_audit_200_empty(settings: Settings) -> None:
    _seed_demo_scenario(settings)
    client = _client(settings)
    response = client.get("/audit", auth=AUTH)
    assert response.status_code == 200
    assert "Chain intact" in response.text


def test_audit_200_broken_chain_shown_as_broken(settings: Settings) -> None:
    _seed_demo_scenario(settings)
    (settings.state_dir / "cra-audit.jsonl").write_text('{"bad": true}\n', encoding="utf-8")
    client = _client(settings)
    response = client.get("/audit", auth=AUTH)
    assert response.status_code == 200
    assert "Chain broken" in response.text


def test_overview_friendly_state_when_no_snapshot_yet(settings: Settings) -> None:
    """Never a 500/traceback when watch has never run for this SBOM."""
    client = _client(settings)
    response = client.get("/", auth=AUTH)
    assert response.status_code == 200
    assert "watch" in response.text


# -- the write flow: mark stage complete --------------------------------------------


def test_mark_stage_complete_end_to_end(settings: Settings) -> None:
    finding = _seed_demo_scenario(settings)
    client = _client(settings)
    from euvd_watch.cra.state import Event
    from euvd_watch.web.dashboard import event_url_id

    event_id = Event.make_id(finding.component.dedupe_key, finding.record.euvd_id)
    url_id = event_url_id(event_id)

    response = client.post(
        f"/cra/{url_id}/mark",
        data={"stage": "early_warning", "note": "filed via CSIRT portal"},
        auth=AUTH,
        follow_redirects=False,
    )
    assert response.status_code == 303

    detail = client.get(f"/cra/{url_id}", auth=AUTH)
    assert "filed via CSIRT portal" in detail.text

    audit = client.get("/audit", auth=AUTH)
    assert "filed via CSIRT portal" in audit.text
    assert "Chain intact" in audit.text


def test_mark_unknown_stage_is_a_client_error_not_a_crash(settings: Settings) -> None:
    finding = _seed_demo_scenario(settings)
    client = _client(settings)
    from euvd_watch.cra.state import Event
    from euvd_watch.web.dashboard import event_url_id

    event_id = Event.make_id(finding.component.dedupe_key, finding.record.euvd_id)
    response = client.post(
        f"/cra/{event_url_id(event_id)}/mark",
        data={"stage": "not-a-real-stage"},
        auth=AUTH,
    )
    assert response.status_code == 400


def test_mark_nothing_to_record_is_a_client_error(settings: Settings) -> None:
    finding = _seed_demo_scenario(settings)
    client = _client(settings)
    from euvd_watch.cra.state import Event
    from euvd_watch.web.dashboard import event_url_id

    event_id = Event.make_id(finding.component.dedupe_key, finding.record.euvd_id)
    response = client.post(f"/cra/{event_url_id(event_id)}/mark", data={}, auth=AUTH)
    assert response.status_code == 400


def test_mark_unknown_event_404s(settings: Settings) -> None:
    _seed_demo_scenario(settings)
    client = _client(settings)
    response = client.post(
        "/cra/0000000000000000/mark", data={"stage": "early_warning"}, auth=AUTH
    )
    assert response.status_code == 404


# -- CSP-friendliness: no inline styles or event handlers anywhere ------------------


_INLINE_STYLE = re.compile(r'\sstyle="')
_INLINE_HANDLER = re.compile(r"\son[a-z]+=", re.IGNORECASE)


def test_no_inline_styles_or_event_handlers_anywhere(settings: Settings) -> None:
    finding = _seed_demo_scenario(settings)
    client = _client(settings)
    from euvd_watch.cra.state import Event
    from euvd_watch.web.dashboard import comp_hash, event_url_id

    event_id = Event.make_id(finding.component.dedupe_key, finding.record.euvd_id)
    h = comp_hash(finding.component.dedupe_key)
    url_id = event_url_id(event_id)

    paths = [
        "/",
        "/findings",
        f"/findings/{h}/{finding.record.euvd_id}",
        "/cra",
        f"/cra/{url_id}",
        f"/cra/{url_id}/draft",
        "/audit",
    ]
    for path in paths:
        response = client.get(path, auth=AUTH)
        assert response.status_code == 200, path
        assert not _INLINE_STYLE.search(response.text), f"inline style= on {path}"
        assert not _INLINE_HANDLER.search(response.text), f"inline event handler on {path}"


def test_scrollable_snippet_blocks_are_keyboard_focusable(settings: Settings) -> None:
    """Regression test for a real axe finding (Step 6.3, scrollable-region-focusable,
    WCAG 2.1.1): `<pre class="snippet">` blocks can overflow-scroll and must be
    reachable by keyboard, not just a mouse wheel."""
    finding = _seed_demo_scenario(settings)
    client = _client(settings)
    from euvd_watch.web.dashboard import comp_hash

    h = comp_hash(finding.component.dedupe_key)
    detail = client.get(f"/findings/{h}/{finding.record.euvd_id}", auth=AUTH)
    assert detail.text.count('class="snippet" tabindex="0"') == 2  # vex snippet + cli hint

    from euvd_watch.cra.state import Event
    from euvd_watch.web.dashboard import event_url_id

    event_id = Event.make_id(finding.component.dedupe_key, finding.record.euvd_id)
    draft = client.get(f"/cra/{event_url_id(event_id)}/draft", auth=AUTH)
    assert 'class="snippet" id="draft-text" tabindex="0"' in draft.text


def test_disclaimer_link_is_not_color_only(settings: Settings) -> None:
    """Regression test for a real axe finding (Step 6.3, link-in-text-block, WCAG
    1.4.1): a link embedded in the disclaimer sentence must be distinguishable from
    the surrounding text by more than color alone (underlined via CSS `.disclaimer a`,
    checked here at the CSS-source level since the property isn't visible in HTML)."""
    css = Path("src/euvd_watch/web/static/dashboard.css").read_text(encoding="utf-8")
    assert ".disclaimer a" in css
    assert "text-decoration: underline" in css.split(".disclaimer a")[1].split("}")[0]


def test_findings_filters_and_pagination_query_params(settings: Settings) -> None:
    _seed_demo_scenario(settings)
    client = _client(settings)
    response = client.get(
        "/findings?confidence=high&exploited=yes&vex_status=affected&page=1", auth=AUTH
    )
    assert response.status_code == 200
    assert "No findings match these filters" in response.text


def test_web_serve_requires_web_extra_password_hash_before_create_app(settings: Settings) -> None:
    """create_app itself never checks password_hash - `web_serve` in cli.py does, before
    calling here. Documented here so the boundary is explicit and doesn't silently move."""
    naked_settings = Settings(state_dir=settings.state_dir)  # no password_hash
    app = create_app(naked_settings, sbom_path=SBOM, host="127.0.0.1", port=8642)
    client = TestClient(app)
    # Every credential fails verify_password() against a None hash -> always 401,
    # never accidentally open.
    response = client.get("/", auth=("admin", "anything"))
    assert response.status_code == 401
