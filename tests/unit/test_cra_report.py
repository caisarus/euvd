"""Covers implementation_plan.md Step 4.3: the notification draft renderer."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from euvd_watch.config import CraTriggerConfig, OrganizationConfig, Settings
from euvd_watch.cra.report import DISCLAIMER, DraftError, render_json, render_markdown
from euvd_watch.cra.state import Event
from euvd_watch.euvd.match import Confidence, Finding, Strategy
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.models import Component, SourceFormat

pytestmark = pytest.mark.unit

GOLDEN_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "golden"
GENERATED_AT = "2026-01-02T09:00:00+00:00"
NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)  # 12h after first_seen: early_warning pending
FIRST_SEEN = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _settings() -> Settings:
    # Romanian diacritics on purpose (test plan 4.3): drafts must render non-ASCII org
    # identities without mangling.
    return Settings(
        organization=OrganizationConfig(
            name="Exemplu Țesătorie S.R.L.",
            contact_email="securitate@exemplu.ro",
            product_name="Produsul Înțelept",
        )
    )


def _event() -> Event:
    component = Component(
        name="jinja2",
        version="3.1.6",
        purl="pkg:pypi/jinja2@3.1.6",
        normalized_purl="pkg:pypi/jinja2@3.1.6",
        source_format=SourceFormat.CYCLONEDX,
        raw_ref="ref-1",
    )
    record = EuvdRecord(
        euvd_id="EUVD-2026-0001",
        aliases=["CVE-2099-0001", "GHSA-test-0001"],
        description="Sandbox escape in the template engine.",
        exploited=True,
        exploited_since="Jan 1, 2026, 12:00:00 AM",
        references=["https://example.org/advisory-1", "https://example.org/advisory-2"],
        cvss_score=8.8,
    )
    finding = Finding(
        component=component,
        record=record,
        confidence=Confidence.HIGH,
        strategy=Strategy.STRUCTURED,
        explanation="Vendor 'pallets' and product 'jinja2' match exactly and version "
        "3.1.6 is inside affected range '<3.1.7' (pep440).",
        epss_score=0.87,
        in_kev=True,
    )
    return Event(
        event_id=Event.make_id(component.dedupe_key, record.euvd_id),
        finding=finding,
        fired_rules=["euvd_exploited", "cisa_kev", "epss_over_threshold"],
        first_seen=FIRST_SEEN,
        policy_snapshot=CraTriggerConfig(),
        epss_threshold=0.5,
    )


def test_markdown_draft_matches_golden_byte_for_byte() -> None:
    text = render_markdown(_event(), _settings(), GENERATED_AT, now=NOW)
    golden = (GOLDEN_DIR / "cra-early-warning.md").read_text(encoding="utf-8")
    assert text == golden


def test_json_draft_matches_golden_and_is_versioned() -> None:
    import json

    text = render_json(_event(), _settings(), GENERATED_AT, now=NOW)
    golden = (GOLDEN_DIR / "cra-early-warning.json").read_text(encoding="utf-8")
    assert text == golden
    artifact = json.loads(text)
    assert artifact["schema_version"] == 1
    assert artifact["kind"] == "cra_early_warning_draft"


def test_every_human_judgment_field_is_marked() -> None:
    text = render_markdown(_event(), _settings(), GENERATED_AT, now=NOW)
    # Contact person, usage location, impact assessment, your-product exploitation,
    # corrective measures (x2): the human-judgment fields must be unmissable.
    assert text.count("TODO-HUMAN") >= 5


def test_disclaimer_present_in_both_formats() -> None:
    assert DISCLAIMER in render_markdown(_event(), _settings(), GENERATED_AT, now=NOW)
    assert DISCLAIMER in render_json(_event(), _settings(), GENERATED_AT, now=NOW)


def test_epss_signal_is_never_upgraded_to_an_exploitation_claim() -> None:
    # REQ-CRA-004: the EPSS sentence must carry its demotion to a probability signal.
    text = render_markdown(_event(), _settings(), GENERATED_AT, now=NOW)
    assert "NOT direct evidence of active exploitation" in text
    # The exploitation-language sentence must be attributed to its source, not generic.
    assert "ENISA's EUVD marks this vulnerability as actively exploited" in text


def test_first_fire_basis_is_rendered_not_latest_knowledge() -> None:
    # The awareness basis must reflect what fired at first_seen even after refreshes.
    event = _event()
    weaker_later = event.finding.model_copy(update={"epss_score": 0.01, "in_kev": False})
    refreshed = event.model_copy(update={"latest_finding": weaker_later})
    text = render_markdown(refreshed, _settings(), GENERATED_AT, now=NOW)
    assert "0.870" in text  # the first-fire EPSS score, not 0.01
    assert "Known Exploited Vulnerabilities" in text  # KEV rule still in the basis


def test_missing_org_config_error_names_the_exact_fields() -> None:
    settings = Settings(organization=OrganizationConfig(contact_email="a@b.c"))
    with pytest.raises(DraftError) as excinfo:
        render_markdown(_event(), settings, GENERATED_AT, now=NOW)
    message = str(excinfo.value)
    assert "organization.name" in message
    assert "organization.product_name" in message
    assert "organization.contact_email" not in message  # it was provided


def test_romanian_diacritics_survive_rendering() -> None:
    text = render_markdown(_event(), _settings(), GENERATED_AT, now=NOW)
    assert "Exemplu Țesătorie S.R.L." in text
    assert "Produsul Înțelept" in text


def test_rendering_is_deterministic() -> None:
    args = (_event(), _settings(), GENERATED_AT)
    assert render_markdown(*args, now=NOW) == render_markdown(*args, now=NOW)
    assert render_json(*args, now=NOW) == render_json(*args, now=NOW)
