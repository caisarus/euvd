"""Covers implementation_plan.md Step 1.4: correctness of the matcher's raw material."""

import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from euvd_watch.models import Component, SourceFormat
from euvd_watch.sbom.normalize import (
    clean_version,
    normalize_component,
    normalize_purl,
    parse_cpe,
    synthesize_purl,
)

pytestmark = pytest.mark.unit

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "sboms" / "syft-demo.cdx.json"


def _real_purls() -> list[str]:
    data = json.loads(FIXTURE.read_text())
    return sorted({c["purl"] for c in data["components"] if c.get("purl")})


def _real_cpes() -> list[str]:
    data = json.loads(FIXTURE.read_text())
    return sorted({c["cpe"] for c in data["components"] if c.get("cpe")})


# --- Table-driven: >=30 real-world messy identifier cases, derived from the real Syft
# fixture (mixed-case variants of genuinely-shipped purls) plus the fixture's real,
# often-garbled CPEs. ---

_REAL_PURLS = _real_purls()
assert len(_REAL_PURLS) >= 30, "fixture shrank below the >=30 messy-case requirement"


def _messy_case_variant(purl: str) -> str:
    # Mangle only the type/name portion (mixed case): packageurl-python correctly preserves
    # version-string case as-is, so title-casing the whole purl would corrupt the version too.
    head, _, version = purl.partition("@")
    return f"{head.title().replace('Pkg:', 'pkg:')}@{version}" if version else head.title()


_MESSY_PURL_CASES = [(_messy_case_variant(purl), purl) for purl in _REAL_PURLS]


def test_messy_purl_table_normalizes_to_real_canonical_form() -> None:
    for messy, expected_canonical in _MESSY_PURL_CASES:
        assert normalize_purl(messy) == expected_canonical


def test_normalize_purl_is_idempotent_over_real_fixture_purls() -> None:
    for purl in _REAL_PURLS:
        assert normalize_purl(normalize_purl(purl)) == normalize_purl(purl)


def test_normalize_purl_tolerates_malformed_input() -> None:
    assert normalize_purl("not a purl at all") == "not a purl at all"


@given(
    st.sampled_from(["pypi", "npm", "golang", "maven", "gem", "cargo"]),
    st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Nd"), max_codepoint=122),
        min_size=1,
        max_size=20,
    ),
    st.text(alphabet="0123456789.", min_size=1, max_size=10),
)
def test_normalize_purl_idempotence_property(ecosystem: str, name: str, version: str) -> None:
    purl = f"pkg:{ecosystem}/{name}@{version}"
    once = normalize_purl(purl)
    twice = normalize_purl(once)
    assert once == twice


def test_parse_cpe_on_all_real_fixture_cpes() -> None:
    cpes = _real_cpes()
    assert len(cpes) >= 30
    for cpe in cpes:
        parsed = parse_cpe(cpe)
        assert parsed is not None
        assert set(parsed) == {
            "part",
            "vendor",
            "product",
            "version",
            "update",
            "edition",
            "language",
            "sw_edition",
            "target_sw",
            "target_hw",
            "other",
        }


def test_parse_cpe_decodes_escaped_special_characters() -> None:
    cpe = (
        r"cpe:2.3:a:adrian_garcia_badaracco_\<1755071\+adriangb_project:"
        r"python-annotated-types:0.7.0:*:*:*:*:*:*:*"
    )
    parsed = parse_cpe(cpe)
    assert parsed is not None
    # Values come back decoded (literal characters), not in CPE wire encoding: the M2
    # matcher compares vendor/product text and must not see the backslashes.
    assert parsed["vendor"] == "adrian_garcia_badaracco_<1755071+adriangb_project"
    assert parsed["product"] == "python-annotated-types"
    assert parsed["version"] == "0.7.0"


def test_parse_cpe_rejects_non_cpe_strings() -> None:
    assert parse_cpe("not a cpe") is None
    assert parse_cpe("cpe:2.2:a:too:old:a:version:scheme") is None


def test_parse_cpe_rejects_wrong_field_count() -> None:
    assert parse_cpe("cpe:2.3:a:vendor:product") is None


@given(st.text(min_size=0, max_size=200))
def test_parse_cpe_never_raises(text: str) -> None:
    parse_cpe(text)  # must not raise, regardless of input


def test_clean_version_strips_leading_v() -> None:
    assert clean_version("v1.2.3") == "1.2.3"
    assert clean_version("V2.0.0") == "2.0.0"


def test_clean_version_strips_debian_epoch() -> None:
    assert clean_version("1:1.2.3-1") == "1.2.3-1"


def test_clean_version_strips_whitespace() -> None:
    assert clean_version("  1.2.3  ") == "1.2.3"


def test_clean_version_leaves_plain_version_untouched() -> None:
    assert clean_version("1.2.3") == "1.2.3"


def test_clean_version_does_not_strip_v_from_non_version_word() -> None:
    assert clean_version("vendor") == "vendor"


def test_synthesize_purl_builds_from_ecosystem() -> None:
    assert synthesize_purl("widget", "1.0.0", "pypi") == "pkg:pypi/widget@1.0.0"


def test_synthesize_purl_without_version() -> None:
    assert synthesize_purl("widget", None, "pypi") == "pkg:pypi/widget"


def test_synthesize_purl_returns_none_without_ecosystem() -> None:
    assert synthesize_purl("widget", "1.0.0", None) is None


def test_synthesized_purls_are_always_canonical() -> None:
    # Messy name (space, mixed case) and messy version (leading v): the result must be a
    # valid canonical purl, i.e. a fixed point of normalize_purl.
    purl = synthesize_purl("My Widget", "v1.0.0", "pypi")
    assert purl == "pkg:pypi/my%20widget@1.0.0"
    assert purl == normalize_purl(purl)


def test_synthesize_purl_uses_cleaned_version() -> None:
    purl = synthesize_purl("widget", "1:2.0-1", "pypi")
    assert purl == "pkg:pypi/widget@2.0-1"  # epoch stripped, same as normalized_version


def test_normalize_component_populates_normalized_purl() -> None:
    c = Component(
        name="requests",
        version="2.31.0",
        purl="pkg:PyPI/Requests@2.31.0",
        source_format=SourceFormat.CYCLONEDX,
        raw_ref="ref-1",
    )
    normalized = normalize_component(c)
    assert normalized.normalized_purl == "pkg:pypi/requests@2.31.0"
    assert normalized.normalized_version == "2.31.0"
    assert normalized.synthesized is False


def test_normalize_component_synthesizes_purl_from_cpe_ecosystem_prefix() -> None:
    c = Component(
        name="annotated-doc",
        version="0.0.4",
        cpe="cpe:2.3:a:python-annotated-doc:python-annotated-doc:0.0.4:*:*:*:*:*:*:*",
        source_format=SourceFormat.CYCLONEDX,
        raw_ref="ref-2",
    )
    normalized = normalize_component(c)
    assert normalized.normalized_purl == "pkg:pypi/annotated-doc@0.0.4"
    assert normalized.synthesized is True
    assert normalized.cpe_parts is not None


def test_normalize_component_no_synthesis_without_recognizable_ecosystem() -> None:
    c = Component(
        name="mystery",
        version="1.0.0",
        cpe="cpe:2.3:a:acme:mystery:1.0.0:*:*:*:*:*:*:*",
        source_format=SourceFormat.CYCLONEDX,
        raw_ref="ref-3",
    )
    normalized = normalize_component(c)
    assert normalized.normalized_purl is None
    assert normalized.synthesized is False


def test_normalize_component_is_idempotent() -> None:
    c = Component(
        name="requests",
        version="v2.31.0",
        purl="pkg:PyPI/Requests@2.31.0",
        source_format=SourceFormat.CYCLONEDX,
        raw_ref="ref-4",
    )
    once = normalize_component(c)
    twice = normalize_component(once)
    assert once.model_dump() == twice.model_dump()
