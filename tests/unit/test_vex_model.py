"""Covers implementation_plan.md Step 3.1: OpenVEX document model & deterministic writer."""

import json
from pathlib import Path

import jsonschema
import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from euvd_watch.vex.model import (
    OPENVEX_CONTEXT,
    Identifiers,
    Justification,
    OpenVexDocument,
    Product,
    Statement,
    Status,
    Vulnerability,
)
from euvd_watch.vex.write import render, sort_statements

pytestmark = pytest.mark.unit

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "openvex" / "schema.json").read_text(
        encoding="utf-8"
    )
)
GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "golden" / "sample.openvex.json"


def _sample_document() -> OpenVexDocument:
    return OpenVexDocument(
        id="urn:euvd-watch:vex:test-digest",
        author="euvd-watch",
        timestamp="2026-01-01T00:00:00Z",
        statements=[
            Statement(
                vulnerability=Vulnerability(name="CVE-2026-59890", aliases=["EUVD-2026-42323"]),
                status=Status.NOT_AFFECTED,
                products=[Product(identifiers=Identifiers(purl="pkg:pypi/setuptools@79.0.1"))],
                justification=Justification.VULNERABLE_CODE_NOT_PRESENT,
                impact_statement="Version 79.0.1 is outside affected range '<83.0.0'.",
            ),
            Statement(
                vulnerability=Vulnerability(name="CVE-2026-24049", aliases=["EUVD-2026-4133"]),
                status=Status.UNDER_INVESTIGATION,
                products=[Product(identifiers=Identifiers(purl="pkg:pypi/wheel@0.45.1"))],
            ),
        ],
    )


def test_document_uses_the_fixed_openvex_context() -> None:
    doc = _sample_document()
    assert doc.context == OPENVEX_CONTEXT == "https://openvex.dev/ns/v0.2.0"


def test_rendered_document_validates_against_vendored_schema() -> None:
    text = render(_sample_document())
    jsonschema.validate(json.loads(text), SCHEMA)


def test_rendered_document_matches_golden_byte_for_byte() -> None:
    text = render(_sample_document())
    golden = GOLDEN.read_text(encoding="utf-8")
    assert text == golden


def test_round_trip_write_read_write_is_byte_stable() -> None:
    text = render(_sample_document())
    parsed = OpenVexDocument.model_validate_json(text)
    assert render(parsed) == text


def test_not_affected_without_justification_or_impact_statement_is_rejected() -> None:
    with pytest.raises(ValidationError, match="justification or an impact_statement"):
        Statement(
            vulnerability=Vulnerability(name="CVE-1"),
            status=Status.NOT_AFFECTED,
        )


def test_affected_without_action_statement_is_rejected() -> None:
    with pytest.raises(ValidationError, match="action_statement"):
        Statement(vulnerability=Vulnerability(name="CVE-1"), status=Status.AFFECTED)


def test_product_without_id_or_identifiers_is_rejected() -> None:
    with pytest.raises(ValidationError, match="@id or identifiers"):
        Product()


def test_under_investigation_needs_no_extra_fields() -> None:
    # The default status; no justification/impact/action required.
    Statement(vulnerability=Vulnerability(name="CVE-1"), status=Status.UNDER_INVESTIGATION)


@given(st.permutations(_sample_document().statements))
def test_statement_ordering_is_stable_under_input_shuffling(shuffled: list[Statement]) -> None:
    base = render(_sample_document())
    shuffled_doc = _sample_document().model_copy(update={"statements": list(shuffled)})
    assert render(shuffled_doc) == base


def test_sort_statements_is_order_independent() -> None:
    statements = _sample_document().statements
    assert sort_statements(statements) == sort_statements(list(reversed(statements)))
