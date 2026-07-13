# SPDX-License-Identifier: EUPL-1.2
"""Deterministic OpenVEX serialization (Step 3.1).

Byte-stable regardless of the order evaluations/findings arrived in: `render` sorts
statements itself (by product identifier, then vulnerability name) rather than trusting
callers to pre-sort - a defensive default that also makes the ordering trivially testable
in isolation (test_plan.md's "shuffle input, output identical" requirement).
"""

from __future__ import annotations

import json

from euvd_watch.vex.model import OpenVexDocument, Statement


def _statement_sort_key(statement: Statement) -> tuple[str, str]:
    product = statement.products[0] if statement.products else None
    if product is None:
        product_key = ""
    elif product.identifiers and product.identifiers.purl:
        product_key = product.identifiers.purl
    elif product.id:
        product_key = product.id
    else:
        product_key = ""
    return (product_key, statement.vulnerability.name)


def sort_statements(statements: list[Statement]) -> list[Statement]:
    """Deterministic, input-order-independent statement ordering."""
    return sorted(statements, key=_statement_sort_key)


def render(document: OpenVexDocument) -> str:
    """Serialize an OpenVexDocument to deterministic JSON text (trailing newline)."""
    sorted_document = document.model_copy(
        update={"statements": sort_statements(document.statements)}
    )
    data = sorted_document.model_dump(mode="json", by_alias=True, exclude_none=True)
    return json.dumps(data, sort_keys=True, indent=2) + "\n"
