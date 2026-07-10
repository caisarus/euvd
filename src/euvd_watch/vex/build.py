"""Assembling OpenVEX Statements/Documents from (Evaluation, Decision) pairs (Step 3.4).

Field mapping: `not_affected`/`fixed`/`under_investigation` carry the decision's
explanation as `impact_statement` (always present - Decision.explanation is required,
so this alone satisfies the not_affected schema requirement even if a human decision
supplied no justification); `affected` carries it as the required `action_statement`.
"""

from __future__ import annotations

from euvd_watch.euvd.match import Evaluation
from euvd_watch.euvd.models import EuvdRecord
from euvd_watch.models import Component
from euvd_watch.vex.merge import ResolvedDecision
from euvd_watch.vex.model import (
    Identifiers,
    OpenVexDocument,
    Product,
    Statement,
    Status,
    Vulnerability,
)
from euvd_watch.vex.rules import Decision


def _product_for_component(component: Component) -> Product:
    purl = component.normalized_purl or component.purl
    if purl:
        return Product(identifiers=Identifiers(purl=purl))
    # No purl at all (rare): the schema still requires @id or identifiers. Constructed via
    # model_validate (not the `id=` keyword) to sidestep a mypy/pydantic PEP 681 quirk where
    # dataclass_transform checks constructor keywords against the field's alias ("@id"),
    # not its populate_by_name-enabled Python name, even with populate_by_name=True set.
    return Product.model_validate({"@id": f"urn:euvd-watch:component:{component.dedupe_key}"})


def _vulnerability_for_record(record: EuvdRecord) -> Vulnerability:
    # A CVE alias is more universally recognized than the EUVD id, so it leads when
    # available; the EUVD id and every other alias are still listed for findability.
    cve_aliases = [a for a in record.aliases if a.startswith("CVE-")]
    name = cve_aliases[0] if cve_aliases else record.euvd_id
    others = [record.euvd_id, *record.aliases]
    seen: set[str] = {name}
    aliases: list[str] = []
    for alias in others:
        if alias not in seen:
            seen.add(alias)
            aliases.append(alias)
    return Vulnerability(name=name, aliases=aliases)


def build_statement(evaluation: Evaluation, decision: Decision) -> Statement:
    """One evaluation + its final decision -> one OpenVEX statement."""
    product = _product_for_component(evaluation.component)
    vulnerability = _vulnerability_for_record(evaluation.record)
    if decision.status is Status.AFFECTED:
        return Statement(
            vulnerability=vulnerability,
            status=decision.status,
            products=[product],
            action_statement=decision.explanation,
        )
    return Statement(
        vulnerability=vulnerability,
        status=decision.status,
        products=[product],
        justification=decision.justification,
        impact_statement=decision.explanation,
    )


def build_document(
    resolved: list[ResolvedDecision],
    *,
    document_id: str,
    author: str,
    timestamp: str,
) -> OpenVexDocument:
    """Assemble the full OpenVEX document. Statement order is handled by vex/write.py."""
    statements = [build_statement(r.evaluation, r.decision) for r in resolved]
    return OpenVexDocument.model_validate(
        {
            "@id": document_id,
            "author": author,
            "timestamp": timestamp,
            "statements": statements,
        }
    )
