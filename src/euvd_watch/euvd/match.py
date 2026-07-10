"""The matching engine (Step 2.3): does EUVD record X affect component Y, and how sure?

Core problem: the SBOM side speaks purl/CPE; the EUVD side speaks (vendor, product,
version-range) text. Candidates are derived per component (CPE fields first — best signal —
then purl, assisted by the curated aliases table), then strategies run in order and the
best result per (component, record) is kept. Confidence is honest by construction:

- high   — structured (vendor, product) equality AND version provably inside the range
           with a trustworthy comparison scheme, on a non-synthesized identifier.
- medium — structured equality with an ambiguous/open range, or product-only equality
           with the version in range; also every would-be high hit by a hard cap.
- low    — fuzzy name similarity only; exists to surface candidates for human review,
           never for automated downstream decisions.

Hard caps (enforced here, re-asserted in tests/invariants/): a synthesized identifier can
never exceed medium; a tokenwise version comparison can never support high. Every Finding
carries a mandatory human-readable explanation — this feeds VEX/CRA auditability.

Pure functions over Inventory + records; no I/O except reading the packaged aliases table.
"""

from __future__ import annotations

import re
from enum import StrEnum
from functools import lru_cache
from importlib.resources import files

import yaml
from pydantic import BaseModel, ConfigDict

from euvd_watch.euvd.models import AffectedProduct, EuvdRecord
from euvd_watch.euvd.versions import RangeResult, Scheme, evaluate_range
from euvd_watch.models import Component, Inventory


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


def confidence_at_least(value: Confidence, floor: Confidence) -> bool:
    return _CONFIDENCE_RANK[value] >= _CONFIDENCE_RANK[floor]


class Strategy(StrEnum):
    STRUCTURED = "structured"
    PARTIAL = "partial"
    FUZZY = "fuzzy"


class Finding(BaseModel):
    """One (component, record) match with an honest confidence and a mandatory why."""

    model_config = ConfigDict(frozen=True)

    component: Component
    record: EuvdRecord
    confidence: Confidence
    strategy: Strategy
    explanation: str
    epss_score: float | None = None  # filled by enrichment (FIRST.org, authoritative)
    in_kev: bool | None = None  # filled by enrichment (CISA KEV membership)


class Candidate(BaseModel):
    """A (vendor, product) guess for a component, with where it came from."""

    model_config = ConfigDict(frozen=True)

    vendor: str | None
    product: str
    source: str  # "cpe" | "alias" | "purl" | "name"


_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def normalize_text(value: str) -> str:
    """Lowercase, punctuation-insensitive form used for all vendor/product equality."""
    return _NON_ALNUM.sub("", value.lower())


def _tokens(value: str) -> set[str]:
    return {t for t in _NON_ALNUM.split(value.lower()) if t}


@lru_cache(maxsize=1)
def _load_aliases() -> dict[str, dict[str, str]]:
    raw = files("euvd_watch.euvd").joinpath("aliases.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    return {str(k): dict(v) for k, v in data.items() if isinstance(v, dict)}


def _versionless_purl(purl: str) -> str:
    return purl.split("@", 1)[0]


def derive_candidates(component: Component) -> list[Candidate]:
    """(vendor, product) candidates for a component, best signal first, deduplicated."""
    candidates: list[Candidate] = []

    cpe = component.cpe_parts or {}
    cpe_vendor = cpe.get("vendor", "")
    cpe_product = cpe.get("product", "")
    if cpe_product and cpe_product != "*":
        vendor = cpe_vendor if cpe_vendor and cpe_vendor != "*" else None
        candidates.append(Candidate(vendor=vendor, product=cpe_product, source="cpe"))

    purl = component.normalized_purl or component.purl
    if purl:
        alias = _load_aliases().get(_versionless_purl(purl))
        if alias and alias.get("product"):
            candidates.append(
                Candidate(vendor=alias.get("vendor"), product=alias["product"], source="alias")
            )
        # purl namespace (if any) is a weak vendor hint; the name is the product.
        rest = purl.removeprefix("pkg:").split("@", 1)[0]
        segments = rest.split("/")
        if len(segments) >= 2:
            name = segments[-1]
            namespace = segments[-2] if len(segments) >= 3 else None
            candidates.append(Candidate(vendor=namespace, product=name, source="purl"))

    candidates.append(Candidate(vendor=None, product=component.name, source="name"))

    seen: set[tuple[str, str]] = set()
    unique: list[Candidate] = []
    for candidate in candidates:
        key = (normalize_text(candidate.vendor or ""), normalize_text(candidate.product))
        if key in seen or not key[1]:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


_FUZZY_THRESHOLD = 0.6


def _fuzzy_similarity(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


class _Evaluation(BaseModel):
    model_config = ConfigDict(frozen=True)

    confidence: Confidence
    strategy: Strategy
    explanation: str


def _evaluate_pair(
    component: Component, candidate: Candidate, affected: AffectedProduct
) -> _Evaluation | None:
    """Evaluate one candidate against one affected-product entry. None = no match."""
    product_equal = normalize_text(candidate.product) == normalize_text(affected.product)
    vendor_known = bool(candidate.vendor) and bool(affected.vendor)
    vendor_equal = vendor_known and normalize_text(candidate.vendor or "") == normalize_text(
        affected.vendor or ""
    )

    if component.version is not None and affected.version_range:
        # Raw version, never normalized_version: deb epochs (docs/matching.md).
        range_result, scheme = evaluate_range(component.version, affected.version_range)
    else:
        range_result, scheme = RangeResult.AMBIGUOUS, Scheme.TOKENWISE

    range_text = affected.version_range or "(none published)"

    if product_equal and vendor_equal:
        if range_result is RangeResult.OUTSIDE and scheme is not Scheme.TOKENWISE:
            return None  # provably outside the affected range
        if range_result is RangeResult.INSIDE:
            if scheme is Scheme.TOKENWISE:
                return _Evaluation(
                    confidence=Confidence.MEDIUM,
                    strategy=Strategy.STRUCTURED,
                    explanation=(
                        f"Vendor '{affected.vendor}' and product '{affected.product}' match "
                        f"exactly and version {component.version} appears inside range "
                        f"'{range_text}', but only the fallback comparator could evaluate it "
                        f"(capped at medium)."
                    ),
                )
            if component.synthesized:
                return _Evaluation(
                    confidence=Confidence.MEDIUM,
                    strategy=Strategy.STRUCTURED,
                    explanation=(
                        f"Vendor '{affected.vendor}' and product '{affected.product}' match "
                        f"exactly and version {component.version} is inside range "
                        f"'{range_text}' ({scheme}), but the component identifier was "
                        f"synthesized (capped at medium)."
                    ),
                )
            return _Evaluation(
                confidence=Confidence.HIGH,
                strategy=Strategy.STRUCTURED,
                explanation=(
                    f"Vendor '{affected.vendor}' and product '{affected.product}' match "
                    f"exactly and version {component.version} is inside affected range "
                    f"'{range_text}' ({scheme})."
                ),
            )
        return _Evaluation(
            confidence=Confidence.MEDIUM,
            strategy=Strategy.PARTIAL,
            explanation=(
                f"Vendor '{affected.vendor}' and product '{affected.product}' match exactly "
                f"but the affected range '{range_text}' could not be reliably evaluated "
                f"against version {component.version}."
            ),
        )

    if product_equal:
        if vendor_known and not vendor_equal:
            # Same product name, different vendor: classic false-positive shape unless the
            # version is in range — and even then, only medium.
            if range_result is RangeResult.INSIDE:
                return _Evaluation(
                    confidence=Confidence.MEDIUM,
                    strategy=Strategy.PARTIAL,
                    explanation=(
                        f"Product '{affected.product}' matches and version "
                        f"{component.version} is inside range '{range_text}', but the "
                        f"vendors differ ('{candidate.vendor}' vs '{affected.vendor}')."
                    ),
                )
            return None
        if range_result is RangeResult.OUTSIDE and scheme is not Scheme.TOKENWISE:
            return None
        if range_result is RangeResult.INSIDE:
            return _Evaluation(
                confidence=Confidence.MEDIUM,
                strategy=Strategy.PARTIAL,
                explanation=(
                    f"Product '{affected.product}' matches (vendor unknown on one side) and "
                    f"version {component.version} is inside range '{range_text}'."
                ),
            )
        return _Evaluation(
            confidence=Confidence.LOW,
            strategy=Strategy.PARTIAL,
            explanation=(
                f"Product '{affected.product}' matches (vendor unknown on one side) but the "
                f"range '{range_text}' could not be reliably evaluated."
            ),
        )

    similarity = _fuzzy_similarity(candidate.product, affected.product)
    if similarity >= _FUZZY_THRESHOLD:
        if range_result is RangeResult.OUTSIDE and scheme is not Scheme.TOKENWISE:
            return None
        return _Evaluation(
            confidence=Confidence.LOW,
            strategy=Strategy.FUZZY,
            explanation=(
                f"Component name '{candidate.product}' is similar to affected product "
                f"'{affected.product}' (token similarity {similarity:.2f}); flagged for "
                f"human review only."
            ),
        )
    return None


def _evaluate_affected(
    component: Component, candidates: list[Candidate], affected: AffectedProduct
) -> _Evaluation | None:
    """Best evaluation of one affected entry, letting informed candidates be decisive.

    If any candidate *knows* its vendor and its product equals the affected product, only
    those candidates decide the outcome: a vendor-less fallback (e.g. the bare component
    name) must not resurrect a match that the known vendor already contradicted.
    """
    informed = [
        c
        for c in candidates
        if c.vendor and normalize_text(c.product) == normalize_text(affected.product)
    ]
    pool = informed or candidates
    best: _Evaluation | None = None
    for candidate in pool:
        evaluation = _evaluate_pair(component, candidate, affected)
        if evaluation is None:
            continue
        if (
            best is None
            or _CONFIDENCE_RANK[evaluation.confidence] > _CONFIDENCE_RANK[best.confidence]
        ):
            best = evaluation
    return best


def match_component(component: Component, records: list[EuvdRecord]) -> list[Finding]:
    """Match one component against records, keeping the best evaluation per record."""
    candidates = derive_candidates(component)
    findings: list[Finding] = []
    for record in records:
        best: _Evaluation | None = None
        for affected in record.affected_products:
            evaluation = _evaluate_affected(component, candidates, affected)
            if evaluation is None:
                continue
            if (
                best is None
                or _CONFIDENCE_RANK[evaluation.confidence] > _CONFIDENCE_RANK[best.confidence]
            ):
                best = evaluation
        if best is not None:
            findings.append(
                Finding(
                    component=component,
                    record=record,
                    confidence=best.confidence,
                    strategy=best.strategy,
                    explanation=best.explanation,
                )
            )
    return findings


def match_inventory(inventory: Inventory, records: list[EuvdRecord]) -> list[Finding]:
    """Match every component; deterministic ordering by (dedupe_key, euvd_id)."""
    findings: list[Finding] = []
    for component in inventory.components:
        findings.extend(match_component(component, records))
    findings.sort(key=lambda f: (f.component.dedupe_key, f.record.euvd_id))
    return findings
