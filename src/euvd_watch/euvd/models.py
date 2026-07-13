# SPDX-License-Identifier: EUPL-1.2
"""Typed EUVD records: stable shapes the matcher consumes, insulated from beta-API churn.

Parsing here is tolerant (the API is beta: unknown fields ignored, missing fields default),
with one hard rule: a record without a usable `euvd_id` is skipped with a warning — identity
keys must never be empty (see the plan's hardening rules).

API quirks handled here (verified live, documented in docs/euvd-api.md):
- `aliases` and `references` arrive as newline-joined strings, not arrays.
- `epss` arrives on a 0-100 scale; we normalize to 0-1 to match FIRST.org and the
  configured `epss_threshold`.
- There is no `exploited` boolean: the presence of `exploitedSince` is the flag.
- Dates are US-format display strings; kept verbatim (determinism), never parsed here.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)


class AffectedProduct(BaseModel):
    """One (vendor, product, version-range) triple as published by EUVD — text, not purl."""

    model_config = ConfigDict(frozen=True)

    vendor: str | None = None
    product: str
    version_range: str | None = None


class EuvdRecord(BaseModel):
    """One EUVD vulnerability record, normalized for matching."""

    model_config = ConfigDict(frozen=True)

    euvd_id: str
    aliases: list[str] = []
    description: str = ""
    affected_products: list[AffectedProduct] = []
    exploited: bool = False
    exploited_since: str | None = None
    epss: float | None = None
    cvss_score: float | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    references: list[str] = []
    date_published: str | None = None
    date_updated: str | None = None


def _split_lines(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []
    return [line.strip() for line in value.splitlines() if line.strip()]


def _parse_products(raw: Any) -> list[AffectedProduct]:
    products: list[AffectedProduct] = []
    for entry in raw or []:
        if not isinstance(entry, dict):
            continue
        product_obj = entry.get("product") or {}
        if not isinstance(product_obj, dict):
            continue
        name = str(product_obj.get("name") or "").strip()
        if not name:
            continue
        vendor_obj = product_obj.get("vendor") or {}
        vendor = None
        if isinstance(vendor_obj, dict) and vendor_obj.get("name"):
            vendor = str(vendor_obj["name"]).strip() or None
        version_range = entry.get("product_version")
        products.append(
            AffectedProduct(
                vendor=vendor,
                product=name,
                version_range=str(version_range).strip() if version_range else None,
            )
        )
    return products


def _opt_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def parse_record(raw: dict[str, Any]) -> EuvdRecord | None:
    """Parse one raw API record. Returns None (with a warning) if it has no usable id."""
    euvd_id = str(raw.get("id") or "").strip()
    if not euvd_id:
        logger.warning("Skipping EUVD record without an id: %.120r", raw)
        return None

    exploited_since = raw.get("exploitedSince")
    epss_raw = _opt_float(raw.get("epss"))

    return EuvdRecord(
        euvd_id=euvd_id,
        aliases=_split_lines(raw.get("aliases")),
        description=str(raw.get("description") or ""),
        affected_products=_parse_products(raw.get("enisaIdProduct")),
        exploited=exploited_since is not None,
        exploited_since=str(exploited_since) if exploited_since is not None else None,
        # EUVD publishes epss on a 0-100 scale; normalize to FIRST.org's 0-1.
        epss=epss_raw / 100.0 if epss_raw is not None else None,
        cvss_score=_opt_float(raw.get("baseScore")),
        cvss_version=str(raw["baseScoreVersion"]) if raw.get("baseScoreVersion") else None,
        cvss_vector=str(raw["baseScoreVector"]) if raw.get("baseScoreVector") else None,
        references=_split_lines(raw.get("references")),
        date_published=str(raw["datePublished"]) if raw.get("datePublished") else None,
        date_updated=str(raw["dateUpdated"]) if raw.get("dateUpdated") else None,
    )


def parse_records(raw_list: Any) -> list[EuvdRecord]:
    """Parse a list of raw records, skipping unusable entries with warnings."""
    records: list[EuvdRecord] = []
    for raw in raw_list or []:
        if not isinstance(raw, dict):
            logger.warning("Skipping non-object EUVD record entry: %.80r", raw)
            continue
        record = parse_record(raw)
        if record is not None:
            records.append(record)
    return records
