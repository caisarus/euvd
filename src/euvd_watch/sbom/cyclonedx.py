"""CycloneDX (JSON) parser. Supports spec versions 1.4-1.6 via tolerant field extraction.

Purpose (plans/implementation_plan.md Step 1.2): CycloneDX is the most common SBOM output of
Syft/cdxgen, so parsing it correctly is the highest-value input path. We deliberately do not
pull in a heavyweight schema validator - unknown/extra fields are ignored, and only the fields
we actually consume are extracted, tolerating the messiness real-world SBOMs contain.
Components that cannot participate in matching (no name) are skipped with a warning rather
than silently collapsing together downstream.
"""

from __future__ import annotations

import itertools
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from euvd_watch.models import Component, ComponentType, Inventory, SourceFormat
from euvd_watch.sbom._load import load_json
from euvd_watch.sbom.errors import SbomParseError

logger = logging.getLogger(__name__)

_TYPE_MAP = {
    "library": ComponentType.LIBRARY,
    "framework": ComponentType.LIBRARY,
    "application": ComponentType.APPLICATION,
    "operating-system": ComponentType.OS,
    "container": ComponentType.CONTAINER,
}


def _extract_licenses(raw_licenses: list[dict[str, Any]] | None) -> list[str]:
    licenses: list[str] = []
    for entry in raw_licenses or []:
        if not isinstance(entry, dict):
            continue
        if "expression" in entry:
            licenses.append(str(entry["expression"]))
            continue
        license_obj = entry.get("license")
        if not isinstance(license_obj, dict):
            continue
        if "id" in license_obj:
            licenses.append(str(license_obj["id"]))
        elif "name" in license_obj:
            licenses.append(str(license_obj["name"]))
    return licenses


def _extract_hashes(raw_hashes: list[dict[str, Any]] | None) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for entry in raw_hashes or []:
        if not isinstance(entry, dict):
            continue
        alg = entry.get("alg")
        content = entry.get("content")
        if alg and content:
            hashes[str(alg)] = str(content)
    return hashes


def _opt_str(value: Any) -> str | None:
    return str(value) if value is not None else None


def _flatten_components(
    raw_components: list[dict[str, Any]] | None, counter: Iterator[int], ref: str
) -> list[Component]:
    """Recursively flatten CycloneDX's nested `components` arrays into a flat list."""
    flat: list[Component] = []
    for raw in raw_components or []:
        if not isinstance(raw, dict):
            continue
        raw_ref = str(raw.get("bom-ref") or f"cyclonedx-component-{next(counter)}")
        name = str(raw.get("name") or "").strip()
        if name:
            flat.append(
                Component(
                    name=name,
                    version=_opt_str(raw.get("version")),
                    purl=_opt_str(raw.get("purl")),
                    cpe=_opt_str(raw.get("cpe")),
                    licenses=_extract_licenses(raw.get("licenses")),
                    hashes=_extract_hashes(raw.get("hashes")),
                    type=_TYPE_MAP.get(str(raw.get("type", "")), ComponentType.OTHER),
                    source_format=SourceFormat.CYCLONEDX,
                    raw_ref=raw_ref,
                )
            )
        else:
            # A nameless component can never be matched; dropping it silently downstream
            # (where empty names would collide in dedup) is worse than skipping it loudly.
            logger.warning("Skipping component without a name (ref=%s) in %s", raw_ref, ref)
        # A nameless container may still hold named children - always recurse.
        flat.extend(_flatten_components(raw.get("components"), counter, ref))
    return flat


def _extract_tool(metadata: dict[str, Any]) -> str | None:
    tools = metadata.get("tools")
    if isinstance(tools, dict):
        candidates = tools.get("components") or tools.get("services") or []
    elif isinstance(tools, list):
        candidates = tools
    else:
        candidates = []
    for candidate in candidates:
        if isinstance(candidate, dict) and candidate.get("name"):
            version = candidate.get("version")
            return f"{candidate['name']}/{version}" if version else str(candidate["name"])
    return None


def _parse_document(data: dict[str, Any], ref: str) -> Inventory:
    metadata = data.get("metadata") or {}
    doc_component = metadata.get("component") or {}

    try:
        components = _flatten_components(data.get("components"), itertools.count(1), ref)
    except ValidationError as exc:
        raise SbomParseError(f"Invalid component data in {ref}: {exc}") from exc

    return Inventory(
        components=components,
        document_name=_opt_str(doc_component.get("name")),
        tool=_extract_tool(metadata),
        timestamp=_opt_str(metadata.get("timestamp")),
        format_version=_opt_str(data.get("specVersion")),
    )


def parse(path_or_bytes: str | Path | bytes) -> Inventory:
    """Parse a CycloneDX JSON document into a normalized Inventory."""
    data, ref = load_json(path_or_bytes)
    return _parse_document(data, ref)
