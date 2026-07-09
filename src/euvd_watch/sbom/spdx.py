"""SPDX 2.3 (JSON) parser.

Purpose (plans/implementation_plan.md Step 1.3): SPDX is the second major SBOM format
(GitHub's SBOM export, ORT, etc.); supporting it doubles the addressable input. Same
tolerant-parse philosophy as the CycloneDX parser - unknown fields are ignored.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from euvd_watch.models import Component, ComponentType, Inventory, SourceFormat
from euvd_watch.sbom._load import load_json

_UNASSERTED = {"NOASSERTION", "NONE"}

_PURPOSE_MAP = {
    "APPLICATION": ComponentType.APPLICATION,
    "FRAMEWORK": ComponentType.LIBRARY,
    "LIBRARY": ComponentType.LIBRARY,
    "CONTAINER": ComponentType.CONTAINER,
    "OPERATING_SYSTEM": ComponentType.OS,
}


def _extract_licenses(package: dict[str, Any]) -> list[str]:
    licenses: list[str] = []
    for field in ("licenseConcluded", "licenseDeclared"):
        value = package.get(field)
        if isinstance(value, str) and value not in _UNASSERTED and value not in licenses:
            licenses.append(value)
    return licenses


def _extract_refs(package: dict[str, Any]) -> tuple[str | None, str | None]:
    purl: str | None = None
    cpe: str | None = None
    for ref in package.get("externalRefs") or []:
        if not isinstance(ref, dict):
            continue
        ref_type = ref.get("referenceType")
        locator = ref.get("referenceLocator")
        if ref_type == "purl" and locator:
            purl = str(locator)
        elif ref_type == "cpe23Type" and locator:
            cpe = str(locator)
    return purl, cpe


def _extract_hashes(package: dict[str, Any]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for entry in package.get("checksums") or []:
        if not isinstance(entry, dict):
            continue
        alg = entry.get("algorithm")
        value = entry.get("checksumValue")
        if alg and value:
            hashes[str(alg)] = str(value)
    return hashes


def _extract_tool(creation_info: dict[str, Any]) -> str | None:
    for creator in creation_info.get("creators") or []:
        if isinstance(creator, str) and creator.startswith("Tool:"):
            return creator.removeprefix("Tool:").strip()
    return None


def _parse_document(data: dict[str, Any], ref: str) -> Inventory:
    creation_info = data.get("creationInfo") or {}
    components: list[Component] = []

    for package in data.get("packages") or []:
        if not isinstance(package, dict):
            continue
        purl, cpe = _extract_refs(package)
        purpose = str(package.get("primaryPackagePurpose", ""))
        components.append(
            Component(
                name=str(package.get("name", "")),
                version=package.get("versionInfo"),
                purl=purl,
                cpe=cpe,
                licenses=_extract_licenses(package),
                hashes=_extract_hashes(package),
                type=_PURPOSE_MAP.get(purpose, ComponentType.LIBRARY),
                source_format=SourceFormat.SPDX,
                raw_ref=str(package.get("SPDXID") or f"spdx-package-{len(components) + 1}"),
            )
        )

    return Inventory(
        components=components,
        document_name=data.get("name"),
        tool=_extract_tool(creation_info),
        timestamp=creation_info.get("created"),
        format_version=data.get("spdxVersion"),
    )


def parse(path_or_bytes: str | Path | bytes) -> Inventory:
    """Parse an SPDX 2.3 JSON document into a normalized Inventory."""
    data, ref = load_json(path_or_bytes)
    return _parse_document(data, ref)
