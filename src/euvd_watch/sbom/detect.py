# SPDX-License-Identifier: EUPL-1.2
"""Format detection and single-entry-point parsing for any supported SBOM format."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from euvd_watch.models import Inventory, SourceFormat
from euvd_watch.sbom import cyclonedx, spdx
from euvd_watch.sbom._load import load_json
from euvd_watch.sbom.errors import UnsupportedFormatError


def detect_format(data: dict[str, Any]) -> SourceFormat:
    """Sniff CycloneDX vs SPDX from a parsed JSON document."""
    if data.get("bomFormat") == "CycloneDX":
        return SourceFormat.CYCLONEDX
    if "spdxVersion" in data:
        return SourceFormat.SPDX
    raise UnsupportedFormatError(
        "Document is valid JSON but is neither CycloneDX (missing bomFormat) "
        "nor SPDX (missing spdxVersion)."
    )


def parse_any(path_or_bytes: str | Path | bytes) -> Inventory:
    """Detect the SBOM format and parse it, loading the document only once."""
    data, ref = load_json(path_or_bytes)
    fmt = detect_format(data)
    if fmt is SourceFormat.CYCLONEDX:
        return cyclonedx._parse_document(data, ref)
    return spdx._parse_document(data, ref)
