# SPDX-License-Identifier: EUPL-1.2
"""The single normalized Component/Inventory shape shared by every SBOM format.

This is the contract for the whole pipeline (plans/implementation_plan.md Step 1.1): the
matcher (M2) never needs to know whether a Component came from CycloneDX or SPDX.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class ComponentType(StrEnum):
    LIBRARY = "library"
    APPLICATION = "application"
    OS = "os"
    CONTAINER = "container"
    OTHER = "other"


class SourceFormat(StrEnum):
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


class Component(BaseModel):
    """One normalized software component, regardless of source SBOM format."""

    model_config = ConfigDict(frozen=True)

    name: str
    version: str | None = None
    purl: str | None = None
    cpe: str | None = None
    licenses: list[str] = []
    hashes: dict[str, str] = {}
    type: ComponentType = ComponentType.LIBRARY
    source_format: SourceFormat
    raw_ref: str

    # Populated by sbom/normalize.py (Step 1.4). Present here from the start so the frozen
    # model never needs reshaping once downstream code depends on it; all default to
    # "not yet normalized".
    normalized_purl: str | None = None
    normalized_version: str | None = None
    cpe_parts: dict[str, str] | None = None
    synthesized: bool = False

    @property
    def dedupe_key(self) -> str:
        """A stable identity for deduplication: purl beats (name, version).

        Always a string (prefix-disambiguated) so collections of keys sort without
        TypeError - M2's deterministic findings ordering sorts by this key.
        """
        purl = self.normalized_purl or self.purl
        if purl:
            return f"purl:{purl}"
        return f"name:{self.name.lower()}@{self.version}"


class Inventory(BaseModel):
    """A parsed and normalized SBOM: its components plus source document metadata."""

    # Version of this JSON shape as a public contract (scan --output json consumers).
    # Bump on breaking changes to Component/Inventory serialization.
    schema_version: int = 1
    components: list[Component]
    document_name: str | None = None
    tool: str | None = None
    # Kept verbatim from the source document (never generated at parse time) so that
    # re-parsing the same file always produces byte-identical output.
    timestamp: str | None = None
    format_version: str | None = None
