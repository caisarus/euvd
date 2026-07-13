# SPDX-License-Identifier: EUPL-1.2
"""OpenVEX document models (Step 3.1), mirroring the vendored schema exactly.

Schema vendored at tests/fixtures/openvex/schema.json, fetched from
https://raw.githubusercontent.com/openvex/spec/main/openvex_json_schema.json and verified
live 2026-07-10 (schema id openvex_json_schema_0.2.0.json). Field names with "@" use
pydantic aliases; `populate_by_name=True` lets callers construct with the plain Python name.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Fixed per the spec; not user-configurable.
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"


class Status(StrEnum):
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class Justification(StrEnum):
    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


class Identifiers(BaseModel):
    """Software identifiers for a product/subcomponent. At least one field expected."""

    model_config = ConfigDict(populate_by_name=True)

    purl: str | None = None
    cpe22: str | None = None
    cpe23: str | None = None


class Product(BaseModel):
    """A product (or subcomponent) a statement applies to. Requires @id or identifiers."""

    model_config = ConfigDict(populate_by_name=True)

    id: str | None = Field(default=None, alias="@id")
    identifiers: Identifiers | None = None

    @model_validator(mode="after")
    def _require_id_or_identifiers(self) -> Product:
        if self.id is None and self.identifiers is None:
            raise ValueError("A Product requires either @id or identifiers.")
        return self


class Vulnerability(BaseModel):
    """The vulnerability struct: a name plus alternate identifiers."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    aliases: list[str] = []


class Statement(BaseModel):
    """One VEX assertion: the impact of a vulnerability on one or more products."""

    model_config = ConfigDict(populate_by_name=True)

    vulnerability: Vulnerability
    status: Status
    products: list[Product] = []
    justification: Justification | None = None
    impact_statement: str | None = None
    action_statement: str | None = None

    @model_validator(mode="after")
    def _status_specific_requirements(self) -> Statement:
        if self.status is Status.NOT_AFFECTED and not (self.justification or self.impact_statement):
            raise ValueError(
                "A not_affected statement requires a justification or an impact_statement."
            )
        if self.status is Status.AFFECTED and not self.action_statement:
            raise ValueError("An affected statement requires an action_statement.")
        return self


class OpenVexDocument(BaseModel):
    """The top-level OpenVEX document."""

    model_config = ConfigDict(populate_by_name=True)

    context: str = Field(default=OPENVEX_CONTEXT, alias="@context")
    id: str = Field(alias="@id")
    author: str
    timestamp: str
    version: int = 1
    statements: list[Statement]
