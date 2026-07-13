# SPDX-License-Identifier: EUPL-1.2
"""Human decisions file (Step 3.3): the human-in-the-loop mechanism.

Humans record judgments ("we don't ship that code path") that persist across runs and
override automated drafts (vex/merge.py). Same validation philosophy as config.py:
extra="forbid" and actionable field-naming errors.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from euvd_watch.vex.model import Justification, Status


class DecisionsError(Exception):
    """Raised when the decisions file fails to load or validate; names the bad field(s)."""


class DecisionEntry(BaseModel):
    """One human judgment: identifies a (vulnerability, component) pair and a VEX status.

    Identified by `euvd_id` and/or `cve` (at least one required) plus a `purl`. A purl
    with no `@version` acts as a pattern matching any version of that package; an exact
    `name@version` purl matches only that version (see vex/merge.py::_matches).
    """

    model_config = ConfigDict(extra="forbid")

    euvd_id: str | None = None
    cve: str | None = None
    purl: str
    status: Status
    justification: Justification | None = None
    statement: str
    author: str
    date: str

    @model_validator(mode="after")
    def _requires_an_identifier(self) -> DecisionEntry:
        if not self.euvd_id and not self.cve:
            raise ValueError("A decision entry needs at least one of euvd_id or cve.")
        return self


class DecisionsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decisions: list[DecisionEntry] = []


def load_decisions(path: Path) -> DecisionsFile:
    """Load and validate a vex-decisions.yaml file."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DecisionsError(f"Could not read decisions file {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise DecisionsError(f"Decisions file {path} is not valid UTF-8: {exc}") from exc

    data: Any = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise DecisionsError(f"{path} must contain a YAML mapping at the top level.")

    try:
        return DecisionsFile.model_validate(data)
    except ValidationError as exc:
        fields = ", ".join(".".join(str(p) for p in err["loc"]) for err in exc.errors())
        raise DecisionsError(
            f"Invalid decisions file {path} for field(s): {fields}\n{exc}"
        ) from exc
