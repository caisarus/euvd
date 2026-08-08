# SPDX-License-Identifier: EUPL-1.2
"""Parsing for the versioned findings artifact (`match --save-findings` / watch snapshots).

Extracted from cli.py (Step 6.2) so `web/dashboard.py` reads watch snapshots through the
exact same parser the CLI uses - one code path for "is this a valid findings artifact",
never a second one that could silently drift and accept/reject differently.
"""

from __future__ import annotations

import json
from pathlib import Path

from euvd_watch.euvd.match import Finding


class FindingsArtifactError(Exception):
    """Raised when a findings artifact (saved or watch-snapshotted) can't be parsed."""


def parse_findings_artifact(raw: str, source: str) -> list[Finding]:
    """Parse a findings artifact from JSON text; `source` names it in error messages."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FindingsArtifactError(f"{source} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "findings" not in data:
        raise FindingsArtifactError(
            f"{source} does not look like a findings artifact (missing 'findings')."
        )
    if data.get("schema_version") != 1:
        raise FindingsArtifactError(
            f"{source} has schema_version={data.get('schema_version')!r}, expected 1. "
            f"This build of euvd-watch only understands schema_version 1."
        )
    try:
        return [Finding.model_validate(f) for f in data["findings"]]
    except Exception as exc:  # pydantic.ValidationError, kept generic to avoid a new import
        raise FindingsArtifactError(f"{source} contains invalid finding data: {exc}") from exc


def load_findings_artifact(path: Path) -> list[Finding]:
    raw = path.read_text(encoding="utf-8")  # OSError -> caught by the cli_command boundary
    return parse_findings_artifact(raw, str(path))
