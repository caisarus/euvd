"""Shared "read + JSON-parse" step used by every format parser and by format detection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from euvd_watch.sbom.errors import SbomParseError


def load_json(path_or_bytes: str | Path | bytes) -> tuple[dict[str, Any], str]:
    """Read and JSON-decode an SBOM document, returning (data, a reference for error messages)."""
    if isinstance(path_or_bytes, bytes):
        raw, ref = path_or_bytes.decode("utf-8"), "<bytes>"
    else:
        path = Path(path_or_bytes)
        ref = str(path)
        try:
            raw = path.read_text()
        except OSError as exc:
            raise SbomParseError(f"Could not read {ref}: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SbomParseError(
            f"Malformed JSON in {ref} at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise SbomParseError(f"{ref} does not contain a JSON object at the top level.")

    return data, ref
