"""Unit tests for the findings-artifact loader (findings_artifact.py).

The `--findings FILE` CLI argument (and CI systems passing a findings artifact between
jobs) point this loader at a user-supplied file, so pathological input must fail as a
clean FindingsArtifactError, never an uncaught crash.
"""

import pytest

from euvd_watch.findings_artifact import FindingsArtifactError, parse_findings_artifact

pytestmark = pytest.mark.unit


def test_deeply_nested_json_raises_clean_error_not_recursionerror() -> None:
    """A findings file nested past the interpreter's recursion limit must surface as a
    FindingsArtifactError (-> clean stderr + exit 2), not an uncaught RecursionError
    (traceback + exit 1). json.loads is itself recursive."""
    depth = 5000
    raw = "{" + '"schema_version":1,"findings":' + "[" * depth + "]" * depth + "}"
    with pytest.raises(FindingsArtifactError):
        parse_findings_artifact(raw, "test artifact")


def test_valid_empty_artifact_parses() -> None:
    assert parse_findings_artifact('{"schema_version": 1, "findings": []}', "t") == []
