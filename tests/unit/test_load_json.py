"""Unit tests for the shared SBOM loader (sbom/_load.py).

The loader is the single untrusted-input choke point for both format parsers: a
scanned SBOM may come from an untrusted third party (the whole point of a
supply-chain tool), so pathological input must fail as a clean SbomParseError, never
an uncaught crash with a traceback and the wrong exit code.
"""

import pytest

from euvd_watch.sbom._load import load_json
from euvd_watch.sbom.errors import SbomParseError

pytestmark = pytest.mark.unit


def _deeply_nested_json(depth: int) -> bytes:
    """A syntactically valid but pathologically deep CycloneDX-shaped document."""
    head = '{"bomFormat":"CycloneDX","specVersion":"1.5","components":['
    open_part = "".join(f'{{"name":"n{i}","components":[' for i in range(depth))
    leaf = '{"name":"leaf","version":"1.0"}'
    return (head + open_part + leaf + ("]}" * depth) + "]}").encode("utf-8")


def test_deeply_nested_json_raises_clean_parse_error_not_recursionerror() -> None:
    """A crafted SBOM nested past the interpreter's recursion limit must surface as a
    SbomParseError (-> clean stderr message + exit 2 at the CLI), not an uncaught
    RecursionError (traceback + exit 1). json.loads is itself recursive and blows up
    well before any parser code runs."""
    with pytest.raises(SbomParseError):
        load_json(_deeply_nested_json(5000))


def test_moderately_nested_json_still_parses() -> None:
    """The fix must not reject legitimately nested (if unusual) documents - only ones
    past the interpreter limit."""
    data, ref = load_json(_deeply_nested_json(50))
    assert data["bomFormat"] == "CycloneDX"
