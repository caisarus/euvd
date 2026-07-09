"""Logging bootstrap: one place where --verbose becomes a logging configuration.

Exists so every module can just `logging.getLogger(__name__)` and emit warnings (parsers)
or request traces (M2's HTTP layer, which requires structured logging of every request)
without owning any configuration. All log output goes to stderr, keeping stdout reserved
for command output (the --output json purity contract).
"""

from __future__ import annotations

import logging
import sys


def setup_logging(verbose: bool) -> None:
    """Configure the root logger: warnings by default, debug-level detail with --verbose."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
