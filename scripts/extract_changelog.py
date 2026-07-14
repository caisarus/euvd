#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Extract one version's section from a Keep-a-Changelog CHANGELOG.md.

Used by the release workflow (.github/workflows/workflow.yaml) to turn the
changelog section for the tagged version into GitHub release notes.

Lookup order (deterministic):
  1. the exact version              (``## [0.3.1rc1]``)
  2. the base X.Y.Z of a pre-release (``## [0.3.1]`` for ``0.3.1rc1``)

A missing section is an error (exit 1): every release must have a written
changelog entry before it can be tagged.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

_HEADING = "## ["
_BASE_VERSION = re.compile(r"^(\d+\.\d+\.\d+)")


def extract_section(changelog: str, version: str) -> str:
    """Return the body of ``## [version]`` (heading excluded, edges stripped).

    Falls back to the base ``X.Y.Z`` section for pre-release versions.
    Raises ``KeyError`` if neither section exists.
    """
    candidates = [version]
    base = _BASE_VERSION.match(version)
    if base and base.group(1) != version:
        candidates.append(base.group(1))

    for candidate in candidates:
        section = _find_section(changelog, candidate)
        if section is not None:
            return section
    raise KeyError(f"no changelog section found for {' or '.join(candidates)}")


def _find_section(changelog: str, version: str) -> str | None:
    lines = changelog.splitlines()
    start: int | None = None
    for i, line in enumerate(lines):
        if line.startswith(f"{_HEADING}{version}]"):
            start = i + 1
            break
    if start is None:
        return None
    end = len(lines)
    for i in range(start, len(lines)):
        if lines[i].startswith(_HEADING) or lines[i].startswith("## "):
            end = i
            break
    return "\n".join(lines[start:end]).strip()


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: print the section to stdout, exit 1 if absent."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="release version, without the leading v")
    parser.add_argument(
        "changelog",
        nargs="?",
        default="CHANGELOG.md",
        type=pathlib.Path,
        help="path to the changelog (default: CHANGELOG.md)",
    )
    args = parser.parse_args(argv)
    try:
        print(extract_section(args.changelog.read_text(encoding="utf-8"), args.version))
    except KeyError as exc:
        print(f"error: {exc.args[0]}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
