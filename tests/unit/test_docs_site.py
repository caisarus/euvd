# SPDX-License-Identifier: EUPL-1.2
"""The documentation site's own link surface, checked independently of the repository's.

`0.4.1`'s "0 broken relative links" sweep was true for the repository and said nothing
about PyPI, where the same markdown is served from a different root — two defects shipped
through that gap (see the `1.0.0rc2` note in `CHANGELOG.md`). The site is a third surface
with a third root, so it gets its own check rather than an assumption.

`mkdocs build --strict` catches this too, but only where mkdocs runs; these tests run in
the ordinary suite, on every push, without installing the docs toolchain.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from build_docs_tree import build  # noqa: E402

LINK = re.compile(r"\]\(([^)\s]*)\)")


def _staged(tmp_path: Path) -> Path:
    build(tmp_path / "site-src")
    return tmp_path / "site-src"


def test_every_relative_link_resolves_to_a_staged_page(tmp_path: Path) -> None:
    """No page may link to a path the site does not publish."""
    root = _staged(tmp_path)
    broken: list[str] = []

    for page in sorted(root.rglob("*.md")):
        for target in LINK.findall(page.read_text(encoding="utf-8")):
            if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            resolved = (page.parent / target.split("#", 1)[0]).resolve()
            if not resolved.exists():
                broken.append(f"{page.relative_to(root)} -> {target}")

    assert not broken, f"broken links on the docs site: {broken}"


def test_the_home_page_keeps_the_reader_on_the_site(tmp_path: Path) -> None:
    """The README's `blob/main` links are for PyPI; on the site they must be local.

    Left as written, every link on the site's front page would bounce the reader straight
    back to GitHub on their first click.
    """
    index = (_staged(tmp_path) / "index.md").read_text(encoding="utf-8")
    escapees = [
        target
        for target in LINK.findall(index)
        if target.startswith("https://github.com/caisarus/euvd/blob/main/")
        and target.endswith(".md")
    ]
    assert not escapees, f"home page still links off-site for markdown: {escapees}"


def test_the_nav_and_the_staged_tree_agree(tmp_path: Path) -> None:
    """`mkdocs.yml`'s nav and this script's file lists drift apart silently otherwise.

    Both directions matter, and the expectation is read from `mkdocs.yml` rather than from
    the script's own lists — deriving it from `ROOT_PAGES`/`DOCS_PAGES` would make the test
    circular, and a nav entry pointing at a page nobody stages would sail through it. (It
    did, until a deliberate mutation caught it.)
    """
    nav_block = (REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8").split("\nnav:\n", 1)[1]
    nav_block = nav_block.split("\nextra:", 1)[0]
    in_nav = set(re.findall(r":\s*([\w./-]+\.md)\s*$", nav_block, flags=re.MULTILINE))

    root = _staged(tmp_path)
    staged = {str(p.relative_to(root)) for p in root.rglob("*.md")}

    assert in_nav - staged == set(), f"mkdocs.yml nav names pages nobody stages: {in_nav - staged}"
    assert staged - in_nav == set(), f"staged pages missing from mkdocs.yml nav: {staged - in_nav}"


def test_staging_is_deterministic(tmp_path: Path) -> None:
    """Same inputs, byte-identical output — the project's rule, applied to the docs too."""
    first = {p.name: p.read_bytes() for p in _staged(tmp_path / "a").rglob("*.md")}
    second = {p.name: p.read_bytes() for p in _staged(tmp_path / "b").rglob("*.md")}
    assert first == second
