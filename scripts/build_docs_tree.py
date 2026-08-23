# SPDX-License-Identifier: EUPL-1.2
"""Stage the repository's markdown into a tree MkDocs can build.

The documentation lives at the repository root (`README.md`, `GLOSSARY.md`, …) plus
`docs/`, because that is where GitHub and PyPI need it — moving it would re-break the
front page that `0e3a046` fixed. MkDocs wants a single `docs_dir` it owns, so this script
copies the published subset into one, rewriting links so the *site* surface is correct
without touching the repository surface:

1. ``README.md`` becomes ``index.md`` (the site's home page), and links pointing at
   ``README.md`` are re-pointed at it.
2. The README's absolute ``blob/main`` links become relative. They are absolute in the
   repository on purpose — PyPI serves the same markdown from a different root and does
   not rewrite relative links (see the `1.0.0rc2` note in `CHANGELOG.md`) — but on the
   site they would send every visitor straight back to GitHub on their first click.
3. Links into the repository that the site has no page for — ``LICENSE``, a test module,
   a directory — become absolute GitHub URLs, because that is what they always meant.

The rewrites are pure text transforms over a fixed file list, so the staged tree is
deterministic: same inputs, byte-identical output. Nothing here touches the network.

Usage::

    python scripts/build_docs_tree.py [target-dir]     # default: build/docs-site
"""

from __future__ import annotations

import posixpath
import re
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Repo-root markdown published to the site, in nav order. ``README.md`` is handled
#: separately because it becomes ``index.md``.
ROOT_PAGES = (
    "README.simple.md",
    "README.ro.md",
    "GLOSSARY.md",
    "GLOSSARY.ro.md",
    "ARCHITECTURE.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CHANGELOG.md",
)

#: `docs/` pages published to the site. Deliberately **not** the whole directory:
#: `AUDIT_AND_REMEDIATION_PLAN.md` and `dashboard-design.md` are internal working
#: documents, and nothing links to them, so they stay in the repository only.
DOCS_PAGES = (
    "cra.md",
    "matching.md",
    "euvd-api.md",
    "watch.md",
    "integrations.md",
    "web.md",
    "deploy.md",
    "storage.md",
    "accessibility.md",
    "release.md",
)

BLOB_PREFIX = "https://github.com/caisarus/euvd/blob/main/"

#: Targets that stay absolute: they are not markdown, so the site has no page for them.
NON_MARKDOWN_BLOB_TARGETS = ("LICENSE",)


def _staged_markdown_targets() -> set[str]:
    """Return the repo-relative paths this script stages, as link targets would spell them."""
    return {"README.md", *ROOT_PAGES, *(f"docs/{name}" for name in DOCS_PAGES)}


def rewrite(text: str, *, source: str) -> str:
    """Rewrite one page's links for the staged tree.

    Three cases, decided per link:

    * a target this script stages becomes a site-relative link (``README.md`` resolving to
      ``index.md``);
    * a target that exists in the repository but has no page on the site — ``LICENSE``, a
      test module, a directory — becomes an absolute GitHub URL, because that is what the
      link always meant;
    * anything else (external URLs, anchors, mail) is left exactly as written.

    Args:
        text: The page's markdown source.
        source: The page's repo-relative path, e.g. ``docs/deploy.md``.

    Returns:
        The rewritten markdown.
    """
    staged = _staged_markdown_targets()
    here = posixpath.dirname(source)
    depth = source.count("/")
    up = "../" * depth

    def _site_link(repo_path: str) -> str:
        return f"]({up}{'index.md' if repo_path == 'README.md' else repo_path})"

    def _github_link(repo_path: str, *, is_dir: bool) -> str:
        kind = "tree" if is_dir else "blob"
        return f"](https://github.com/caisarus/euvd/{kind}/main/{repo_path.rstrip('/')})"

    def _one(match: re.Match[str]) -> str:
        target = match.group(1)

        if target.startswith(BLOB_PREFIX):
            repo_path = target[len(BLOB_PREFIX) :]
            if repo_path in NON_MARKDOWN_BLOB_TARGETS or repo_path not in staged:
                return match.group(0)
            return _site_link(repo_path)

        if not target or target.startswith(("http://", "https://", "mailto:", "#")):
            return match.group(0)

        repo_path = posixpath.normpath(posixpath.join(here, target))
        if repo_path in staged:
            return _site_link(repo_path)
        return _github_link(repo_path, is_dir=target.endswith("/"))

    return re.sub(r"\]\(([^)\s]*)\)", _one, text)


def build(target: Path) -> list[Path]:
    """Stage the published markdown into `target`, replacing whatever was there.

    Args:
        target: Directory to write the staged tree into. Removed first if it exists.

    Returns:
        The staged files, in nav order.
    """
    if target.exists():
        shutil.rmtree(target)
    (target / "docs").mkdir(parents=True)

    written: list[Path] = []

    index = target / "index.md"
    index.write_text(
        rewrite((REPO_ROOT / "README.md").read_text(encoding="utf-8"), source="README.md"),
        encoding="utf-8",
    )
    written.append(index)

    for name in ROOT_PAGES:
        dest = target / name
        dest.write_text(
            rewrite((REPO_ROOT / name).read_text(encoding="utf-8"), source=name),
            encoding="utf-8",
        )
        written.append(dest)

    for name in DOCS_PAGES:
        dest = target / "docs" / name
        dest.write_text(
            rewrite((REPO_ROOT / "docs" / name).read_text(encoding="utf-8"), source=f"docs/{name}"),
            encoding="utf-8",
        )
        written.append(dest)

    return written


def main() -> int:
    """Stage the tree at the path given on the command line, or `build/docs-site`."""
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "build" / "docs-site"
    written = build(target.resolve())
    print(f"staged {len(written)} pages into {target}")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via tests, not imported
    raise SystemExit(main())
