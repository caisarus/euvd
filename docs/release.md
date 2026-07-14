# Release process & version policy

## Versioning

euvd-watch follows [Semantic Versioning](https://semver.org/).

- **Until `1.0.0`**: minor versions (`0.X.0`) may contain breaking changes; every
  breaking change is listed explicitly in `CHANGELOG.md` under **Changed** with a
  **Breaking** prefix.
- **From `1.0.0`**: breaking changes to the CLI contract (commands, flags, exit
  codes), the findings/VEX/CRA JSON schemas (`schema_version` fields), or the
  config file format require a major version bump. Deprecations are announced in
  the changelog at least one minor version before removal, and deprecated flags
  emit a warning on use.
- Pre-releases use PEP 440 `rc` suffixes: version `X.Y.ZrcN`, tag `vX.Y.ZrcN`.

The version lives in **two places that must agree**: `pyproject.toml`
(`project.version`) and `src/euvd_watch/__init__.py` (`__version__`). The release
workflow refuses to build if they disagree with each other or with the tag.

## Release automation (Step 5.1)

Releases are driven entirely by pushing a tag —
`.github/workflows/workflow.yaml` does the rest. The filename is load-bearing:
PyPI/TestPyPI trusted publishing (OIDC, no tokens) is registered against
`workflow.yaml` and the `pypi` / `testpypi` GitHub environments.

| Tag | What happens |
| --- | --- |
| `vX.Y.ZrcN` | build → sdist+wheel → **TestPyPI** → clean-venv `pip install` from TestPyPI → `euvd-watch version` smoke check |
| `vX.Y.Z` | build → sdist+wheel → **PyPI** → clean-venv install check → GitHub release with the `CHANGELOG.md` section as notes |

The Docker image is published separately by `image.yml` on the same final tags
(GHCR `:X.Y.Z` + `:latest`).

## Cutting a release — checklist

1. Move the `[Unreleased]` changelog content into a new `## [X.Y.Z] — YYYY-MM-DD`
   section (the build job fails if the section is missing —
   `scripts/extract_changelog.py` must find it).
2. Bump the version in `pyproject.toml` **and** `src/euvd_watch/__init__.py`.
3. Commit (`chore(release): X.Y.Z`), push, wait for CI green.
4. For anything beyond a trivial patch, exercise the path first:
   `git tag vX.Y.Zrc1 && git push origin vX.Y.Zrc1`, watch the TestPyPI install
   check pass.
5. `git tag vX.Y.Z && git push origin vX.Y.Z`. Everything after that is
   automatic; verify the PyPI page, the GitHub release, and the GHCR tags.

No manual upload step exists or should be reintroduced; there are no PyPI API
tokens to rotate or leak.
