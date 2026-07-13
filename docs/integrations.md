# CI/CD integrations (M5, Steps 5.2–5.3)

How to run euvd-watch from a container, a GitHub workflow, or a GitLab pipeline.
For `watch` mode see `docs/watch.md`; for the CRA workflow see `docs/cra.md`.

> **Publishing status.** The Docker image, the GitHub Action, and the GitLab template are
> implemented and exercised by this repository's own CI (see "How this repo dogfoods
> them" below). *External* consumption — `ghcr.io/<org>/euvd-watch`, `uses:
> <org>/euvd-watch@v1`, `include: remote:` — additionally needs the repository to be
> public and (for the Action/template default install path) the first PyPI release
> (Step 5.1, blocked on reserving the `euvd-watch` name). `<org>` in the examples below
> is a placeholder until the public home is settled.

## Docker image (Step 5.2)

`docker/Dockerfile` builds a multi-stage image on `python:3.12-slim`: the wheel is built
in a throwaway stage, the final image carries no build tooling, runs as the non-root user
`euvd` (uid 1000), and uses `euvd-watch` as its entrypoint. Size budget: **< 200 MB**
(current: ~152 MB), enforced in CI.

Build locally (from the repository root — the build context needs `pyproject.toml`,
`src/`, `readme/`, `LICENSE`):

```bash
docker build -f docker/Dockerfile -t euvd-watch .
```

Run — the entrypoint is the CLI, so arguments are exactly the normal CLI arguments:

```bash
docker run --rm -v "$PWD:/work:ro" euvd-watch match /work/sbom.cdx.json
```

Once published, the same one-liner against GHCR:

```bash
docker run --rm -v "$PWD:/work:ro" ghcr.io/<org>/euvd-watch match /work/sbom.cdx.json
```

Persistence: the HTTP cache lives in `/home/euvd/.cache/euvd-watch` and durable state
(CRA events, audit log, watch snapshots) in `/home/euvd/.local/share/euvd-watch`. Both
are lost when the container exits unless you mount volumes over them:

```bash
docker run --rm \
  -v "$PWD:/work" \
  -v euvd-cache:/home/euvd/.cache/euvd-watch \
  -v euvd-state:/home/euvd/.local/share/euvd-watch \
  euvd-watch watch /work/sbom.cdx.json --once
```

Publishing (`.github/workflows/image.yml`): every PR touching the image inputs re-runs
the four assertions (`version` exits 0; `scan` of a mounted fixture SBOM works; `id -u`
≠ 0; size < 200 MB); pushes to `main` publish `:edge`; `vX.Y.Z` tags publish `:X.Y.Z`
and `:latest`. Only the workflow-scoped `GITHUB_TOKEN` is used — no long-lived secrets.

## GitHub Action (Step 5.3)

A composite action at the repository root (`action.yml`). Generate an SBOM first (Syft
via `anchore/sbom-action` shown here), then match it:

```yaml
jobs:
  euvd-watch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anchore/sbom-action@v0          # generate the SBOM with Syft
        with:
          format: cyclonedx-json
          output-file: sbom.cdx.json
      - uses: <org>/euvd-watch@v1
        with:
          sbom-path: sbom.cdx.json
          fail-on: exploited
```

Inputs:

| Input | Default | Meaning |
|---|---|---|
| `sbom-path` | *(required)* | CycloneDX or SPDX SBOM to match. |
| `fail-on` | `any` | Gate: `none`, `any`, or `exploited`. |
| `min-confidence` | *(tool default)* | Drop findings below `low`/`medium`/`high`. |
| `output-file` | `euvd-findings.json` | Where the findings JSON is written. |
| `artifact-name` | `euvd-findings` | Uploaded artifact name (unique per matrix leg). |
| `extra-args` | *(empty)* | Extra `euvd-watch match` flags, e.g. `--exploited-only --no-enrich`. |
| `version` | *(latest)* | PyPI version pin; `source` installs from the action checkout (dogfooding). |
| `python-version` | `3.12` | Python set up for the tool. |

Outputs: `exit-code` (`0` clean, `1` findings above the gate) and `findings-file`. The
findings JSON is uploaded as a workflow artifact **even when the gate fails** (an exit
code ≥ 2 — execution error — fails immediately instead; there are no findings to keep).

## GitLab CI template (Step 5.3)

`templates/euvd-watch.gitlab-ci.yml` adds one `test`-stage job. Generate the SBOM in an
earlier job (Syft shown), then:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/<org>/euvd-watch/main/templates/euvd-watch.gitlab-ci.yml'

sbom:
  stage: build
  image: anchore/syft:latest
  script:
    - /syft scan dir:. -o cyclonedx-json > sbom.cdx.json
  artifacts:
    paths: [sbom.cdx.json]

euvd-watch:
  variables:
    EUVDWATCH_SBOM: "sbom.cdx.json"
    EUVDWATCH_FAIL_ON: "exploited"
```

All knobs are `EUVDWATCH_*` variables (see the template header for the full list).
**Deliberately not `EUVD_WATCH_*`**: the CLI reads `EUVD_WATCH_*` environment variables
as configuration overrides and rejects unknown keys, so job-control variables must stay
out of that namespace. The findings JSON is kept as a job artifact (`when: always`).

## How this repo dogfoods them (no network in CI)

Blocking CI jobs never hit the network (test plan §1), so the `dogfood` job in
`.github/workflows/ci.yml` consumes the action (`uses: ./`, `version: source`) against a
**cache primed from a committed fixture**:

- `tests/fixtures/euvd/dogfood-seeded-exploited.json` — one clearly-labeled **seeded**
  record (`EUVD-DOGFOOD-0001`, not a real vulnerability) that matches the demo SBOM's
  real `jinja2 3.1.6` component.
- `scripts/prime_cache.py` writes it into the HTTP cache under the exact key the client
  computes for `/search?exploited=true` page 0 (with `total` rewritten so pagination
  stops there). The cache-first `ApiClient` then never opens a connection.
- The job runs `match --exploited-only --no-enrich` through the action for each
  `fail-on` value and asserts the contracted exit codes (`none`→0, `any`→1,
  `exploited`→1) plus exactly one finding with the seeded id.

The GitLab template and every workflow file are schema-linted offline in
`tests/integration/test_ci_templates.py` (check-jsonschema's vendored schemastore
schemas); the same file pins the action's published input/output surface.

## Copy-paste verification (acceptance)

The 5.3 acceptance criterion — "copy-paste snippet from README works in a fresh repo,
verified once manually" — **cannot be executed yet**: it needs the public repo (for
`uses:`/`include: remote:`) and the first PyPI release (for the default install path).
Tracked as an open item in `tasks/todo.md`; everything verifiable without those two
owner actions is verified by the dogfood job and the image workflow described above.
