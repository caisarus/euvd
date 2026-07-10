# Fixture provenance & regeneration

Fixtures are committed and tests never hit the network (test_plan.md §1 principle 2).
This file records where each fixture came from and how to regenerate it — and, more
importantly, when **not** to.

## ⚠️ Golden coupling

`golden/*.inventory.json` are byte-coupled to their source fixtures **and** to the
`Component`/`Inventory` model shape. Regenerating a source fixture, or changing model
fields/serialization, invalidates them. Regenerate goldens only as a deliberate,
reviewed step:

```bash
python3 - <<'EOF'
from euvd_watch.sbom import cyclonedx, spdx, load_inventory_with_stats
inv = cyclonedx.parse('tests/fixtures/sboms/syft-demo.cdx.json')
open('tests/fixtures/golden/syft-demo.inventory.json', 'w').write(inv.model_dump_json(indent=2) + '\n')
inv = spdx.parse('tests/fixtures/sboms/github-export.spdx.json')
open('tests/fixtures/golden/github-export.inventory.json', 'w').write(inv.model_dump_json(indent=2) + '\n')
inv, _ = load_inventory_with_stats('examples/sboms/demo.cdx.json')
open('tests/fixtures/golden/scan-demo.inventory.json', 'w').write(inv.model_dump_json() + '\n')
EOF
```

## Real fixtures (captured from real tools — do not edit by hand)

### `sboms/syft-demo.cdx.json` (also copied to `examples/sboms/demo.cdx.json`)

Real Syft scan of this project's own `.venv` (dogfooding), CycloneDX **1.5** (Syft
defaults to a newer spec than the 1.4–1.6 range the parser targets — the `@1.5` pin
matters). 70 library components; several tests assert that exact count and specific
package names.

```bash
docker run --rm -v "$PWD":/src anchore/syft:latest scan dir:/src/.venv \
  --override-default-catalogers 'python-installed-package-cataloger' \
  --select-catalogers '-file' \
  --source-name euvd-watch --source-version 0.1.0 \
  -o cyclonedx-json@1.5
```

Cataloger-selection gotchas: `--select-catalogers '+name'` *adds* to the default set
(doesn't replace); `--override-default-catalogers` replaces the base set but re-adds the
`file` cataloger, hence the extra `-file`. **Do not regenerate casually** — the venv's
contents change with every dependency bump, which would churn component counts, three
golden files, and the tests that assert exact counts.

### `sboms/github-export.spdx.json`

GitHub's dependency-graph SBOM export for `fastapi/typer` (SPDX 2.3, 105 packages,
real license diversity). Works unauthenticated for public repos:

```bash
curl -s https://api.github.com/repos/fastapi/typer/dependency-graph/sbom \
  | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['sbom'], indent=2, sort_keys=True))"
```

Note the `{"sbom": {...}}` envelope that must be unwrapped. GitHub's export never emits
`cpe23Type` refs — that's why `cpe-ref.spdx.json` exists. Regenerating changes package
counts/versions (the upstream repo moves), so the same caution as above applies.

### `euvd/*.json`

Real EUVD API responses captured by `scripts/capture_fixtures.py` (manual run;
politeness-delayed; re-serialized with `indent=2, sort_keys=True` for reviewable diffs).
Endpoint quirks they encode (204 misses, newline-joined aliases, 0–100 epss scale, the dead
CVE endpoint) are documented in `docs/euvd-api.md`. Several client tests assert exact item
counts from these files — regenerating refreshes live data and **will change counts and
record contents**; treat a regeneration like a fixture migration, not a refresh.

## Handcrafted fixtures (edit deliberately, keep minimal)

| Fixture | Exercises |
|---|---|
| `sboms/minimal.cdx.json` / `minimal.spdx.json` | Smallest valid document per format |
| `sboms/nested-licenses.cdx.json` | Nested `components` flattening; license `id`/`name`/`expression` forms |
| `sboms/malformed.cdx.json` / `malformed.spdx.json` | JSON syntax error → `SbomParseError` with line/column |
| `sboms/cpe-ref.spdx.json` | `cpe23Type` external ref extraction (real GitHub exports lack it) |
| `sboms/parity.cdx.json` / `parity.spdx.json` | Same logical package in both formats → equal `Component`s (the format-blind matcher proof) — **keep these two in sync** |
| `sboms/duplicates.cdx.json` | Dedup by normalized purl, first-occurrence-wins |
| `sboms/garbage.json`, `empty.json`, `valid-json-not-sbom.json` | Format-detection failure matrix |
| `config/*.yaml` | Config precedence/validation cases (Step 0.3) |
