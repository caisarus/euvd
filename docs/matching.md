# Matching strategies & confidence scoring

How euvd-watch decides *whether EUVD record X affects component Y*, and how sure it is.
Implemented in `euvd/match.py` + `euvd/versions.py`; regression-guarded by the truth table
at `tests/fixtures/matching/cases.yaml` (every wild bug becomes a row there before its fix
merges).

## The core problem

The SBOM side speaks purl/CPE. The EUVD side speaks `(vendor, product, version-range)`
**text** derived from CVE data (see `docs/euvd-api.md`). The matcher first derives
(vendor, product) candidates per component, best signal first:

1. **CPE fields** (`Component.cpe_parts`, already backslash-decoded by `sbom/normalize.py`)
   — best signal, carries a vendor.
2. **Curated alias table** (`euvd/aliases.yaml`): canonical versionless purl → the
   vendor/product names EUVD actually publishes (e.g. `pkg:pypi/pillow` →
   `python-pillow` / `pillow`). Only add entries after seeing the EUVD-side naming in real
   records.
3. **purl namespace/name** — namespace (when present) as a weak vendor hint.
4. **Component name** — vendor-less last resort.

All vendor/product equality is on a normalized form: lowercase, punctuation-insensitive
(`Spring-Framework` == `spring framework`).

**Informed candidates are decisive:** if any candidate *knows* its vendor and its product
equals the affected product, only those candidates decide the outcome for that affected
entry. A vendor-less fallback must not resurrect as "vendor unknown" a match the known
vendor already contradicted.

## Strategies and confidence

| # | Evidence | Confidence |
|---|---|---|
| 1 | vendor+product equal AND version provably inside the range with a trustworthy scheme, non-synthesized identifier | **high** |
| 2 | vendor+product equal but range ambiguous/missing/unevaluable; or product equal with vendor unknown on one side + version in range; or product equal with **mismatched** vendor + version in range | **medium** |
| 3 | fuzzy token-set similarity ≥ 0.6 between component name and affected product, no reliable version signal | **low** — surfaces candidates for human review, never feeds automated decisions |

No finding at all when: version is provably **outside** the range with a trustworthy
scheme; product names equal but vendors mismatch and the version is not provably in range;
fuzzy similarity below threshold; or fuzzy similarity with a provably-outside version.

### Hard caps (invariants, enforced in `tests/invariants/`)

- A component whose identifier was **synthesized** (Step 1.4) can never exceed `medium` —
  this contains the damage of a mis-inferred ecosystem (e.g. a CPE `go-` prefix on what is
  actually a pypi package; truth-table case `mis-inferred-ecosystem-still-capped-medium`).
- A version comparison made by the **tokenwise fallback** can never support `high`.
- Every `Finding.explanation` is a non-empty human-readable sentence — this feeds VEX (M3)
  and CRA (M4) auditability.

## Version-range evaluation (`euvd/versions.py`)

EUVD publishes ranges as free text. Recognized shapes (observed live): `A-B` (hyphen range,
split at the **first** hyphen, inclusive ends, both sides must look like versions), `<X`,
`<=X`, `>X`, `>=X`, `=X`, `>=A <B`, and bare exact versions. Anything else — including
empty/missing ranges and prose like "all versions before the fix" — is **AMBIGUOUS**: the
matcher caps at medium rather than guessing.

Comparison schemes, tried in order: **PEP 440** (via `packaging` — broadest real-world
coverage for our pypi-heavy inputs; note it accepts leading `v`), strict **semver**, then a
**tokenwise fallback** that exists only so something deterministic can be said. The
comparator returns the scheme it used so the caps above are enforceable.

### deb/rpm epochs — raw versions only

`Component.normalized_version` strips debian epochs (`1:1.0` → `1.0`), which destroys deb
ordering (`1:1.0` sorts *after* `2.0`). The matcher therefore always evaluates ranges
against the **raw** `Component.version`. Any future deb/rpm-aware comparison scheme must do
the same. (M0/M1 review item 3.3.)

## Query strategy (two tiers, `match` command)

- **Tier 1 — always:** sync the full actively-exploited catalog
  (`search?exploited=true`, paginated; ~1.6k records) into the cache and match the entire
  inventory against it locally. Cheap, and covers the CRA-critical case even for huge SBOMs.
- **Tier 2 — unless `--exploited-only`:** per-component keyword searches
  (`search?product=<candidate>`), deduplicated across components and served from the cache.

If EUVD is unreachable: proceed on cache within TTL with a loud warning and a
`data_freshness` stamp in every output; with no usable cache, exit 2. Never silently report
"no findings" on missing data.
