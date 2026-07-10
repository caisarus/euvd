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

Purls are parsed with `packageurl-python`, never string splitting (audit 2026-07-10,
finding TECH-001): qualifiers on a *versionless* purl sit exactly where a naive
`split("@")` expects the version, and percent-encoded npm scopes (`%40babel`) need
decoding. Alias-table keys and versionless decision patterns use the same
library-built identity (`sbom/normalize.py::strip_purl_version`).

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

No finding at all when: product names equal but vendors mismatch and the version is not
provably in range; fuzzy similarity below threshold; or fuzzy similarity with a
provably-outside version.

**Provably outside is not silently discarded** (M3): when the version is provably outside
the range with a trustworthy scheme, on identity evidence at least as strong as a real
match (product equal, vendor equal or unknown but never *contradicted*, non-synthesized),
the matcher records `Outcome.NOT_AFFECTED` instead of nothing — `high` confidence when
vendor+product both matched, `medium` when the vendor side was simply unknown. `match`'s
public `Finding`s (M2) only ever see `Outcome.MATCH`; `evaluate_component`/
`evaluate_inventory` expose both outcomes to `vex/rules.py`, which is the only M3 consumer:
its one real rule (`ProvablyOutsideRule`) turns `NOT_AFFECTED` straight into an OpenVEX
`not_affected` statement with justification `component_not_present` — the proof is that
the component *at an affected version* is not present; no code was inspected, so
`vulnerable_code_not_present` would overclaim (owner decision, 2026-07-10). See `vex/*.py`
and `plans/feedback_m2.md`'s carried-forward design note for why this exists.

**`vex generate --findings <path>` is auto-`not_affected`-blind by construction:** a saved
findings artifact (schema_version 1) only ever stores `MATCH` outcomes, so replaying it has
no `NOT_AFFECTED` evidence to draft from — everything defaults to `under_investigation`
unless a human decision (`vex-decisions.yaml`) overrides it. This is itself conservative
(less certainty available → the safer default), not a limitation to work around. Only the
full pipeline (`vex generate <sbom>`, live-matching) can auto-draft `not_affected`.

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

## Third-party OpenVEX consumption check (Step 3.4 acceptance criterion)

Verified 2026-07-10: `euvd-watch vex generate examples/sboms/demo.cdx.json` (live EUVD, 70
components, 20 statements — 6 `not_affected`, 14 `under_investigation`) was fed to
`vexctl merge` (the reference OpenVEX tool, `ghcr.io/openvex/vexctl:v0.2.6` via Docker —
`ghcr.io/openvex/vexctl:latest` doesn't exist, pin a real tag):

```bash
docker run --rm -v /path/to/dir:/data ghcr.io/openvex/vexctl:v0.2.6 merge /data/demo.openvex.json
```

`vexctl` parsed the document without error and re-emitted all 20 statements with full
fidelity: vulnerability names/aliases, product purls, statuses, and both `justification`
and `impact_statement` on every `not_affected` statement survived the round-trip exactly.
