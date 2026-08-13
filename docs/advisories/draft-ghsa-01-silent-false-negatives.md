# DRAFT — GHSA 1 of 2: silent false negatives in matching and EUVD retrieval

> **Status: unpublished draft.** Paste into
> <https://github.com/caisarus/euvd/security/advisories/new>. Replace this file with the
> published GHSA link once it is live. Fixed in `0.4.1`; text derived from the
> `CHANGELOG.md` `[0.4.1]` section and the fix commits.

## Advisory form fields

| Field | Value |
| --- | --- |
| **Title** | euvd-watch reports "no findings" and exits 0 for components affected by an actively exploited vulnerability |
| **Ecosystem** | pip |
| **Package name** | `euvd-watch` |
| **Affected versions** | `< 0.4.1` |
| **Patched versions** | `0.4.1` |
| **Severity** | High |
| **CVSS v3.1 vector (suggested)** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` (7.5) |
| **CWEs** | CWE-697 (Incorrect Comparison); CWE-754 (Improper Check for Unusual or Exceptional Conditions) |
| **Credits** | caisarus — found in the internal pre-1.0 audit |
| **CVE** | Request one via the GHSA form (owner decision) |

Severity note: no attacker is required — ordinary EUVD data and ordinary SBOM version
strings trigger all three defects. The vector above rates the integrity of the tool's
security-relevant output as High and leaves confidentiality/availability untouched;
adjust in the form if you prefer to rate it lower for the absence of an attacker.

## Summary

Every euvd-watch release before `0.4.1` could report **no findings, with a success exit
code**, for a component affected by an actively exploited vulnerability — and in one case
publish a high-confidence OpenVEX `not_affected` statement asserting the opposite. Three
independent defects produce this, all found in the pre-1.0 audit and all fixed in `0.4.1`.

**A previously clean euvd-watch run is not evidence of a clean result.**

## Impact

For anyone using euvd-watch as a CI gate, as a VEX source, or as their EU Cyber
Resilience Act Article 14 trigger, the consequences of a suppressed finding are:

- a **green CI gate** over a vulnerable component;
- a **false `not_affected` assertion distributed to downstream consumers** (defect 1 only,
  which reached `high` confidence — the level the VEX engine auto-drafts from);
- **no CRA Article 14 trigger** for what may have been a reportable, actively exploited
  vulnerability.

## Details

### 1. An inverted version range was treated as proof of safety (critical)

A distro-style exact version is also a valid hyphen-range shape, and the range parser
claimed it unconditionally: `2.4.0-2` parsed as low=`2.4.0`, high=`2`. That range is
inverted, so it contains nothing, and *every* version evaluated as "provably outside"
with a trusted `pep440` comparison.

A component sitting on exactly the affected, actively exploited version therefore
produced **zero findings** plus a **high-confidence `not_affected`**. Genuinely malformed
EUVD ranges (`>=2.0 <1.0`) suppressed findings the same way.

Fixed in `b24c679`: inverted ranges are never trusted at any of the three parse sites. The
hyphen form is re-read as the exact version it is (equal ⇒ affected); inverted compound and
comma ranges are unevaluable (`AMBIGUOUS`), which keeps the finding alive at `medium`
confidence for a human.

### 2. A purl namespace could veto a product-name match (high)

Any candidate that knew a vendor became decisive for an affected entry, and the purl
**namespace** was fed in as a vendor — a value the matcher's own comment calls "a weak
vendor hint". Reverse-DNS namespaces and scopes therefore "contradicted" EUVD's prose
vendor text and erased the finding.

`pkg:maven/org.apache.logging.log4j/log4j-core` reported nothing where the identical
component without a namespace (`pkg:pypi/log4j-core`) reported normally — so **every
namespaced ecosystem (maven, scoped npm, golang, composer) was systematically blinder than
the rest**, for a spelling difference.

Fixed in `c8de6be`: veto power now belongs only to the CPE and the curated alias table. A
namespace remains a positive signal, and an authoritative vendor contradiction still vetoes.

### 3. An unreadable EUVD search page was read as "no results" (high)

The paginator stopped on any page that was not a `dict` and returned what it had
accumulated, so an unexpected response envelope became an empty record set rather than an
error. Reproduced through the real CLI: three valid-JSON-but-wrong-shape responses each
produced `0 findings (0 exploited) across 70 components` and **exit 0** — including a body
that stated outright `"total": 1742`. The EUVD API is beta, so an envelope change is a
realistic event, not a hypothetical.

Fixed in `3a1dce5`: any page that is not an object with an `items` list raises, which the
CLI already surfaces as exit `2` and *"Refusing to report 'no findings' on missing data."*
The legitimately empty `{"items": [], "total": 0}` is unchanged.

## Patches

Upgrade to **`0.4.1`**:

```bash
pip install --upgrade "euvd-watch>=0.4.1"
# or
docker pull ghcr.io/caisarus/euvd-watch:0.4.1
```

Container images `ghcr.io/caisarus/euvd-watch` tagged `0.3.0`, `0.3.1` and `0.4.0` are
affected as well; `:latest` now resolves to `0.4.1`.

## Workarounds

None. The defects are in the matching and retrieval paths themselves, and each produces a
clean-looking result rather than an error, so no configuration change or output check
detects them.

## Remediation after upgrading

1. **Re-run `match`** against your current SBOMs — findings that never appeared may appear now.
2. **Re-check any OpenVEX documents you distributed.** Statements asserting `not_affected`
   for a component whose EUVD range text carried a release suffix (`2.4.0-2`) may have been
   drafted from defect 1 and may be wrong.
3. **Re-run `cra check`.** A CRA Article 14 trigger that never fired may fire now; treat the
   result as a fresh assessment, not as a change since the last run.
4. Anyone consuming your VEX or CI results as evidence of a clean scan should be told the
   evidence predates this fix.

## References

- `CHANGELOG.md`, section `[0.4.1]`
- Fix commits: `b24c679`, `c8de6be`, `3a1dce5`
- Truth-table regression rows: `tests/fixtures/matching/cases.yaml`
