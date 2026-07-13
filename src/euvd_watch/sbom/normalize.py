# SPDX-License-Identifier: EUPL-1.2
"""Identifier normalization & reconciliation (plans/implementation_plan.md Step 1.4).

Matching quality (M2) lives or dies on identifiers. PURLs and CPEs from real SBOMs are messy:
mixed case, missing qualifiers, vendor quirks. Normalizing here means the matcher can stay
simple. Every function here is pure (no I/O) and tolerant: malformed input never raises, it
just yields "nothing learned" (None / the original value unchanged).
"""

from __future__ import annotations

import re

from packageurl import PackageURL

from euvd_watch.models import Component

_CPE_FIELDS = [
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
]

# Recognizable ecosystem prefixes in CPE vendor/product fields (Syft and similar tools
# generate CPEs this way when a package has no purl of its own). Maps to a purl type.
_ECOSYSTEM_PREFIXES = {
    "python-": "pypi",
    "python_": "pypi",
    "npm-": "npm",
    "node-": "npm",
    "golang-": "golang",
    "go-": "golang",
    "maven-": "maven",
    "java-": "maven",
    "rubygems-": "gem",
    "ruby-": "gem",
    "cargo-": "cargo",
    "rust-": "cargo",
}

_UNESCAPED_COLON = re.compile(r"(?<!\\):")
_CPE_ESCAPE = re.compile(r"\\(.)")
_LEADING_V = re.compile(r"^[vV](?=\d)")
_DEB_EPOCH = re.compile(r"^\d+:(.*)$")


def normalize_purl(purl: str) -> str:
    """Canonicalize a purl via packageurl-python. Idempotent; tolerant of malformed input."""
    try:
        return PackageURL.from_string(purl).to_string()
    except ValueError:
        return purl


def strip_purl_version(purl: str) -> str | None:
    """The canonical type/namespace/name form of a purl: no version, qualifiers, or subpath.

    This is the package-identity key used for alias-table lookups (euvd/match.py) and for
    versionless decision patterns (vex/merge.py). Built through PackageURL, never by string
    splitting: qualifiers on a versionless purl sit where a naive `split("@")` expects the
    version to be. Returns None if the string isn't a parseable purl.
    """
    try:
        parsed = PackageURL.from_string(purl)
    except ValueError:
        return None
    return PackageURL(type=parsed.type, namespace=parsed.namespace, name=parsed.name).to_string()


def parse_cpe(cpe: str) -> dict[str, str] | None:
    """Split a CPE 2.3 formatted string into its 11 fields, respecting backslash-escaping.

    Field values are returned *decoded* (``\\<`` becomes ``<``): the M2 matcher compares
    vendor/product text, so it needs the literal characters, not the CPE wire encoding.
    Returns None (never raises) if the string isn't a well-formed CPE 2.3 identifier.
    """
    if not cpe.startswith("cpe:2.3:"):
        return None
    parts = _UNESCAPED_COLON.split(cpe)
    if len(parts) != 2 + len(_CPE_FIELDS):
        return None
    return {
        field: _CPE_ESCAPE.sub(r"\1", value)
        for field, value in zip(_CPE_FIELDS, parts[2:], strict=True)
    }


def _infer_ecosystem(cpe_parts: dict[str, str]) -> str | None:
    for field in ("vendor", "product"):
        value = cpe_parts.get(field, "").lower()
        for prefix, ecosystem in _ECOSYSTEM_PREFIXES.items():
            if value.startswith(prefix):
                return ecosystem
    return None


def synthesize_purl(name: str, version: str | None, ecosystem: str | None) -> str | None:
    """Build a low-confidence purl from name/version/ecosystem. None if data is insufficient.

    Constructed through PackageURL (not string formatting) so the result is always canonical:
    names get the ecosystem's case/encoding rules applied, and the version is cleaned the
    same way normalized_version is. Downstream code may rely on
    normalize_purl(synthesized) == synthesized.
    """
    if not ecosystem or not name or not name.strip():
        return None
    try:
        purl = PackageURL(
            type=ecosystem,
            name=name.strip(),
            version=clean_version(version) if version else None,
        ).to_string()
    except ValueError:
        return None
    # Round-trip guarantees full canonical form (encoding of characters the constructor
    # accepts verbatim, e.g. spaces).
    return normalize_purl(purl)


def clean_version(version: str) -> str:
    """Strip a leading v/V and a debian-style epoch prefix (N:) for the normalized form.

    Epoch stripping loses deb/rpm ordering information (1:1.0 sorts after 2.0): M2's version
    comparator must evaluate deb/rpm ranges against the *raw* Component.version, never this
    normalized form.
    """
    cleaned = _LEADING_V.sub("", version.strip())
    match = _DEB_EPOCH.match(cleaned)
    return match.group(1) if match else cleaned


def normalize_component(component: Component) -> Component:
    """Populate a Component's normalized_purl/normalized_version/cpe_parts/synthesized fields."""
    updates: dict[str, object] = {}

    cpe_parts = parse_cpe(component.cpe) if component.cpe else None
    if cpe_parts is not None:
        updates["cpe_parts"] = cpe_parts

    if component.purl:
        updates["normalized_purl"] = normalize_purl(component.purl)
    elif cpe_parts is not None:
        ecosystem = _infer_ecosystem(cpe_parts)
        synthesized_purl = synthesize_purl(component.name, component.version, ecosystem)
        if synthesized_purl is not None:
            updates["normalized_purl"] = synthesized_purl
            updates["synthesized"] = True

    if component.version is not None:
        updates["normalized_version"] = clean_version(component.version)

    return component.model_copy(update=updates) if updates else component
