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
_LEADING_V = re.compile(r"^[vV](?=\d)")
_DEB_EPOCH = re.compile(r"^\d+:(.*)$")


def normalize_purl(purl: str) -> str:
    """Canonicalize a purl via packageurl-python. Idempotent; tolerant of malformed input."""
    try:
        return PackageURL.from_string(purl).to_string()
    except ValueError:
        return purl


def parse_cpe(cpe: str) -> dict[str, str] | None:
    """Split a CPE 2.3 formatted string into its 11 fields, respecting backslash-escaping.

    Returns None (never raises) if the string isn't a well-formed CPE 2.3 identifier.
    """
    if not cpe.startswith("cpe:2.3:"):
        return None
    parts = _UNESCAPED_COLON.split(cpe)
    if len(parts) != 2 + len(_CPE_FIELDS):
        return None
    return dict(zip(_CPE_FIELDS, parts[2:], strict=True))


def _infer_ecosystem(cpe_parts: dict[str, str]) -> str | None:
    for field in ("vendor", "product"):
        value = cpe_parts.get(field, "").lower()
        for prefix, ecosystem in _ECOSYSTEM_PREFIXES.items():
            if value.startswith(prefix):
                return ecosystem
    return None


def synthesize_purl(name: str, version: str | None, ecosystem: str | None) -> str | None:
    """Build a low-confidence purl from name/version/ecosystem. None if data is insufficient."""
    if not ecosystem or not name:
        return None
    return f"pkg:{ecosystem}/{name}@{version}" if version else f"pkg:{ecosystem}/{name}"


def clean_version(version: str) -> str:
    """Strip a leading v/V and a debian-style epoch prefix (N:) for the normalized form."""
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
