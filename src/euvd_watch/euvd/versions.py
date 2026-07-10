"""Version comparison and EUVD version-range evaluation (Step 2.3).

The comparator always reports *which scheme* it used, because the matcher's confidence
caps depend on it: a comparison made by the tokenwise fallback can never support a `high`
confidence match (hard invariant).

deb/rpm caution (plans/implementation_plan.md, M0/M1 review item 3.3): callers must pass
the *raw* component version, never `normalized_version` — normalization strips debian
epochs (`1:1.0` -> `1.0`), which destroys deb ordering (`1:1.0` sorts after `2.0`).
This module receives whatever the caller passes; the matcher passes raw versions.
"""

from __future__ import annotations

import re
from enum import StrEnum

from packaging.version import InvalidVersion, Version


class Scheme(StrEnum):
    PEP440 = "pep440"
    SEMVER = "semver"
    TOKENWISE = "tokenwise"  # fallback: never sufficient for high confidence


_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
_TOKEN_SPLIT = re.compile(r"[.\-_+]")


def _semver_key(match: re.Match[str]) -> tuple[int, int, int, tuple[str, ...]]:
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    prerelease = match.group(4)
    # Per semver, a version with a prerelease sorts *before* the same version without one;
    # encode "no prerelease" as a tuple that sorts after any prerelease tuple.
    pre_key = tuple(prerelease.split(".")) if prerelease else ("~",)
    return (major, minor, patch, pre_key)


def _token_key(version: str) -> tuple[tuple[int, str], ...]:
    tokens: list[tuple[int, str]] = []
    for token in _TOKEN_SPLIT.split(version.strip().lower()):
        # isdigit() alone is unsafe: it is True for e.g. superscript digits that int()
        # rejects (found by hypothesis). ascii-only digits are what versions actually use.
        if token.isdigit() and token.isascii():
            tokens.append((int(token), ""))
        else:
            tokens.append((-1, token))
    return tuple(tokens)


def compare(a: str, b: str) -> tuple[int, Scheme]:
    """Compare two version strings. Returns (-1|0|1, scheme actually used).

    Tries PEP 440 first (broadest real-world coverage for our pypi-heavy inputs), then
    strict semver, then a tokenwise fallback that exists only so *something* deterministic
    can be said — the matcher must treat tokenwise results as low-trust.
    """
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion:
        pass
    else:
        return ((va > vb) - (va < vb), Scheme.PEP440)

    ma, mb = _SEMVER.match(a.strip()), _SEMVER.match(b.strip())
    if ma and mb:
        ka, kb = _semver_key(ma), _semver_key(mb)
        return ((ka > kb) - (ka < kb), Scheme.SEMVER)

    ka2, kb2 = _token_key(a), _token_key(b)
    return ((ka2 > kb2) - (ka2 < kb2), Scheme.TOKENWISE)


class RangeResult(StrEnum):
    INSIDE = "inside"
    OUTSIDE = "outside"
    AMBIGUOUS = "ambiguous"  # unparseable/open-ended range text: never a guess


# Observed EUVD product_version shapes (docs/euvd-api.md): "A-B", "<X", "<=X", ">=A <B",
# exact versions, and free text (-> AMBIGUOUS).
# Non-greedy first group: "1.0.0-6.6.1" must split at the FIRST hyphen (low=1.0.0,
# high=6.6.1), and both sides must independently look like versions.
_HYPHEN_RANGE = re.compile(r"^\s*(\S+?)\s*-\s*(\S+)\s*$")
_BOUND = re.compile(r"^\s*(<=|>=|<|>|=)\s*(\S+)\s*$")
_COMPOUND = re.compile(r"^\s*(>=|>)\s*(\S+)\s+(<=|<)\s*(\S+)\s*$")
_VERSIONISH = re.compile(r"^\d[\w.+]*(\.\w+)*$")


def _looks_versionish(text: str) -> bool:
    return bool(_VERSIONISH.match(text.strip()))


def _check_bound(version: str, op: str, boundary: str) -> tuple[bool, Scheme]:
    result, scheme = compare(version, boundary)
    inside = {
        "<": result < 0,
        "<=": result <= 0,
        ">": result > 0,
        ">=": result >= 0,
        "=": result == 0,
    }[op]
    return inside, scheme


def evaluate_range(version: str, range_text: str) -> tuple[RangeResult, Scheme]:
    """Evaluate whether `version` falls inside EUVD's free-text `range_text`.

    Returns (result, weakest scheme used across the comparisons). Anything the parser
    doesn't positively recognize is AMBIGUOUS — the conservative default that caps
    confidence at medium rather than guessing.
    """
    text = (range_text or "").strip()
    if not text:
        return (RangeResult.AMBIGUOUS, Scheme.TOKENWISE)

    compound = _COMPOUND.match(text)
    if compound:
        low_in, scheme_low = _check_bound(version, compound.group(1), compound.group(2))
        high_in, scheme_high = _check_bound(version, compound.group(3), compound.group(4))
        scheme = _weakest(scheme_low, scheme_high)
        return (RangeResult.INSIDE if (low_in and high_in) else RangeResult.OUTSIDE, scheme)

    bound = _BOUND.match(text)
    if bound:
        inside, scheme = _check_bound(version, bound.group(1), bound.group(2))
        return (RangeResult.INSIDE if inside else RangeResult.OUTSIDE, scheme)

    hyphen = _HYPHEN_RANGE.match(text)
    if hyphen and _looks_versionish(hyphen.group(1)) and _looks_versionish(hyphen.group(2)):
        low, high = hyphen.group(1), hyphen.group(2)
        cmp_low, scheme_low = compare(version, low)
        cmp_high, scheme_high = compare(version, high)
        scheme = _weakest(scheme_low, scheme_high)
        if cmp_low >= 0 and cmp_high <= 0:
            return (RangeResult.INSIDE, scheme)
        return (RangeResult.OUTSIDE, scheme)

    # A bare token that looks like a version: treat as an exact-version constraint.
    if not any(ch.isspace() for ch in text) and _looks_versionish(text):
        result, scheme = compare(version, text)
        return (RangeResult.INSIDE if result == 0 else RangeResult.OUTSIDE, scheme)

    return (RangeResult.AMBIGUOUS, Scheme.TOKENWISE)


_SCHEME_STRENGTH = {Scheme.PEP440: 2, Scheme.SEMVER: 2, Scheme.TOKENWISE: 0}


def _weakest(a: Scheme, b: Scheme) -> Scheme:
    return a if _SCHEME_STRENGTH[a] <= _SCHEME_STRENGTH[b] else b
