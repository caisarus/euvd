# SPDX-License-Identifier: EUPL-1.2
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

from packaging.version import Version


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


def _safe_int(token: str) -> int | None:
    """int(token), or None if it can't be converted.

    Guards Python 3.11's int-string-conversion limit (default 4300 digits): a numeric
    run longer than that raises ValueError, and a version segment that long is not a real
    version anyway - never crash on it (that limit exists precisely to stop the O(n^2)
    int-parse of a hostile digit run, so we must not raise the cap; we skip instead).
    """
    try:
        return int(token)
    except ValueError:
        return None


def _token_key(version: str) -> tuple[tuple[int, str], ...]:
    tokens: list[tuple[int, str]] = []
    for token in _TOKEN_SPLIT.split(version.strip().lower()):
        # isdigit() alone is unsafe: it is True for e.g. superscript digits that int()
        # rejects (found by hypothesis). ascii-only digits are what versions actually use.
        numeric = _safe_int(token) if token.isdigit() and token.isascii() else None
        if numeric is not None:
            tokens.append((numeric, ""))
        else:
            # Non-numeric, or an oversized numeric run: sort as an opaque string token.
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
    except ValueError:
        # InvalidVersion (a ValueError subclass) for unparseable input, or a bare
        # ValueError when a numeric segment exceeds Python's int-string limit (a hostile
        # 4300+-digit version) - either way, PEP 440 can't handle it; fall through.
        pass
    else:
        return ((va > vb) - (va < vb), Scheme.PEP440)

    ma, mb = _SEMVER.match(a.strip()), _SEMVER.match(b.strip())
    if ma and mb:
        try:
            ka, kb = _semver_key(ma), _semver_key(mb)
        except ValueError:
            pass  # oversized numeric segment: fall through to the tokenwise fallback
        else:
            return ((ka > kb) - (ka < kb), Scheme.SEMVER)

    ka2, kb2 = _token_key(a), _token_key(b)  # never raises: _safe_int handles oversized runs
    return ((ka2 > kb2) - (ka2 < kb2), Scheme.TOKENWISE)


class RangeResult(StrEnum):
    INSIDE = "inside"
    OUTSIDE = "outside"
    AMBIGUOUS = "ambiguous"  # unparseable/open-ended range text: never a guess


# Observed EUVD product_version shapes (docs/euvd-api.md): "A-B", "<X", "<=X", ">=A <B",
# "A, < B" (introduced-at/fixed-before, seen live on EUVD-2026-4133), exact versions, and
# free text (-> AMBIGUOUS).
# Non-greedy first group: "1.0.0-6.6.1" must split at the FIRST hyphen (low=1.0.0,
# high=6.6.1), and both sides must independently look like versions.
_HYPHEN_RANGE = re.compile(r"^\s*(\S+?)\s*-\s*(\S+)\s*$")
_BOUND = re.compile(r"^\s*(<=|>=|<|>|=)\s*(\S+)\s*$")
_COMPOUND = re.compile(r"^\s*(>=|>)\s*(\S+)\s+(<=|<)\s*(\S+)\s*$")
# "0.40.0, < 0.46.2": inclusive introduced-at, explicit upper bound (M2 review 3.1).
_COMMA_RANGE = re.compile(r"^\s*(\S+?)\s*,\s*(<=|<)\s*(\S+)\s*$")
# NB: no trailing `(\.\w+)*` group. Every character that group could match (`.` and
# word chars) is already in the preceding `[\w.+]*`, so it accepted an identical
# language while introducing quadratic backtracking on crafted range text from the
# (untrusted, beta) EUVD API - a ReDoS: 40 KB hung for ~6 s. This single greedy
# quantifier is linear and accepts exactly the same strings (proven by exhaustive
# equivalence check over the version alphabet).
_VERSIONISH = re.compile(r"^\d[\w.+]*$")


def _looks_versionish(text: str) -> bool:
    return bool(_VERSIONISH.match(text.strip()))


def _is_inverted(low: str, high: str) -> bool:
    """True when a parsed range's lower bound is above its upper bound.

    An inverted range contains nothing, so evaluating it reports *every* version as
    "outside" - a proof of safety manufactured out of range text we misread. Two real
    sources: a distro-style exact version claimed by the hyphen-range parser ("2.4.0-2"
    splits to low="2.4.0", high="2"), and genuinely malformed EUVD entries (">=2.0 <1.0").
    Neither may ever suppress a finding, so callers treat inversion as "not evaluable".
    """
    return compare(low, high)[0] > 0


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
        if _is_inverted(compound.group(2), compound.group(4)):
            return (RangeResult.AMBIGUOUS, Scheme.TOKENWISE)
        low_in, scheme_low = _check_bound(version, compound.group(1), compound.group(2))
        high_in, scheme_high = _check_bound(version, compound.group(3), compound.group(4))
        scheme = _weakest(scheme_low, scheme_high)
        return (RangeResult.INSIDE if (low_in and high_in) else RangeResult.OUTSIDE, scheme)

    comma = _COMMA_RANGE.match(text)
    if comma and _looks_versionish(comma.group(1)):
        if _is_inverted(comma.group(1), comma.group(3)):
            return (RangeResult.AMBIGUOUS, Scheme.TOKENWISE)
        low_in, scheme_low = _check_bound(version, ">=", comma.group(1))
        high_in, scheme_high = _check_bound(version, comma.group(2), comma.group(3))
        scheme = _weakest(scheme_low, scheme_high)
        return (RangeResult.INSIDE if (low_in and high_in) else RangeResult.OUTSIDE, scheme)

    bound = _BOUND.match(text)
    if bound:
        inside, scheme = _check_bound(version, bound.group(1), bound.group(2))
        return (RangeResult.INSIDE if inside else RangeResult.OUTSIDE, scheme)

    hyphen = _HYPHEN_RANGE.match(text)
    if hyphen and _looks_versionish(hyphen.group(1)) and _looks_versionish(hyphen.group(2)):
        low, high = hyphen.group(1), hyphen.group(2)
        if _is_inverted(low, high):
            # Not a range: one version carrying a distro/release suffix ("2.4.0-2",
            # "1.2.3-1ubuntu2"), which docs/euvd-api.md lists as an observed exact-version
            # shape. Read it as exactly that - equality means affected. Never OUTSIDE: a
            # suffixed exact version says nothing trustworthy about any other version.
            result, scheme = compare(version, text)
            if result == 0:
                return (RangeResult.INSIDE, scheme)
            return (RangeResult.AMBIGUOUS, Scheme.TOKENWISE)
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
