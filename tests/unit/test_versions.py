"""Covers implementation_plan.md Step 2.3: the version comparator and range evaluator."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from euvd_watch.euvd.versions import RangeResult, Scheme, compare, evaluate_range

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("a", "b", "expected", "scheme"),
    [
        ("1.0.0", "2.0.0", -1, Scheme.PEP440),
        ("2.0.0", "1.0.0", 1, Scheme.PEP440),
        ("1.0.0", "1.0.0", 0, Scheme.PEP440),
        ("1.0.0rc1", "1.0.0", -1, Scheme.PEP440),  # PEP 440 prerelease
        ("v1.9.0", "1.9.1", -1, Scheme.PEP440),  # leading v accepted by packaging
        ("1.0.0-alpha", "1.0.0", -1, Scheme.PEP440),
        ("zebra", "zzz", -1, Scheme.TOKENWISE),  # not versions at all
        ("1.2.3.DEV", "1.2.3.dev", 0, Scheme.PEP440),
    ],
)
def test_compare_reports_result_and_scheme(a: str, b: str, expected: int, scheme: Scheme) -> None:
    assert compare(a, b) == (expected, scheme)


def test_semver_prerelease_when_pep440_rejects() -> None:
    # Semver's free-form dotted prerelease identifiers (spec example "1.0.0-x.7.z.92") are
    # not valid PEP 440, so these fall to the semver parser.
    result, scheme = compare("1.0.0-x.7.z.92", "1.0.0-x.7.z.93")
    assert result == -1
    assert scheme is Scheme.SEMVER


@pytest.mark.parametrize(
    ("version", "range_text", "result"),
    [
        ("6.0.0", "1.0.0-6.6.1", RangeResult.INSIDE),  # real EUVD hyphen-range shape
        ("7.0.0", "1.0.0-6.6.1", RangeResult.OUTSIDE),
        ("1.0.0", "1.0.0-6.6.1", RangeResult.INSIDE),  # inclusive low edge
        ("6.6.1", "1.0.0-6.6.1", RangeResult.INSIDE),  # inclusive high edge
        ("2.9.0", "<3.0.0", RangeResult.INSIDE),
        ("3.0.0", "<3.0.0", RangeResult.OUTSIDE),
        ("3.0.0", "<=3.0.0", RangeResult.INSIDE),
        ("0.9.0", ">=1.0 <2.0", RangeResult.OUTSIDE),
        ("1.5.0", ">=1.0 <2.0", RangeResult.INSIDE),
        ("1.2.3", "1.2.3", RangeResult.INSIDE),
        ("1.2.4", "1.2.3", RangeResult.OUTSIDE),
        ("1.2.3", "all versions before fix", RangeResult.AMBIGUOUS),
        ("1.2.3", "", RangeResult.AMBIGUOUS),
        ("1.2.3", "n/a", RangeResult.AMBIGUOUS),
    ],
)
def test_evaluate_range(version: str, range_text: str, result: RangeResult) -> None:
    assert evaluate_range(version, range_text)[0] is result


def test_hyphen_range_splits_at_first_hyphen() -> None:
    # "1.0.0-6.6.1" must be (low=1.0.0, high=6.6.1), not (low=1.0.0-6.6, high=1).
    assert evaluate_range("6.6.1", "1.0.0-6.6.1")[0] is RangeResult.INSIDE
    assert evaluate_range("0.9.9", "1.0.0-6.6.1")[0] is RangeResult.OUTSIDE


def test_ambiguous_results_report_tokenwise_scheme() -> None:
    _, scheme = evaluate_range("1.0", "who knows")
    assert scheme is Scheme.TOKENWISE


@given(st.text(max_size=60), st.text(max_size=60))
def test_evaluate_range_never_raises(version: str, range_text: str) -> None:
    result, scheme = evaluate_range(version, range_text)
    assert result in set(RangeResult)
    assert scheme in set(Scheme)


@given(st.text(min_size=1, max_size=40), st.text(min_size=1, max_size=40))
def test_compare_is_antisymmetric(a: str, b: str) -> None:
    result_ab, scheme_ab = compare(a, b)
    result_ba, scheme_ba = compare(b, a)
    assert result_ab == -result_ba
    assert scheme_ab == scheme_ba
