"""Covers implementation_plan.md Step 6.2: dashboard password hashing.

hash_password/verify_password are the only credential material the dashboard trusts;
malformed stored hashes must fail closed, never raise into an unauthenticated 500.
"""

import pytest

from euvd_watch.web.auth import hash_password, verify_password

pytestmark = pytest.mark.unit


def test_hash_then_verify_round_trips() -> None:
    stored = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", stored)


def test_verify_rejects_wrong_password() -> None:
    stored = hash_password("correct horse battery staple")
    assert not verify_password("wrong password", stored)


def test_hash_is_salted_differently_each_time() -> None:
    a = hash_password("same password")
    b = hash_password("same password")
    assert a != b
    assert verify_password("same password", a)
    assert verify_password("same password", b)


@pytest.mark.parametrize(
    "malformed",
    [
        "",
        "not-a-hash-at-all",
        "pbkdf2_sha256$notanumber$aa$bb",
        "pbkdf2_sha256$600000$nothex$bb",
        "bcrypt$600000$aa$bb",
        "pbkdf2_sha256$600000$aa",
    ],
)
def test_verify_fails_closed_on_malformed_hash(malformed: str) -> None:
    assert not verify_password("anything", malformed)
