# SPDX-License-Identifier: EUPL-1.2
"""Password hashing + HTTP Basic auth for the dashboard (Step 6.2).

Stdlib-only PBKDF2-HMAC-SHA256 (no extra dependency for something this narrow: one
operator password, not a multi-user credential store). Format is a single
self-describing string so a hash can be pasted into `euvd-watch.yaml` verbatim:

    pbkdf2_sha256$<iterations>$<salt-hex>$<hash-hex>

`verify_password` re-derives with the stored salt/iteration count and compares in
constant time (`hmac.compare_digest`) - never a plain `==` on secret material.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_ALGORITHM = "pbkdf2_sha256"
_ITERATIONS = 600_000  # OWASP 2023 minimum for PBKDF2-HMAC-SHA256
_SALT_BYTES = 16


class PasswordHashError(Exception):
    """Raised when a stored password hash is malformed (wrong shape, unknown algorithm)."""


def hash_password(password: str) -> str:
    """Hash a plaintext password into the storable `pbkdf2_sha256$...` format."""
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return f"{_ALGORITHM}${_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time check of `password` against a `hash_password()` string.

    A malformed stored hash fails closed (returns False) rather than raising - a typo
    in config must lock the dashboard out, never crash it into an unauthenticated state.
    """
    parts = stored_hash.split("$")
    if len(parts) != 4 or parts[0] != _ALGORITHM:
        return False
    _, iterations_text, salt_hex, digest_hex = parts
    try:
        iterations = int(iterations_text)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate, expected)
