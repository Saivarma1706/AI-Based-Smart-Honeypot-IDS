"""Authentication module for Smart Honeypot IDS.

This file provides two reusable functions:
- hash_password()
- validate_login()

Security notes (beginner-friendly):
- Plaintext passwords are insecure because anyone with DB/log access can read them.
- Hashing converts a password into a fixed-length digest.
- To make hashing more resilient, we use a *salt* (random data mixed into the hash).
- We use timing-safe comparison (hmac.compare_digest) to reduce subtle info leaks.

IMPORTANT: This honeypot example stores a small in-module user database.
In a real system, user records (salt + hash) should be stored in a DB.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Final


# --- Honeypot user store (salted SHA256) ---
#
# We keep SHA256 as requested, but we improve password security by salting.
# A salt prevents attackers from using precomputed/rainbow tables effectively
# and makes identical passwords hash differently.
#
# Password used for the admin demo user is: CoreAccess@2026

_SALT_ADMIN: Final[str] = "honeypot-salt-sys_admin-2026"



def _sha256_hex(data: str) -> str:
    """Return SHA256 hex digest of the provided text."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:

    """Hash plaintext password using SHA256.

    Beginner explanation:
    - Hashing is one-way: you cannot "undo" the hash to get the password back.
    - However, hashing alone (unsalted) can be weaker than salted hashing.

    Note:
    - The validate_login() flow uses a per-user salt.
    - This function is kept reusable per the project requirement.
    """

    if not isinstance(password, str):
        raise TypeError("password must be a string")

    # SHA256(password) (unsalted) is what this function technically does.
    # For real usage in this project, prefer the salted validation path.
    return _sha256_hex(password)


# Internal storage: username -> {salt, password_hash}
_USERS: Final[dict[str, dict[str, str]]] = {
    # Requested demo credentials:
    # Username: sys_admin
    # Password: CoreAccess@2026
    "sys_admin": {
        "salt": _SALT_ADMIN,
        # salted hash = SHA256(salt + password)
        "password_hash": _sha256_hex(_SALT_ADMIN + "CoreAccess@2026"),
    }
}



_USERNAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_]{1,32}$")


def _is_valid_username(username: str) -> bool:
    """Validate usernames to prevent weird/hostile inputs."""
    if not isinstance(username, str):
        return False
    return _USERNAME_RE.match(username) is not None


def _hash_password_with_salt(password: str, salt: str) -> str:
    """Compute salted SHA256 digest.

    This is the hash scheme used for validation.
    """
    return _sha256_hex(salt + password)


def validate_login(username: str, password: str) -> bool:
    """Validate submitted credentials.

    Security-focused behavior:
    - Unknown usernames fail without revealing which part was wrong.
    - Hash comparisons use hmac.compare_digest (timing-safe).
    """

    if not _is_valid_username(username):
        return False

    # If user doesn't exist, return False (do not leak existence).
    user_record = _USERS.get(username)
    if not user_record:
        # Dummy compare to keep runtime more consistent.
        # (Not perfect, but better than early exit in beginners' code.)
        dummy_hash = _sha256_hex("unknown-salt" + (password or ""))
        return hmac.compare_digest("", dummy_hash) is True

    salt = user_record["salt"]
    expected_hash = user_record["password_hash"]

    # Compute salted hash of supplied password
    supplied_hash = _hash_password_with_salt(password=password, salt=salt)

    # Timing-safe comparison prevents leaking info via comparison timing.
    return hmac.compare_digest(expected_hash, supplied_hash)


