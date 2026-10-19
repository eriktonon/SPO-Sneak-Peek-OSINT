# -*- coding:UTF-8 -*-
"""
Password hashing and verification utility for SPO.
Upgraded from legacy static-salt SHA-256 to Werkzeug PBKDF2/Scrypt password hashing,
with automatic backward-compatible verification for legacy hashes.
"""
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash


class PasswdHash:
    def hash(self, passwd: str) -> str:
        """Generate a salted adaptive hash using PBKDF2-SHA256."""
        if not passwd:
            raise ValueError("Password cannot be empty")
        return generate_password_hash(passwd, method="pbkdf2:sha256", salt_length=16)

    def verify(self, stored_hash: str, candidate_passwd: str) -> bool:
        """Verify candidate password against stored hash (supports modern & legacy hashes)."""
        if not stored_hash or not candidate_passwd:
            return False
        if stored_hash.startswith(("pbkdf2:", "scrypt:")):
            return check_password_hash(stored_hash, candidate_passwd)
        # Fallback for legacy SHA-256 + "potato" salt from SPO v1
        legacy_hash = hashlib.sha256((candidate_passwd + "potato").encode("utf-8")).hexdigest()
        return stored_hash == legacy_hash