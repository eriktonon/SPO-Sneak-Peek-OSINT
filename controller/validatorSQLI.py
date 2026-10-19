# -*- coding:UTF-8 -*-
"""
Input sanitizer and SQL injection pattern detector.
Note: All database operations in DataFactory and spoDAO now use parameterized
prepared statements (?). This validator serves as an additional defense-in-depth layer.
"""
import re


class ValidateSQLI:
    DANGEROUS_PATTERN = re.compile(
        r"(['\"#;]|--|/\*|\*/|\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC)\b)",
        re.IGNORECASE,
    )

    def validatorSQLI(self, query: str) -> bool:
        """
        Return True if the input string contains suspicious SQL injection tokens,
        or False if the input is clean.
        """
        if query is None:
            return False
        text = str(query)
        # Check for single/double quotes, comment markers, or SQL keywords
        if any(ch in text for ch in ("'", '"', "#", ";", "=")):
            return True
        return bool(self.DANGEROUS_PATTERN.search(text))
