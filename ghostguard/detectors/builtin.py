"""
Built-in detectors for common sensitive information types
"""

import re

from ghostguard.detectors.base import RegexDetector
from ghostguard.types import SensitivityLevel


class PhoneDetector(RegexDetector):
    """Detect Chinese phone numbers"""

    def __init__(self):
        super().__init__(r"(?<![\d\-])(?:\+?86[-\s]?)?(1[3-9]\d{9})(?![\d\-])")

    @property
    def name(self) -> str:
        return "phone"

    @property
    def risk_level(self) -> SensitivityLevel:
        return SensitivityLevel.MEDIUM


class EmailDetector(RegexDetector):
    """Detect email addresses"""

    def __init__(self):
        super().__init__(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

    @property
    def name(self) -> str:
        return "email"

    @property
    def risk_level(self) -> SensitivityLevel:
        return SensitivityLevel.MEDIUM


class IDCardDetector(RegexDetector):
    """Detect Chinese ID card numbers"""

    def __init__(self):
        super().__init__(
            r"(?<![\dXx])\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![\dXx])"
        )

    @property
    def name(self) -> str:
        return "id_card"

    @property
    def risk_level(self) -> SensitivityLevel:
        return SensitivityLevel.CRITICAL


class BankCardDetector(RegexDetector):
    """Detect bank card numbers with Luhn validation"""

    def __init__(self):
        super().__init__(r"(?<![\d])\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?![\d])")

    @property
    def name(self) -> str:
        return "bank_card"

    @property
    def risk_level(self) -> SensitivityLevel:
        return SensitivityLevel.HIGH

    def validate(self, value: str) -> bool:
        """Validate using Luhn algorithm"""
        digits = [int(d) for d in value if d.isdigit()]
        if not digits:
            return False

        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0


class SSNDetector(RegexDetector):
    """Detect US Social Security Numbers"""

    def __init__(self):
        super().__init__(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b")

    @property
    def name(self) -> str:
        return "ssn"

    @property
    def risk_level(self) -> SensitivityLevel:
        return SensitivityLevel.CRITICAL


class IPv4Detector(RegexDetector):
    """Detect IPv4 addresses"""

    def __init__(self):
        super().__init__(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        )

    @property
    def name(self) -> str:
        return "ipv4"

    @property
    def risk_level(self) -> SensitivityLevel:
        return SensitivityLevel.LOW


class URLDetector(RegexDetector):
    """Detect URLs"""

    def __init__(self):
        super().__init__(
            r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
        )
        self._false_positives = [
            "www.w3.org",
            "www.w3schools.com",
            "schemas.xmlsoap.org",
            "xmlns.com",
            "purl.org",
            "dublincore.org",
        ]

    @property
    def name(self) -> str:
        return "url"

    @property
    def risk_level(self) -> SensitivityLevel:
        return SensitivityLevel.LOW

    def validate(self, value: str) -> bool:
        return not any(fp in value for fp in self._false_positives)


class ChinaPassportDetector(RegexDetector):
    """Detect Chinese passport numbers"""

    def __init__(self):
        super().__init__(r"(?<![\dA-Z])[A-Z]\d{8,9}(?![\dA-Z])")

    @property
    def name(self) -> str:
        return "china_passport"

    @property
    def risk_level(self) -> SensitivityLevel:
        return SensitivityLevel.HIGH


class ChinaCreditCodeDetector(RegexDetector):
    """Detect Chinese unified social credit code"""

    def __init__(self):
        super().__init__(r"(?<![\d])91[12]\d{16}(?![\d])")

    @property
    def name(self) -> str:
        return "china_credit_code"

    @property
    def risk_level(self) -> SensitivityLevel:
        return SensitivityLevel.CRITICAL

    def validate(self, value: str) -> bool:
        """Validate credit code using check digit"""
        if len(value) != 18:
            return False

        weight = [3, 7, 9, 10, 5, 8, 4, 2, 0, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        check_codes = "0123456789ABCDEFGHJKLMNPQRTUWXY"

        code = value.upper()
        try:
            checksum = sum(weight[i] * check_codes.index(code[i]) for i in range(17))
            return code[17] == check_codes[checksum % 31]
        except (ValueError, IndexError):
            return False


class JWTTokenDetector(RegexDetector):
    """Detect JWT tokens"""

    def __init__(self):
        super().__init__(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

    @property
    def name(self) -> str:
        return "jwt_token"

    @property
    def risk_level(self) -> SensitivityLevel:
        return SensitivityLevel.HIGH


class AmountDetector(RegexDetector):
    """Detect monetary amounts"""

    def __init__(self):
        super().__init__(
            r"(?:[￥¥$]\s*[\d,]+(?:\.\d{2})?)|(?:[\d,]+(?:\.\d{2})?\s*(?:元|美元|USD|CNY|RMB))"
        )

    @property
    def name(self) -> str:
        return "amount"

    @property
    def risk_level(self) -> SensitivityLevel:
        return SensitivityLevel.LOW


# Factory function to get all built-in detectors
def get_builtin_detectors() -> list:
    """Get all built-in detector instances"""
    return [
        PhoneDetector(),
        EmailDetector(),
        IDCardDetector(),
        BankCardDetector(),
        SSNDetector(),
        IPv4Detector(),
        URLDetector(),
        ChinaPassportDetector(),
        ChinaCreditCodeDetector(),
        JWTTokenDetector(),
        AmountDetector(),
    ]
