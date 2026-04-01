"""
Detectors for sensitive information
"""

from ghostguard.detectors.base import BaseDetector, Detector
from ghostguard.detectors.builtin import (
    PhoneDetector,
    EmailDetector,
    IDCardDetector,
    BankCardDetector,
    SSNDetector,
    IPv4Detector,
    URLDetector,
    ChinaPassportDetector,
    ChinaCreditCodeDetector,
    JWTTokenDetector,
    AmountDetector,
    get_builtin_detectors,
)

__all__ = [
    "BaseDetector",
    "Detector",
    "PhoneDetector",
    "EmailDetector",
    "IDCardDetector",
    "BankCardDetector",
    "SSNDetector",
    "IPv4Detector",
    "URLDetector",
    "ChinaPassportDetector",
    "ChinaCreditCodeDetector",
    "JWTTokenDetector",
    "AmountDetector",
    "get_builtin_detectors",
]
