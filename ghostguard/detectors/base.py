"""
Base detector interface
"""

import re
from abc import ABC, abstractmethod
from typing import List, Optional

from ghostguard.types import DetectionResult, SensitivityLevel


class BaseDetector(ABC):
    """Base class for all detectors"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Detector name (e.g., 'phone', 'email')"""
        pass

    @property
    @abstractmethod
    def risk_level(self) -> SensitivityLevel:
        """Default risk level for this detector"""
        pass

    @abstractmethod
    def find_matches(self, text: str) -> List[DetectionResult]:
        """Find all matches in text"""
        pass

    def validate(self, value: str) -> bool:
        """Optional validation after regex match"""
        return True


class RegexDetector(BaseDetector):
    """Base class for regex-based detectors"""

    def __init__(self, pattern: str, flags: int = 0):
        self._pattern = re.compile(pattern, flags)
        self._counter = 0

    def find_matches(self, text: str) -> List[DetectionResult]:
        results = []
        for match in self._pattern.finditer(text):
            value = match.group()
            if not self.validate(value):
                continue

            self._counter += 1
            results.append(
                DetectionResult(
                    info_type=self.name,
                    original_value=value,
                    placeholder=f"[REDACTED_{self.name.upper()}_{self._counter}]",
                    risk_level=self.risk_level,
                    start=match.start(),
                    end=match.end(),
                )
            )
        return results

    def reset_counter(self):
        self._counter = 0


# Alias for convenience
Detector = RegexDetector
