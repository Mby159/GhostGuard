"""
Type definitions for GhostGuard
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class SensitivityLevel(str, Enum):
    """Risk levels for sensitive information"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RedactionStrategy(str, Enum):
    """Strategies for redacting sensitive information"""

    PLACEHOLDER = "placeholder"  # [REDACTED_PHONE_1]
    MASK = "mask"  # 138****5678
    REMOVE = "remove"  # Remove completely
    HASH = "hash"  # SHA256 hash


@dataclass
class DetectionResult:
    """Result of detecting sensitive information"""

    info_type: str
    original_value: str
    placeholder: str
    risk_level: SensitivityLevel
    start: int
    end: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RedactedText:
    """Result of redacting text"""

    text: str
    mapping: Dict[str, str]  # placeholder -> original
    detections: List[DetectionResult]

    @property
    def has_sensitive_info(self) -> bool:
        return len(self.detections) > 0

    @property
    def count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for d in self.detections:
            counts[d.info_type] = counts.get(d.info_type, 0) + 1
        return counts


@dataclass
class PrivacyConfig:
    """Configuration for privacy detection"""

    enabled_types: Optional[List[str]] = None
    disabled_types: Optional[List[str]] = None
    min_risk_level: SensitivityLevel = SensitivityLevel.LOW
    custom_rules: Dict[str, "CustomRule"] = field(default_factory=dict)

    def is_type_enabled(self, info_type: str) -> bool:
        if self.disabled_types and info_type in self.disabled_types:
            return False
        if self.enabled_types:
            return info_type in self.enabled_types
        return True


@dataclass
class CustomRule:
    """Custom detection rule"""

    name: str
    pattern: str
    risk_level: SensitivityLevel = SensitivityLevel.MEDIUM
    description: str = ""
