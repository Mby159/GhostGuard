"""
Migration adapter for privacy-proxy consumers.

This module lets code that previously used::

    from privacy_processor import PrivacyProcessor
    from config import PrivacyConfig
    from models import PrivacyResult, SensitiveItem, RiskLevel

now work when PrivacyProcessor is adapted to use ghostguard.core.GhostGuard
instead of the standalone privacy_guard module.

Usage after migration::
    # Old imports (still work via this adapter)
    from ghostguard.compat.proxy_adapter import PrivacyProcessor, PrivacyConfig
    from ghostguard.compat.proxy_adapter import PrivacyResult, SensitiveItem, RiskLevel
"""

from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum

from ghostguard.core import GhostGuard
from ghostguard.types import (
    SensitivityLevel,
    RedactionStrategy,
    PrivacyConfig as GGConfig,
)


class RiskLevel(str, Enum):
    """Backwards-compatible risk-level constants."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SensitiveItem:
    info_type: str
    original_value: str
    placeholder: str
    risk_level: RiskLevel
    position: Optional[int] = None


@dataclass
class PrivacyResult:
    original_text: str
    processed_text: str
    mapping: Dict[str, str] = field(default_factory=dict)
    detected_items: List[SensitiveItem] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    processing_time_ms: float = 0.0

    @property
    def has_sensitive_info(self) -> bool:
        return len(self.detected_items) > 0


class PrivacyConfig:
    """Backwards-compatible config object."""

    def __init__(
        self,
        enabled: bool = True,
        strategy: str = "placeholder",
        auto_redact: bool = True,
        skip_validation: bool = False,
        excluded_types: List[str] = None,
        custom_rules: List[Dict[str, Any]] = None,
    ):
        self.enabled = enabled
        self.strategy = strategy
        self.auto_redact = auto_redact
        self.skip_validation = skip_validation
        self.excluded_types = excluded_types or []
        self.custom_rules = custom_rules or []


class PrivacyProcessor:
    """Adapter: PrivacyProcessor backed by GhostGuard instead of privacy_guard."""

    def __init__(self, config: Optional[PrivacyConfig] = None):
        self.config = config or PrivacyConfig()
        self.guard = GhostGuard()
        self._load_custom_rules()

    def _load_custom_rules(self) -> None:
        from ghostguard.types import CustomRule

        for rule in self.config.custom_rules:
            name = rule.get("name")
            pattern = rule.get("pattern")
            risk_level = rule.get("risk_level", "medium")
            if name and pattern:
                try:
                    rl = SensitivityLevel(risk_level)
                except ValueError:
                    rl = SensitivityLevel.MEDIUM
                self.guard.add_custom_rule(
                    CustomRule(name=name, pattern=pattern, risk_level=rl)
                )

    def process_text(self, text: str, strategy: Optional[str] = None) -> PrivacyResult:
        import time

        if not self.config.enabled:
            return PrivacyResult(original_text=text, processed_text=text)
        start = time.time()
        detections = self.guard.detect(text)
        items = []
        for d in detections:
            items.append(
                SensitiveItem(
                    info_type=d.info_type,
                    original_value=d.original_value,
                    placeholder=d.placeholder,
                    risk_level=RiskLevel(d.risk_level.value),
                )
            )
        # Filter excluded types
        if self.config.excluded_types:
            items = [i for i in items if i.info_type not in self.config.excluded_types]
        risk = self._calculate_risk(items)
        # Redact if needed
        use_strategy = strategy or self.config.strategy
        processed = text
        mapping: Dict[str, str] = {}
        if items and self.config.auto_redact:
            strat = _resolve_strategy(use_strategy)
            redacted = self.guard.redact(text, strategy=strat)
            processed = redacted.text
            mapping = redacted.mapping
        elapsed = (time.time() - start) * 1000
        return PrivacyResult(
            original_text=text,
            processed_text=processed,
            mapping=mapping,
            detected_items=items,
            risk_level=risk,
            processing_time_ms=elapsed,
        )

    def process_openai_messages(
        self, messages: List[Dict[str, str]], strategy: Optional[str] = None
    ) -> List[Dict[str, str]]:
        processed, _ = self.process_openai_messages_with_mapping(messages, strategy)
        return processed

    def process_openai_messages_with_mapping(
        self, messages: List[Dict[str, str]], strategy: Optional[str] = None
    ) -> tuple[List[Dict[str, str]], Dict[str, str]]:
        if not self.config.enabled:
            return messages, {}
        processed_messages = []
        combined_mapping: Dict[str, str] = {}
        for message in messages:
            if message.get("role") == "user" and "content" in message:
                content = message["content"]
                if isinstance(content, str):
                    result = self.process_text(content, strategy)
                    processed_content = result.processed_text
                    combined_mapping.update(result.mapping)
                elif isinstance(content, list):
                    processed_content = []
                    for part in content:
                        if part.get("type") == "text":
                            text = part["text"]
                            result = self.process_text(text, strategy)
                            combined_mapping.update(result.mapping)
                            processed_part = part.copy()
                            processed_part["text"] = result.processed_text
                            processed_content.append(processed_part)
                        else:
                            processed_content.append(part)
                else:
                    processed_content = content
                processed_message = message.copy()
                processed_message["content"] = processed_content
                processed_messages.append(processed_message)
            else:
                processed_messages.append(message)
        return processed_messages, combined_mapping

    @staticmethod
    def _calculate_risk(items: List[SensitiveItem]) -> RiskLevel:
        if not items:
            return RiskLevel.LOW
        order = {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.CRITICAL: 3,
        }
        max_order = max(order.get(i.risk_level, 0) for i in items)
        for lvl, o in order.items():
            if o == max_order:
                return lvl
        return RiskLevel.LOW


def _resolve_strategy(strategy: str) -> RedactionStrategy:
    mapping = {
        "placeholder": RedactionStrategy.PLACEHOLDER,
        "mask": RedactionStrategy.MASK,
        "remove": RedactionStrategy.REMOVE,
    }
    return mapping.get(strategy, RedactionStrategy.PLACEHOLDER)
