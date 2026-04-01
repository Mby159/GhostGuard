"""
Core privacy middleware for GhostGuard
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Optional, Callable, Any

from ghostguard.types import (
    DetectionResult,
    RedactedText,
    PrivacyConfig,
    RedactionStrategy,
    SensitivityLevel,
    CustomRule,
)
from ghostguard.detectors.base import BaseDetector
from ghostguard.detectors.builtin import get_builtin_detectors


class GhostGuard:
    """
    Main privacy middleware class.

    Usage:
        guard = GhostGuard()

        # Detect sensitive info
        results = guard.detect("Call me at 13812345678")

        # Redact text
        redacted = guard.redact("My phone is 13812345678")
        print(redacted.text)  # "My phone is [REDACTED_PHONE_1]"

        # Restore text
        original = guard.restore(redacted.text, redacted.mapping)
        print(original)  # "My phone is 13812345678"

        # Use as middleware
        input_text = "User: 张三，电话13812345678"
        clean_input, mapping = guard.process_input(input_text)
        # ... AI generates response ...
        response = "好的张三，我会联系您"
        final_response = guard.process_output(response, mapping)
    """

    def __init__(
        self,
        config: Optional[PrivacyConfig] = None,
        strategy: RedactionStrategy = RedactionStrategy.PLACEHOLDER,
    ):
        self.config = config or PrivacyConfig()
        self.strategy = strategy
        self._detectors: Dict[str, BaseDetector] = {}
        self._custom_detectors: Dict[str, BaseDetector] = {}
        self._on_detect_callbacks: List[Callable] = []

        # Load built-in detectors
        self._load_builtin_detectors()

    def _load_builtin_detectors(self):
        """Load all built-in detectors"""
        for detector in get_builtin_detectors():
            if self.config.is_type_enabled(detector.name):
                self._detectors[detector.name] = detector

    def register_detector(self, detector: BaseDetector):
        """Register a custom detector"""
        self._custom_detectors[detector.name] = detector
        self._detectors[detector.name] = detector

    def add_custom_rule(self, rule: CustomRule):
        """Add a custom detection rule"""
        from ghostguard.detectors.base import RegexDetector

        class CustomDetector(RegexDetector):
            def __init__(self, pattern: str, name: str, risk_level):
                super().__init__(pattern)
                self._custom_name = name
                self._custom_risk_level = risk_level

            @property
            def name(self):
                return self._custom_name

            @property
            def risk_level(self):
                return self._custom_risk_level

        detector = CustomDetector(rule.pattern, rule.name, rule.risk_level)
        self.register_detector(detector)

    def on_detect(self, callback: Callable):
        """Register a callback for when sensitive info is detected"""
        self._on_detect_callbacks.append(callback)
        return callback

    def _get_risk_order(self, level: SensitivityLevel) -> int:
        """Get numeric order for risk level comparison"""
        order = {
            SensitivityLevel.LOW: 0,
            SensitivityLevel.MEDIUM: 1,
            SensitivityLevel.HIGH: 2,
            SensitivityLevel.CRITICAL: 3,
        }
        return order.get(level, 0)

    def detect(self, text: str) -> List[DetectionResult]:
        """Detect all sensitive information in text"""
        all_results = []
        min_risk_order = self._get_risk_order(self.config.min_risk_level)

        for detector in self._detectors.values():
            if not self.config.is_type_enabled(detector.name):
                continue

            results = detector.find_matches(text)
            for result in results:
                if self._get_risk_order(result.risk_level) >= min_risk_order:
                    all_results.append(result)

                    # Call callbacks
                    for callback in self._on_detect_callbacks:
                        callback(result)

        # Sort by position for consistent processing
        all_results.sort(key=lambda x: x.start)
        return all_results

    def redact(
        self,
        text: str,
        strategy: Optional[RedactionStrategy] = None,
    ) -> RedactedText:
        """Redact sensitive information from text"""
        strategy = strategy or self.strategy
        detections = self.detect(text)

        if not detections:
            return RedactedText(
                text=text,
                mapping={},
                detections=[],
            )

        # Process from end to start to maintain positions
        redacted = text
        mapping: Dict[str, str] = {}

        for detection in reversed(detections):
            placeholder = self._generate_replacement(detection, strategy)
            redacted = (
                redacted[: detection.start] + placeholder + redacted[detection.end :]
            )
            mapping[placeholder] = detection.original_value

        return RedactedText(
            text=redacted,
            mapping=mapping,
            detections=detections,
        )

    def _generate_replacement(
        self,
        detection: DetectionResult,
        strategy: RedactionStrategy,
    ) -> str:
        """Generate replacement text based on strategy"""
        value = detection.original_value

        if strategy == RedactionStrategy.PLACEHOLDER:
            return detection.placeholder

        elif strategy == RedactionStrategy.MASK:
            if len(value) <= 4:
                return "*" * len(value)
            elif len(value) <= 8:
                return value[:2] + "*" * (len(value) - 4) + value[-2:]
            return value[:3] + "*" * (len(value) - 6) + value[-3:]

        elif strategy == RedactionStrategy.REMOVE:
            return ""

        elif strategy == RedactionStrategy.HASH:
            hash_val = hashlib.sha256(value.encode()).hexdigest()[:8]
            return f"[HASH_{hash_val}]"

        return detection.placeholder

    def restore(self, text: str, mapping: Dict[str, str]) -> str:
        """Restore redacted text using the mapping"""
        restored = text

        # Sort by placeholder length (longest first) to avoid partial replacements
        for placeholder, original in sorted(
            mapping.items(),
            key=lambda x: len(x[0]),
            reverse=True,
        ):
            restored = restored.replace(placeholder, original)

        return restored

    def process_input(self, text: str) -> tuple[str, Dict[str, str]]:
        """
        Middleware: Process user input before sending to AI.

        Returns:
            Tuple of (redacted_text, mapping)
        """
        result = self.redact(text)
        return result.text, result.mapping

    def process_output(self, text: str, mapping: Dict[str, str]) -> str:
        """
        Middleware: Process AI output before showing to user.

        Args:
            text: AI generated text
            mapping: Mapping from process_input

        Returns:
            Restored text with original sensitive info
        """
        return self.restore(text, mapping)

    def batch_detect(self, texts: List[str]) -> List[List[DetectionResult]]:
        """Detect sensitive info in multiple texts"""
        return [self.detect(text) for text in texts]

    def batch_redact(
        self,
        texts: List[str],
        strategy: Optional[RedactionStrategy] = None,
    ) -> List[RedactedText]:
        """Redact sensitive info in multiple texts"""
        return [self.redact(text, strategy) for text in texts]

    def clear_callbacks(self):
        """Clear all on_detect callbacks"""
        self._on_detect_callbacks.clear()

    def get_detector_names(self) -> List[str]:
        """Get list of all enabled detector names"""
        return list(self._detectors.keys())


# Re-export SensitivityLevel for convenience
SensitivityLevel = SensitivityLevel
