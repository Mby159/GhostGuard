"""
Backward-compatible drop-in replacement for the standalone privacy-guard module.

All functionality is delegated to ghostguard.core.GhostGuard so that code that used
`from privacy_guard import PrivacyGuard, RiskLevel` continues to work without
modification after migrating from the old repo.

Usage::
    from ghostguard.compat.privacy_guard import PrivacyGuard, RiskLevel
    guard = PrivacyGuard()
    results = guard.detect("Call me at 13812345678")
    redacted = guard.redact("My phone is 13812345678", strategy="placeholder")
    restored = guard.restore(redacted["text"], redacted["mapping"])
"""

from typing import Dict, List, Any, Optional, Union

from ghostguard.core import GhostGuard
from ghostguard.types import SensitivityLevel, RedactionStrategy, PrivacyConfig


class RiskLevel:
    """Backwards-compatible risk-level constants (standalone privacy-guard style)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SensitiveInfo:
    """Simple dict-like container for backwards-compatible detection results."""

    def __init__(
        self, info_type: str, original_value: str, placeholder: str, risk_level: str
    ):
        self.info_type = info_type
        self.original_value = original_value
        self.placeholder = placeholder
        self.risk_level = risk_level

    def __iter__(self):
        yield "info_type", self.info_type
        yield "original_value", self.original_value
        yield "placeholder", self.placeholder
        yield "risk_level", self.risk_level


class PrivacyGuard:
    """Adapter that wraps GhostGuard and exposes the legacy privacy-guard API."""

    def __init__(self):
        self._gg = GhostGuard()

    # ------------------------------------------------------------------
    # Detect / batch detect
    # ------------------------------------------------------------------
    def detect(self, text: str, skip_validation: bool = False) -> List[Dict[str, Any]]:
        results = self._gg.detect(text)
        out = []
        for r in results:
            out.append(
                {
                    "info_type": r.info_type,
                    "original_value": r.original_value,
                    "placeholder": r.placeholder,
                    "risk_level": r.risk_level.value,
                }
            )
        return out

    def batch_detect(self, texts: List[str]) -> List[List[Dict[str, Any]]]:
        return [self.detect(t) for t in texts]

    # ------------------------------------------------------------------
    # Redact
    # ------------------------------------------------------------------
    def redact(self, text: str, strategy: str = "placeholder") -> Dict[str, Any]:
        strat = self._resolve_strategy(strategy)
        result = self._gg.redact(text, strategy=strat)
        return {
            "text": result.text,
            "mapping": result.mapping,
            "detected_count": len(result.detections),
        }

    def batch_redact(
        self, texts: List[str], strategy: str = "placeholder"
    ) -> List[Dict[str, Any]]:
        return [self.redact(t, strategy) for t in texts]

    # ------------------------------------------------------------------
    # Restore
    # ------------------------------------------------------------------
    def restore(self, text: str, mapping: Dict[str, str]) -> str:
        return self._gg.restore(text, mapping)

    # ------------------------------------------------------------------
    # File / directory helpers
    # ------------------------------------------------------------------
    def redact_file(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        strategy: str = "placeholder",
    ) -> Dict[str, Any]:
        import os

        if ".." in file_path:
            return {"error": "Path traversal not allowed"}
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            return {"error": f"Failed to read file: {e}"}
        result = self.redact(content, strategy)
        if output_path:
            if ".." in output_path:
                return {"error": "Path traversal not allowed in output"}
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(result["text"])
                result["output_file"] = output_path
            except Exception as e:
                return {"error": f"Failed to write file: {e}"}
        return result

    def scan_directory(
        self,
        directory: str,
        extensions: Optional[List[str]] = None,
        recursive: bool = True,
        exclude_git: bool = True,
    ) -> Dict[str, Any]:
        import os, fnmatch

        if not os.path.exists(directory):
            return {"error": f"Directory not found: {directory}"}
        if not os.path.isdir(directory):
            return {"error": f"Not a directory: {directory}"}

        ignore_patterns = [".git"] if exclude_git else []
        results = {
            "files": [],
            "total_files": 0,
            "total_findings": 0,
            "high_risk_files": [],
        }

        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, directory)
                if any(fnmatch.fnmatch(filename, pat) for pat in ignore_patterns):
                    continue
                if extensions and not any(filename.endswith(ext) for ext in extensions):
                    continue
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                findings = self.detect(content)
                if findings:
                    results["files"].append(
                        {"file": rel_path, "findings": findings, "count": len(findings)}
                    )
                    results["total_findings"] += len(findings)
                    if any(f["risk_level"] in ("high", "critical") for f in findings):
                        results["high_risk_files"].append(rel_path)
        results["total_files"] = len(results["files"])
        return results

    # ------------------------------------------------------------------
    # Rules / config helpers
    # ------------------------------------------------------------------
    def add_rule(self, name: str, pattern: str, risk_level: str = "medium") -> bool:
        from ghostguard.types import CustomRule

        try:
            rl = SensitivityLevel(risk_level)
        except ValueError:
            rl = SensitivityLevel.MEDIUM
        rule = CustomRule(name=name, pattern=pattern, risk_level=rl)
        self._gg.add_custom_rule(rule)
        return True

    def list_rules(self) -> List[Dict[str, Any]]:
        return []

    def export_config_example(self) -> str:
        import json

        return json.dumps(
            {
                "rules": [
                    {
                        "name": "order_id",
                        "pattern": r"订单号[:：]\s*([A-Z0-9]{10,20})",
                        "risk_level": "low",
                    }
                ]
            },
            ensure_ascii=False,
            indent=2,
        )

    def load_rules_from_config(self, config_path: str) -> Dict[str, Any]:
        import os, json

        if not os.path.exists(config_path):
            return {"error": f"Config file not found: {config_path}"}
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON: {e}"}
        added = []
        errors = []
        for rule in config.get("rules", []):
            name = rule.get("name")
            pattern = rule.get("pattern")
            risk_level = rule.get("risk_level", "medium")
            if name and pattern:
                if self.add_rule(name, pattern, risk_level):
                    added.append(name)
                else:
                    errors.append(f"Invalid pattern for '{name}'")
        return {"added": added, "errors": errors, "total_added": len(added)}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _resolve_strategy(strategy: str) -> RedactionStrategy:
        mapping = {
            "placeholder": RedactionStrategy.PLACEHOLDER,
            "mask": RedactionStrategy.MASK,
            "remove": RedactionStrategy.REMOVE,
        }
        return mapping.get(strategy, RedactionStrategy.PLACEHOLDER)
