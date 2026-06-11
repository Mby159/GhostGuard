"""
GhostGuard - Privacy middleware for AI applications.

The base package keeps core detection/redaction imports lightweight. Optional
features such as global listeners, AI proxy, secrets scanning, and OCR are
loaded lazily so `from ghostguard import GhostGuard` works without installing
platform-specific extras like pywin32 or OCR dependencies.
"""

from __future__ import annotations

from typing import Any

from ghostguard.core import GhostGuard, SensitivityLevel
from ghostguard.detectors import Detector, BaseDetector
from ghostguard.types import DetectionResult, RedactedText, PrivacyConfig

__version__ = "0.1.0"

_LAZY_EXPORTS = {
    "GlobalPrivacyService": ("ghostguard.global_listener", "GlobalPrivacyService"),
    "AIProxy": ("ghostguard.agents", "AIProxy"),
    "AIProxyServer": ("ghostguard.agents", "AIProxyServer"),
    "SecretsDetector": ("ghostguard.secrets", "SecretsDetector"),
    "FileScanner": ("ghostguard.secrets", "FileScanner"),
    "RepoScanner": ("ghostguard.secrets", "RepoScanner"),
    "ImageDetector": ("ghostguard.ocr", "ImageDetector"),
    "ImageProcessor": ("ghostguard.ocr", "ImageProcessor"),
}


def __getattr__(name: str) -> Any:
    """Lazily import optional components on first access."""
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module 'ghostguard' has no attribute {name!r}")

    module_name, attr_name = _LAZY_EXPORTS[name]
    try:
        module = __import__(module_name, fromlist=[attr_name])
        value = getattr(module, attr_name)
    except ImportError as exc:
        raise ImportError(
            f"Optional GhostGuard component {name!r} requires extra dependencies. "
            "Install the corresponding optional extra, e.g. ghostguard[global], "
            "ghostguard[agents], or ghostguard[ocr]."
        ) from exc

    globals()[name] = value
    return value


__all__ = [
    "GhostGuard",
    "GlobalPrivacyService",
    "AIProxy",
    "AIProxyServer",
    "SecretsDetector",
    "FileScanner",
    "RepoScanner",
    "ImageDetector",
    "ImageProcessor",
    "SensitivityLevel",
    "Detector",
    "BaseDetector",
    "DetectionResult",
    "RedactedText",
    "PrivacyConfig",
]
