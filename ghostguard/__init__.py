"""
GhostGuard - Privacy middleware for AI applications
"""

from ghostguard.core import GhostGuard, SensitivityLevel
from ghostguard.detectors import Detector, BaseDetector
from ghostguard.types import DetectionResult, RedactedText, PrivacyConfig
from ghostguard.global_listener import GlobalPrivacyService
from ghostguard.agents import AIProxy, AIProxyServer
from ghostguard.secrets import SecretsDetector, FileScanner, RepoScanner
from ghostguard.ocr import ImageDetector, ImageProcessor

__version__ = "0.1.0"

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
