"""
GhostGuard OCR - Detect sensitive information in images

Extract text from images using OCR and detect sensitive information.
"""

from ghostguard.ocr.detector import ImageDetector
from ghostguard.ocr.processor import ImageProcessor

__all__ = [
    "ImageDetector",
    "ImageProcessor",
]
