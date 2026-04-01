"""
Image Detector - Detect sensitive information in images
"""

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ghostguard.core import GhostGuard
from ghostguard.types import DetectionResult, SensitivityLevel


@dataclass
class ImageFinding:
    """A finding from image analysis"""

    text: str
    bounding_box: Tuple[int, int, int, int]  # x, y, width, height
    confidence: float
    detections: List[DetectionResult] = field(default_factory=list)


@dataclass
class ImageScanResult:
    """Result of scanning an image"""

    image_path: str
    ocr_text: str
    findings: List[ImageFinding]
    total_detections: int
    sensitive_items: List[DetectionResult]

    @property
    def has_sensitive_info(self) -> bool:
        return self.total_detections > 0


class ImageDetector:
    """
    Detect sensitive information in images using OCR.

    Usage:
        detector = ImageDetector()
        result = detector.scan("screenshot.png")
        print(f"Found {result.total_detections} sensitive items")

        # Get redacted image
        detector.redact_image("screenshot.png", "redacted.png")
    """

    def __init__(
        self,
        guard: Optional[GhostGuard] = None,
        ocr_engine: str = "auto",  # auto, tesseract, easyocr, paddleocr
    ):
        self.guard = guard or GhostGuard()
        self.ocr_engine = ocr_engine
        self._engine = None

    def _get_engine(self):
        """Lazy load OCR engine"""
        if self._engine is not None:
            return self._engine

        # Try engines in order
        engines = ["easyocr", "tesseract", "paddleocr"]

        if self.ocr_engine != "auto":
            engines = [self.ocr_engine] + [e for e in engines if e != self.ocr_engine]

        for engine in engines:
            try:
                if engine == "tesseract":
                    import pytesseract
                    from PIL import Image

                    self._engine = ("tesseract", pytesseract, Image)
                    return self._engine
                elif engine == "easyocr":
                    import easyocr

                    self._engine = ("easyocr", easyocr.Reader(["ch_sim", "en"]), None)
                    return self._engine
                elif engine == "paddleocr":
                    from paddleocr import PaddleOCR

                    self._engine = (
                        "paddleocr",
                        PaddleOCR(use_angle_cls=True, lang="ch"),
                        None,
                    )
                    return self._engine
            except ImportError:
                continue

        raise RuntimeError(
            "No OCR engine found. Install one:\n"
            "  pip install pytesseract (requires Tesseract installed)\n"
            "  pip install easyocr\n"
            "  pip install paddleocr"
        )

    def scan(self, image_path: str) -> ImageScanResult:
        """
        Scan an image for sensitive information.

        Args:
            image_path: Path to the image file

        Returns:
            ImageScanResult with all findings
        """
        engine_name, engine, pil_image = self._get_engine()

        # Extract text and bounding boxes
        if engine_name == "tesseract":
            ocr_results = self._tesseract_scan(engine, pil_image, image_path)
        elif engine_name == "easyocr":
            ocr_results = self._easyocr_scan(engine, image_path)
        elif engine_name == "paddleocr":
            ocr_results = self._paddleocr_scan(engine, image_path)
        else:
            raise ValueError(f"Unknown engine: {engine_name}")

        # Build full text
        full_text = "\n".join([r["text"] for r in ocr_results])

        # Detect sensitive info in each region
        findings = []
        all_detections = []

        for ocr_result in ocr_results:
            text = ocr_result["text"]
            bbox = ocr_result["bbox"]
            confidence = ocr_result.get("confidence", 0.0)

            # Detect sensitive info
            detections = self.guard.detect(text)

            finding = ImageFinding(
                text=text,
                bounding_box=bbox,
                confidence=confidence,
                detections=detections,
            )
            findings.append(finding)
            all_detections.extend(detections)

        return ImageScanResult(
            image_path=image_path,
            ocr_text=full_text,
            findings=findings,
            total_detections=len(all_detections),
            sensitive_items=all_detections,
        )

    def _tesseract_scan(self, pytesseract, pil_image, image_path: str) -> List[dict]:
        """Scan using Tesseract"""
        image = pil_image.open(image_path)

        # Get detailed data
        data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)

        results = []
        for i in range(len(data["text"])):
            text = data["text"][i].strip()
            if not text:
                continue

            results.append(
                {
                    "text": text,
                    "bbox": (
                        data["left"][i],
                        data["top"][i],
                        data["width"][i],
                        data["height"][i],
                    ),
                    "confidence": float(data["conf"][i]) / 100,
                }
            )

        return results

    def _easyocr_scan(self, reader, image_path: str) -> List[dict]:
        """Scan using EasyOCR"""
        results = reader.readtext(image_path)

        return [
            {
                "text": r[1],
                "bbox": (
                    int(r[0][0][0]),
                    int(r[0][0][1]),
                    int(r[0][2][0] - r[0][0][0]),
                    int(r[0][2][1] - r[0][0][1]),
                ),
                "confidence": r[2],
            }
            for r in results
        ]

    def _paddleocr_scan(self, ocr, image_path: str) -> List[dict]:
        """Scan using PaddleOCR"""
        results = ocr.ocr(image_path, cls=True)

        output = []
        for line in results[0]:
            bbox = line[0]
            text = line[1][0]
            confidence = line[1][1]

            x_min = min(p[0] for p in bbox)
            y_min = min(p[1] for p in bbox)
            x_max = max(p[0] for p in bbox)
            y_max = max(p[1] for p in bbox)

            output.append(
                {
                    "text": text,
                    "bbox": (
                        int(x_min),
                        int(y_min),
                        int(x_max - x_min),
                        int(y_max - y_min),
                    ),
                    "confidence": confidence,
                }
            )

        return output

    def scan_text(self, text: str) -> List[DetectionResult]:
        """Directly scan text without OCR"""
        return self.guard.detect(text)

    def get_summary(self, result: ImageScanResult) -> Dict:
        """Get a summary of scan results"""
        summary = {
            "image": result.image_path,
            "ocr_text_length": len(result.ocr_text),
            "text_regions": len(result.findings),
            "sensitive_count": result.total_detections,
            "by_type": {},
            "by_risk": {},
        }

        for det in result.sensitive_items:
            # By type
            t = det.info_type
            summary["by_type"][t] = summary["by_type"].get(t, 0) + 1

            # By risk
            r = det.risk_level.value
            summary["by_risk"][r] = summary["by_risk"].get(r, 0) + 1

        return summary
