"""
Image Processor - Redact sensitive information in images
"""

from pathlib import Path
from typing import List, Optional, Tuple

from ghostguard.core import GhostGuard
from ghostguard.ocr.detector import ImageDetector, ImageScanResult, ImageFinding


class ImageProcessor:
    """
    Process images to redact sensitive information.

    Usage:
        processor = ImageProcessor()
        processor.redact("input.png", "output.png")
        processor.blur("input.png", "output.png")
        processor.pixelate("input.png", "output.png")
    """

    def __init__(self, detector: Optional[ImageDetector] = None):
        self.detector = detector or ImageDetector()

    def redact(
        self,
        input_path: str,
        output_path: str,
        color: Tuple[int, int, int] = (0, 0, 0),
        padding: int = 5,
    ) -> dict:
        """
        Redact sensitive areas with solid color.

        Args:
            input_path: Input image path
            output_path: Output image path
            color: RGB color for redaction (default: black)
            padding: Padding around detected areas

        Returns:
            dict with redaction info
        """
        from PIL import Image, ImageDraw

        result = self.detector.scan(input_path)

        if not result.has_sensitive_info:
            # Just copy the file
            Image.open(input_path).save(output_path)
            return {"redacted": 0, "output": output_path}

        image = Image.open(input_path)
        draw = ImageDraw.Draw(image)

        redacted_count = 0

        for finding in result.findings:
            if finding.detections:  # Has sensitive info
                x, y, w, h = finding.bounding_box

                # Apply padding
                x = max(0, x - padding)
                y = max(0, y - padding)
                w = w + (padding * 2)
                h = h + (padding * 2)

                # Draw rectangle
                draw.rectangle(
                    [x, y, x + w, y + h],
                    fill=color,
                )
                redacted_count += 1

        image.save(output_path)

        return {
            "redacted": redacted_count,
            "output": output_path,
            "detections": result.total_detections,
        }

    def blur(
        self,
        input_path: str,
        output_path: str,
        blur_radius: int = 15,
        padding: int = 5,
    ) -> dict:
        """
        Blur sensitive areas.

        Args:
            input_path: Input image path
            output_path: Output image path
            blur_radius: Blur intensity
            padding: Padding around detected areas
        """
        from PIL import Image, ImageFilter

        result = self.detector.scan(input_path)

        if not result.has_sensitive_info:
            Image.open(input_path).save(output_path)
            return {"blurred": 0, "output": output_path}

        image = Image.open(input_path)
        blurred_count = 0

        for finding in result.findings:
            if finding.detections:
                x, y, w, h = finding.bounding_box

                # Apply padding
                x = max(0, x - padding)
                y = max(0, y - padding)
                w = w + (padding * 2)
                h = h + (padding * 2)

                # Crop, blur, paste
                region = image.crop((x, y, x + w, y + h))
                blurred = region.filter(ImageFilter.GaussianBlur(blur_radius))
                image.paste(blurred, (x, y))
                blurred_count += 1

        image.save(output_path)

        return {
            "blurred": blurred_count,
            "output": output_path,
            "detections": result.total_detections,
        }

    def pixelate(
        self,
        input_path: str,
        output_path: str,
        pixel_size: int = 10,
        padding: int = 5,
    ) -> dict:
        """
        Pixelate sensitive areas.

        Args:
            input_path: Input image path
            output_path: Output image path
            pixel_size: Size of pixels
            padding: Padding around detected areas
        """
        from PIL import Image

        result = self.detector.scan(input_path)

        if not result.has_sensitive_info:
            Image.open(input_path).save(output_path)
            return {"pixelated": 0, "output": output_path}

        image = Image.open(input_path)
        pixelated_count = 0

        for finding in result.findings:
            if finding.detections:
                x, y, w, h = finding.bounding_box

                # Apply padding
                x = max(0, x - padding)
                y = max(0, y - padding)
                w = w + (padding * 2)
                h = h + (padding * 2)

                # Crop, shrink, enlarge (pixelate)
                region = image.crop((x, y, x + w, y + h))
                small = region.resize(
                    (max(1, w // pixel_size), max(1, h // pixel_size)),
                    Image.NEAREST,
                )
                pixelated = small.resize((w, h), Image.NEAREST)
                image.paste(pixelated, (x, y))
                pixelated_count += 1

        image.save(output_path)

        return {
            "pixelated": pixelated_count,
            "output": output_path,
            "detections": result.total_detections,
        }

    def add_text_overlay(
        self,
        input_path: str,
        output_path: str,
        text: str = "[REDACTED]",
        color: Tuple[int, int, int] = (255, 255, 255),
        bg_color: Tuple[int, int, int] = (0, 0, 0),
        padding: int = 5,
    ) -> dict:
        """
        Add text overlay on sensitive areas.

        Args:
            input_path: Input image path
            output_path: Output image path
            text: Overlay text
            color: Text color
            bg_color: Background color
            padding: Padding around detected areas
        """
        from PIL import Image, ImageDraw, ImageFont

        result = self.detector.scan(input_path)

        if not result.has_sensitive_info:
            Image.open(input_path).save(output_path)
            return {"overlaid": 0, "output": output_path}

        image = Image.open(input_path)
        draw = ImageDraw.Draw(image)

        # Try to get a font
        try:
            font = ImageFont.truetype("arial.ttf", 14)
        except IOError:
            font = ImageFont.load_default()

        overlaid_count = 0

        for finding in result.findings:
            if finding.detections:
                x, y, w, h = finding.bounding_box

                # Apply padding
                x = max(0, x - padding)
                y = max(0, y - padding)
                w = w + (padding * 2)
                h = h + (padding * 2)

                # Draw background
                draw.rectangle([x, y, x + w, y + h], fill=bg_color)

                # Draw text (centered)
                text_bbox = draw.textbbox((0, 0), text, font=font)
                text_w = text_bbox[2] - text_bbox[0]
                text_h = text_bbox[3] - text_bbox[1]
                text_x = x + (w - text_w) // 2
                text_y = y + (h - text_h) // 2
                draw.text((text_x, text_y), text, fill=color, font=font)

                overlaid_count += 1

        image.save(output_path)

        return {
            "overlaid": overlaid_count,
            "output": output_path,
            "detections": result.total_detections,
        }

    def batch_redact(
        self,
        input_paths: List[str],
        output_dir: str,
        method: str = "redact",
        **kwargs,
    ) -> List[dict]:
        """
        Process multiple images.

        Args:
            input_paths: List of input image paths
            output_dir: Output directory
            method: Redaction method (redact, blur, pixelate, overlay)
            **kwargs: Additional arguments for the method
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        results = []

        method_func = {
            "redact": self.redact,
            "blur": self.blur,
            "pixelate": self.pixelate,
            "overlay": self.add_text_overlay,
        }.get(method, self.redact)

        for input_path in input_paths:
            input_name = Path(input_path).name
            output_file = str(output_path / input_name)

            result = method_func(input_path, output_file, **kwargs)
            results.append(result)

        return results
