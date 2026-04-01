"""Core module tests"""

import pytest
from ghostguard import GhostGuard
from ghostguard.types import RedactionStrategy, SensitivityLevel


class TestGhostGuard:
    def setup_method(self):
        self.guard = GhostGuard()

    def test_detect_phone(self):
        results = self.guard.detect("Phone: 13812345678")
        assert len(results) >= 1
        assert any(r.info_type == "phone" for r in results)

    def test_detect_email(self):
        results = self.guard.detect("Email: test@example.com")
        assert len(results) >= 1
        assert any(r.info_type == "email" for r in results)

    def test_redact(self):
        result = self.guard.redact("Call 13812345678")
        assert len(result.mapping) >= 1
        assert "13812345678" not in result.text

    def test_restore(self):
        result = self.guard.redact("Call 13812345678")
        restored = self.guard.restore(result.text, result.mapping)
        assert "13812345678" in restored

    def test_middleware_flow(self):
        text = "User: Zhang, phone 13812345678"
        clean, mapping = self.guard.process_input(text)
        assert "13812345678" not in clean

        response = "OK, calling 13812345678"
        final = self.guard.process_output(response, mapping)
        assert "13812345678" in final

    def test_multiple_types(self):
        text = "Phone 13812345678, email test@example.com, ID 110101199003074562"
        results = self.guard.detect(text)
        types = {r.info_type for r in results}
        assert "phone" in types
        assert "email" in types
        assert "id_card" in types

    def test_mask_strategy(self):
        result = self.guard.redact("13812345678", RedactionStrategy.MASK)
        assert "*" in result.text

    def test_empty_text(self):
        results = self.guard.detect("")
        assert len(results) == 0

    def test_no_sensitive_info(self):
        results = self.guard.detect("Hello world")
        assert len(results) == 0


class TestDetectors:
    def test_detector_names(self):
        guard = GhostGuard()
        names = guard.get_detector_names()
        assert "phone" in names
        assert "email" in names
        assert "id_card" in names


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
