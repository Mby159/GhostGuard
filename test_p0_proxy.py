"""
Regression tests for P0 fix in GhostGuard proxy agent.

P0#4: list-format prompt must be properly redacted (not passed through raw).
"""

import pytest
from ghostguard.agents.proxy import AIProxy
from ghostguard.core import GhostGuard


class TestListPromptRedaction:
    def test_list_prompt_items_redacted(self):
        """P0 fix: list-format prompt items must be redacted, not passed raw."""
        proxy = AIProxy()
        phone = "13812345678"
        request = {
            "prompt": [
                f"Call me at {phone}",
                "Just a normal string",
            ],
        }

        cleaned, mapping = proxy.process_request(request)

        # All items in the list must be redacted
        for item in cleaned["prompt"]:
            assert phone not in item, f"Sensitive phone still present: {item}"

        # Mapping should contain the placeholder
        assert len(mapping) > 0
        values = list(mapping.values())
        assert phone in values

    def test_mixed_list_and_dict_content(self):
        """Proxy handles various content types in list."""
        proxy = AIProxy()
        request = {
            "prompt": [
                "Email: alice@example.com",
                {
                    "text": "Phone: 13987654321"
                },  # dict in list – not processed by current fix
            ],
        }
        cleaned, mapping = proxy.process_request(request)

        # String items must be redacted
        assert "alice@example.com" not in cleaned["prompt"][0]
        # Dict items are left untouched (current fix only handles strings)
        # This is expected – extending to dict is a future enhancement

    def test_string_prompt_still_works(self):
        """Regular string prompt must continue to be redacted."""
        proxy = AIProxy()
        request = {"prompt": "My number is 13812345678"}
        cleaned, mapping = proxy.process_request(request)
        assert "13812345678" not in cleaned["prompt"]
        assert len(mapping) == 1

    def test_messages_array_redacted(self):
        """OpenAI-style messages array must have content redacted."""
        proxy = AIProxy()
        request = {
            "messages": [
                {"role": "user", "content": "I live at 110101199003078515"},
            ],
        }
        cleaned, mapping = proxy.process_request(request)
        assert "110101199003078515" not in cleaned["messages"][0]["content"]
        assert len(mapping) > 0

    def test_statistics_updated(self):
        """Proxy stats must reflect processed requests."""
        proxy = AIProxy()
        request = {"prompt": [f"Call {i}380000000{i}" for i in range(3)]}
        proxy.process_request(request)
        assert proxy.stats["requests_processed"] == 1
        assert proxy.stats["items_redacted"] > 0
