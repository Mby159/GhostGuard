"""
AI Proxy - Process AI API requests/responses for privacy
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from copy import deepcopy

from ghostguard.core import GhostGuard
from ghostguard.types import RedactionStrategy


class AIProxy:
    """
    Privacy proxy for AI API calls.

    Processes requests and responses to/from AI providers like OpenAI, Anthropic, etc.

    Usage:
        proxy = AIProxy()

        # Process request before sending to AI
        clean_request, mapping = proxy.process_request(original_request)

        # Process response from AI
        final_response = proxy.process_response(ai_response, mapping)
    """

    # Known AI API patterns
    OPENAI_CHAT_COMPLETIONS = "/v1/chat/completions"
    OPENAI_COMPLETIONS = "/v1/completions"
    ANTHROPIC_MESSAGES = "/v1/messages"

    def __init__(
        self,
        guard: Optional[GhostGuard] = None,
        strategy: RedactionStrategy = RedactionStrategy.PLACEHOLDER,
        providers: Optional[List[str]] = None,
    ):
        self.guard = guard or GhostGuard()
        self.strategy = strategy
        self.providers = providers or ["openai", "anthropic", "azure", "custom"]

        # Statistics
        self.stats = {
            "requests_processed": 0,
            "responses_processed": 0,
            "items_redacted": 0,
        }

    def process_request(
        self, request: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """
        Process an AI API request, redacting sensitive information.

        Args:
            request: The API request body (e.g., OpenAI chat completion request)

        Returns:
            Tuple of (cleaned_request, mapping)
        """
        request = deepcopy(request)
        all_mapping: Dict[str, str] = {}

        # Process messages array (common in chat APIs)
        if "messages" in request:
            for message in request["messages"]:
                if "content" in message and isinstance(message["content"], str):
                    cleaned, mapping = self.guard.process_input(message["content"])
                    message["content"] = cleaned
                    all_mapping.update(mapping)

        # Process prompt (for completion APIs)
        if "prompt" in request:
            if isinstance(request["prompt"], str):
                cleaned, mapping = self.guard.process_input(request["prompt"])
                request["prompt"] = cleaned
                all_mapping.update(mapping)
            elif isinstance(request["prompt"], list):
                # P0 fix: actually write cleaned text back to list items
                for i, item in enumerate(request["prompt"]):
                    if isinstance(item, str):
                        cleaned, mapping = self.guard.process_input(item)
                        request["prompt"][i] = cleaned
                        all_mapping.update(mapping)

        # Process system message if separate
        if "system" in request and isinstance(request["system"], str):
            cleaned, mapping = self.guard.process_input(request["system"])
            request["system"] = cleaned
            all_mapping.update(mapping)

        # Process input array (for batch/embeddings)
        if "input" in request:
            if isinstance(request["input"], str):
                cleaned, mapping = self.guard.process_input(request["input"])
                request["input"] = cleaned
                all_mapping.update(mapping)
            elif isinstance(request["input"], list):
                for i, item in enumerate(request["input"]):
                    if isinstance(item, str):
                        cleaned, mapping = self.guard.process_input(item)
                        request["input"][i] = cleaned
                        all_mapping.update(mapping)

        self.stats["requests_processed"] += 1
        self.stats["items_redacted"] += len(all_mapping)

        return request, all_mapping

    def process_response(
        self, response: Dict[str, Any], mapping: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Process an AI API response, restoring sensitive information.

        Args:
            response: The API response body
            mapping: The mapping from process_request

        Returns:
            Restored response
        """
        if not mapping:
            return response

        response = deepcopy(response)

        # Process choices (OpenAI format)
        if "choices" in response:
            for choice in response["choices"]:
                # Chat completion format
                if "message" in choice and "content" in choice["message"]:
                    if isinstance(choice["message"]["content"], str):
                        choice["message"]["content"] = self.guard.restore(
                            choice["message"]["content"], mapping
                        )

                # Completion format
                if "text" in choice and isinstance(choice["text"], str):
                    choice["text"] = self.guard.restore(choice["text"], mapping)

        # Process content array (Anthropic format)
        if "content" in response and isinstance(response["content"], list):
            for block in response["content"]:
                if block.get("type") == "text" and "text" in block:
                    block["text"] = self.guard.restore(block["text"], mapping)

        # Process text field directly
        if "text" in response and isinstance(response["text"], str):
            response["text"] = self.guard.restore(response["text"], mapping)

        # Process output (some APIs)
        if "output" in response and isinstance(response["output"], str):
            response["output"] = self.guard.restore(response["output"], mapping)

        self.stats["responses_processed"] += 1

        return response

    def process_stream_chunk(
        self,
        chunk: str,
        mapping: Dict[str, str],
        buffer: str = "",
    ) -> Tuple[str, str]:
        """
        Process a streaming response chunk.

        For streaming, placeholders might be split across chunks.
        We buffer and restore when we detect complete placeholders.

        Args:
            chunk: The chunk of streaming response
            mapping: The placeholder -> original mapping
            buffer: Buffer from previous chunks

        Returns:
            Tuple of (processed_chunk, new_buffer)
        """
        if not mapping:
            return chunk, buffer

        # Combine with buffer
        text = buffer + chunk

        # Try to restore any complete placeholders
        restored = self.guard.restore(text, mapping)

        # Check if any placeholders are incomplete at the end
        new_buffer = ""
        for placeholder in sorted(mapping.keys(), key=len, reverse=True):
            if placeholder in text and placeholder not in restored:
                # Placeholder was partial, keep in buffer
                idx = text.rfind(placeholder[:10])  # Check partial match
                if idx >= 0:
                    new_buffer = text[idx:]
                    restored = restored[:idx] + text[idx:]  # Keep original for now

        # If we restored everything, buffer is empty
        if restored == text:
            # Check for partial placeholders
            for placeholder in sorted(mapping.keys(), key=len, reverse=True):
                for i in range(1, len(placeholder)):
                    if text.endswith(placeholder[:i]):
                        new_buffer = text[-i:]
                        restored = text[:-i]
                        break

        return restored, new_buffer

    def detect_provider(self, url: str, headers: Dict[str, str]) -> str:
        """Detect AI provider from URL and headers"""
        url_lower = url.lower()

        if "openai" in url_lower:
            return "openai"
        elif "anthropic" in url_lower:
            return "anthropic"
        elif "azure" in url_lower:
            return "azure"
        elif "api.deepseek" in url_lower:
            return "deepseek"
        elif "api.moonshot" in url_lower:
            return "moonshot"
        elif "api.bigmodel" in url_lower or "zhipu" in url_lower:
            return "zhipu"
        elif "dashscope" in url_lower or "aliyun" in url_lower:
            return "alibaba"

        # Check headers
        auth = headers.get("authorization", "")
        if "Bearer sk-" in auth:
            return "openai-style"

        return "custom"

    def get_stats(self) -> Dict[str, int]:
        """Get processing statistics"""
        return self.stats.copy()

    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            "requests_processed": 0,
            "responses_processed": 0,
            "items_redacted": 0,
        }
