"""
AI Proxy Server - HTTP proxy that intercepts AI API calls
"""

import asyncio
import json
import logging
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

try:
    import httpx

    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

from ghostguard.core import GhostGuard
from ghostguard.types import RedactionStrategy
from ghostguard.agents.proxy import AIProxy


logger = logging.getLogger("ghostguard.proxy")


class AIProxyServer:
    """
    HTTP proxy server for AI API calls.

    Intercepts requests to AI providers, redacts sensitive info in requests,
    and restores it in responses.

    Usage:
        server = AIProxyServer()
        await server.start(host="127.0.0.1", port=8888)

        # Configure client to use proxy:
        # openai.api_base = "http://localhost:8888/v1"
    """

    def __init__(
        self,
        guard: Optional[GhostGuard] = None,
        strategy: RedactionStrategy = RedactionStrategy.PLACEHOLDER,
        pass_through: bool = True,
    ):
        if not HAS_HTTPX:
            raise RuntimeError(
                "httpx is required. Install: pip install ghostguard[agents]"
            )

        self.guard = guard or GhostGuard()
        self.proxy = AIProxy(self.guard, strategy)
        self.pass_through = pass_through  # Pass unknown hosts through

        self._server: Optional[asyncio.Server] = None
        self._running = False

        # Request tracking for streaming
        self._stream_mappings: Dict[str, Dict[str, str]] = {}

    async def start(self, host: str = "127.0.0.1", port: int = 8888):
        """Start the proxy server"""
        self._server = await asyncio.start_server(
            self._handle_connection,
            host,
            port,
        )
        self._running = True

        addr = self._server.sockets[0].getsockname()
        print(f"[GhostGuard Proxy] Listening on http://{addr[0]}:{addr[1]}")
        print(
            f"[GhostGuard Proxy] Set openai.api_base = 'http://localhost:{addr[1]}/v1'"
        )

        async with self._server:
            await self._server.serve_forever()

    async def stop(self):
        """Stop the proxy server"""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._running = False

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Handle incoming connection"""
        try:
            # Parse HTTP request
            request_line = await reader.readline()
            if not request_line:
                return

            method, url, version = request_line.decode().strip().split(" ", 2)

            # Read headers
            headers = {}
            while True:
                line = await reader.readline()
                if line == b"\r\n":
                    break
                if b":" in line:
                    key, value = line.decode().split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            # Read body if present
            body = b""
            if "content-length" in headers:
                content_length = int(headers["content-length"])
                body = await reader.read(content_length)

            # Handle the request
            (
                response_status,
                response_headers,
                response_body,
            ) = await self._handle_request(method, url, headers, body)

            # Send response back
            writer.write(f"HTTP/1.1 {response_status}\r\n".encode())
            for key, value in response_headers.items():
                writer.write(f"{key}: {value}\r\n".encode())
            writer.write(b"\r\n")
            writer.write(response_body)

            await writer.drain()

        except Exception as e:
            logger.error(f"Error handling request: {e}")
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        finally:
            writer.close()

    async def _handle_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: bytes,
    ) -> Tuple[str, Dict[str, str], bytes]:
        """Process and forward the request"""

        # Parse URL
        parsed = urlparse(url)
        target_host = parsed.netloc or headers.get("host", "")

        # Build target URL
        if not target_host:
            # Relative URL - assume OpenAI
            target_host = "api.openai.com"
            target_url = f"https://{target_host}{url}"
        elif not url.startswith("http"):
            target_url = f"https://{target_host}{url}"
        else:
            target_url = url

        # Check if this is an AI API request
        is_ai_request = self._is_ai_request(target_url, headers)

        if not is_ai_request and not self.pass_through:
            return (
                "400 Bad Request",
                {"Content-Type": "text/plain"},
                b"Not an AI API request",
            )

        # Process the request body if it's JSON
        processed_body = body
        mapping = {}

        if (
            is_ai_request
            and body
            and headers.get("content-type", "").startswith("application/json")
        ):
            try:
                request_data = json.loads(body)
                request_data, mapping = self.proxy.process_request(request_data)
                processed_body = json.dumps(request_data).encode()

                if mapping:
                    logger.info(f"Redacted {len(mapping)} items from request")

            except json.JSONDecodeError:
                pass

        # Forward the request
        try:
            async with httpx.AsyncClient() as client:
                # Prepare headers for upstream
                upstream_headers = {
                    k: v
                    for k, v in headers.items()
                    if k.lower() not in ("host", "content-length", "transfer-encoding")
                }
                upstream_headers["host"] = target_host

                # Forward request
                response = await client.request(
                    method=method,
                    url=target_url,
                    headers=upstream_headers,
                    content=processed_body,
                    timeout=120.0,
                )

                # Get response
                response_status = f"{response.status_code} {response.reason_phrase}"
                response_headers = dict(response.headers)
                response_body = response.content

                # Process response if we have a mapping
                if mapping and is_ai_request:
                    content_type = response_headers.get("content-type", "")

                    if "application/json" in content_type:
                        try:
                            response_data = json.loads(response_body)
                            response_data = self.proxy.process_response(
                                response_data, mapping
                            )
                            response_body = json.dumps(response_data).encode()

                            # Update content-length
                            response_headers["content-length"] = str(len(response_body))

                        except json.JSONDecodeError:
                            pass

                    # Handle streaming (SSE)
                    elif "text/event-stream" in content_type:
                        response_body = self._process_sse_stream(response_body, mapping)
                        response_headers["content-length"] = str(len(response_body))

                return response_status, response_headers, response_body

        except Exception as e:
            logger.error(f"Error forwarding request: {e}")
            return "502 Bad Gateway", {"Content-Type": "text/plain"}, str(e).encode()

    def _is_ai_request(self, url: str, headers: Dict[str, str]) -> bool:
        """Check if this is an AI API request"""
        url_lower = url.lower()

        # Common AI API patterns
        ai_patterns = [
            "openai.com",
            "anthropic.com",
            "api.deepseek",
            "api.moonshot",
            "dashscope",
            "api.bigmodel",
            "zhipu",
            "ai.azure",
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
            "/v1/messages",
        ]

        for pattern in ai_patterns:
            if pattern in url_lower:
                return True

        # Check for OpenAI-style API key
        auth = headers.get("authorization", "")
        if "Bearer sk-" in auth:
            return True

        return False

    def _process_sse_stream(self, data: bytes, mapping: Dict[str, str]) -> bytes:
        """Process Server-Sent Events stream"""
        try:
            text = data.decode("utf-8")
            lines = text.split("\n")
            processed_lines = []

            for line in lines:
                if line.startswith("data: "):
                    data_content = line[6:]
                    if data_content == "[DONE]":
                        processed_lines.append(line)
                        continue

                    try:
                        chunk = json.loads(data_content)
                        chunk = self.proxy.process_response(chunk, mapping)
                        processed_lines.append(f"data: {json.dumps(chunk)}")
                    except json.JSONDecodeError:
                        processed_lines.append(line)
                else:
                    processed_lines.append(line)

            return "\n".join(processed_lines).encode("utf-8")

        except Exception as e:
            logger.error(f"Error processing SSE stream: {e}")
            return data

    def get_stats(self) -> Dict:
        """Get proxy statistics"""
        return self.proxy.get_stats()


async def run_server(host: str = "127.0.0.1", port: int = 8888):
    """Convenience function to run the server"""
    server = AIProxyServer()
    await server.start(host, port)


if __name__ == "__main__":
    asyncio.run(run_server())
