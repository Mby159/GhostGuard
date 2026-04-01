"""
Clipboard monitor - detect and redact sensitive info in clipboard
"""

import time
import threading
import win32clipboard
import win32con

from ghostguard.core import GhostGuard
from ghostguard.types import RedactionStrategy


class ClipboardMonitor:
    """
    Monitors clipboard for sensitive information.

    Usage:
        monitor = ClipboardMonitor()
        monitor.start()

        # When user copies sensitive info, it's automatically redacted
        # When pasting, use monitor.get_safe_clipboard() to restore
    """

    def __init__(
        self,
        guard: GhostGuard | None = None,
        auto_redact: bool = True,
        strategy: RedactionStrategy = RedactionStrategy.PLACEHOLDER,
    ):
        self.guard = guard or GhostGuard()
        self.auto_redact = auto_redact
        self.strategy = strategy

        self._running = False
        self._thread: threading.Thread | None = None
        self._last_content = ""
        self._original_mapping: dict[str, str] = {}  # redacted -> original
        self._pending_mapping: dict[str, str] = {}  # placeholder -> original

        self._callbacks: list[callable] = []

    def on_redact(self, callback: callable):
        """Register callback when content is redacted"""
        self._callbacks.append(callback)
        return callback

    def start(self):
        """Start monitoring clipboard"""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop monitoring"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                content = self._get_clipboard_text()

                if content and content != self._last_content:
                    self._last_content = content
                    self._process_clipboard(content)

            except Exception as e:
                pass  # Clipboard might be locked

            time.sleep(0.1)  # Check 10 times per second

    def _get_clipboard_text(self) -> str:
        """Get text from clipboard"""
        try:
            win32clipboard.OpenClipboard()
            try:
                data = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
                return data if isinstance(data, str) else ""
            finally:
                win32clipboard.CloseClipboard()
        except:
            return ""

    def _set_clipboard_text(self, text: str):
        """Set text to clipboard"""
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32con.CF_UNICODETEXT, text)
            win32clipboard.CloseClipboard()
        except:
            pass

    def _process_clipboard(self, content: str):
        """Process clipboard content"""
        if not self.auto_redact:
            return

        result = self.guard.redact(content, self.strategy)

        if result.has_sensitive_info:
            # Store mapping for restore
            self._pending_mapping.update(result.mapping)

            # Replace clipboard with redacted content
            self._set_clipboard_text(result.text)
            self._last_content = result.text

            # Notify callbacks
            for callback in self._callbacks:
                try:
                    callback(result)
                except:
                    pass

    def restore_clipboard(self):
        """Restore original content to clipboard"""
        if self._pending_mapping:
            current = self._get_clipboard_text()
            restored = self.guard.restore(current, self._pending_mapping)
            self._set_clipboard_text(restored)
            self._pending_mapping.clear()

    def get_mapping(self) -> dict[str, str]:
        """Get current placeholder -> original mapping"""
        return self._pending_mapping.copy()

    def clear_mapping(self):
        """Clear stored mappings"""
        self._pending_mapping.clear()
