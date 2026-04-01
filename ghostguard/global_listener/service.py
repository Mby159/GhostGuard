"""
Global privacy service - main entry point for system-wide privacy protection
"""

import sys
import signal
import threading
from typing import Callable

from ghostguard.core import GhostGuard
from ghostguard.types import RedactionStrategy
from ghostguard.global_listener.clipboard import ClipboardMonitor
from ghostguard.global_listener.keyboard import KeyboardListener


class GlobalPrivacyService:
    """
    System-wide privacy protection service.

    Monitors clipboard and keyboard to automatically redact/restore
    sensitive information anywhere in the system.

    Usage:
        service = GlobalPrivacyService()

        # Start with defaults
        service.start()

        # Or configure
        service.start(
            auto_redact=True,
            hotkeys=True,
            strategy=RedactionStrategy.MASK,
        )

        # Run until Ctrl+C
        service.wait()
    """

    def __init__(self, guard: GhostGuard | None = None):
        self.guard = guard or GhostGuard()
        self.clipboard = ClipboardMonitor(self.guard)
        self.keyboard = KeyboardListener()

        self._running = False
        self._auto_redact = True
        self._hotkeys_enabled = False

        # Event callbacks
        self._on_redact_callbacks: list[Callable] = []
        self._on_restore_callbacks: list[Callable] = []

        self._setup_default_hotkeys()

    def _setup_default_hotkeys(self):
        """Setup default hotkey bindings"""
        if not self.keyboard.available:
            return

        self.keyboard.register(
            "ctrl+shift+p", self._hotkey_redact, "Redact clipboard content"
        )
        self.keyboard.register(
            "ctrl+shift+r", self._hotkey_restore, "Restore last redacted content"
        )
        self.keyboard.register(
            "ctrl+shift+d", self._hotkey_toggle, "Toggle auto-redact mode"
        )

    def _hotkey_redact(self):
        """Hotkey: manually redact clipboard"""
        self.clipboard.restore_clipboard()  # Reset first
        content = self.clipboard._get_clipboard_text()
        if content:
            result = self.guard.redact(content)
            if result.has_sensitive_info:
                self.clipboard._set_clipboard_text(result.text)
                self.clipboard._pending_mapping = result.mapping
                self._notify_redact(result)

    def _hotkey_restore(self):
        """Hotkey: restore clipboard"""
        self.clipboard.restore_clipboard()
        self._notify_restore()

    def _hotkey_toggle(self):
        """Hotkey: toggle auto-redact"""
        self._auto_redact = not self._auto_redact
        self.clipboard.auto_redact = self._auto_redact
        status = "ON" if self._auto_redact else "OFF"
        print(f"Auto-redact: {status}")

    def on_redact(self, callback: Callable):
        """Register callback for redact events"""
        self._on_redact_callbacks.append(callback)
        self.clipboard.on_redact(callback)
        return callback

    def on_restore(self, callback: Callable):
        """Register callback for restore events"""
        self._on_restore_callbacks.append(callback)
        return callback

    def _notify_redact(self, result):
        for cb in self._on_redact_callbacks:
            try:
                cb(result)
            except:
                pass

    def _notify_restore(self):
        for cb in self._on_restore_callbacks:
            try:
                cb()
            except:
                pass

    def start(
        self,
        auto_redact: bool = True,
        hotkeys: bool = True,
        strategy: RedactionStrategy = RedactionStrategy.PLACEHOLDER,
    ):
        """
        Start the global privacy service.

        Args:
            auto_redact: Automatically redact clipboard content
            hotkeys: Enable hotkey listeners
            strategy: Redaction strategy to use
        """
        if self._running:
            return

        self._running = True
        self._auto_redact = auto_redact

        # Configure clipboard monitor
        self.clipboard.auto_redact = auto_redact
        self.clipboard.strategy = strategy

        # Start clipboard monitoring
        self.clipboard.start()
        print("[GhostGuard] Clipboard monitor started")

        # Start keyboard listener
        if hotkeys and self.keyboard.available:
            self._hotkeys_enabled = True
            self.keyboard.start()
            print("[GhostGuard] Hotkeys enabled:")
            for hk in self.keyboard.get_registered():
                print(f"  {hk['hotkey']}: {hk['description']}")
        elif hotkeys:
            print("[GhostGuard] Hotkeys disabled (keyboard module not installed)")

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        print(
            f"\n[GhostGuard] Service running (Auto-redact: {'ON' if auto_redact else 'OFF'})"
        )
        print("[GhostGuard] Press Ctrl+C to stop\n")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print("\n[GhostGuard] Shutting down...")
        self.stop()
        sys.exit(0)

    def stop(self):
        """Stop the service"""
        if not self._running:
            return

        self._running = False
        self.clipboard.stop()

        if self._hotkeys_enabled:
            self.keyboard.stop()

        print("[GhostGuard] Service stopped")

    def wait(self):
        """Block and wait until interrupted"""
        try:
            while self._running:
                threading.Event().wait(1)
        except KeyboardInterrupt:
            self.stop()

    def status(self) -> dict:
        """Get current service status"""
        return {
            "running": self._running,
            "auto_redact": self._auto_redact,
            "hotkeys_enabled": self._hotkeys_enabled,
            "pending_mappings": len(self.clipboard.get_mapping()),
            "detectors": self.guard.get_detector_names(),
        }
