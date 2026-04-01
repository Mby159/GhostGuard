"""
Keyboard listener - hotkey triggers for privacy actions
"""

import threading
from typing import Callable

try:
    import keyboard

    HAS_KEYBOARD = True
except ImportError:
    HAS_KEYBOARD = False


class KeyboardListener:
    """
    Listen for hotkeys to trigger privacy actions.

    Default hotkeys:
        - Ctrl+Shift+P: Redact current selection/clipboard
        - Ctrl+Shift+R: Restore last redacted content
        - Ctrl+Shift+D: Toggle auto-redact mode
    """

    def __init__(self):
        self._callbacks: dict[str, Callable] = {}
        self._registered_hotkeys: list[str] = []
        self._running = False

    @property
    def available(self) -> bool:
        """Check if keyboard module is available"""
        return HAS_KEYBOARD

    def register(self, hotkey: str, callback: Callable, description: str = ""):
        """Register a hotkey callback"""
        self._callbacks[hotkey] = {
            "callback": callback,
            "description": description,
        }

    def start(self):
        """Start listening for hotkeys"""
        if not HAS_KEYBOARD:
            raise RuntimeError(
                "keyboard module not installed. Run: pip install keyboard"
            )

        if self._running:
            return

        self._running = True

        for hotkey, info in self._callbacks.items():
            try:
                keyboard.add_hotkey(hotkey, info["callback"])
                self._registered_hotkeys.append(hotkey)
            except Exception as e:
                print(f"Failed to register hotkey {hotkey}: {e}")

    def stop(self):
        """Stop listening"""
        if not self._running:
            return

        self._running = False
        keyboard.unhook_all()
        self._registered_hotkeys.clear()

    def get_registered(self) -> list[dict]:
        """Get list of registered hotkeys"""
        return [
            {"hotkey": k, "description": v.get("description", "")}
            for k, v in self._callbacks.items()
        ]

    def wait(self):
        """Block and wait for hotkeys (for CLI usage)"""
        if not HAS_KEYBOARD:
            raise RuntimeError("keyboard module not installed")

        print("Listening for hotkeys... (Ctrl+C to exit)")
        try:
            keyboard.wait()
        except KeyboardInterrupt:
            self.stop()
