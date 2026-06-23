# src/waterwall/audit/idle_watcher.py
"""Tracks per-session last-seen timestamps; fires a callback when idle."""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

_log = logging.getLogger("waterwall.idle")


class IdleWatcher:
    def __init__(self, idle_timeout_seconds: float, on_idle: Callable[[str], None]) -> None:
        self._timeout = idle_timeout_seconds
        self._on_idle = on_idle
        self._last_seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def touch(self, session_id: str) -> None:
        with self._lock:
            self._last_seen[session_id] = time.monotonic()

    def tick(self) -> None:
        """Called periodically (e.g., by a 60s background thread or admin poll)."""
        now = time.monotonic()
        cutoff = now - self._timeout
        expired: list[str] = []
        with self._lock:
            for sid, ts in list(self._last_seen.items()):
                if ts < cutoff:
                    expired.append(sid)
                    del self._last_seen[sid]
        # Argus issue #17: isolate each callback — sids are already removed
        # from tracking above, so a raising callback must not abort the loop
        # and starve every remaining session of its manifest.
        for sid in expired:
            try:
                self._on_idle(sid)
            except Exception:
                _log.warning("on_idle callback failed for %s", sid, exc_info=True)
