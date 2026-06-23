# src/waterwall/proxy/killswitch.py
"""Four-source OR-composed kill switch. Spec §11.1, §11.2."""

from __future__ import annotations

import os
import signal
import threading
from pathlib import Path


class KillSwitch:
    def __init__(self, sentinel_path: Path = Path("/run/waterwall/kill")) -> None:
        self._sentinel_path = sentinel_path
        self._lock = threading.Lock()
        self._config_flag = False
        self._sigusr1_latch = False
        self._http_armed = False
        self._http_reason: str = ""

    def set_config_flag(self, value: bool) -> None:
        with self._lock:
            self._config_flag = bool(value)

    def install_sigusr1_handler(self) -> None:
        if os.name != "posix":
            return
        signal.signal(signal.SIGUSR1, self._toggle_sigusr1)

    def _toggle_sigusr1(self, _signum, _frame) -> None:
        # NO lock here: signal handlers run on the main thread, which holds
        # self._lock inside active_sources() on every request — taking it
        # again deadlocks the proxy (argus issue #15). A bool flip is atomic
        # under the GIL.
        self._sigusr1_latch = not self._sigusr1_latch

    def arm_http(self, reason: str = "") -> None:
        with self._lock:
            self._http_armed = True
            self._http_reason = reason

    def disarm_http(self) -> None:
        with self._lock:
            self._http_armed = False
            self._http_reason = ""

    def _sentinel_present(self) -> bool:
        try:
            return self._sentinel_path.exists()
        except OSError:
            return False

    def active_sources(self) -> list[str]:
        with self._lock:
            sources = []
            if self._config_flag:
                sources.append("config")
            if self._sigusr1_latch:
                sources.append("sigusr1")
            if self._sentinel_present():
                sources.append("sentinel")
            if self._http_armed:
                sources.append("http")
            return sources

    def is_active(self) -> bool:
        return bool(self.active_sources())

    def status(self) -> dict:
        with self._lock:
            sources = []
            if self._config_flag:
                sources.append("config")
            if self._sigusr1_latch:
                sources.append("sigusr1")
            if self._sentinel_present():
                sources.append("sentinel")
            if self._http_armed:
                sources.append("http")
            return {
                "config": self._config_flag,
                "sigusr1": self._sigusr1_latch,
                "sentinel": self._sentinel_present(),
                "http": self._http_armed,
                "active": bool(sources),
            }
