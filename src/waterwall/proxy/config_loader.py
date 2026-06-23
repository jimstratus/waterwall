# src/waterwall/proxy/config_loader.py
"""Config hot-reload watcher. Spec §11.3.

Watches /etc/waterwall/config.yaml (or any supplied path) and calls
``killswitch.set_config_flag(bool)`` when the ``kill_switch:`` key changes.

All other kill-switch sources (sigusr1, sentinel, http) are unaffected because
this loader only calls set_config_flag — the single mutation point for the
config source.

Platform strategy mirrors pattern_loader:
  Linux   — inotify_simple
  Windows — watchdog Observer
"""

from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path

import yaml

from waterwall.proxy.killswitch import KillSwitch

_log = logging.getLogger("waterwall.config_loader")


class ConfigLoader:
    """Hot-reload watcher for config.yaml.

    Public API:
        start()  — begin watching (spawns daemon thread)
        stop()   — clean shutdown (joins thread)
    """

    def __init__(self, path: Path, killswitch: KillSwitch) -> None:
        self._path = Path(path)
        self._ks = killswitch
        self._stop_event = threading.Event()
        self._ready_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the file-watch thread. Performs an initial load so the
        kill-switch reflects the file's current state before any subsequent
        change events. Blocks until the watcher is registered."""
        self._stop_event.clear()
        self._ready_event.clear()
        self._try_reload()  # initial sync — apply current file state
        if sys.platform == "linux":
            self._thread = threading.Thread(
                target=self._run_inotify, daemon=True, name="config-loader-inotify"
            )
        else:
            self._thread = threading.Thread(
                target=self._run_watchdog, daemon=True, name="config-loader-watchdog"
            )
        self._thread.start()
        self._ready_event.wait(timeout=2.0)

    def stop(self) -> None:
        """Signal the watch thread to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    # ------------------------------------------------------------------
    # Internal: file parsing
    # ------------------------------------------------------------------

    def _try_reload(self) -> None:
        """Attempt to reload config.yaml; leave kill-switch state intact on failure."""
        try:
            raw = self._path.read_text(encoding="utf-8")
            doc = yaml.safe_load(raw)
            if not isinstance(doc, dict):
                raise ValueError(f"config.yaml top-level must be a mapping, got {type(doc).__name__}")
            flag = bool(doc.get("kill_switch", False))
            self._ks.set_config_flag(flag)
        except Exception as exc:
            # Do NOT re-raise into the watcher loop — leave kill-switch state intact.
            _log.warning("reload refused: %s", exc)

    # ------------------------------------------------------------------
    # Internal: platform watchers
    # ------------------------------------------------------------------

    def _run_inotify(self) -> None:
        """Linux watcher using inotify_simple."""
        import inotify_simple  # type: ignore[import]

        inotify = inotify_simple.INotify()
        flags = (
            inotify_simple.flags.MODIFY
            | inotify_simple.flags.CLOSE_WRITE
            | inotify_simple.flags.MOVED_TO
        )
        # Watch parent directory to catch atomic-replace editors (write-rename)
        watch_dir = self._path.parent
        inotify.add_watch(str(watch_dir), flags)
        self._ready_event.set()

        target_name = self._path.name

        while not self._stop_event.is_set():
            try:
                events = inotify.read(timeout=200)
            except Exception:
                break
            for event in events:
                if event.name == target_name or not event.name:
                    self._try_reload()

        try:
            inotify.close()
        except Exception:
            pass

    def _run_watchdog(self) -> None:
        """Windows watcher using watchdog (hard dep on win32 per pyproject.toml)."""
        from watchdog.observers import Observer  # type: ignore[import]
        from watchdog.events import FileSystemEventHandler  # type: ignore[import]

        loader = self

        class _Handler(FileSystemEventHandler):
            def on_modified(self, event):  # type: ignore[override]
                if not event.is_directory and Path(event.src_path).name == loader._path.name:
                    loader._try_reload()

        observer = Observer()
        observer.schedule(_Handler(), str(self._path.parent), recursive=False)
        observer.start()
        self._ready_event.set()

        self._stop_event.wait()

        observer.stop()
        observer.join(timeout=2.0)
