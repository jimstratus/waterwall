# src/waterwall/proxy/pattern_loader.py
"""Pattern hot-reload watcher. Spec §11.3.

Watches a Python file containing a top-level ``PATTERNS = [(label, regex), ...]``
assignment and atomically swaps the compiled pattern set on successful re-parse.

Platform strategy:
  Linux   — inotify_simple (kernel-level notification, fast)
  Windows — watchdog Observer (filesystem events)

The module is importable on both platforms; the platform-specific watcher is
instantiated lazily inside start() so the import itself never fails.
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import re
import sys
import threading
from collections.abc import Callable
from pathlib import Path

_log = logging.getLogger("waterwall.pattern_loader")


class PatternLoader:
    """Hot-reload watcher for a PATTERNS file.

    Public API:
        start()        — begin watching (spawns daemon thread)
        stop()         — clean shutdown (joins thread)
        policy_hash()  — SHA-256 hex of current compiled pattern set
    """

    def __init__(
        self,
        path: Path,
        on_reload: Callable[[], None] | None = None,
    ) -> None:
        self._path = Path(path)
        self._on_reload = on_reload
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._ready_event = threading.Event()
        self._thread: threading.Thread | None = None

        # Load initial state synchronously so policy_hash() is valid before start()
        patterns, phash = self._load_file()
        self._patterns: list[tuple[str, re.Pattern[str]]] = patterns
        self._hash: str = phash

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the file-watch thread. Blocks until the watcher is registered
        so subsequent file modifications are guaranteed to be observed."""
        self._stop_event.clear()
        self._ready_event.clear()
        if sys.platform == "linux":
            self._thread = threading.Thread(
                target=self._run_inotify, daemon=True, name="pattern-loader-inotify"
            )
        else:
            self._thread = threading.Thread(
                target=self._run_watchdog, daemon=True, name="pattern-loader-watchdog"
            )
        self._thread.start()
        self._ready_event.wait(timeout=2.0)

    def stop(self) -> None:
        """Signal the watch thread to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def policy_hash(self) -> str:
        """SHA-256 hex of the canonical-JSON of the current pattern set."""
        with self._lock:
            return self._hash

    def compiled(self) -> list[tuple[str, re.Pattern[str]]]:
        """Snapshot of the currently loaded compiled extension patterns."""
        with self._lock:
            return list(self._patterns)

    # ------------------------------------------------------------------
    # Internal: file parsing
    # ------------------------------------------------------------------

    def _load_file(self) -> tuple[list[tuple[str, re.Pattern[str]]], str]:
        """Parse the watched file and return (compiled_patterns, hash).

        Raises ValueError on any parse/compile error.
        """
        source = self._path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(self._path))
        except SyntaxError as exc:
            raise ValueError(f"SyntaxError in patterns file: {exc}") from exc

        raw: list | None = None
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "PATTERNS"
            ):
                raw = ast.literal_eval(node.value)
                break

        if raw is None:
            raise ValueError("No top-level PATTERNS assignment found")
        if not isinstance(raw, list):
            raise ValueError("PATTERNS must be a list")
        for item in raw:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not isinstance(item[1], str)
            ):
                raise ValueError(f"Each PATTERNS entry must be (str, str), got {item!r}")

        # Compile regexes — raises re.error on bad pattern
        compiled: list[tuple[str, re.Pattern[str]]] = [
            (label, re.compile(pattern)) for label, pattern in raw
        ]

        # Compute canonical hash: [(label, pattern, flags), ...]
        payload = [(label, p.pattern, p.flags) for label, p in compiled]
        phash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

        return compiled, phash

    def _try_reload(self) -> bool:
        """Attempt to reload the file; leave state intact and return False on failure."""
        try:
            patterns, phash = self._load_file()
        except Exception as exc:
            # Do NOT re-raise into the watcher loop — leave existing state intact.
            _log.warning("reload refused: %s", exc)
            return False
        with self._lock:
            self._patterns = patterns
            self._hash = phash
        if self._on_reload is not None:
            try:
                self._on_reload()
            except Exception as exc:
                _log.warning("on_reload callback raised: %s", exc)
        return True

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
                # event.name is the filename within the watched directory
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

        self._stop_event.wait()  # block until stop() is called

        observer.stop()
        observer.join(timeout=2.0)
