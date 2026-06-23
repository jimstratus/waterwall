# src/waterwall/proxy/store.py
"""LRU placeholder store with optional TTL. Thread-safe.

Spec §7 mapping store.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict


class PlaceholderStore:
    def __init__(self, capacity: int = 10_000, ttl_seconds: float = 4 * 3600.0) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._capacity = capacity
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        # OrderedDict: oldest-first; move_to_end() refreshes LRU position
        self._data: OrderedDict[str, tuple[str, float]] = OrderedDict()

    def put(self, hmac8: str, plaintext: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._evict_expired(now)
            if hmac8 in self._data:
                self._data.move_to_end(hmac8)
            self._data[hmac8] = (plaintext, now)
            self._data.move_to_end(hmac8)
            while len(self._data) > self._capacity:
                self._data.popitem(last=False)

    def get(self, hmac8: str) -> str | None:
        now = time.monotonic()
        with self._lock:
            self._evict_expired(now)
            entry = self._data.get(hmac8)
            if entry is None:
                return None
            self._data.move_to_end(hmac8)
            return entry[0]

    def size(self) -> int:
        with self._lock:
            self._evict_expired(time.monotonic())
            return len(self._data)

    def capacity(self) -> int:
        return self._capacity

    def _evict_expired(self, now: float) -> None:
        if self._ttl <= 0:
            return
        cutoff = now - self._ttl
        # Scan ALL entries: timestamps are insertion-time and never refresh on get(),
        # so an LRU-touched entry can sit anywhere in the OrderedDict. Cannot
        # break early on first non-expired since LRU order != timestamp order.
        expired = [k for k, (_, ts) in self._data.items() if ts < cutoff]
        for k in expired:
            del self._data[k]
