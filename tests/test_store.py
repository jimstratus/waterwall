# tests/test_store.py
"""LRU placeholder store with capacity, TTL, thread-safety."""

import time
import threading
from waterwall.proxy.store import PlaceholderStore


def test_store_round_trip():
    s = PlaceholderStore(capacity=10, ttl_seconds=60)
    s.put("hmac8aaa", "secret-value-1")
    assert s.get("hmac8aaa") == "secret-value-1"


def test_store_get_missing_returns_none():
    s = PlaceholderStore(capacity=10, ttl_seconds=60)
    assert s.get("nosuch") is None


def test_store_lru_evicts_oldest():
    s = PlaceholderStore(capacity=3, ttl_seconds=60)
    s.put("a", "A")
    s.put("b", "B")
    s.put("c", "C")
    s.put("d", "D")  # forces eviction of "a"
    assert s.get("a") is None
    assert s.get("b") == "B"
    assert s.get("c") == "C"
    assert s.get("d") == "D"


def test_store_get_refreshes_lru_position():
    s = PlaceholderStore(capacity=3, ttl_seconds=60)
    s.put("a", "A")
    s.put("b", "B")
    s.put("c", "C")
    # touch "a" so it becomes most-recent
    assert s.get("a") == "A"
    s.put("d", "D")  # should evict "b" (now LRU), not "a"
    assert s.get("a") == "A"
    assert s.get("b") is None
    assert s.get("c") == "C"
    assert s.get("d") == "D"


def test_store_ttl_expires_entries():
    s = PlaceholderStore(capacity=10, ttl_seconds=0.05)
    s.put("a", "A")
    time.sleep(0.1)
    assert s.get("a") is None


def test_store_size_reports_live_entries():
    s = PlaceholderStore(capacity=10, ttl_seconds=60)
    assert s.size() == 0
    s.put("a", "A")
    s.put("b", "B")
    assert s.size() == 2


def test_store_thread_safe_under_concurrent_writers():
    s = PlaceholderStore(capacity=1000, ttl_seconds=60)

    def worker(start: int):
        for i in range(100):
            key = f"k{start}-{i}"
            s.put(key, f"v{start}-{i}")
            assert s.get(key) == f"v{start}-{i}"

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert s.size() == 1000


def test_store_ttl_evicts_lru_touched_old_entries():
    """Regression: TTL must not be fooled by LRU-touched entries whose
    insertion timestamp is older than entries near the front (Wave-1 review)."""
    s = PlaceholderStore(capacity=100, ttl_seconds=0.05)
    s.put("a", "A")           # ts ~= 0
    time.sleep(0.02)
    s.put("b", "B")           # ts ~= 0.02
    time.sleep(0.02)
    assert s.get("a") == "A"  # touches A → moves to end; ts still ~0
    time.sleep(0.04)          # now ~0.08s; A's ts(~0) age > ttl(0.05)
    assert s.get("a") is None # must be evicted despite being LRU-end
    assert s.get("b") is None # also expired
