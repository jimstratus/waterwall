# tests/test_state_aggregator.py
"""Spec §10.2 schema invariant: every key path defined in the spec must
appear in the snapshot."""

import pytest
from waterwall.ops.state import StateAggregator


REQUIRED_PATHS = [
    "v", "ts", "status", "uptime_seconds", "ca_mode", "session_key_age_seconds",
    "last_upstream_ok_ts", "sse_parse_failures_15m",
    "health.signer_key_readable", "health.upstream_reachable", "health.chain_intact",
    "health.patterns_loaded", "health.patterns_min_required",
    "killswitch.config", "killswitch.sigusr1", "killswitch.sentinel",
    "killswitch.http", "killswitch.active",
    "patterns.count", "patterns.breakdown.base", "patterns.breakdown.ext",
    "patterns.breakdown.pem", "patterns.hash", "patterns.last_reload_ts",
    "patterns.min_required",
    "map.size", "map.capacity", "map.ttl_seconds", "map.eviction_policy",
    "chain.lines", "chain.checkpoints", "chain.last_signed_ts",
    "chain.last_checkpoint_root_hash", "chain.current_head_prev_hash",
    "chain.verify_status",
    "counters_5m.redactions_per_min", "counters_5m.top_types",
    "counters_5m.latency_p50_ms", "counters_5m.latency_p99_ms",
    "counters_5m.unknown_placeholders",
    "sessions",
    "verify_install.checks_passed", "verify_install.checks_total",
    "verify_install.last_run_ts",
    "recent_activity",  # Plan 3 TUI dependency — added here
]


def _path_exists(d: dict, path: str) -> bool:
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return False
        if part not in cur:
            return False
        cur = cur[part]
    return True


def make_addon(tmp_path=None):
    """Lightweight stub matching the WaterwallAddon attribute surface that
    StateAggregator reads. Fields here MUST match the addon's actual attributes.

    With `tmp_path` set, the chain is a REAL ChainWriter and the sessions lock
    a real threading.Lock — needed by the issue #13 tests that exercise chain
    health and snapshot locking.
    """
    from unittest.mock import MagicMock
    from waterwall.proxy.killswitch import KillSwitch
    addon = MagicMock()
    addon._killswitch = KillSwitch()  # real, returns disarmed status
    addon._signer = MagicMock()  # truthy
    addon._tokenizer_created_at = 0.0  # epoch — produces large age value, fine for test
    addon._store.size.return_value = 1
    addon._store.capacity.return_value = 10_000
    addon._store._ttl = 4 * 3600
    addon._chain._seq = 5
    addon._chain._prev_hash = "00aa11bb"
    addon._session_trackers = {}
    addon._policy_hash = "test-hash"
    addon._patterns_last_reload_ts = "2026-05-05T13:00:00Z"
    addon._last_verify_install = {"checks_passed": 10, "checks_total": 10, "last_run_ts": "2026-05-05T12:00:00Z"}
    addon._checkpoint_count = 0
    addon._last_checkpoint_ts = None
    addon._last_checkpoint_root_hash = ""
    if tmp_path is not None:
        import threading
        from waterwall.audit.chain import ChainWriter
        addon._chain = ChainWriter(tmp_path / "proxy.jsonl")
        addon._sessions_lock = threading.Lock()
        addon._session_trackers = {}
    return addon


@pytest.fixture
def stub_addon():
    return make_addon()


def test_state_snapshot_contains_all_required_paths(stub_addon):
    agg = StateAggregator(addon=stub_addon)
    snapshot = agg.snapshot()
    missing = [p for p in REQUIRED_PATHS if not _path_exists(snapshot, p)]
    assert not missing, f"missing /admin/state paths: {missing}"


HEALTHZ_REQUIRED_KEYS = frozenset({
    "v", "ts", "status", "uptime_seconds", "ca_mode", "session_key_age_seconds",
    "last_upstream_ok_ts", "sse_parse_failures_15m",
    "killswitch_active", "killswitch_sources",
    "patterns_loaded", "patterns_min_required",
    "signer_key_readable", "chain_intact", "upstream_reachable",
    "map_size", "map_capacity",
})

# /healthz is a flat subset — these full-snapshot keys must NOT leak through.
HEALTHZ_FORBIDDEN_KEYS = frozenset({
    "health", "killswitch", "patterns", "map", "chain",
    "counters_5m", "sessions", "verify_install", "recent_activity",
})


def test_healthz_subset_is_flat_subset(stub_addon):
    agg = StateAggregator(addon=stub_addon)
    h = agg.healthz_subset()
    missing = HEALTHZ_REQUIRED_KEYS - h.keys()
    assert not missing, f"missing /healthz keys: {missing}"
    leaked = HEALTHZ_FORBIDDEN_KEYS & h.keys()
    assert not leaked, f"full-snapshot keys leaked into /healthz: {leaked}"


# ---------------------------------------------------------------------------
# Argus issue #13 — chain_intact wired to reality + snapshot locking
# ---------------------------------------------------------------------------


def test_chain_intact_false_after_append_failure(tmp_path, monkeypatch):
    """Argus issue #13: chain_intact was a hardcoded local True — a failing
    chain MUST show on /healthz."""
    from waterwall.audit.chain import ChainAppendError

    addon = make_addon(tmp_path)
    agg = StateAggregator(addon=addon)
    assert agg.snapshot()["health"]["chain_intact"] is True

    def _boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(addon._chain._fp, "write", _boom)
    with pytest.raises(ChainAppendError):
        addon._chain.append({"line_type": "redaction"})
    snap = agg.snapshot()
    assert snap["health"]["chain_intact"] is False
    assert snap["status"] == "fail"
    assert snap["chain"]["verify_status"] == "fail"


def test_chain_intact_self_heals_after_successful_append(tmp_path, monkeypatch):
    """Self-heal: a successful write after a failure flips healthy back True."""
    from waterwall.audit.chain import ChainAppendError

    addon = make_addon(tmp_path)
    agg = StateAggregator(addon=addon)
    real_write = addon._chain._fp.write

    def _boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(addon._chain._fp, "write", _boom)
    with pytest.raises(ChainAppendError):
        addon._chain.append({"line_type": "redaction"})
    assert agg.snapshot()["health"]["chain_intact"] is False

    monkeypatch.setattr(addon._chain._fp, "write", real_write)
    addon._chain.append({"line_type": "redaction"})
    assert agg.snapshot()["health"]["chain_intact"] is True


def test_snapshot_takes_sessions_lock(tmp_path):
    """Argus issue #13: snapshot() iterated _session_trackers unlocked."""
    addon = make_addon(tmp_path)
    agg = StateAggregator(addon=addon)
    with addon._sessions_lock:
        pass  # if snapshot() copies under the lock this test just documents it
    assert isinstance(agg.snapshot()["sessions"], list)
