# src/waterwall/ops/state.py
"""Single source of truth for /admin/state and /healthz responses.

Spec §10.1 + §10.2.
"""

from __future__ import annotations

import os
import socket
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

from waterwall.proxy.patterns import (
    REQUIRED_BASE_LABELS,
    loaded_labels,
    pattern_breakdown,
    pattern_count,
)


def _probe_listener(port: int | None = None, timeout: float = 0.25) -> bool:
    """TCP-connect probe of the mitmproxy listener (argus issue #13 — the
    previous hardcoded True conflated 'admin thread alive' with 'proxy bound')."""
    port = port or int(os.environ.get("WATERWALL_PORT", "8888"))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


class StateAggregator:
    def __init__(self, addon: Any, max_activity: int = 50) -> None:
        self._addon = addon
        self._started_at = time.monotonic()
        self._recent_activity: deque[dict] = deque(maxlen=max_activity)
        self._upstream_ok_ts: str | None = None
        self._sse_parse_failures: deque[float] = deque(maxlen=200)

    def record_activity(self, event: dict) -> None:
        self._recent_activity.append(event)

    def record_upstream_ok(self) -> None:
        self._upstream_ok_ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    def snapshot(self) -> dict:
        now = time.monotonic()
        ks_status = (
            self._addon._killswitch.status()
            if self._addon._killswitch
            else {
                "config": False,
                "sigusr1": False,
                "sentinel": False,
                "http": False,
                "active": False,
            }
        )

        loaded = loaded_labels()
        # Argus issue #13: was a hardcoded local True — a failing chain never
        # showed. ChainWriter.healthy flips False on append/checkpoint OSError.
        chain_intact = bool(getattr(self._addon._chain, "healthy", True))

        return {
            "v": 1,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "status": "ok" if all((
                self._addon._signer is not None,
                len(loaded) >= 16,
                chain_intact,
            )) else "fail",
            "uptime_seconds": int(now - self._started_at),
            # Argus issue #13: was a hardcoded literal — reflect deployment truth.
            "ca_mode": os.environ.get("WATERWALL_CA_MODE", "NODE_EXTRA_CA_CERTS"),
            "session_key_age_seconds": int(now - self._addon._tokenizer_created_at),
            "last_upstream_ok_ts": self._upstream_ok_ts,
            "sse_parse_failures_15m": sum(
                1 for t in self._sse_parse_failures if t > now - 900
            ),
            "health": {
                "signer_key_readable": self._addon._signer is not None,
                "upstream_reachable": self._upstream_ok_ts is not None,
                "chain_intact": chain_intact,
                "patterns_loaded": pattern_count(),
                "patterns_min_required": len(REQUIRED_BASE_LABELS),
            },
            "killswitch": ks_status,
            "patterns": {
                "count": pattern_count(),
                "breakdown": pattern_breakdown(),
                "hash": self._addon._policy_hash,
                "last_reload_ts": getattr(self._addon, "_patterns_last_reload_ts", None),
                "min_required": len(REQUIRED_BASE_LABELS),
            },
            "map": {
                "size": self._addon._store.size(),
                "capacity": self._addon._store.capacity(),
                "ttl_seconds": int(self._addon._store._ttl),
                "eviction_policy": "lru",
            },
            "chain": {
                "lines": self._addon._chain._seq,
                "checkpoints": getattr(self._addon, "_checkpoint_count", 0),
                "last_signed_ts": getattr(self._addon, "_last_checkpoint_ts", None),
                "last_checkpoint_root_hash": getattr(
                    self._addon, "_last_checkpoint_root_hash", ""
                ),
                "current_head_prev_hash": self._addon._chain._prev_hash,
                "verify_status": "ok" if chain_intact else "fail",
            },
            "counters_5m": {
                "redactions_per_min": 0,  # filled by per-event aggregation
                "top_types": [],
                "latency_p50_ms": 0,
                "latency_p99_ms": 0,
                "unknown_placeholders": 0,
            },
            "sessions": self._sessions_snapshot(),
            "verify_install": getattr(
                self._addon,
                "_last_verify_install",
                {"checks_passed": 0, "checks_total": 10, "last_run_ts": None},
            ),
            "recent_activity": list(self._recent_activity),
            # Runtime probes — read by verify-install --runtime mode (spec §11.4
            # checks 5 + 6). Listener bound = real TCP-connect probe (argus
            # issue #13: the previous hardcoded True conflated "admin thread
            # alive" with "proxy bound"). Admin loopback is bound iff the addon
            # spawned an _admin_thread.
            "_runtime_listener_bound": _probe_listener(),
            "_runtime_admin_bound_loopback": (
                getattr(self._addon, "_admin_thread", None) is not None
                and self._addon._admin_thread.is_alive()
            ),
        }

    def _sessions_snapshot(self) -> list[dict]:
        """Copy trackers under the addon's lock (argus issue #13: snapshot()
        iterated _session_trackers unlocked, racing the proxy thread)."""
        with self._addon._sessions_lock:
            items = list(self._addon._session_trackers.items())
        return [
            {
                "session_id": sid,
                "redactions": t.redaction_total,
                "started_ts": t.started_at.isoformat(timespec="milliseconds"),
            }
            for sid, t in items
        ]

    def healthz_subset(self) -> dict:
        full = self.snapshot()
        return {
            "v": full["v"],
            "ts": full["ts"],
            "status": full["status"],
            "uptime_seconds": full["uptime_seconds"],
            "ca_mode": full["ca_mode"],
            "session_key_age_seconds": full["session_key_age_seconds"],
            "last_upstream_ok_ts": full["last_upstream_ok_ts"],
            "sse_parse_failures_15m": full["sse_parse_failures_15m"],
            "killswitch_active": full["killswitch"]["active"],
            "killswitch_sources": [
                k for k, v in full["killswitch"].items() if v and k != "active"
            ],
            "patterns_loaded": full["health"]["patterns_loaded"],
            "patterns_min_required": full["health"]["patterns_min_required"],
            "signer_key_readable": full["health"]["signer_key_readable"],
            "chain_intact": full["health"]["chain_intact"],
            "upstream_reachable": full["health"]["upstream_reachable"],
            "map_size": full["map"]["size"],
            "map_capacity": full["map"]["capacity"],
        }
