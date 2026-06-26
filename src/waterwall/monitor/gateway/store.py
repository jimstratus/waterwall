"""Gateway fleet state — SQLite latest-report-per-host. Spec §3.4."""
from __future__ import annotations

import sqlite3
import threading

_COLS = ("host", "canary", "health", "version", "ts")

# Module-level re-entrant lock: the gateway's async ingest handler and the
# background dead-man's-switch sweeper share one connection (check_same_thread
# =False). This serializes access so a concurrent read/commit from the two
# threads can't interleave. RLock because record_report() calls get_state()
# (argus #store). sqlite3.Connection can't hold custom attributes, so the lock
# lives here rather than on the connection.
_LOCK = threading.RLock()


def open_store(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS reports("
        "host TEXT PRIMARY KEY, canary TEXT, health TEXT, version TEXT, ts REAL)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS stale_alerted(host TEXT PRIMARY KEY)")
    conn.commit()
    return conn


def get_stale_alerted(conn: sqlite3.Connection) -> set[str]:
    """Return the set of hosts currently in the alerted-stale state (persisted)."""
    with _LOCK:
        return {row[0] for row in conn.execute("SELECT host FROM stale_alerted")}


def set_stale_alerted(conn: sqlite3.Connection, hosts: set[str]) -> None:
    """Replace the entire persisted stale-alerted set atomically."""
    with _LOCK:
        conn.execute("DELETE FROM stale_alerted")
        conn.executemany("INSERT INTO stale_alerted(host) VALUES(?)", ((h,) for h in hosts))
        conn.commit()


def get_state(conn: sqlite3.Connection, host: str) -> dict | None:
    with _LOCK:
        row = conn.execute("SELECT * FROM reports WHERE host=?", (host,)).fetchone()
        return dict(row) if row else None


def record_report(conn: sqlite3.Connection, report: dict) -> dict | None:
    """Upsert the report; return the host's PREVIOUS state (or None if first sighting)
    so the caller can run transition detection."""
    with _LOCK:
        prev = get_state(conn, report["host"])
        conn.execute(
            "INSERT INTO reports(host,canary,health,version,ts) VALUES(?,?,?,?,?) "
            "ON CONFLICT(host) DO UPDATE SET canary=excluded.canary, health=excluded.health, "
            "version=excluded.version, ts=excluded.ts",
            tuple(report[c] for c in _COLS))
        conn.commit()
        return prev


def get_fleet(conn: sqlite3.Connection) -> list[dict]:
    with _LOCK:
        return [dict(r) for r in conn.execute("SELECT * FROM reports ORDER BY host")]
