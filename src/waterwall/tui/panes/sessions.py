# src/waterwall/tui/panes/sessions.py
"""Sessions pane — active sessions table with computed uptime. Spec §13.2."""

from __future__ import annotations

from datetime import datetime


def _parse_iso(ts: str) -> datetime | None:
    if not ts:
        return None
    cleaned = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def _uptime_str(now: datetime, started: datetime) -> str:
    delta = now - started
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    rem_min = minutes - hours * 60
    if rem_min:
        return f"{hours}h {rem_min}m"
    return f"{hours}h"


def _short_sid(sid: str) -> str:
    """Truncate UUID-style session IDs to a readable prefix; full IDs go in
    the chain log if anyone needs to correlate. Spec §13.2 prioritizes
    readability over completeness in the live pane."""
    if not sid:
        return "—"
    return sid[:8] if len(sid) > 8 else sid


def render_sessions(state: dict) -> str:
    sessions = state.get("sessions") or []
    if not sessions:
        return "—  no active sessions"
    now = _parse_iso(state.get("ts", ""))
    lines = [f"{'Session':<10}  {'Redactions':>10}  Uptime"]
    for s in sessions:
        sid = _short_sid(s.get("session_id", "—"))
        redactions = s.get("redactions", 0)
        started = _parse_iso(s.get("started_ts", ""))
        if now and started:
            uptime = _uptime_str(now, started)
        else:
            uptime = "—"
        lines.append(f"{sid:<10}  {redactions:>10}  {uptime}")
    return "\n".join(lines)
