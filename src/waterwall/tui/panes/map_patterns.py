# src/waterwall/tui/panes/map_patterns.py
"""Map + patterns pane — store size, pattern breakdown, policy hash. Spec §13.2."""

from __future__ import annotations


def _short_hash(h: str | None) -> str:
    if not h:
        return "—"
    return h[:8] if len(h) > 8 else h


def _time_only(ts: str | None) -> str:
    """Extract HH:MM:SS from an ISO 8601 timestamp."""
    if not ts:
        return "—"
    if "T" in ts:
        return ts.split("T", 1)[1].split(".", 1)[0].split("+", 1)[0].split("Z", 1)[0]
    return ts


def render_map_patterns(state: dict) -> str:
    m = state.get("map", {}) or {}
    p = state.get("patterns", {}) or {}
    bd = p.get("breakdown", {}) or {}

    size = m.get("size")
    cap = m.get("capacity")
    ttl = m.get("ttl_seconds")
    count = p.get("count")
    base = bd.get("base")
    ext = bd.get("ext")
    pem = bd.get("pem")
    phash = p.get("hash")
    last_reload = p.get("last_reload_ts")

    if size is None or cap is None:
        size_line = "Map size:    —"
    else:
        pct = (size / cap * 100) if cap else 0
        size_line = f"Map size:    {size} / {cap}  ({pct:.1f}%)"

    ttl_line = f"TTL:         {ttl // 3600} h" if ttl else "TTL:         —"

    if count is not None and base is not None and ext is not None and pem is not None:
        patterns_line = f"Patterns:    {base} base + {ext} ext + {pem} PEM = {count} total"
    else:
        patterns_line = "Patterns:    —"

    hash_line = f"Policy hash: {_short_hash(phash)}..."
    reload_line = f"Last reload: {_time_only(last_reload)}"

    return "\n".join([size_line, ttl_line, patterns_line, hash_line, reload_line])
