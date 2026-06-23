# src/waterwall/tui/panes/counters.py
"""Counters pane — redactions/min, top types, latency p50/p99. Spec §13.2."""

from __future__ import annotations


def _bar(value: int, scale: int = 20, width: int = 20) -> str:
    """Horizontal bar: ▰ filled, ▱ empty. Caps at width."""
    filled = min(width, max(0, int(value / max(1, scale) * width)))
    return "▰" * filled + "▱" * (width - filled)


def render_counters(state: dict) -> str:
    c = state.get("counters_5m", {}) or {}
    rpm = c.get("redactions_per_min", 0)
    top = c.get("top_types", []) or []
    p50 = c.get("latency_p50_ms", 0)
    p99 = c.get("latency_p99_ms", 0)
    unknown = c.get("unknown_placeholders", 0)

    lines = [f"Redactions/min: {rpm:>4}  {_bar(rpm)}"]
    if top:
        lines.append("Top types:")
        max_count = max((t.get("count", 0) for t in top), default=1)
        for t in top[:5]:
            label = t.get("type", "—")
            count = t.get("count", 0)
            lines.append(f"  {label:<22} {count:>4}  {_bar(count, scale=max_count)}")
    else:
        lines.append("Top types:  —")
    lines.append(f"Latency p50: {p50:>4} ms")
    lines.append(f"Latency p99: {p99:>4} ms")
    lines.append(f"Unknown placeholders: {unknown}")
    return "\n".join(lines)
