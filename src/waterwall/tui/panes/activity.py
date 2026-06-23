# src/waterwall/tui/panes/activity.py
"""Live activity pane — last N redaction/detokenization events. Spec §13.2."""

from __future__ import annotations


def render_activity(state: dict, max_lines: int = 10) -> str:
    activity = state.get("recent_activity")
    if not activity:
        return "—  no activity yet"
    out_lines = []
    for evt in activity[-max_lines:]:
        ts = evt.get("ts", "—")
        direction = evt.get("direction", "?").upper()
        req = evt.get("request_id", "—")
        if direction == "OUT":
            count = evt.get("redactions", 0)
            types = " ".join(evt.get("types", []))
            out_lines.append(f"{ts}  OUT  {req}  {count} redacts  {types}")
        elif direction == "IN":
            count = evt.get("detok_count", 0)
            out_lines.append(f"{ts}  IN   {req}  {count} detok")
        else:
            out_lines.append(f"{ts}  {direction}  {req}")
    return "\n".join(out_lines)
