# src/waterwall/tui/panes/killswitch.py
"""Kill switch pane — 4-source detail. Spec §13.2 + §11.1.

DISARMED = NORMAL OPERATION. Redaction active. Traffic flows.
ARMED    = EMERGENCY STOP. All requests fail-closed with HTTP 502.

The naming is confusing because 'armed' colloquially means 'working' but in
security it means 'primed to fire' — and what fires is 'refuse all traffic'.
The pane uses Rich markup to make the distinction loud."""

from __future__ import annotations


SOURCES = ("config", "sigusr1", "sentinel", "http")


def render_killswitch(state: dict) -> str:
    ks = state.get("killswitch", {}) or {}
    active = bool(ks.get("active"))
    if active:
        lines = [
            "[bold #ff003c blink]▆▆▆ ARMED — BLOCKING ALL TRAFFIC ▆▆▆[/]",
            "[#ff003c]   fail-closed — every request returns HTTP 502[/]",
            "",
        ]
    else:
        lines = [
            "[bold #00ff41]● DISARMED — NORMAL OPERATION[/]",
            "[#888888]   passing — redaction + detokenization active[/]",
            "",
        ]
    for src in SOURCES:
        if ks.get(src):
            lines.append(f"  [bold #ff003c]●[/]  [bold]{src}[/]")
        else:
            lines.append(f"  [#444444]✗[/]  {src}")
    if active:
        asserted = [s for s in SOURCES if ks.get(s)]
        lines.append("")
        lines.append(f"  [bold #ff003c]Asserted by:[/] {', '.join(asserted)}")
    return "\n".join(lines)
