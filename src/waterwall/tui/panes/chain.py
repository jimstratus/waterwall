# src/waterwall/tui/panes/chain.py
"""Chain pane — split-cadence: signed checkpoint root + live head prev_hash.
Spec §10.2 + §13.2."""

from __future__ import annotations


def _short_hash(h: str | None) -> str:
    if not h:
        return "—"
    return h[:8] if len(h) > 8 else h


def render_chain(state: dict) -> str:
    c = state.get("chain", {}) or {}
    lines_count = c.get("lines", 0)
    cps = c.get("checkpoints", 0)
    last_signed = c.get("last_signed_ts")
    cp_root = c.get("last_checkpoint_root_hash") or ""
    head = c.get("current_head_prev_hash") or ""
    verify = c.get("verify_status", "—")

    cp_root_render = _short_hash(cp_root) if cp_root else "—"
    head_render = _short_hash(head) if head else "—"
    last_signed_render = last_signed if last_signed else "—"

    glyph = "●" if verify == "ok" else "✗"
    status_line = f"Verify status:    {verify.upper()}  {glyph}"

    return "\n".join([
        f"Lines:            {lines_count}",
        f"Checkpoints:      {cps}",
        f"Checkpoint root:  {cp_root_render}  (last_signed: {last_signed_render})",
        f"Live chain head:  {head_render}  (unsigned, every line)",
        status_line,
    ])
