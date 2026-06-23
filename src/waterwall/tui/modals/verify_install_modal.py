# src/waterwall/tui/modals/verify_install_modal.py
"""Verify-install modal — runs `waterwall verify-install --runtime` on a worker thread.
Spec §13."""

from __future__ import annotations

import json
import subprocess

from textual import work
from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Static


def render_check_table(payload: dict) -> str:
    """Pure renderer for verify-install JSON output."""
    checks = payload.get("checks", [])
    if not checks:
        # Runtime-unreachable path emits {ok, error} with no checks key —
        # rendering that as "0/0 passing" hid the cause (argus issue #16).
        return (
            "verify-install FAILED to run:\n"
            f"  {payload.get('error', 'no checks returned')}"
        )
    passed = sum(1 for c in checks if c.get("ok"))
    total = len(checks)
    lines = [f"verify-install: {passed}/{total} passing", ""]
    for c in checks:
        marker = "✓ PASS" if c.get("ok") else "✗ FAIL"
        detail = f"  ({c.get('detail')})" if c.get("detail") else ""
        lines.append(f"  {marker}  {c['name']}{detail}")
    return "\n".join(lines)


class VerifyInstallModal(ModalScreen[None]):
    CSS = """
    VerifyInstallModal { align: center middle; }
    #verify-install-body {
        background: #000000;
        border: heavy #00ff41;
        padding: 1 2;
        width: 80;
        max-height: 30;
    }
    """

    def compose(self) -> ComposeResult:
        with Container(id="verify-install-body"):
            yield Static("Running verify-install --runtime...", id="vi-text")
            yield Button("Close", id="vi-close")

    def on_mount(self) -> None:
        self._run_check_worker()

    @work(thread=True)
    def _run_check_worker(self) -> None:
        """Spec §13.5: subprocess MUST run on a worker thread or the
        event loop freezes for up to 15 s. Use call_from_thread to mutate UI."""
        try:
            r = subprocess.run(
                ["waterwall", "verify-install", "--runtime"],
                capture_output=True, text=True, timeout=15,
            )
            payload = json.loads(r.stdout)
        except Exception as e:
            payload = {"ok": False, "checks": [
                {"name": "subprocess_failure", "ok": False, "detail": str(e)},
            ]}
        self.app.call_from_thread(
            self.query_one("#vi-text", Static).update,
            render_check_table(payload),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "vi-close":
            self.dismiss()
