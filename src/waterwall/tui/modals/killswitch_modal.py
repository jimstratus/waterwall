# src/waterwall/tui/modals/killswitch_modal.py
"""Killswitch modal — surfaces partial-disarm UX (spec issue 11)."""

from __future__ import annotations

import httpx
from textual import work
from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Static


def _disarm_hint(source: str) -> str:
    return {
        "config": "set kill_switch: false in /etc/waterwall/config.yaml",
        "sigusr1": "kill -USR1 $(pidof waterwall-proxy)",
        "sentinel": "rm /run/waterwall/kill",
        "http": "POST /admin/killswitch action=disarm (or restart the proxy)",
    }.get(source, source)


def build_arm_message(status_code: int) -> str:
    """For an emergency stop, claiming armed-when-not is the worst-case
    message (argus issue #15) — only 2xx may report success."""
    if 200 <= status_code < 300:
        return "Kill switch armed via HTTP."
    return f"arm FAILED: /admin/killswitch returned {status_code}"


def build_disarm_message(remaining_sources: list[str]) -> str:
    """Compose the post-disarm message — surface ANY non-HTTP source still active."""
    if not remaining_sources:
        return "Kill switch disarmed."
    return (
        f"HTTP source disarmed. Other sources still active: "
        f"{', '.join(remaining_sources)}.\n"
        f"To fully disarm, clear: "
        f"{', '.join(_disarm_hint(s) for s in remaining_sources)}"
    )


class KillswitchModal(ModalScreen[None]):
    CSS = """
    KillswitchModal { align: center middle; }
    #ks-body {
        background: #000000;
        border: heavy #ff003c;
        padding: 1 2;
        width: 70;
    }
    """

    def compose(self) -> ComposeResult:
        with Container(id="ks-body"):
            yield Static("Kill switch (HTTP source)", id="ks-title")
            yield Static("", id="ks-result")
            yield Button("Arm", id="ks-arm", variant="error")
            yield Button("Disarm", id="ks-disarm", variant="primary")
            yield Button("Close", id="ks-close")

    @work(thread=True)
    def _arm_via_http(self) -> None:
        # Argus issue #15: check the HTTP status — a non-2xx must never read
        # as "armed". Broad except so a JSON/decode error can't kill the app.
        try:
            with httpx.Client(timeout=5.0) as client:
                r = client.post("http://127.0.0.1:8889/admin/killswitch",
                                json={"action": "arm", "reason": "tui"})
            self.app.call_from_thread(self._set_result, build_arm_message(r.status_code))
        except Exception as e:
            self.app.call_from_thread(self._set_result, f"arm failed: {e}")

    @work(thread=True)
    def _disarm_via_http(self) -> None:
        try:
            with httpx.Client(timeout=5.0) as client:
                r = client.post("http://127.0.0.1:8889/admin/killswitch",
                                json={"action": "disarm"})
                if r.status_code != 200:
                    self.app.call_from_thread(
                        self._set_result, f"disarm FAILED: returned {r.status_code}")
                    return
                state = client.get("http://127.0.0.1:8889/admin/state").json()
            ks = state.get("killswitch", {}) or {}
            # Argus issue #15: include "http" so a stuck http arm is visible.
            remaining = [s for s in ("config", "sigusr1", "sentinel", "http") if ks.get(s)]
            msg = build_disarm_message(remaining)
            self.app.call_from_thread(self._set_result, msg)
        except Exception as e:
            self.app.call_from_thread(self._set_result, f"disarm failed: {e}")

    def _set_result(self, msg: str) -> None:
        self.query_one("#ks-result", Static).update(msg)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ks-arm":
            self._arm_via_http()
        elif event.button.id == "ks-disarm":
            self._disarm_via_http()
        elif event.button.id == "ks-close":
            self.dismiss()
