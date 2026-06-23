# src/waterwall/tui/app.py
"""Waterwall cyberpunk TUI app. Spec §13."""

from __future__ import annotations

import socket
from pathlib import Path

import httpx
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import Footer, Static

from waterwall.tui.state_client import StateClient, StateUnavailable
from waterwall.tui.panes import (
    activity, counters, killswitch, map_patterns, chain, sessions,
)


THEME_CSS = (Path(__file__).parent / "themes" / "cyberpunk.css").read_text()


def _humanize_uptime(seconds: int) -> str:
    if seconds <= 0:
        return "—"
    h, rem = divmod(seconds, 3600)
    m, _ = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


LOGO = """██╗    ██╗ █████╗ ████████╗███████╗██████╗ ██╗    ██╗ █████╗ ██╗     ██╗
██║    ██║██╔══██╗╚══██╔══╝██╔════╝██╔══██╗██║    ██║██╔══██╗██║     ██║
██║ █╗ ██║███████║   ██║   █████╗  ██████╔╝██║ █╗ ██║███████║██║     ██║
██║███╗██║██╔══██║   ██║   ██╔══╝  ██╔══██╗██║███╗██║██╔══██║██║     ██║
╚███╔███╔╝██║  ██║   ██║   ███████╗██║  ██║╚███╔███╔╝██║  ██║███████╗███████╗
 ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝"""


class WaterwallTUI(App):
    CSS = THEME_CSS
    BINDINGS = [
        ("r", "reload_patterns",   "[r] reload"),
        ("k", "killswitch_modal",  "[k] killswitch"),
        ("v", "verify_install",    "[v] verify-install"),
        ("e", "export_evidence",   "[e] export"),
        ("t", "toggle_tail",       "[t] tail"),
        ("q", "quit",              "[q] quit"),
    ]

    state: reactive[dict | None] = reactive(None)
    offline: reactive[bool] = reactive(False)
    tail_active: reactive[bool] = reactive(True)

    PANEL_IDS = ["#p-activity", "#p-counters", "#p-killswitch",
                 "#p-map", "#p-chain", "#p-sessions"]

    def __init__(self, state_client: StateClient | None = None,
                 hostname: str | None = None) -> None:
        super().__init__()
        self._client = state_client or StateClient()
        # Short hostname, uppercased, resolved once. Spec §13: identifies the
        # box waterwall is running on so an operator with multiple TUIs open
        # never confuses test-host with prod-host. Override via constructor arg for
        # tests.
        raw = hostname if hostname is not None else socket.gethostname()
        self._hostname = (raw.split(".")[0] or "UNKNOWN").upper()

    def compose(self) -> ComposeResult:
        with Container(id="outer-frame"):
            yield Static(LOGO, classes="logo-ascii")
            with Horizontal(id="header-strip"):
                yield Static("▼  reversible egress firewall  ▼", classes="tagline")
                yield Static(f"⌂ {self._hostname}", id="hostname",
                             classes="hostname-chip")
                yield Static("●UP  uptime —", id="status-indicator", classes="status-good")
            yield Static("", id="offline-banner")
            with Horizontal(id="panels-row"):
                with Vertical(classes="panels-col"):
                    yield self._make_panel("LIVE ACTIVITY", "p-activity")
                    yield self._make_panel("MAP / PATTERNS", "p-map")
                    yield self._make_panel("CHAIN / AUDIT", "p-chain")
                with Vertical(classes="panels-col"):
                    yield self._make_panel("COUNTERS (5m)", "p-counters")
                    yield self._make_panel("KILL SWITCH", "p-killswitch")
                    yield self._make_panel("ACTIVE SESSIONS", "p-sessions")
        yield Footer()

    def _make_panel(self, title: str, panel_id: str) -> Static:
        w = Static("", classes="panel", id=panel_id)
        w.border_title = title
        return w

    @staticmethod
    def _should_clear_offline(panels_cleared: bool) -> bool:
        return panels_cleared

    def on_mount(self) -> None:
        self.set_interval(1.0, self._poll_state)
        self._poll_state()

    def _poll_state(self) -> None:
        self._poll_state_worker()

    @work(thread=True, exclusive=True, group="state-poll")
    def _poll_state_worker(self) -> None:
        """Blocking httpx fetch runs on a worker thread (argus issue #16 — it
        froze the event loop for up to 1 s per tick); UI mutations marshal back
        via call_from_thread. Own worker group so `exclusive` never cancels
        the pattern-reload worker."""
        try:
            new_state = self._client.fetch()
        except StateUnavailable as e:
            self.call_from_thread(self._apply_offline, str(e))
            return
        self.call_from_thread(self._apply_online, new_state)

    def _apply_online(self, new_state: dict) -> None:
        self.state = new_state
        panels_cleared = False
        try:
            if self.offline:
                for pid in self.PANEL_IDS:
                    self.query_one(pid, Static).remove_class("status-fail")
                self.query_one("#status-indicator", Static).remove_class("status-fail")
            banner = self.query_one("#offline-banner", Static)
            banner.update("")
            banner.remove_class("armed")
            panels_cleared = True
        except NoMatches:
            # Modal open — keep offline True so the NEXT poll retries the
            # class removal (argus issue #16: setting it False here left every
            # panel stuck in status-fail after the modal closed).
            pass
        if self._should_clear_offline(panels_cleared):
            self.offline = False

    def _apply_offline(self, reason: str) -> None:
        # Spec §13.5: flip ALL panels to status-fail and replace content
        # with offline marker. Stale data is forbidden.
        self.offline = True
        self.state = None
        try:
            banner = self.query_one("#offline-banner", Static)
            banner.update(
                f"  PROXY OFFLINE — RUN `waterwall verify-install`  ({reason})  "
            )
            banner.add_class("armed")
            for pid in self.PANEL_IDS:
                w = self.query_one(pid, Static)
                w.add_class("status-fail")
                w.update("—  proxy offline")
            si = self.query_one("#status-indicator", Static)
            si.set_classes("status-fail")
            si.update("●OFFLINE  proxy unreachable")
        except NoMatches:
            # Modal active when proxy went offline — banner update will fire
            # on the next poll after modal dismiss.
            pass

    def watch_state(self, new_state: dict | None) -> None:
        if new_state is None:
            return
        # When a modal screen is pushed (e.g. KillswitchModal), the main panels
        # leave the App.query namespace until the modal closes. The 1Hz poll
        # keeps firing in the background — silently skip panel updates rather
        # than crashing on NoMatches. The next poll after the modal closes will
        # repaint everything.
        try:
            if self.tail_active:
                self.query_one("#p-activity", Static).update(activity.render_activity(new_state))
            self.query_one("#p-counters",   Static).update(counters.render_counters(new_state))
            self.query_one("#p-killswitch", Static).update(killswitch.render_killswitch(new_state))
            self.query_one("#p-map",        Static).update(map_patterns.render_map_patterns(new_state))
            self.query_one("#p-chain",      Static).update(chain.render_chain(new_state))
            self.query_one("#p-sessions",   Static).update(sessions.render_sessions(new_state))

            status_widget = self.query_one("#status-indicator", Static)
            if new_state.get("status") == "ok":
                status_widget.set_classes("status-good")
                status_widget.update(f"●UP  uptime {_humanize_uptime(new_state.get('uptime_seconds', 0))}")
            else:
                status_widget.set_classes("status-fail")
                status_widget.update("●FAIL  /healthz reports unhealthy")
        except NoMatches:
            return

    @work(thread=True)
    def _do_reload_patterns(self) -> None:
        try:
            with httpx.Client(timeout=5.0) as client:
                r = client.post("http://127.0.0.1:8889/admin/reload")
            if r.status_code == 200:
                self.call_from_thread(self.notify, "patterns reloaded")
            else:
                detail = ""
                try:
                    detail = r.json().get("error", "")
                except Exception:
                    pass
                self.call_from_thread(
                    self.notify,
                    f"reload FAILED ({r.status_code}): {detail}",
                    severity="error",
                )
        except httpx.HTTPError as e:
            self.call_from_thread(self.notify, f"reload failed: {e}", severity="error")

    def action_reload_patterns(self) -> None:
        self._do_reload_patterns()

    def action_killswitch_modal(self) -> None:
        from waterwall.tui.modals.killswitch_modal import KillswitchModal
        self.push_screen(KillswitchModal())

    def action_verify_install(self) -> None:
        from waterwall.tui.modals.verify_install_modal import VerifyInstallModal
        self.push_screen(VerifyInstallModal())

    def action_export_evidence(self) -> None:
        from waterwall.tui.modals.export_evidence_modal import ExportEvidenceModal
        self.push_screen(ExportEvidenceModal())

    def action_toggle_tail(self) -> None:
        self.tail_active = not self.tail_active
        self.notify(f"tail {'ON' if self.tail_active else 'PAUSED'}")
