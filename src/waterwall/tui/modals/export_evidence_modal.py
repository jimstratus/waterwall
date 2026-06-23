# src/waterwall/tui/modals/export_evidence_modal.py
"""Export-evidence modal — date-range pickers + run subprocess on worker thread."""

from __future__ import annotations

import subprocess

from textual import work
from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static


# Deployment defaults (spec §15 layout on the production host).
DEFAULT_CHAIN = "/var/log/waterwall/proxy.jsonl"
DEFAULT_POLICY = "/etc/waterwall/patterns.py"
DEFAULT_PUBKEY = "/etc/waterwall/signing.pub"
DEFAULT_SIGNING_KEY = "/etc/waterwall/signing.key"
DEFAULT_RECEIPTS = "/var/log/waterwall/receipts"
DEFAULT_MANIFESTS = "/var/log/waterwall/manifests"


def build_export_command(*, since: str, until: str, out: str) -> list[str]:
    """Build the subprocess argv. Empty since/until are omitted.
    Includes every flag export-evidence requires (argus issue #12 — the
    previous 3-flag argv exited 2 on every invocation)."""
    cmd = [
        "waterwall", "export-evidence",
        "--chain", DEFAULT_CHAIN,
        "--receipts-dir", DEFAULT_RECEIPTS,
        "--manifests-dir", DEFAULT_MANIFESTS,
        "--policy", DEFAULT_POLICY,
        "--pubkey", DEFAULT_PUBKEY,
        "--signing-key", DEFAULT_SIGNING_KEY,
    ]
    if since:
        cmd.extend(["--since", since])
    if until:
        cmd.extend(["--until", until])
    cmd.extend(["-o", out])
    return cmd


class ExportEvidenceModal(ModalScreen[None]):
    CSS = """
    ExportEvidenceModal { align: center middle; }
    #ee-body {
        background: #000000;
        border: heavy #00ffff;
        padding: 1 2;
        width: 70;
    }
    Input { margin: 0 0 1 0; }
    """

    def compose(self) -> ComposeResult:
        with Container(id="ee-body"):
            yield Static("Export evidence bundle", id="ee-title")
            yield Input(placeholder="since (YYYY-MM-DD, optional)", id="ee-since")
            yield Input(placeholder="until (YYYY-MM-DD, optional)", id="ee-until")
            yield Input(placeholder="output path", id="ee-out", value="/tmp/evidence.tar.gz")
            yield Static("", id="ee-status")
            yield Button("Run", id="ee-run", variant="primary")
            yield Button("Close", id="ee-close")

    @work(thread=True)
    def _run_export(self, since: str, until: str, out: str) -> None:
        cmd = build_export_command(since=since, until=until, out=out)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                msg = f"OK  {out}\n{r.stdout.strip()}"
            else:
                msg = f"FAIL  exit={r.returncode}\n{r.stderr.strip() or r.stdout.strip()}"
        except Exception as e:
            msg = f"FAIL  {e}"
        self.app.call_from_thread(self.query_one("#ee-status", Static).update, msg)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ee-run":
            since = self.query_one("#ee-since", Input).value
            until = self.query_one("#ee-until", Input).value
            out = self.query_one("#ee-out", Input).value
            self._run_export(since, until, out)
        elif event.button.id == "ee-close":
            self.dismiss()
