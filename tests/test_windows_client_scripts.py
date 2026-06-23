"""Static + runtime regression tests for Windows client-side helper scripts."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
WINDOWS_DIR = REPO_ROOT / "deploy" / "windows"
README_PATH = WINDOWS_DIR / "README.md"
TUNNEL_TASK_PATH = WINDOWS_DIR / "install_tunnel_task.ps1"
HOOK_INSTALLER_PATH = WINDOWS_DIR / "install_claude_hook.ps1"
HOOK_SCRIPT_PATH = WINDOWS_DIR / "waterwall-sessionstart.ps1"


def _powershell_executable() -> str | None:
    for name in ("powershell.exe", "pwsh"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_windows_client_scripts_exist():
    assert WINDOWS_DIR.exists()
    assert README_PATH.exists()
    assert TUNNEL_TASK_PATH.exists()
    assert HOOK_INSTALLER_PATH.exists()
    assert HOOK_SCRIPT_PATH.exists()


def test_tunnel_task_script_registers_reboot_safe_ssh_tunnel():
    text = _read(TUNNEL_TASK_PATH)
    assert "Register-ScheduledTask" in text
    assert "New-ScheduledTaskTrigger -AtLogOn" in text
    assert "Get-Command ssh.exe" in text
    assert "ExitOnForwardFailure=yes" in text
    assert "ServerAliveInterval=30" in text
    assert "$LocalProxyPort" in text
    assert "$LocalAdminPort" in text
    assert "$RemoteHost" in text
    assert "$RemoteProxyPort" in text
    assert "$RemoteAdminPort" in text
    assert "'-L'" in text
    assert "TunnelHost" in text


def test_sessionstart_hook_script_checks_health_and_emits_contract_json():
    # issue #17: SessionStart hooks have no 'decision' field — the script must
    # emit hookSpecificOutput.additionalContext (informational) and rely on
    # the exit code (0 allow / 1 block) as the wrapper-enforceable contract.
    text = _read(HOOK_SCRIPT_PATH)
    assert "http://127.0.0.1:8889/healthz" in text
    assert "hookSpecificOutput" in text
    assert "hookEventName" in text and "'SessionStart'" in text
    assert "additionalContext" in text
    assert "ConvertTo-Json -Compress" in text
    assert '"decision"' not in text and "decision = " not in text
    assert "exit 0" in text
    assert "exit 1" in text
    assert "killswitch_active" in text
    assert "Test-NetConnection" in text


def test_claude_hook_installer_merges_sessionstart_without_clobbering():
    text = _read(HOOK_INSTALLER_PATH)
    assert ".claude" in text
    assert "settings.json" in text
    assert "SessionStart" in text
    assert "ConvertFrom-Json" in text
    assert "ConvertTo-Json" in text
    assert "hooks" in text


def test_windows_client_readme_documents_dedicated_host_tunnel_and_hook():
    text = _read(README_PATH)
    assert "dedicated Waterwall proxy host" in text
    assert "install_tunnel_task.ps1" in text
    assert "install_claude_hook.ps1" in text
    assert "waterwall-sessionstart.ps1" in text
    assert "Task Scheduler" in text
    assert "SessionStart" in text


@pytest.mark.skipif(
    os.name != "nt" or _powershell_executable() is None,
    reason="SessionStart hook is a PowerShell script; requires Windows + powershell.exe/pwsh",
)
def test_sessionstart_hook_executes_and_returns_block_when_proxy_unreachable(tmp_path):
    """Runtime smoke test: the hook must actually parse + execute, not just be statically grep-able.

    Points at a port no one is listening on. Expects exit code 1 and a JSON
    object carrying hookSpecificOutput.additionalContext (issue #17:
    SessionStart has no 'decision' field; the exit code is the enforcement
    contract). This catches PowerShell parse errors that [Parser]::ParseFile
    misses (e.g. invalid drive-qualified variable references like "$Var:"
    inside double-quoted strings).
    """
    ps = _powershell_executable()
    assert ps is not None  # narrowed by the skipif guard
    # Pick an unused high port — anything in this range is overwhelmingly likely
    # to be unbound. The script's Test-NetConnection call uses a ~1-2s timeout.
    completed = subprocess.run(
        [
            ps,
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(HOOK_SCRIPT_PATH),
            "-ProxyHost",
            "127.0.0.1",
            "-ProxyPort",
            "59999",
            "-HealthzUrl",
            "http://127.0.0.1:59999/healthz",
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 1, (
        f"Expected block exit 1, got {completed.returncode}.\n"
        f"stdout: {completed.stdout!r}\nstderr: {completed.stderr!r}"
    )
    stdout = completed.stdout.strip()
    # Last non-empty line should be the JSON decision; tolerate stray output above.
    decision_line = next(
        (line for line in reversed(stdout.splitlines()) if line.strip()),
        "",
    )
    payload = json.loads(decision_line)
    ctx = payload["hookSpecificOutput"]
    assert ctx["hookEventName"] == "SessionStart"
    assert "WATERWALL BLOCK" in ctx["additionalContext"], (
        "block output must carry the warning in additionalContext (issue #17)"
    )


@pytest.mark.skipif(
    os.name != "nt" or _powershell_executable() is None,
    reason="install_claude_hook is a PowerShell script; requires Windows + powershell.exe/pwsh",
)
def test_install_claude_hook_executes_and_preserves_existing_settings(tmp_path):
    """Runtime smoke test: install_claude_hook.ps1 must parse + execute + write
    a valid settings.json that preserves existing entries and adds a non-clobbering
    SessionStart entry. Catches parse errors and JSON-mangling regressions.
    """
    ps = _powershell_executable()
    assert ps is not None  # narrowed by skipif

    settings_path = tmp_path / "settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "theme": "dark",
                "hooks": {
                    "PostToolUse": [
                        {"matcher": "*", "hooks": [{"type": "command", "command": "echo preexisting"}]}
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            ps,
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(HOOK_INSTALLER_PATH),
            "-SettingsPath",
            str(settings_path),
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, (
        f"installer exited {completed.returncode}\n"
        f"stdout: {completed.stdout!r}\nstderr: {completed.stderr!r}"
    )

    written = json.loads(settings_path.read_text(encoding="utf-8"))
    # Pre-existing top-level key must survive.
    assert written.get("theme") == "dark"
    # Pre-existing hook category must survive.
    post = written["hooks"].get("PostToolUse")
    assert post and post[0]["hooks"][0]["command"] == "echo preexisting"
    # SessionStart entry must be present and reference our hook script.
    sess = written["hooks"].get("SessionStart")
    assert sess and any(
        entry.get("matcher") == "*"
        and any("waterwall-sessionstart.ps1" in h.get("command", "") for h in entry.get("hooks", []))
        for entry in sess
    ), f"SessionStart entry missing or malformed: {sess!r}"

    # Idempotency: running twice should not duplicate the entry.
    subprocess.run(
        [
            ps,
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(HOOK_INSTALLER_PATH),
            "-SettingsPath",
            str(settings_path),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    after_second = json.loads(settings_path.read_text(encoding="utf-8"))
    matching = [
        entry
        for entry in after_second["hooks"]["SessionStart"]
        if entry.get("matcher") == "*"
        and any("waterwall-sessionstart.ps1" in h.get("command", "") for h in entry.get("hooks", []))
    ]
    assert len(matching) == 1, f"Idempotency broken: {matching!r}"
