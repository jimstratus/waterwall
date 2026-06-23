# tests/test_systemd_unit.py
"""Configuration regression tests for the systemd unit at
deploy/systemd/waterwall-proxy.service.

These are CONFIGURATION assertions, not behavior tests. They prove that
specific flags survive future edits to the unit file.

Spec §3 (CA name-constraints + egress allowlist) and v2 §4.1
(multi-permittedSubtree + upstream_cert=false to keep leaf SANs
host-bound) are both load-bearing — drift in the unit file would silently
break v2 multi-host TLS or v1 single-host hardening.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


UNIT_PATH = Path(__file__).resolve().parent.parent / "deploy" / "systemd" / "waterwall-proxy.service"


@pytest.fixture(scope="module")
def exec_start() -> str:
    """Concatenate the multi-line ExecStart= block into a single string for
    flag-presence assertions. Strips line continuations and surrounding
    whitespace."""
    text = UNIT_PATH.read_text(encoding="utf-8")
    match = re.search(
        r"^ExecStart=(?P<body>.+?)(?=^\s*$|^\[|^Restart=|^[A-Z][A-Za-z]+=)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match, "ExecStart= block not found in waterwall-proxy.service"
    return " ".join(line.rstrip("\\").strip() for line in match.group("body").splitlines() if line.strip())


def test_unit_file_exists():
    assert UNIT_PATH.exists(), f"systemd unit not at {UNIT_PATH}"


def test_exec_start_pins_loopback_listener(exec_start: str):
    """spec §3: proxy MUST bind 127.0.0.1 only (homelab single-operator gate)."""
    assert "--listen-host 127.0.0.1" in exec_start, (
        "Listener must be loopback-only. mitmproxy default is 0.0.0.0 — security regression."
    )


def test_exec_start_uses_upstream_cert_false(exec_start: str):
    """v2 §4.1 + Phase v2-G lab: upstream_cert=false makes mitmproxy issue
    leaf certs whose SAN matches only the SNI host (not the upstream's
    wildcard). Required so wildcard-SAN providers (DeepSeek's *.deepseek.com,
    likely OpenAI/OpenRouter too) don't fail validation under per-host
    permittedSubtree NameConstraints."""
    assert "--set upstream_cert=false" in exec_start, (
        "v2 multi-host TLS regression: upstream_cert=false missing. "
        "Without it, wildcard-SAN providers fail TLS handshake under the "
        "v2 explicit-host permittedSubtree CA. See "
        "docs/superpowers/lab-notes/phase-v2-G.md."
    )


def test_exec_start_allow_hosts_covers_v2_defaults(exec_start: str):
    """v2 §4.1: --allow-hosts is the egress-allowlist gate (mitmproxy
    refuses to even MITM unlisted hosts). Must include all v2-default
    permitted hosts so traffic to those hosts can reach the addon."""
    match = re.search(r"--allow-hosts\s+'([^']+)'", exec_start)
    assert match, "ExecStart must specify --allow-hosts as a single-quoted regex"
    regex = match.group(1)
    # Each v2 default host must be present (literal-match within the regex,
    # accepting either escaped dots or unescaped — operators may evolve the
    # regex shape but each default host name must appear.)
    for host in ("anthropic", "deepseek", "openai", "openrouter"):
        assert host in regex, (
            f"--allow-hosts regex missing '{host}' — would block v2 traffic to that provider. "
            f"Current regex: {regex!r}"
        )
    # Argus issue #17: api.openrouter.ai does not exist in public DNS — the
    # real host is the apex, openrouter.ai. With the wrong name mitmproxy
    # passes that provider's traffic through UNINTERCEPTED (unredacted egress).
    assert "api\\.openrouter" not in regex and "api.openrouter" not in regex, (
        f"--allow-hosts must use 'openrouter\\.ai' (apex), not the nonexistent "
        f"api.openrouter.ai. Current regex: {regex!r}"
    )


def test_exec_start_uses_venv_mitmdump(exec_start: str):
    """Production install uses the editable-venv mitmdump (not /usr/bin/mitmdump
    which doesn't exist on Debian without pipx — see docs/handoffs/HANDOFF.md fix `a051e04`)."""
    assert "/opt/waterwall/.venv/bin/mitmdump" in exec_start


def test_unit_file_drops_memory_deny_write_execute():
    """spec §15: MemoryDenyWriteExecute=yes is incompatible with mitmproxy's
    pyopenssl/cffi callbacks (docs/handoffs/HANDOFF.md fix `c5f104d`). Must NOT be present."""
    text = UNIT_PATH.read_text(encoding="utf-8")
    # The directive may appear as a commented-out explanation; ensure it's
    # not active (i.e., not a non-comment line).
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert "MemoryDenyWriteExecute=yes" not in stripped, (
            "MemoryDenyWriteExecute=yes blocks pyopenssl ffi callbacks; was removed in fix c5f104d"
        )


def test_runtime_directory_preserved_across_restart():
    """Argus issue #15: default RuntimeDirectoryPreserve=no wipes the
    /run/waterwall/kill sentinel on the weekly timer restart."""
    unit = UNIT_PATH.read_text(encoding="utf-8")
    assert "RuntimeDirectoryPreserve=restart" in unit
