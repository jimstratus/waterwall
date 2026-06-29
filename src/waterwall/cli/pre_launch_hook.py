# src/waterwall/cli/pre_launch_hook.py
"""Claude Code SessionStart pre-launch hook. Spec §11.5."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

from waterwall.monitor.canary import run_canary
from waterwall.monitor.health import load_proxy_env


HEALTHZ_URL = os.environ.get("WATERWALL_HEALTHZ_URL", "http://127.0.0.1:8889/healthz")
TIMEOUT_SECONDS = 5.0


def gate_decision(verdict: str, on_error: str) -> tuple[str, str | None]:
    """Map a canary verdict + on-error policy to an action.

    Returns (action, reason) where action is "allow" | "warn" | "block".
    Only on_error == "block" fails closed on an unverifiable canary; any other
    value (including a config typo) fails open to "warn" so a bad setting can't
    silently strand every launch.
    """
    if verdict == "exposed":
        return "block", "canary EXPOSED — secrets bypassing Waterwall"
    if verdict == "error":
        if on_error == "block":
            return "block", "canary unverifiable (on_error=block)"
        return "warn", "canary unverifiable — proceeding (fail-open)"
    return "allow", None


def _load_gate_config() -> tuple[str, str, str, str] | None:
    """Return (canary_url, synthetic, client_env, on_error) when the launch gate
    is enabled in config.yaml, else None. Read at call time so tests can point
    WATERWALL_CONFIG at a fixture; a missing/unparseable file disables the gate."""
    import yaml

    path = os.environ.get("WATERWALL_CONFIG", "/etc/waterwall/config.yaml")
    try:
        doc = yaml.safe_load(Path(path).read_text())
    except (OSError, yaml.YAMLError):
        return None       # missing or unparseable config disables the gate (fail-safe)
    if not isinstance(doc, dict):
        return None       # empty or non-mapping top level -> gate disabled
    m = doc.get("monitor", {}) or {}
    gate = m.get("gate", {}) or {}
    if not gate.get("enabled"):
        return None

    def _str(d: dict, key: str, default: str) -> str:
        # A present-but-non-string value (e.g. `client_env: null`) bypasses dict.get's
        # default; coerce it back so a null/typo can't crash downstream (kilocode CRITICAL).
        v = d.get(key, default)
        return v if isinstance(v, str) else default

    return (
        _str(m, "canary_url", "https://canary.waterwall.local/canary"),
        _str(m, "synthetic", "AKIAIOSFODNN7EXAMPLE"),
        _str(m, "client_env", "/etc/waterwall/client.env"),
        _str(gate, "on_error", "warn"),
    )


def _block(reason: str) -> int:
    """Exit 1 for the waterwall-launch wrapper (the real enforcement point —
    SessionStart hooks cannot block a session; argus issue #17). The JSON uses
    SessionStart's only supported channel, additionalContext, so a hook-only
    install still surfaces the warning inside the session."""
    sys.stderr.write(f"waterwall pre-launch-hook: BLOCK — {reason}\n")
    sys.stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": (
                f"⚠ WATERWALL BLOCK: {reason}. Outbound traffic may be "
                f"UNREDACTED. Stop and fix the proxy before sending secrets."
            ),
        }
    }) + "\n")
    return 1


def _warn(reason: str) -> int:
    """Allow launch (exit 0) but surface an unverifiable-canary warning on both
    stderr and the SessionStart additionalContext channel."""
    sys.stderr.write(f"waterwall pre-launch-hook: WARN — {reason}\n")
    sys.stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": (
                f"⚠ WATERWALL WARN: {reason}. Redaction could not be verified; "
                f"proceeding. Check the canary echo."
            ),
        }
    }) + "\n")
    return 0


def _canary_gate() -> int | None:
    """Fire a fresh canary through the agent's egress path and enforce policy.
    Returns None when the gate is disabled (caller proceeds), else an exit code."""
    cfg = _load_gate_config()
    if cfg is None:
        return None
    canary_url, synthetic, client_env, on_error = cfg
    try:
        env = load_proxy_env(client_env)
    except (OSError, ValueError, TypeError):
        verdict = "error"   # unreadable/undecodable/bad path — never crash the hook
    else:
        verdict = run_canary(canary_url, synthetic,
                             proxy=env.get("HTTPS_PROXY"),
                             ca_path=env.get("NODE_EXTRA_CA_CERTS"))
    action, reason = gate_decision(verdict, on_error)
    if action == "block":
        return _block(reason)
    if action == "warn":
        return _warn(reason)
    return 0


def run() -> int:
    try:
        with httpx.Client(timeout=TIMEOUT_SECONDS) as client:
            r = client.get(HEALTHZ_URL)
    except httpx.HTTPError as e:
        return _block(f"waterwall proxy unreachable at {HEALTHZ_URL}: {e}")

    if r.status_code != 200:
        try:
            body = r.json()
        except Exception:
            body = {}
        return _block(
            f"waterwall /healthz returned {r.status_code}: {body.get('reason', 'unhealthy')}"
        )

    try:
        body = r.json()
    except Exception as e:
        return _block(f"waterwall /healthz returned non-JSON: {e}")

    if body.get("killswitch_active"):
        return _block(
            f"waterwall kill switch is active (sources: {body.get('killswitch_sources', '?')})"
        )

    gate_rc = _canary_gate()
    return 0 if gate_rc is None else gate_rc


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
