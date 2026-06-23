# src/waterwall/cli/pre_launch_hook.py
"""Claude Code SessionStart pre-launch hook. Spec §11.5."""

from __future__ import annotations

import json
import os
import sys

import httpx


HEALTHZ_URL = os.environ.get("WATERWALL_HEALTHZ_URL", "http://127.0.0.1:8889/healthz")
TIMEOUT_SECONDS = 5.0


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

    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
