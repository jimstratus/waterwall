"""Canary client — sends the synthetic secret down the agent's egress path. Spec §3.3.

Sourcing the agent's proxy config (`HTTPS_PROXY`) is what makes this faithful: if the
agent's env is broken, the canary connects directly to the echo and the echo sees the raw
secret, surfacing the silent-bypass case (#3).
"""
from __future__ import annotations

import logging

import httpx

_log = logging.getLogger(__name__)


def run_canary(canary_url: str, synthetic: str, *, ca_path: str | None = None,
               proxy: str | None = None, transport=None, timeout: float = 5.0) -> str:
    """POST {"q": synthetic} to the canary echo via `proxy` (None = direct/bypass),
    trusting `ca_path`. Returns the echo's verdict ('pass'|'exposed') or 'error' on any
    network/TLS/parse failure (which also means 'could not verify')."""
    try:
        kwargs: dict = {"timeout": timeout}
        if transport is not None:
            kwargs["transport"] = transport
        else:
            if proxy:
                kwargs["proxy"] = proxy
            if ca_path:
                kwargs["verify"] = ca_path
        with httpx.Client(**kwargs) as client:
            resp = client.post(canary_url, json={"q": synthetic})
            return resp.json().get("verdict", "error")
    except Exception as exc:  # network/TLS/parse — all mean "could not verify"
        _log.warning("canary error: %s", exc.__class__.__name__)
        return "error"
