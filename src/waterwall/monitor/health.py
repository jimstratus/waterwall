"""Read /healthz -> ok|degraded|down, and parse client.env. Spec §3.1/§3.3."""
from __future__ import annotations

import httpx


def read_health(healthz_url: str, *, transport=None, timeout: float = 3.0) -> str:
    """Map the local /healthz to 'ok' (200 + status==ok), 'degraded' (200 but not ok),
    or 'down' (non-200 / unreachable)."""
    try:
        kwargs: dict = {"timeout": timeout}
        if transport is not None:
            kwargs["transport"] = transport
        with httpx.Client(**kwargs) as client:
            r = client.get(healthz_url)
        if r.status_code != 200:
            return "down"
        return "ok" if r.json().get("status") == "ok" else "degraded"
    except Exception:
        return "down"


def load_proxy_env(path: str) -> dict[str, str]:
    """Parse a `client.env` file (KEY=VALUE / export KEY=VALUE lines) into a dict.
    This is the single source of truth shared by the agent and the canary."""
    out: dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            if "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    return out
