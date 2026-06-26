"""Reporter — fire canary + read health + push to gateway. Spec §3.3.

Off by default; enabled per instance via `monitor.enabled: true` in config.yaml.
"""
from __future__ import annotations

import logging
import time

import httpx

from waterwall.monitor.canary import run_canary
from waterwall.monitor.health import load_proxy_env, read_health

_log = logging.getLogger(__name__)


def build_report(host: str, canary: str, health: str, version: str, ts: float) -> dict:
    """Pure payload builder — `ts` injected so tests are deterministic."""
    return {"host": host, "canary": canary, "health": health, "version": version, "ts": ts}


def _default_post(url: str, json: dict, headers: dict) -> bool:
    try:
        with httpx.Client(timeout=5.0) as c:
            r = c.post(url, json=json, headers=headers)
        return r.status_code < 400
    except Exception as exc:
        _log.warning("gateway post failed: %s", exc.__class__.__name__)
        return False


def report_once(cfg: dict, *, post=_default_post, clock=time.time) -> dict | None:
    """One cycle: canary (via the agent's proxy) + health, push to the gateway.
    Returns the report on success, None if posting failed (logged, non-fatal)."""
    proxy, ca_path = cfg.get("proxy"), cfg.get("ca_path")
    canary = None
    # Re-read client.env every cycle so post-startup proxy drift is caught — the
    # canary must travel the agent's *current* path, not a startup snapshot (argus #1).
    # A missing/unreadable file must NOT crash the loop (argus v2 #1): report 'error'
    # (path unverifiable) and keep the heartbeat alive.
    if cfg.get("client_env"):
        try:
            env = load_proxy_env(cfg["client_env"])
            proxy = env.get("HTTPS_PROXY")
            ca_path = env.get("NODE_EXTRA_CA_CERTS")
        except OSError as exc:
            _log.warning("client.env unreadable (%s): canary=error", exc.__class__.__name__)
            canary = "error"
    if canary is None:
        canary = run_canary(cfg["canary_url"], cfg["synthetic"], ca_path=ca_path, proxy=proxy)
    health = read_health(cfg["healthz_url"])
    report = build_report(cfg["host"], canary, health, cfg["version"], clock())
    headers = {"Authorization": f"Bearer {cfg['token']}"}
    return report if post(cfg["gateway_url"], report, headers) else None


def run_loop(cfg: dict) -> None:
    while True:
        try:
            report_once(cfg)
        except Exception as exc:  # never let one bad cycle kill the heartbeat
            _log.warning("report cycle error: %s", exc.__class__.__name__)
        time.sleep(cfg.get("interval", 45))


def main_cli() -> int:
    import os
    import socket
    from pathlib import Path

    import yaml

    doc = yaml.safe_load(
        Path(os.environ.get("WATERWALL_CONFIG", "/etc/waterwall/config.yaml")).read_text())
    m = (doc or {}).get("monitor", {})
    if not m.get("enabled"):
        _log.info("monitor.enabled is false — reporter not started")
        return 0
    gateway_url = m.get("gateway_url")
    token = m.get("token")
    if not gateway_url:
        _log.error("monitor.gateway_url is required when monitor.enabled is true")
    if not token:
        _log.error("monitor.token is required when monitor.enabled is true")
    if not gateway_url or not token:
        return 1
    cfg = {
        "host": m.get("host", socket.gethostname()),
        "version": m.get("version", "v2"),
        "gateway_url": gateway_url,
        "token": token,
        "canary_url": m.get("canary_url", "https://canary.waterwall.local/canary"),
        "healthz_url": m.get("healthz_url", "http://127.0.0.1:8889/healthz"),
        "synthetic": m.get("synthetic", "AKIAIOSFODNN7EXAMPLE"),
        # client.env is re-read every cycle (report_once) so proxy drift is caught.
        "client_env": m.get("client_env", "/etc/waterwall/client.env"),
        "interval": m.get("interval", 45),
    }
    run_loop(cfg)
    return 0
