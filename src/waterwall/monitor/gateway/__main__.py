"""`waterwall monitor-gateway` — run the monitor gateway. Spec §3.4.

Loads the `gateway.*` block from config.yaml, starts the Starlette app under
uvicorn, and runs a background dead-man's-switch sweeper.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path

_log = logging.getLogger(__name__)


def main_cli() -> int:
    import yaml
    import uvicorn

    from waterwall.monitor.gateway.app import build_gateway_app, sweep_stale

    doc = yaml.safe_load(
        Path(os.environ.get("WATERWALL_CONFIG", "/etc/waterwall/config.yaml")).read_text())
    g = (doc or {}).get("gateway", {})
    token = g.get("token")
    if not token:
        _log.error("gateway.token is required in config.yaml")
        return 1
    app = build_gateway_app(
        db_path=g.get("db", "/var/log/waterwall/monitor.db"),
        token=token,
        discord_webhook=g.get("discord_webhook", ""))

    threshold = g.get("interval", 45) * g.get("miss_factor", 3)

    def _sweeper() -> None:
        try:
            sweep_stale(app, time.time(), threshold)
        except Exception as exc:
            _log.warning("initial stale sweep error: %s", exc.__class__.__name__)
        while True:
            time.sleep(threshold)
            try:
                sweep_stale(app, time.time(), threshold)
            except Exception as exc:  # never let the sweeper thread die
                _log.warning("stale sweep error: %s", exc.__class__.__name__)

    threading.Thread(target=_sweeper, daemon=True).start()
    uvicorn.run(app, host=g.get("bind", "127.0.0.1"), port=g.get("port", 8890))
    return 0
