"""Monitor gateway — bearer ingest, fleet API, transition notify, dashboard. Spec §3.4."""
from __future__ import annotations

import secrets
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from waterwall.monitor.gateway.notify import post_discord
from waterwall.monitor.gateway.store import get_fleet, open_store, record_report
from waterwall.monitor.gateway.transitions import Event, detect_stale, detect_transitions

_DASHBOARD = Path(__file__).parent / "dashboard.html"


def build_gateway_app(*, db_path: str, token: str, discord_webhook: str = "",
                      notifier=post_discord) -> Starlette:
    conn = open_store(db_path)

    def _authed(request: Request) -> bool:
        # constant-time compare (argus minor) — avoid leaking the token via timing
        return secrets.compare_digest(
            request.headers.get("Authorization", ""), f"Bearer {token}")

    async def report(request: Request) -> JSONResponse:
        if not _authed(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            rep = await request.json()
            prev = record_report(conn, rep)
        except (ValueError, KeyError):
            return JSONResponse({"error": "bad report"}, status_code=400)
        for event in detect_transitions(prev, rep):
            notifier(discord_webhook, event)
        return JSONResponse({"ok": True})

    async def fleet(request: Request) -> JSONResponse:
        # Gate the fleet DATA with the same bearer as ingest (the dashboard sends
        # it from localStorage/?token=). The '/' HTML shell carries no data and is
        # additionally meant to sit behind CF Access for the human layer.
        if not _authed(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return JSONResponse({"fleet": get_fleet(conn)})

    async def dashboard(request: Request) -> FileResponse:
        return FileResponse(_DASHBOARD)

    app = Starlette(routes=[
        Route("/", dashboard, methods=["GET"]),
        Route("/api/report", report, methods=["POST"]),
        Route("/api/fleet", fleet, methods=["GET"]),
    ])
    app.state.conn = conn
    app.state.notifier = notifier
    app.state.webhook = discord_webhook
    app.state.stale_hosts = set()   # hosts currently in the alerted-stale state
    return app


def sweep_stale(app: Starlette, now: float, threshold: float, *, webhook=None,
                notifier=None) -> list:
    """Dead-man's-switch pass — edge-triggered (argus #2): alert once when a host
    crosses into stale, recover once when it returns. Steady-stale sweeps are silent.
    Uses the app's configured notifier/webhook unless overridden."""
    notifier = notifier or app.state.notifier
    webhook = app.state.webhook if webhook is None else webhook
    current = set(detect_stale(get_fleet(app.state.conn), now, threshold))
    prev = app.state.stale_hosts
    events: list[Event] = []
    for h in sorted(current - prev):
        events.append(Event(h, "alert", f"⛔ {h} no heartbeat — dead man's switch"))
    for h in sorted(prev - current):
        events.append(Event(h, "recovery", f"✅ {h} heartbeat resumed"))
    app.state.stale_hosts = current
    for ev in events:
        notifier(webhook, ev)
    return events
