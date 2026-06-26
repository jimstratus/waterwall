"""Canary echo upstream — the provider stand-in. Spec §3.2.

The echo measures exposure at the egress point: it inspects the body it
received and returns a verdict. It NEVER forwards anywhere. The verdict is a
plain word (not a ``<pl:...>`` placeholder) so Waterwall's inbound
detokenization leaves it intact on the way back to the canary client.
"""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


def classify_body(body: bytes, synthetic: str) -> str:
    """Return 'exposed' if the raw synthetic secret reached the upstream,
    'pass' if a <pl:...> placeholder did instead, else 'error'."""
    if synthetic.encode() in body:
        return "exposed"
    if b"<pl:" in body:
        return "pass"
    return "error"


def build_echo_app(synthetic: str) -> Starlette:
    """Starlette app exposing POST /canary — classifies the received body and
    returns {"verdict": pass|exposed|error}, also recording it on app.state."""
    async def canary(request: Request) -> JSONResponse:
        body = await request.body()
        verdict = classify_body(body, synthetic)
        request.app.state.last_verdict = verdict
        return JSONResponse({"verdict": verdict})

    app = Starlette(routes=[Route("/canary", canary, methods=["POST"])])
    app.state.last_verdict = None
    return app
