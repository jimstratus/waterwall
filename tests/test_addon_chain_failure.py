# tests/test_addon_chain_failure.py
"""Spec §14: chain-append failure returns 502 fail-closed.

Plan §Task 5.7's original test used filesystem chmod to force ChainAppendError,
but that doesn't work on Windows (chmod on dir is no-op) AND doesn't work when
running as root on Linux (root bypasses POSIX permissions). The Phase 5 lab on
test-host exposed both issues. Switched to monkeypatch — platform-independent and
isolates the unit under test (the addon's fail-closed handling) from
filesystem-perms behavior. The 502-return path is what we want to validate."""
import json
import os
from pathlib import Path
import pytest
from mitmproxy.test import tflow, taddons
from waterwall.proxy.addon import WaterwallAddon
from waterwall.audit.chain import ChainAppendError
from waterwall.audit.signer import generate_keypair


def test_chain_append_failure_returns_502(tmp_path: Path, monkeypatch):
    priv = tmp_path / "k.key"; pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    chain_path = tmp_path / "proxy.jsonl"
    addon = WaterwallAddon(
        chain_path=chain_path, session_key=os.urandom(32), signer_path=priv,
    )
    # v2 §4.2: gate on _sse_handlers; seed Anthropic for v1 chain-failure path.
    from waterwall.proxy.sse import SseStreamRewriter
    addon._sse_handlers["api.anthropic.com"] = SseStreamRewriter(store=addon._store)

    # Force ChainAppendError without relying on filesystem perms (which behave
    # differently on Windows vs Linux, and not at all under root). This isolates
    # the unit under test: the addon's fail-closed handling of ChainAppendError.
    def _broken_append(payload):
        raise ChainAppendError("simulated disk full")
    monkeypatch.setattr(addon._chain, "append", _broken_append)

    flow = tflow.tflow(req=tflow.treq(
        host="api.anthropic.com", port=443, scheme=b"https",
        method=b"POST", path=b"/v1/messages",
        content=json.dumps({"messages": [{"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}]}).encode(),
    ))
    with taddons.context(addon) as _:
        addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 502
    body = json.loads(flow.response.content)
    assert body["error"] == "waterwall-chain-append-failed"


def _make_addon_with_registered_host(tmp_path: Path):
    """Addon + Anthropic SSE handler registered, mirroring the request-path test."""
    priv = tmp_path / "k.key"; pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    addon = WaterwallAddon(
        chain_path=tmp_path / "proxy.jsonl", session_key=os.urandom(32),
        signer_path=priv,
    )
    from waterwall.proxy.sse import SseStreamRewriter
    addon._sse_handlers["api.anthropic.com"] = SseStreamRewriter(
        store=addon._store, chain=addon._chain,
    )
    return addon


def test_response_path_chain_failure_502s(tmp_path: Path, monkeypatch):
    """Argus issue #17: a ChainAppendError on the RESPONSE path delivered the
    detokenized secrets with zero audit record. Must 502 instead (spec §14
    fail-closed is bidirectional)."""
    from mitmproxy.http import Response
    addon = _make_addon_with_registered_host(tmp_path)

    def _boom(*a, **k):
        raise ChainAppendError("simulated disk full")
    monkeypatch.setattr(addon._chain, "append", _boom)

    flow = tflow.tflow(req=tflow.treq(
        host="api.anthropic.com", port=443, scheme=b"https",
        method=b"POST", path=b"/v1/messages",
        content=b'{"messages": []}',
    ))
    flow.response = Response.make(
        200,
        json.dumps({"content": [{"type": "text", "text": "hi"}]}).encode(),
        {"content-type": "application/json"},
    )
    with taddons.context(addon) as _:
        addon.response(flow)

    assert flow.response.status_code == 502
    body = json.loads(flow.response.content)
    assert body["error"] == "waterwall-chain-append-failed"


def test_response_path_sse_chain_failure_502s(tmp_path: Path, monkeypatch):
    """Argus issue #17, streaming branch: the SSE rewriter's detokenization
    chain entry must also fail closed — the rewritten stream is replaced by a
    502 body instead of being delivered unaudited."""
    from mitmproxy.http import Response
    addon = _make_addon_with_registered_host(tmp_path)

    def _boom(*a, **k):
        raise ChainAppendError("simulated disk full")
    monkeypatch.setattr(addon._chain, "append", _boom)

    sse_body = (
        b'event: message_start\ndata: {"type": "message_start"}\n\n'
        b'event: message_stop\ndata: {"type": "message_stop"}\n\n'
    )
    flow = tflow.tflow(req=tflow.treq(
        host="api.anthropic.com", port=443, scheme=b"https",
        method=b"POST", path=b"/v1/messages",
        content=b'{"messages": []}',
    ))
    flow.response = Response.make(
        200, sse_body, {"content-type": "text/event-stream"},
    )
    with taddons.context(addon) as _:
        addon.response(flow)

    assert flow.response.status_code == 502
    body = json.loads(flow.response.content)
    assert body["error"] == "waterwall-chain-append-failed"
