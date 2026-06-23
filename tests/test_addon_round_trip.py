# tests/test_addon_round_trip.py
import json
import os
from pathlib import Path

import pytest
from mitmproxy.test import tflow, taddons

from waterwall.proxy.addon import WaterwallAddon


@pytest.fixture
def addon(tmp_path: Path):
    a = WaterwallAddon(chain_path=tmp_path / "proxy.jsonl", session_key=os.urandom(32))
    # v2 §4.2: addon gates on _sse_handlers; seed Anthropic-only for v1 tests.
    from waterwall.proxy.sse import SseStreamRewriter
    a._sse_handlers["api.anthropic.com"] = SseStreamRewriter(store=a._store)
    return a


def test_round_trip_aws_key(addon):
    """Outbound: substitute. Inbound: restore. Client sees plaintext."""
    flow = tflow.tflow(
        req=tflow.treq(
            host="api.anthropic.com", port=443, scheme=b"https",
            method=b"POST", path=b"/v1/messages",
            headers=((b"content-type", b"application/json"),),
            content=json.dumps({
                "messages": [{"role": "user", "content": "echo AKIAIOSFODNN7EXAMPLE"}],
            }).encode(),
        )
    )
    with taddons.context(addon) as _:
        addon.request(flow)

    sent_body = json.loads(flow.request.content)
    assert "AKIAIOSFODNN7EXAMPLE" not in sent_body["messages"][0]["content"]
    placeholder_match = sent_body["messages"][0]["content"]
    assert "<pl:AWS_ACCESS_KEY:" in placeholder_match

    # Simulate Anthropic echoing the placeholder back
    flow.response = tflow.tresp(
        status_code=200,
        headers=((b"content-type", b"application/json"),),
        content=json.dumps({
            "content": [
                {"type": "text", "text": f"got it: {placeholder_match}"}
            ],
        }).encode(),
    )
    with taddons.context(addon) as _:
        addon.response(flow)

    final = json.loads(flow.response.content)
    assert "AKIAIOSFODNN7EXAMPLE" in final["content"][0]["text"]
    assert "<pl:" not in final["content"][0]["text"]


def test_round_trip_handles_query_string_path(addon):
    """Spec parity: response() must apply the same query-string stripping as
    request(). Codex flagged this in argus run 20260506T191904Z (Phase 3
    deferred finding); plan amended pre-implementation to bake it in."""
    flow = tflow.tflow(
        req=tflow.treq(
            host="api.anthropic.com", port=443, scheme=b"https",
            method=b"POST", path=b"/v1/messages?stream=true",
            headers=((b"content-type", b"application/json"),),
            content=json.dumps({
                "messages": [{"role": "user", "content": "echo AKIAIOSFODNN7EXAMPLE"}],
            }).encode(),
        )
    )
    with taddons.context(addon) as _:
        addon.request(flow)
    sent_body = json.loads(flow.request.content)
    placeholder_match = sent_body["messages"][0]["content"]
    assert "<pl:AWS_ACCESS_KEY:" in placeholder_match  # outbound substitution worked

    flow.response = tflow.tresp(
        status_code=200,
        headers=((b"content-type", b"application/json"),),
        content=json.dumps({
            "content": [{"type": "text", "text": f"got it: {placeholder_match}"}]
        }).encode(),
    )
    with taddons.context(addon) as _:
        addon.response(flow)

    final = json.loads(flow.response.content)
    assert "AKIAIOSFODNN7EXAMPLE" in final["content"][0]["text"]
    assert "<pl:" not in final["content"][0]["text"]
