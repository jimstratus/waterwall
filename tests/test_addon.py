# tests/test_addon.py
"""v2 §4.5 — chain entries must carry per-host attribution.

These tests assert the addon emits `host` on both egress (redaction)
and ingress (detokenization) chain.append payloads. The SSE-handler
host-emission paths are covered by tests/test_sse_openai.py and
tests/test_sse_audit_chain.py.
"""
import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from mitmproxy.test import tflow, taddons

from waterwall.proxy.addon import WaterwallAddon
from waterwall.proxy.sse import SseStreamRewriter


@pytest.fixture
def addon_with_chain_spy(tmp_path: Path):
    """Real addon with a MagicMock chain — lets us assert call_args without
    parsing the JSONL log on disk. Real PlaceholderStore + Tokenizer kept so
    walker logic still functions."""
    a = WaterwallAddon(chain_path=tmp_path / "proxy.jsonl", session_key=os.urandom(32))
    # Replace chain with a spy AFTER construction (the real ChainWriter already
    # opened the JSONL + lockfile; we just don't care about its writes here).
    a._chain = MagicMock()
    # v2 §4.2: addon gates request()/response() on _sse_handlers presence.
    a._sse_handlers["api.anthropic.com"] = SseStreamRewriter(store=a._store)
    return a


def test_request_chain_entry_has_host_field(addon_with_chain_spy):
    """v2 §4.5: each egress redaction chain entry must include the upstream host."""
    addon = addon_with_chain_spy
    flow = tflow.tflow(
        req=tflow.treq(
            host="api.anthropic.com", port=443, scheme=b"https",
            method=b"POST", path=b"/v1/messages",
            headers=((b"content-type", b"application/json"),),
            content=json.dumps({
                "messages": [{"role": "user", "content": "leak AKIAIOSFODNN7EXAMPLE"}],
            }).encode(),
        )
    )
    with taddons.context(addon) as _:
        addon.request(flow)

    # Find the redaction entry (filter — not all calls are redactions; e.g.,
    # killswitch/checkpoint paths produce different payloads).
    payloads = [c[0][0] for c in addon._chain.append.call_args_list]
    redaction_entries = [p for p in payloads if p.get("line_type") == "redaction"]
    assert redaction_entries, f"expected a redaction entry; got {payloads}"
    for entry in redaction_entries:
        assert entry.get("host") == "api.anthropic.com", \
            f"redaction entry missing host: {entry}"
        assert entry.get("direction") == "out"


def test_response_chain_entry_has_host_field(addon_with_chain_spy):
    """v2 §4.5: ingress detokenization chain entries must also carry host."""
    addon = addon_with_chain_spy
    flow = tflow.tflow(
        req=tflow.treq(
            host="api.anthropic.com", port=443, scheme=b"https",
            method=b"POST", path=b"/v1/messages",
            headers=((b"content-type", b"application/json"),),
            content=json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode(),
        )
    )
    flow.response = tflow.tresp(
        status_code=200,
        headers=((b"content-type", b"application/json"),),
        content=json.dumps({
            "content": [{"type": "text", "text": "no placeholders here"}]
        }).encode(),
    )
    with taddons.context(addon) as _:
        addon.response(flow)

    payloads = [c[0][0] for c in addon._chain.append.call_args_list]
    detok_entries = [p for p in payloads if p.get("line_type") == "detokenization"]
    assert detok_entries, f"expected a detokenization entry; got {payloads}"
    for entry in detok_entries:
        assert entry.get("host") == "api.anthropic.com", \
            f"detokenization entry missing host: {entry}"
        assert entry.get("direction") == "in"
