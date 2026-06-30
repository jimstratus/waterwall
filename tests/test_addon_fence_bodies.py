# tests/test_addon_fence_bodies.py
"""Empty / non-JSON request and response bodies must silent-skip — never crash,
never write a redaction/detokenization chain line, and never mutate the body.

Spec §5 / CLAUDE.md "v1 silent-failure surfaces": the addon's request() and
response() each gate on `if not content: return` and `except JSONDecodeError:
return`. These were untested (BACKLOG phase-2-7 / phase-3-2). The silent-skip is
the core fail-safe contract: a malformed or empty body from a bypassing client
must not raise into mitmproxy (which would 500 the flow) and must not log a
spurious/no-op audit line.

These pins assert the negative — no exception, no chain.append call, original
content bytes passed through — so a future refactor that e.g. hoists the JSON
parse above the empty check, or removes the try/except, fails loudly here.
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
def addon(tmp_path: Path):
    """Minimal addon: chain spy (no disk) + an SSE handler for the permitted
    host so request()/response() pass the gating `if host not in self._sse_handlers`
    check. session_key is required for WaterwallAddon construction."""
    a = WaterwallAddon(chain_path=tmp_path / "proxy.jsonl", session_key=os.urandom(32))
    a._chain = MagicMock()
    a._sse_handlers["api.anthropic.com"] = SseStreamRewriter(store=a._store)
    # Avoid the real ChainWriter needing a signer / disk during the no-op paths.
    return a


def _req(content):
    return tflow.tflow(
        req=tflow.treq(
            host="api.anthropic.com", port=443, scheme=b"https",
            method=b"POST", path=b"/v1/messages",
            headers=((b"content-type", b"application/json"),),
            content=content,
        )
    )


# ---------------------------------------------------------------------------
# request() — outbound
# ---------------------------------------------------------------------------

def test_request_empty_body_bytes_silent_skips(addon):
    flow = _req(b"")
    with taddons.context(addon) as _:
        addon.request(flow)
    assert addon._chain.append.call_args_list == []
    assert flow.request.content == b""   # untouched, no json.dumps(None) garbage


def test_request_none_content_silent_skips(addon):
    # mitmproxy can present content=None (e.g. a body-stripped flow). The
    # `if not flow.request.content: return` guard treats None as falsy → returns.
    flow = _req(None)
    with taddons.context(addon) as _:
        addon.request(flow)  # must not raise
    assert addon._chain.append.call_args_list == []


def test_request_non_json_body_silent_skips(addon):
    flow = _req(b"<html>not json</html>")
    with taddons.context(addon) as _:
        addon.request(flow)
    assert addon._chain.append.call_args_list == []
    # Non-JSON content must pass through byte-unchanged (no rewrite attempted).
    assert flow.request.content == b"<html>not json</html>"


def test_request_empty_string_object_silent_skips(addon):
    """A valid JSON object whose only scannable leaf is an empty string must
    redact-match nothing and NOT write any chain line — distinct from the
    non-JSON case: this one DOES go through json.dumps rewrite (escape pass on
    empty leaf is a no-op), but emits zero redaction entries."""
    flow = _req(json.dumps({"messages": [{"role": "user", "content": ""}]}).encode())
    with taddons.context(addon) as _:
        addon.request(flow)
    # No redaction line (no matches); content rewritten to canonical JSON.
    payloads = [c[0][0] for c in addon._chain.append.call_args_list]
    assert [p for p in payloads if p.get("line_type") == "redaction"] == []


# ---------------------------------------------------------------------------
# response() — inbound
# ---------------------------------------------------------------------------

def _resp(content, ctype=b"application/json"):
    flow = _req(json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode())
    flow.response = tflow.tresp(
        status_code=200,
        headers=((b"content-type", ctype),),
        content=content,
    )
    return flow


def test_response_empty_body_silent_skips(addon):
    flow = _resp(b"")
    with taddons.context(addon) as _:
        addon.response(flow)
    assert addon._chain.append.call_args_list == []
    assert flow.response.content == b""


def test_response_non_json_body_silent_skips(addon):
    flow = _resp(b"<html>upstream error page</html>")
    with taddons.context(addon) as _:
        addon.response(flow)
    assert addon._chain.append.call_args_list == []
    assert flow.response.content == b"<html>upstream error page</html>"


def test_response_json_with_no_placeholders_writes_detok_line(addon):
    """Contrast pin: a normal JSON response with NO placeholders DOES write a
    detokenization line (detok_count=0) — so the silent-skip only triggers on
    empty/non-JSON, not on 'nothing matched'. Guards against over-suppression."""
    flow = _resp(json.dumps({"content": [{"type": "text", "text": "plain reply"}]}).encode())
    with taddons.context(addon) as _:
        addon.response(flow)
    payloads = [c[0][0] for c in addon._chain.append.call_args_list]
    detok = [p for p in payloads if p.get("line_type") == "detokenization"]
    assert detok and detok[0]["detok_count"] == 0