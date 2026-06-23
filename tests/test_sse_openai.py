# tests/test_sse_openai.py
"""OpenAI Chat Completions SSE handler — v2 spec §4.2."""
import json
from unittest.mock import MagicMock

import pytest

from waterwall.proxy.sse_openai import OpenAiSseHandler
from waterwall.proxy.store import PlaceholderStore


def _make_flow(body_bytes: bytes, host: str = "api.deepseek.com"):
    flow = MagicMock()
    flow.request.host = host  # v2 §4.5 — chain entries carry per-host attribution
    flow.response.content = body_bytes
    flow.response.set_content = MagicMock()
    return flow


def test_single_chunk_with_placeholder_restored():
    """OpenAI SSE: each `data:` line is a JSON delta. Placeholders in
    delta.content must be restored to plaintext."""
    store = MagicMock()
    store.get.return_value = "AKIAIOSFODNN7EXAMPLE"
    chain = MagicMock()
    handler = OpenAiSseHandler(store=store, chain=chain)

    body = (
        b'data: {"choices":[{"delta":{"content":"hello <pl:AWS_ACCESS_KEY:d7d27033d7d27033>"}}]}\n\n'
        b"data: [DONE]\n\n"
    )
    flow = _make_flow(body)
    handler.rewrite(flow)

    written = flow.response.set_content.call_args[0][0]
    assert b"AKIAIOSFODNN7EXAMPLE" in written
    assert b"<pl:AWS_ACCESS_KEY:d7d27033d7d27033>" not in written
    # Audit: one aggregate detokenization chain entry per stream (issue #9)
    assert chain.append.call_count == 1
    call_args = chain.append.call_args[0][0]
    assert call_args["line_type"] == "detokenization"
    assert call_args["direction"] == "in"
    # v2 §4.5 — chain entry must carry the upstream host
    assert call_args["host"] == "api.deepseek.com"


def test_multiple_chunks_aggregate_into_one_chain_entry():
    """Argus issue #9: restoration now runs on the JOINED per-choice content
    (per-chunk matching missed placeholders straddling deltas), so audit
    granularity is ONE detokenization entry per stream with aggregate counts —
    replaces the v1-style per-chunk entries."""
    store = MagicMock()
    store.get.side_effect = ["AKIAIOSFODNN7EXAMPLE", "ghp_" + "X" * 36]
    chain = MagicMock()
    handler = OpenAiSseHandler(store=store, chain=chain)

    body = (
        b'data: {"choices":[{"delta":{"content":"<pl:AWS_ACCESS_KEY:aaaaaaaaaaaaaaaa>"}}]}\n\n'
        b'data: {"choices":[{"delta":{"content":"<pl:GITHUB_TOKEN:bbbbbbbbbbbbbbbb>"}}]}\n\n'
        b"data: [DONE]\n\n"
    )
    flow = _make_flow(body)
    handler.rewrite(flow)
    assert chain.append.call_count == 1
    entry = chain.append.call_args[0][0]
    assert entry["detok_count"] == 2
    assert entry["unknown_placeholders"] == 0
    assert entry["types"] == ["AWS_ACCESS_KEY", "GITHUB_TOKEN"]


def test_done_terminator_passes_through():
    """`data: [DONE]\\n\\n` is OpenAI's stream terminator. Pass through
    unchanged; no detokenization, no chain entry (no content)."""
    store = MagicMock()
    chain = MagicMock()
    handler = OpenAiSseHandler(store=store, chain=chain)
    body = b"data: [DONE]\n\n"
    flow = _make_flow(body)
    handler.rewrite(flow)
    written = flow.response.set_content.call_args[0][0]
    assert written == body
    chain.append.assert_not_called()


def test_unknown_placeholder_passes_through_with_counter():
    """Spec §4.5 + v1 design: server-fabricated placeholders pass through
    unchanged; unknown_placeholders counter increments on the chain entry."""
    store = MagicMock()
    store.get.return_value = None  # not in store
    chain = MagicMock()
    handler = OpenAiSseHandler(store=store, chain=chain)
    body = b'data: {"choices":[{"delta":{"content":"<pl:AWS_ACCESS_KEY:deadbeefdeadbeef>"}}]}\n\ndata: [DONE]\n\n'
    flow = _make_flow(body)
    handler.rewrite(flow)
    written = flow.response.set_content.call_args[0][0]
    assert b"<pl:AWS_ACCESS_KEY:deadbeefdeadbeef>" in written  # passed through
    call_args = chain.append.call_args[0][0]
    assert call_args["unknown_placeholders"] == 1


def test_empty_delta_no_chain_entry():
    """`{"choices":[{"delta":{}}]}` (no content) should not produce an
    audit entry."""
    store = MagicMock()
    chain = MagicMock()
    handler = OpenAiSseHandler(store=store, chain=chain)
    body = b'data: {"choices":[{"delta":{}}]}\n\ndata: [DONE]\n\n'
    flow = _make_flow(body)
    handler.rewrite(flow)
    chain.append.assert_not_called()


def test_malformed_chunk_logged_not_raised():
    """A non-JSON `data:` line should not crash the handler — log + skip."""
    store = MagicMock()
    chain = MagicMock()
    handler = OpenAiSseHandler(store=store, chain=chain)
    body = b"data: not-json-at-all\n\ndata: [DONE]\n\n"
    flow = _make_flow(body)
    # Must not raise
    handler.rewrite(flow)
    written = flow.response.set_content.call_args[0][0]
    # Bad chunk passed through unchanged
    assert b"not-json-at-all" in written


# ---------------------------------------------------------------------------
# Argus issue #9 — canonical regex + cross-chunk restoration
# ---------------------------------------------------------------------------


@pytest.fixture
def make_handler():
    """Build (handler, real PlaceholderStore, flow) — flow.response.set_content
    assigns .content so tests can inspect the rewritten body directly."""
    def _make(host: str = "api.deepseek.com"):
        store = PlaceholderStore()
        chain = MagicMock()
        handler = OpenAiSseHandler(store=store, chain=chain)
        flow = MagicMock()
        flow.request.host = host
        flow.request.headers = {}
        flow.response.content = b""

        def _set_content(b: bytes) -> None:
            flow.response.content = b

        flow.response.set_content = _set_content
        return handler, store, flow

    return _make


def _chunk(payload: dict) -> bytes:
    return b"data: " + json.dumps(payload).encode()


def _delta(content: str) -> dict:
    return {"id": "x", "choices": [{"index": 0, "delta": {"content": content}}]}


def test_full_placeholder_in_single_chunk_restores(make_handler):
    """Argus issue #9: the local regex required 8 hex chars; real placeholders
    carry 16. This is the regression test for the regex drift."""
    handler, store, flow = make_handler()
    hmac8 = "ab" * 8                                  # 16 hex chars
    store.put(hmac8, "sk-ant-api03-SECRET")
    body = b"\n\n".join([
        _chunk(_delta(f"key is <pl:ANTHROPIC_KEY:{hmac8}>")),
        b"data: [DONE]",
    ])
    flow.response.content = body
    handler.rewrite(flow)
    assert b"sk-ant-api03-SECRET" in flow.response.content
    assert b"<pl:" not in flow.response.content


def test_placeholder_split_across_chunks_restores(make_handler):
    """A placeholder echoed across two deltas (the COMMON case at 1-5 tokens
    per delta) must restore. Argus issue #9, second finding."""
    handler, store, flow = make_handler()
    hmac8 = "cd" * 8
    store.put(hmac8, "AKIAIOSFODNN7EXAMPLE")
    ph = f"<pl:AWS_ACCESS_KEY:{hmac8}>"
    body = b"\n\n".join([
        _chunk(_delta("the key " + ph[:10])),
        _chunk(_delta(ph[10:] + " ends")),
        b"data: [DONE]",
    ])
    flow.response.content = body
    handler.rewrite(flow)
    joined = flow.response.content
    assert b"AKIAIOSFODNN7EXAMPLE" in joined
    assert b"<pl:" not in joined


def test_escaped_literal_unescapes(make_handler):
    """spec §5.2 round-trip: a literal `<pl:` escaped outbound must come back
    unescaped on the OpenAI path too."""
    handler, store, flow = make_handler()
    body = b"\n\n".join([
        _chunk(_delta("doc says <pl-esc:FOO:0011223344556677> here")),
        b"data: [DONE]",
    ])
    flow.response.content = body
    handler.rewrite(flow)
    assert b"<pl:FOO:0011223344556677>" in flow.response.content


def test_chain_append_failure_502s_instead_of_delivering():
    """Argus issue #17 (follow-up found during Task 25): a ChainAppendError
    while appending the detokenization audit line must NOT deliver the
    restored secrets — bidirectional fail-closed (spec §14), same contract
    as addon.response() and SseStreamRewriter.rewrite()."""
    from waterwall.audit.chain import ChainAppendError
    store = MagicMock()
    store.get.return_value = "AKIAIOSFODNN7EXAMPLE"
    chain = MagicMock()
    chain.append.side_effect = ChainAppendError("disk full")
    handler = OpenAiSseHandler(store=store, chain=chain)

    body = (
        b'data: {"choices":[{"delta":{"content":"hello <pl:AWS_ACCESS_KEY:d7d27033d7d27033>"}}]}\n\n'
        b"data: [DONE]\n\n"
    )
    flow = _make_flow(body)
    handler.rewrite(flow)

    assert flow.response.status_code == 502
    payload = json.loads(flow.response.content)
    assert payload["error"] == "waterwall-chain-append-failed"
