# tests/test_sse_rewriter.py
"""Strategy (b): buffer text/input_json/thinking/citations deltas per content_block index;
finalize substitution at content_block_stop."""

import os
from waterwall.proxy.sse import SseStreamRewriter
from waterwall.proxy.tokenizer import Tokenizer
from waterwall.proxy.store import PlaceholderStore


def _build_stream(*events: tuple[str, str]) -> bytes:
    out = bytearray()
    for name, data in events:
        out.extend(f"event: {name}\ndata: {data}\n\n".encode())
    return bytes(out)


def test_stream_substitutes_text_at_block_stop():
    tok = Tokenizer(os.urandom(32))
    store = PlaceholderStore()
    placeholder = tok.tokenize("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY")
    hmac8 = placeholder.removeprefix("<pl:AWS_ACCESS_KEY:").removesuffix(">")
    store.put(hmac8, "AKIAIOSFODNN7EXAMPLE")

    rewriter = SseStreamRewriter(store=store)
    stream = _build_stream(
        ("message_start", '{"type":"message_start","message":{"id":"m1"}}'),
        ("content_block_start", '{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}'),
        ("content_block_delta", '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"prefix "}}'),
        ("content_block_delta", '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"' + placeholder + '"}}'),
        ("content_block_stop", '{"type":"content_block_stop","index":0}'),
        ("message_stop", '{"type":"message_stop"}'),
    )
    out = b"".join(rewriter.feed(stream))
    assert b"AKIAIOSFODNN7EXAMPLE" in out
    assert b"<pl:" not in out


def test_stream_handles_torn_input_json_delta():
    """Placeholder split across two partial_json deltas must reassemble."""
    tok = Tokenizer(os.urandom(32))
    store = PlaceholderStore()
    placeholder = tok.tokenize("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY")
    hmac8 = placeholder.removeprefix("<pl:AWS_ACCESS_KEY:").removesuffix(">")
    store.put(hmac8, "AKIAIOSFODNN7EXAMPLE")

    half = len(placeholder) // 2
    p1 = placeholder[:half]
    p2 = placeholder[half:]

    rewriter = SseStreamRewriter(store=store)
    stream = _build_stream(
        ("content_block_start", '{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"foo","input":{}}}'),
        ("content_block_delta", '{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"' + p1 + '"}}'),
        ("content_block_delta", '{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"' + p2 + '"}}'),
        ("content_block_stop", '{"type":"content_block_stop","index":0}'),
    )
    out = b"".join(rewriter.feed(stream))
    assert b"AKIAIOSFODNN7EXAMPLE" in out, "torn placeholder must reassemble across deltas"


def test_stream_passes_through_signature_delta():
    rewriter = SseStreamRewriter(store=PlaceholderStore())
    stream = _build_stream(
        ("content_block_delta", '{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"<pl:FAKE:0011223344556677>"}}'),
    )
    out = b"".join(rewriter.feed(stream))
    assert b"signature_delta" in out
    assert b"<pl:FAKE:0011223344556677>" in out, "signature is server-issued; do not substitute"


def test_stream_unknown_placeholder_passes_through():
    rewriter = SseStreamRewriter(store=PlaceholderStore())
    stream = _build_stream(
        ("content_block_start", '{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}'),
        ("content_block_delta", '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"see <pl:X:0000000000000000>"}}'),
        ("content_block_stop", '{"type":"content_block_stop","index":0}'),
    )
    out = b"".join(rewriter.feed(stream))
    assert b"<pl:X:0000000000000000>" in out


def _collect_text_deltas(raw: bytes) -> str:
    """Parse an SSE output stream and concatenate every delta.text."""
    import json
    text = ""
    for block in raw.decode("utf-8").split("\n\n"):
        data_lines = [
            line[len("data:"):].lstrip()
            for line in block.split("\n")
            if line.startswith("data:")
        ]
        if not data_lines:
            continue
        try:
            obj = json.loads("\n".join(data_lines))
        except json.JSONDecodeError:
            continue
        delta = obj.get("delta") or {}
        text += delta.get("text", "")
    return text


def test_hard_cap_flushes_buffer_instead_of_destroying():
    """Argus issue #14: on cap breach the buffered text (already replaced on
    the wire by heartbeats) must be FLUSHED unsubstituted, not discarded."""
    import json
    import waterwall.proxy.sse as sse_mod

    rewriter = SseStreamRewriter(store=PlaceholderStore())
    old_cap = sse_mod.BUFFER_HARD_CAP_BYTES
    sse_mod.BUFFER_HARD_CAP_BYTES = 1024
    try:
        big = "A" * 600
        stream = _build_stream(
            ("content_block_start", '{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}'),
            ("content_block_delta", json.dumps(
                {"type": "content_block_delta", "index": 0,
                 "delta": {"type": "text_delta", "text": big}})),
            # second delta breaches the 1024-byte cap
            ("content_block_delta", json.dumps(
                {"type": "content_block_delta", "index": 0,
                 "delta": {"type": "text_delta", "text": big}})),
            ("content_block_stop", '{"type":"content_block_stop","index":0}'),
        )
        out = b"".join(rewriter.feed(stream))
        text = _collect_text_deltas(out)
        assert text.count("A") == 1200, "buffered prefix was destroyed on cap breach"
    finally:
        sse_mod.BUFFER_HARD_CAP_BYTES = old_cap


def test_citations_not_duplicated_into_text():
    """Argus issue #14: cited_text/document_title must NOT be appended to the
    text buffer — they were being re-emitted inside the consolidated text_delta."""
    import json

    rewriter = SseStreamRewriter(store=PlaceholderStore())
    stream = _build_stream(
        ("content_block_start", '{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}'),
        ("content_block_delta", '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Answer."}}'),
        ("content_block_delta", json.dumps(
            {"type": "content_block_delta", "index": 0,
             "delta": {"type": "citations_delta",
                       "citation": {"cited_text": "SOURCE QUOTE",
                                    "document_title": "Doc"}}})),
        ("content_block_stop", '{"type":"content_block_stop","index":0}'),
    )
    out = b"".join(rewriter.feed(stream))
    text = _collect_text_deltas(out)
    assert "SOURCE QUOTE" not in text, "citation quote spliced into message text"
    assert "Answer." in text
    # The citations_delta event itself must still pass through to the client
    assert b"citations_delta" in out
    assert b"SOURCE QUOTE" in out


def test_server_tool_use_consolidates_as_input_json_delta():
    """Argus issue #14: server_tool_use streams input_json_delta but the
    consolidated delta was emitted as text_delta, breaking SDK accumulators."""
    rewriter = SseStreamRewriter(store=PlaceholderStore())
    stream = _build_stream(
        ("content_block_start", '{"type":"content_block_start","index":0,"content_block":{"type":"server_tool_use","id":"st","name":"web_search","input":{}}}'),
        ("content_block_delta", '{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"q\\": 1}"}}'),
        ("content_block_stop", '{"type":"content_block_stop","index":0}'),
    )
    out = b"".join(rewriter.feed(stream))
    assert b'"input_json_delta"' in out
    # The consolidated delta must NOT be a text_delta carrying the JSON
    assert b'"text": "{\\"q\\": 1}"' not in out


def test_rewrite_resets_state_between_flows():
    """v2 §4.2: one SseStreamRewriter instance is registered per host and
    serves every flow for that host. State (splitter buffer, content-block
    buffers, block_meta, pending output) MUST clear at rewrite() entry, else
    a truncated/malformed stream from flow A leaks bytes into flow B."""
    from unittest.mock import MagicMock
    tok = Tokenizer(os.urandom(32))
    store = PlaceholderStore()
    placeholder = tok.tokenize("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY")
    hmac8 = placeholder.removeprefix("<pl:AWS_ACCESS_KEY:").removesuffix(">")
    store.put(hmac8, "AKIAIOSFODNN7EXAMPLE")

    rewriter = SseStreamRewriter(store=store)

    # Flow A: truncated mid-block (no content_block_stop) — leaves stale
    # _buffers[0] and possibly partial bytes in _splitter._buf.
    truncated = (
        b"event: content_block_start\ndata: "
        b'{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'
        b"event: content_block_delta\ndata: "
        b'{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"FLOW-A-LEAK"}}\n\n'
    )
    flow_a = MagicMock()
    flow_a.request.host = "api.anthropic.com"
    flow_a.request.headers = {}
    flow_a.response.content = truncated
    rewriter.rewrite(flow_a)

    # Flow B: well-formed, independent stream that should NOT see "FLOW-A-LEAK"
    flow_b_bytes = _build_stream(
        ("content_block_start", '{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}'),
        ("content_block_delta", '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"' + placeholder + '"}}'),
        ("content_block_stop", '{"type":"content_block_stop","index":0}'),
    )
    flow_b = MagicMock()
    flow_b.request.host = "api.anthropic.com"
    flow_b.request.headers = {}
    flow_b.response.content = flow_b_bytes
    rewriter.rewrite(flow_b)

    assert b"FLOW-A-LEAK" not in flow_b.response.content
    assert b"AKIAIOSFODNN7EXAMPLE" in flow_b.response.content
