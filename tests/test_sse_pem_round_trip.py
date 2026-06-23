# tests/test_sse_pem_round_trip.py
"""SSE buffered-response path: a redacted RSA-4096 PEM placeholder echoed back
across torn text_delta events must reassemble to the exact original key —
zero truncation (issue #21, operator concern).

Covers both feed() (event-level) and rewrite(flow) (the v1
buffer-the-full-response entry point the addon dispatches to).
"""
import json
import os

from mitmproxy.test import tflow

from waterwall.proxy.sse import SseLineSplitter, SseStreamRewriter
from waterwall.proxy.store import PlaceholderStore
from waterwall.proxy.tokenizer import Tokenizer


# rsa_4096_pem comes from tests/conftest.py (session-scoped).


def _seed_store(pem: str) -> tuple[PlaceholderStore, str]:
    tok = Tokenizer(os.urandom(32))
    store = PlaceholderStore()
    placeholder = tok.tokenize(pem, "PEM_BLOCK")
    hmac8 = placeholder.removeprefix("<pl:PEM_BLOCK:").removesuffix(">")
    store.put(hmac8, pem)
    return store, placeholder

def _delta_event(text: str) -> tuple[str, str]:
    return (
        "content_block_delta",
        json.dumps({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": text},
        }),
    )


def _build_stream(*events: tuple[str, str]) -> bytes:
    out = bytearray()
    for name, data in events:
        out.extend(f"event: {name}\ndata: {data}\n\n".encode())
    return bytes(out)


def _accumulated_text(sse_bytes: bytes) -> str:
    """Reassemble all index-0 text_delta text from a rewritten SSE stream."""
    splitter = SseLineSplitter()
    text = ""
    for name, data in splitter.feed(sse_bytes):
        if name != "content_block_delta":
            continue
        obj = json.loads(data)
        delta = obj.get("delta", {})
        if delta.get("type") == "text_delta":
            text += delta.get("text", "")
    assert not splitter.residue()
    return text


def _events_for(placeholder: str, chunk_len: int = 7) -> list[tuple[str, str]]:
    """The model echoes the placeholder torn into tiny text_delta pieces,
    framed by prose — worst case for buffered reassembly."""
    full_text = f"your key was:\n{placeholder}\ndo not share it"
    pieces = [full_text[i : i + chunk_len] for i in range(0, len(full_text), chunk_len)]
    events = [
        ("message_start", '{"type":"message_start","message":{"id":"m1"}}'),
        ("content_block_start",
         '{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}'),
    ]
    events += [_delta_event(p) for p in pieces]
    events += [
        ("content_block_stop", '{"type":"content_block_stop","index":0}'),
        ("message_stop", '{"type":"message_stop"}'),
    ]
    return events


def test_pem_placeholder_torn_across_deltas_reassembles_exactly(rsa_4096_pem):
    store, placeholder = _seed_store(rsa_4096_pem)
    rewriter = SseStreamRewriter(store=store)
    stream = _build_stream(*_events_for(placeholder))

    out = b"".join(rewriter.feed(stream)) + rewriter._splitter.residue()
    restored = _accumulated_text(out)
    expected = f"your key was:\n{rsa_4096_pem}\ndo not share it"
    assert restored == expected  # byte-exact incl. every PEM line
    assert b"<pl:" not in out


def test_pem_round_trips_through_rewrite_flow_entry_point(rsa_4096_pem):
    """rewrite(flow) — the addon's actual dispatch target — with the
    placeholder torn at a different (11-char) delta granularity."""
    store, placeholder = _seed_store(rsa_4096_pem)
    rewriter = SseStreamRewriter(store=store)
    stream = _build_stream(*_events_for(placeholder, chunk_len=11))

    flow = tflow.tflow(
        req=tflow.treq(host="api.anthropic.com", port=443, scheme=b"https",
                       method=b"POST", path=b"/v1/messages"),
        resp=tflow.tresp(
            status_code=200,
            headers=((b"content-type", b"text/event-stream"),),
            content=stream,
        ),
    )
    rewriter.rewrite(flow)

    restored = _accumulated_text(flow.response.content)
    expected = f"your key was:\n{rsa_4096_pem}\ndo not share it"
    assert restored == expected
    assert b"<pl:" not in flow.response.content
