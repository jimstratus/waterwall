# tests/test_sse_parser.py
"""SSE-event-stream parser: split byte chunks into (event, data) pairs."""

from waterwall.proxy.sse import SseLineSplitter


def test_split_single_event():
    splitter = SseLineSplitter()
    events = list(splitter.feed(b"event: ping\ndata: {}\n\n"))
    assert events == [("ping", "{}")]


def test_split_multiple_events_in_one_chunk():
    splitter = SseLineSplitter()
    chunk = (
        b"event: message_start\ndata: {\"type\":\"message_start\"}\n\n"
        b"event: ping\ndata: {}\n\n"
    )
    events = list(splitter.feed(chunk))
    assert len(events) == 2
    assert events[0][0] == "message_start"
    assert events[1][0] == "ping"


def test_split_event_across_chunks():
    splitter = SseLineSplitter()
    out = list(splitter.feed(b"event: message_start\ndata: {\"ty"))
    assert out == []
    out = list(splitter.feed(b'pe":"message_start"}\n\n'))
    assert len(out) == 1
    assert out[0][0] == "message_start"


def test_crlf_framed_stream_splits():
    """SSE-legal \\r\\n\\r\\n framing must split — it previously yielded nothing
    and the whole response body was replaced with empty bytes (argus #14)."""
    s = SseLineSplitter()
    chunk = b"event: ping\r\ndata: {}\r\n\r\n"
    events = list(s.feed(chunk))
    assert events == [("ping", "{}")]


def test_rewriter_flushes_unterminated_tail():
    """A truncated upstream stream must not silently lose its tail bytes (argus #14)."""
    from unittest.mock import MagicMock
    from waterwall.proxy.sse import SseStreamRewriter
    from waterwall.proxy.store import PlaceholderStore

    complete = (
        b"event: content_block_start\ndata: "
        b'{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'
    )
    truncated_tail = b'event: content_block_delta\ndata: {"index": 0'

    flow = MagicMock()
    flow.request.host = "api.anthropic.com"
    flow.request.headers = {}
    flow.response.content = complete + truncated_tail

    rewriter = SseStreamRewriter(store=PlaceholderStore())
    rewriter.rewrite(flow)
    assert truncated_tail in flow.response.content, "unterminated tail bytes were dropped"
