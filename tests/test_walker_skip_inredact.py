# tests/test_walker_skip_inredact.py
"""redact_in_place's internal `_process` walker must honor SKIP_PATH_TAILS —
independently of `walk_request_body`.

The skip-rule logic is DUPLICATED: `walk_request_body` (the path-yielder, tested
in test_walker.py) AND `redact_in_place._process` (the in-place recursor) each
call `_skip_key`. A value that MATCHES a pattern but sits under a skipped path
tail (e.g. `{"model": "AKIAIOSFODNN7EXAMPLE"}`) must NOT be redacted —
redacting a protocol metadata field that the server echoes would corrupt the
request. BACKLOG phase-2-5 line 41: this duplication has no test, so a future
change to `_process` that drops its `_skip_key` call would silently start
redacting protocol metadata with no test failing.
"""
import os

from waterwall.proxy.patterns import scan_string
from waterwall.proxy.store import PlaceholderStore
from waterwall.proxy.tokenizer import Tokenizer
from waterwall.proxy.walker import redact_in_place


def _round_trip(body):
    tok = Tokenizer(os.urandom(32))
    store = PlaceholderStore()
    events = redact_in_place(body, tokenizer=tok, store=store, scanner=scan_string)
    return events, store


def test_skipped_key_with_matching_value_is_not_redacted():
    """`model` is in SKIP_PATH_TAILS; its value here MATCHES the AWS pattern.
    _process must skip it (no event, value byte-unchanged), while a matching
    value under a non-skipped key in the same body IS redacted — proving the
    skip is path-specific, not a scanner regression."""
    body = {
        "model": "AKIAIOSFODNN7EXAMPLE",  # skipped path tail
        "messages": [{"role": "user", "content": "also AKIAIOSFODNN7EXAMPLE"}],
    }
    events, store = _round_trip(body)
    # Exactly one redaction (the messages leaf), NOT two
    assert [e.type_label for e in events] == ["AWS_ACCESS_KEY"]
    assert events[0].path == "messages.0.content"
    # The skipped value is passed through byte-unchanged
    assert body["model"] == "AKIAIOSFODNN7EXAMPLE"
    # The non-skipped value was redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in body["messages"][0]["content"]
    assert "<pl:" in body["messages"][0]["content"]


def test_openai_skipped_keys_with_matching_value_not_redacted():
    """v2 SKIP_PATH_TAILS extension covers OpenAI Chat Completions protocol
    keys. Pin a couple whose string-shaped values could collide with a pattern
    — they must survive redaction through _process."""
    body = {
        "user": "ghp_0123456789abcdef0123456789abcdef0123",  # 'user' is skipped
        "seed": "AKIAIOSFODNN7EXAMPLE",                      # 'seed' is skipped
        "content": "real leak AKIAIOSFODNN7EXAMPLE",         # not skipped
    }
    events, store = _round_trip(body)
    assert [e.type_label for e in events] == ["AWS_ACCESS_KEY"]
    assert events[0].path == "content"
    assert body["user"] == "ghp_0123456789abcdef0123456789abcdef0123"
    assert body["seed"] == "AKIAIOSFODNN7EXAMPLE"
    assert "<pl:" in body["content"] and "AKIAIOSFODNN7EXAMPLE" not in body["content"]


def test_data_skips_only_on_redacted_thinking_block():
    """`data` skips ONLY when its parent is a RedactedThinkingBlock
    (argus issue #17 — a blanket global skip hid secrets in tool_result
    payloads). Under any other parent, a matching `data` value MUST redact."""
    # NOT a redacted_thinking block → 'data' is scanned
    body = {"type": "tool_result", "data": "leak AKIAIOSFODNN7EXAMPLE"}
    events, store = _round_trip(body)
    assert events, "tool_result.data must be scanned (argus #17)"
    assert body["data"] != "leak AKIAIOSFODNN7EXAMPLE"
    # A redacted_thinking block → 'data' is skipped (server-issued opaque)
    body2 = {"type": "redacted_thinking", "data": "AKIAIOSFODNN7EXAMPLE"}
    events2, store2 = _round_trip(body2)
    assert events2 == []
    assert body2["data"] == "AKIAIOSFODNN7EXAMPLE"