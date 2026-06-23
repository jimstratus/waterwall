# tests/test_walker_skips.py
"""Argus issue #17: generic skip keys hid secrets under {"data": ...} payloads."""

from waterwall.proxy.walker import walk_request_body


def test_data_key_scanned_unless_redacted_thinking():
    body = {"tool_result": {"data": "AKIAIOSFODNN7EXAMPLE"}}
    leaves = [leaf for _, leaf in walk_request_body(body)]
    assert "AKIAIOSFODNN7EXAMPLE" in leaves, "secret under generic 'data' key skipped"


def test_redacted_thinking_data_still_skipped():
    body = {"content": [{"type": "redacted_thinking", "data": "ENCRYPTED-BLOB"}]}
    leaves = [leaf for _, leaf in walk_request_body(body)]
    assert "ENCRYPTED-BLOB" not in leaves
