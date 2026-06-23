# tests/test_tokenizer.py
import os
from waterwall.proxy.tokenizer import (
    Tokenizer,
    PLACEHOLDER_REGEX,
    escape_literal_placeholders,
    unescape_literal_placeholders,
)


def test_tokenizer_deterministic_within_session():
    key = os.urandom(32)
    t = Tokenizer(session_key=key)
    a = t.tokenize("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY")
    b = t.tokenize("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY")
    assert a == b
    assert a.startswith("<pl:AWS_ACCESS_KEY:")
    assert a.endswith(">")


def test_tokenizer_format_is_16_hex_chars():
    t = Tokenizer(session_key=b"\x00" * 32)
    out = t.tokenize("foo", "TEST_TYPE")
    body = out.removeprefix("<pl:TEST_TYPE:").removesuffix(">")
    assert len(body) == 16
    assert all(c in "0123456789abcdef" for c in body)


def test_tokenizer_different_keys_produce_different_placeholders():
    a = Tokenizer(session_key=b"\x00" * 32).tokenize("foo", "X")
    b = Tokenizer(session_key=b"\x01" * 32).tokenize("foo", "X")
    assert a != b


def test_placeholder_regex_matches_canonical_placeholder():
    m = PLACEHOLDER_REGEX.match("<pl:AWS_ACCESS_KEY:a1b2c3d4e5f67890>")
    assert m is not None
    assert m.group("type") == "AWS_ACCESS_KEY"
    assert m.group("hmac8") == "a1b2c3d4e5f67890"


def test_placeholder_regex_rejects_uppercase_hex():
    assert PLACEHOLDER_REGEX.match("<pl:X:A1B2C3D4E5F67890>") is None


def test_escape_then_unescape_round_trips():
    body = "literal <pl:foo:1234abcd5678ef90> in user input"
    escaped = escape_literal_placeholders(body)
    assert "<pl:" not in escaped
    assert "<pl-esc:" in escaped
    assert unescape_literal_placeholders(escaped) == body


def test_escape_handles_multiple_occurrences():
    body = "<pl:A:1> <pl:B:2> <pl:C:3>"
    assert escape_literal_placeholders(body).count("<pl-esc:") == 3


def test_tokenizer_rejects_invalid_type_label():
    """Wave-1 review: tokenize() must reject labels that would produce
    placeholders unmatchable by PLACEHOLDER_REGEX."""
    import pytest
    t = Tokenizer(session_key=b"\x00" * 32)
    with pytest.raises(ValueError, match=r"\[A-Z0-9_\]\+"):
        t.tokenize("foo", "lowercase_invalid")
    with pytest.raises(ValueError):
        t.tokenize("foo", "")
    with pytest.raises(ValueError):
        t.tokenize("foo", "has-hyphen")
