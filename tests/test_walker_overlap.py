# tests/test_walker_overlap.py
"""Overlapping/duplicate scan matches must not corrupt substitution (issue #21).

The deployed /etc/waterwall/patterns.py seeded by install.sh duplicated the
built-in AWS_ACCESS_KEY pattern. scan_string then returned two identical spans
for one key, and redact_in_place's right-to-left substitution sliced the
already-modified leaf with stale offsets — shipping a mangled body outbound and
restoring plaintext + placeholder-tail garbage inbound. These tests pin the
non-overlapping contract.
"""
import os
import re

import pytest

from waterwall.proxy import patterns
from waterwall.proxy.patterns import scan_string
from waterwall.proxy.store import PlaceholderStore
from waterwall.proxy.tokenizer import Tokenizer
from waterwall.proxy.walker import detokenize_in_place, redact_in_place


@pytest.fixture
def dup_aws_extension():
    """Activate an extension that duplicates the built-in AWS pattern, exactly
    as the install.sh default seed did on prod-host."""
    patterns.set_active_patterns(
        [("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"))]
    )
    yield
    patterns.reset_active_patterns()


def _round_trip(body):
    tok = Tokenizer(os.urandom(32))
    store = PlaceholderStore()
    events = redact_in_place(body, tokenizer=tok, store=store, scanner=scan_string)
    return events, store


def test_duplicate_extension_pattern_round_trips_exactly(dup_aws_extension):
    original = "key: AKIAIOSFODNN7EXAMPLE end"
    body = {"messages": [{"role": "user", "content": original}]}
    events, store = _round_trip(body)

    redacted = body["messages"][0]["content"]
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    # Exactly one well-formed placeholder, no stale-offset tail garbage
    assert re.fullmatch(r"key: <pl:AWS_ACCESS_KEY:[0-9a-f]{16}> end", redacted), redacted

    detokenize_in_place(body, store=store)
    assert body["messages"][0]["content"] == original


def test_duplicate_extension_pattern_records_one_event(dup_aws_extension):
    """The chain must not double-record one secret matched by two identical
    patterns (HANDOFF 2026-06-10 observed doubled redaction lines)."""
    body = {"messages": [{"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}]}
    events, _ = _round_trip(body)
    assert len(events) == 1
    assert events[0].type_label == "AWS_ACCESS_KEY"


def test_contained_match_drops_in_favor_of_outer_span():
    """A single-line token inside a PEM body must not punch a hole in the
    outer PEM substitution: keep the leftmost-longest span, drop the inner."""
    inner = "AKIAIOSFODNN7EXAMPLE"
    begin = "-----BEGIN " + "RSA PRIVATE KEY-----"
    end = "-----END " + "RSA PRIVATE KEY-----"
    pem = f"{begin}\nabc {inner} def\n{end}"
    original = f"here: {pem} done"
    body = {"messages": [{"role": "user", "content": original}]}
    events, store = _round_trip(body)

    redacted = body["messages"][0]["content"]
    assert inner not in redacted
    assert "BEGIN" not in redacted
    assert re.fullmatch(r"here: <pl:PEM_BLOCK:[0-9a-f]{16}> done", redacted), redacted
    assert len(events) == 1
    assert events[0].type_label == "PEM_BLOCK"

    detokenize_in_place(body, store=store)
    assert body["messages"][0]["content"] == original


def test_partial_overlap_merges_to_union_span_no_plaintext_leak():
    """Built-ins alone can partially overlap: TELEGRAM_BOT_TOKEN matches
    digits:colon + the first 35 chars of a JWT whose header ends at the
    boundary. Dropping either match would ship the other's non-overlapped
    tail in plaintext; both spans must merge into one union redaction
    (review finding on the issue #21 fix)."""
    jwt = "eyJ" + "I" * 32 + "." + "J" * 40 + "." + "K" * 50
    original = f"token 1234567890:{jwt} end"
    body = {"messages": [{"role": "user", "content": original}]}
    events, store = _round_trip(body)

    redacted = body["messages"][0]["content"]
    # No fragment of either secret may survive outbound
    assert "1234567890" not in redacted
    assert "JJJJ" not in redacted and "KKKK" not in redacted
    assert re.fullmatch(r"token <pl:[A-Z0-9_]+:[0-9a-f]{16}> end", redacted), redacted
    assert len(events) == 1
    assert events[0].type_label == "JWT_TOKEN"  # longest constituent labels the union

    detokenize_in_place(body, store=store)
    assert body["messages"][0]["content"] == original


def test_chained_overlap_union_labeled_by_longest_constituent():
    """Copilot review on PR #23: when an overlap group widens repeatedly, the
    label comparison must use the longest RAW constituent, not the running
    union's length — otherwise a later, longer match loses to an inflated
    union and the placeholder/audit label misattributes."""
    patterns.set_active_patterns([
        ("TYPE_A", re.compile(r"A{29}B")),    # span (0, 30), len 30
        ("TYPE_B", re.compile(r"BC{31}D")),   # span (29, 62), len 33
        ("TYPE_C", re.compile(r"DE{33}F")),   # span (61, 96), len 35 — longest
    ])
    try:
        leaf = "A" * 29 + "B" + "C" * 31 + "D" + "E" * 33 + "F"
        matches = scan_string(leaf)
        assert len(matches) == 1
        assert (matches[0].start, matches[0].end) == (0, 96)
        assert matches[0].type == "TYPE_C"
        assert matches[0].text == leaf
    finally:
        patterns.reset_active_patterns()


def test_identical_span_tie_still_prefers_builtin(dup_aws_extension):
    """Ties must keep the earlier (built-in) match's label."""
    matches = scan_string("AKIAIOSFODNN7EXAMPLE")
    assert [m.type for m in matches] == ["AWS_ACCESS_KEY"]


def test_scan_string_spans_never_overlap():
    """Producer contract: scan_string output is start-sorted and disjoint."""
    jwt = "eyJ" + "I" * 32 + "." + "J" * 40 + "." + "K" * 50
    matches = scan_string(f"1234567890:{jwt} and AKIAIOSFODNN7EXAMPLE")
    for a, b in zip(matches, matches[1:]):
        assert a.end <= b.start, f"overlap: {a} / {b}"


def test_adjacent_matches_still_both_substitute():
    """Non-overlapping (merely adjacent) matches are NOT collapsed."""
    original = "AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPL2"
    body = {"messages": [{"role": "user", "content": original}]}
    events, store = _round_trip(body)
    assert len(events) == 2
    detokenize_in_place(body, store=store)
    assert body["messages"][0]["content"] == original
