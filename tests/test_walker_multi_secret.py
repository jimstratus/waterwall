# tests/test_walker_multi_secret.py
"""Multiple distinct secrets in one leaf / one request — the strongest spec
guarantee in `redact_in_place` (right-to-left substitution across a leaf that
holds more than one secret, and independent store keying/detokenization of
secret pairs of different types).

BACKLOG 2026-05-05 lines 38 & 79 flagged this as "the strongest spec guarantee
with zero test coverage": the adjacent-duplicate case (test_walker_overlap.py)
and the issue-#21 single-secret cases are covered, but neither (a) two distinct
secrets of the same type separated by prose, nor (b) two distinct TYPES across
one request/response pair, had a guard. These are characterization pins: the
production code already handles them correctly; the tests exist so a future
refactor of `redact_in_place`/`detokenize_in_place` can't silently corrupt
multi-secret leaves (e.g. by reversing the right-to-left order, double-counting
offsets, or clobbering the first placeholder with the second).

The audit `RedactionEvent` list ordering (source order) is ALSO pinned here.
`redact_in_place` substitutes right-to-left for offset safety then reverses the
PER-LEAF span order back (not the whole request) so the audit `redactions`
array, action receipts, and the TUI types list match the body placeholder order
across the whole payload. Without the per-leaf reverse, a multi-secret request
logs its redactions backwards within each leaf (forensically confusing); without
the multi-leaf guard, a naive whole-request `events.reverse()` would flip the
leaf order too (messages[1] before messages[0]).
"""
import os
import re

from waterwall.proxy.patterns import scan_string
from waterwall.proxy.store import PlaceholderStore
from waterwall.proxy.tokenizer import Tokenizer
from waterwall.proxy.walker import detokenize_in_place, redact_in_place


def _round_trip(body):
    tok = Tokenizer(os.urandom(32))
    store = PlaceholderStore()
    events = redact_in_place(body, tokenizer=tok, store=store, scanner=scan_string)
    return events, store


_PL = r"<pl:[A-Z_]+:[0-9a-f]{16}>"


def _hmac(ph: str) -> str:
    return re.search(r":([0-9a-f]{16})>", ph).group(1)


def test_two_distinct_same_type_secrets_in_one_leaf():
    """Right-to-left substitution must redact both secrets in one leaf, each to
    its own placeholder, in source order — and detokenize must restore the
    exact original (incl. the prose separator between them)."""
    k1 = "AKIAIOSFODNN7EXAMPLE"   # AKIA + 16
    k2 = "AKIA0123456789ABCDEF"   # AKIA + 16  (distinct, valid)
    original = f"keys: {k1} and {k2} here"
    body = {"messages": [{"role": "user", "content": original}]}
    events, store = _round_trip(body)

    redacted = body["messages"][0]["content"]
    # No plaintext of EITHER secret survives outbound
    assert k1 not in redacted and k2 not in redacted, redacted
    # Two well-formed placeholders, in source order, distinct hmac8s
    phs = re.findall(_PL, redacted)
    assert len(phs) == 2, redacted
    assert phs[0] != phs[1], phs
    assert redacted == f"keys: {phs[0]} and {phs[1]} here", redacted
    # Two events; both labelled; EVENTS in source order matching the body
    # placeholders (redact_in_place reverses its right-to-left append before
    # returning).
    assert [e.type_label for e in events] == ["AWS_ACCESS_KEY", "AWS_ACCESS_KEY"]
    assert [e.hmac8 for e in events] == [_hmac(phs[0]), _hmac(phs[1])]
    assert events[0].path == "messages.0.content"  # BACKLOG line 39 path pin
    assert events[0].hmac8 != events[1].hmac8

    detokenize_in_place(body, store=store)
    assert body["messages"][0]["content"] == original


def test_two_distinct_secret_types_in_one_request():
    """AWS key + GitHub token in one leaf: both placeholders are distinct TYPES,
    both are independently restored, the exact original is recovered, and the
    events list is in source order. This is the core multi-secret round-trip
    BACKLOG line 79 names as untested."""
    aws = "AKIAIOSFODNN7EXAMPLE"
    gh = "ghp_0123456789abcdef0123456789abcdef0123"  # ghp_ + 36
    original = f"aws {aws}; gh {gh}"
    body = {"messages": [{"role": "user", "content": original}]}
    events, store = _round_trip(body)

    redacted = body["messages"][0]["content"]
    assert aws not in redacted and gh not in redacted, redacted
    phs = re.findall(_PL, redacted)
    assert len(phs) == 2, redacted
    # Distinct types, in source order, matching the events list
    assert re.match(r"<pl:AWS_ACCESS_KEY:[0-9a-f]{16}>", phs[0]), phs
    assert re.match(r"<pl:GITHUB_TOKEN:[0-9a-f]{16}>", phs[1]), phs
    assert [e.type_label for e in events] == ["AWS_ACCESS_KEY", "GITHUB_TOKEN"]
    assert [e.hmac8 for e in events] == [_hmac(phs[0]), _hmac(phs[1])]
    assert len({e.hmac8 for e in events}) == 2  # independently keyed

    detokenize_in_place(body, store=store)
    assert body["messages"][0]["content"] == original
    # Both independently restorable on the response side
    assert aws in body["messages"][0]["content"]
    assert gh in body["messages"][0]["content"]


def test_multi_leaf_events_in_full_source_order():
    """Per-leaf reversal must NOT reverse across leaves: a request with two
    leaves, each holding two same-type secrets, must emit events in full source
    order (leaf0 #1, leaf0 #2, leaf1 #1, leaf1 #2). A whole-request
    `events.reverse()` would put leaf1 before leaf0 (argus 2026-06-29-multisec).
    Also pins that within each leaf the right-to-left order is undone."""
    a1 = "AKIAIOSFODNN7EXAMPLE"
    a2 = "AKIA0123456789ABCDEF"
    b1 = "AKIAFEDCBA9876543210"
    b2 = "AKIA0123456789987654"  # all AKIA + 16
    body = {"messages": [
        {"role": "user", "content": f"leaf0: {a1} and {a2}"},
        {"role": "user", "content": f"leaf1: {b1} and {b2}"},
    ]}
    events, store = _round_trip(body)

    phs0 = re.findall(_PL, body["messages"][0]["content"])
    phs1 = re.findall(_PL, body["messages"][1]["content"])
    seen = [(e.path, e.hmac8) for e in events]
    want = [
        ("messages.0.content", _hmac(phs0[0])), ("messages.0.content", _hmac(phs0[1])),
        ("messages.1.content", _hmac(phs1[0])), ("messages.1.content", _hmac(phs1[1])),
    ]
    assert seen == want, f"\nseen: {seen}\nwant: {want}"
    c0 = body["messages"][0]["content"]
    c1 = body["messages"][1]["content"]
    assert a1 not in c0 and a2 not in c0 and b1 not in c1 and b2 not in c1
    detokenize_in_place(body, store=store)
    assert body["messages"][0]["content"] == f"leaf0: {a1} and {a2}"
    assert body["messages"][1]["content"] == f"leaf1: {b1} and {b2}"


def test_three_distinct_types_in_one_leaf_preserve_order():
    """Stress the right-to-left offset math with three consecutive secrets of
    three different types — the earlier matches' offsets must remain valid after
    the later (rightward) ones are substituted first, events come out in source
    order, and the exact original is recovered."""
    aws = "AKIAIOSFODNN7EXAMPLE"
    gh = "ghp_0123456789abcdef0123456789abcdef0123"
    tg = "1234567890:abcdefghijklmnopqrstuvwxyz012345678"  # 10 digits:colon + 35
    original = f"{aws} {gh} {tg}"
    body = {"messages": [{"role": "user", "content": original}]}
    events, store = _round_trip(body)

    redacted = body["messages"][0]["content"]
    assert aws not in redacted and gh not in redacted and tg not in redacted, redacted
    phs = re.findall(_PL, redacted)
    assert len(phs) == 3, redacted
    assert redacted == " ".join(phs), redacted
    assert [e.type_label for e in events] == [
        "AWS_ACCESS_KEY", "GITHUB_TOKEN", "TELEGRAM_BOT_TOKEN",
    ], [e.type_label for e in events]
    assert [e.hmac8 for e in events] == [_hmac(p) for p in phs]

    detokenize_in_place(body, store=store)
    assert body["messages"][0]["content"] == original