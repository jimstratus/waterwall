# tests/test_pem_round_trip.py
"""Large-PEM round-trip / truncation safety (issue #21, operator concern).

Pins that multi-line PEM keys survive redact -> <pl:...> -> detokenize
byte-exact at every size class:

  - a real RSA-4096 key (~3.2 KB) — well inside the 32768-char regex body bound
  - a synthetic PEM whose body sits exactly AT the bound — last matching size
  - a synthetic PEM just OVER the bound — not redacted (spec §8 ReDoS bound,
    by design) but MUST pass through unmangled
  - a leaf over the 64 KiB PEM_LEAF_MAX_BYTES gate — same pass-through contract
  - a large legitimate non-secret body — byte-identical end to end
"""
import json
import os
from pathlib import Path

import pytest
from mitmproxy.test import tflow, taddons

from waterwall.proxy.addon import WaterwallAddon
from waterwall.proxy.patterns import PEM_LEAF_MAX_BYTES, scan_string
from waterwall.proxy.store import PlaceholderStore
from waterwall.proxy.tokenizer import Tokenizer
from waterwall.proxy.walker import detokenize_in_place, redact_in_place

# The regex body bound from patterns.PEM_BLOCK_PATTERN: (?P<body>.{0,32768}?)
PEM_BODY_BOUND = 32768


# rsa_4096_pem comes from tests/conftest.py (session-scoped).


def _synthetic_pem(body_len: int) -> str:
    """PEM-shaped block with an exact body length (incl. framing newlines)."""
    begin = "-----BEGIN " + "RSA PRIVATE KEY-----"
    end = "-----END " + "RSA PRIVATE KEY-----"
    assert body_len >= 2
    return begin + "\n" + "B" * (body_len - 2) + "\n" + end


def _walker_round_trip(original: str) -> tuple[str, str]:
    """Returns (redacted_leaf, restored_leaf)."""
    body = {"messages": [{"role": "user", "content": original}]}
    tok = Tokenizer(os.urandom(32))
    store = PlaceholderStore()
    redact_in_place(body, tokenizer=tok, store=store, scanner=scan_string)
    redacted = body["messages"][0]["content"]
    detokenize_in_place(body, store=store)
    return redacted, body["messages"][0]["content"]


def test_rsa_4096_round_trips_byte_exact(rsa_4096_pem):
    assert len(rsa_4096_pem) > 3000  # sanity: this is a real ~3.2 KB key
    original = f"deploy key:\n{rsa_4096_pem}\nend of key"
    redacted, restored = _walker_round_trip(original)
    assert "BEGIN RSA PRIVATE KEY" not in redacted
    assert "<pl:PEM_BLOCK:" in redacted
    assert restored == original


def test_pem_body_at_regex_bound_round_trips_byte_exact():
    original = _synthetic_pem(PEM_BODY_BOUND)
    redacted, restored = _walker_round_trip(original)
    assert "<pl:PEM_BLOCK:" in redacted
    assert "BBBB" not in redacted
    assert restored == original


def test_pem_body_over_regex_bound_passes_through_unmangled():
    """Over the 32768-char body bound the PEM is NOT redacted (documented
    spec §8 ReDoS bound) — the contract here is zero mangling/truncation."""
    original = _synthetic_pem(PEM_BODY_BOUND + 1)
    redacted, restored = _walker_round_trip(original)
    assert "<pl:" not in redacted
    assert redacted == original
    assert restored == original


def test_leaf_over_64k_gate_passes_through_unmangled(rsa_4096_pem):
    """Leaves > PEM_LEAF_MAX_BYTES skip the PEM scan entirely (spec §8.2);
    the leaf must come out byte-identical."""
    original = "X" * (PEM_LEAF_MAX_BYTES + 1) + "\n" + rsa_4096_pem
    redacted, restored = _walker_round_trip(original)
    assert "<pl:" not in redacted
    assert redacted == original
    assert restored == original


def test_large_legitimate_body_is_not_mangled():
    """~100 KB of secret-free prose must survive byte-identical."""
    original = ("All work and no play makes Jack a dull boy. " * 2500).rstrip()
    assert len(original) > 100_000
    redacted, restored = _walker_round_trip(original)
    assert redacted == original
    assert restored == original


# ---------------------------------------------------------------------------
# Full addon path (request -> response), mirrors test_addon_round_trip.py
# ---------------------------------------------------------------------------

@pytest.fixture
def addon(tmp_path: Path):
    a = WaterwallAddon(chain_path=tmp_path / "proxy.jsonl", session_key=os.urandom(32))
    from waterwall.proxy.sse import SseStreamRewriter
    a._sse_handlers["api.anthropic.com"] = SseStreamRewriter(store=a._store)
    return a


def test_rsa_4096_round_trips_through_addon(addon, rsa_4096_pem):
    original = f"key follows\n{rsa_4096_pem}\ntrailing context"
    flow = tflow.tflow(
        req=tflow.treq(
            host="api.anthropic.com", port=443, scheme=b"https",
            method=b"POST", path=b"/v1/messages",
            headers=((b"content-type", b"application/json"),),
            content=json.dumps({
                "messages": [{"role": "user", "content": original}],
            }).encode(),
        )
    )
    with taddons.context(addon) as _:
        addon.request(flow)

    sent_leaf = json.loads(flow.request.content)["messages"][0]["content"]
    assert "BEGIN RSA PRIVATE KEY" not in flow.request.content.decode()
    assert "<pl:PEM_BLOCK:" in sent_leaf

    flow.response = tflow.tresp(
        status_code=200,
        headers=((b"content-type", b"application/json"),),
        content=json.dumps({
            "content": [{"type": "text", "text": f"echo: {sent_leaf}"}],
        }).encode(),
    )
    with taddons.context(addon) as _:
        addon.response(flow)

    final_leaf = json.loads(flow.response.content)["content"][0]["text"]
    assert final_leaf == f"echo: {original}"
