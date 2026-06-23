# tests/test_walker_detok.py
import os
from waterwall.proxy.walker import detokenize_in_place
from waterwall.proxy.tokenizer import Tokenizer
from waterwall.proxy.store import PlaceholderStore


def test_detok_substitutes_known_placeholder():
    tok = Tokenizer(os.urandom(32))
    store = PlaceholderStore()
    placeholder = tok.tokenize("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY")
    hmac8 = placeholder.removeprefix("<pl:AWS_ACCESS_KEY:").removesuffix(">")
    store.put(hmac8, "AKIAIOSFODNN7EXAMPLE")

    body = {
        "content": [{"type": "text", "text": f"the key is {placeholder} please use it"}]
    }
    result = detokenize_in_place(body, store=store)
    assert result.detok_count == 1
    assert result.unknown_placeholders == 0
    assert "AKIAIOSFODNN7EXAMPLE" in body["content"][0]["text"]
    assert "<pl:" not in body["content"][0]["text"]


def test_detok_unknown_placeholder_passes_through():
    body = {
        "content": [{"type": "text", "text": "see <pl:AWS_ACCESS_KEY:deadbeefcafe1234>"}]
    }
    store = PlaceholderStore()
    result = detokenize_in_place(body, store=store)
    assert result.detok_count == 0
    assert result.unknown_placeholders == 1
    assert "<pl:AWS_ACCESS_KEY:deadbeefcafe1234>" in body["content"][0]["text"]


def test_detok_substitute_before_unescape():
    """Spec §5.2 invariant: substitute first, then unescape."""
    body = {"content": [{"type": "text", "text": "literal <pl-esc:fake:1234>"}]}
    store = PlaceholderStore()
    detokenize_in_place(body, store=store)
    assert body["content"][0]["text"] == "literal <pl:fake:1234>"


def test_detok_skips_signature():
    body = {"content": [{"type": "thinking", "thinking": "ok", "signature": "<pl:fake:1234>"}]}
    store = PlaceholderStore()
    result = detokenize_in_place(body, store=store)
    assert body["content"][0]["signature"] == "<pl:fake:1234>", \
        "signature is server-issued; do not detokenize"
