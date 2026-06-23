# tests/test_walker_redact.py
import os
from waterwall.proxy.walker import redact_in_place
from waterwall.proxy.tokenizer import Tokenizer
from waterwall.proxy.store import PlaceholderStore
from waterwall.proxy.patterns import scan_string


def test_redact_in_place_substitutes_aws_key():
    body = {
        "messages": [{"role": "user", "content": "leak AKIAIOSFODNN7EXAMPLE here"}]
    }
    tok = Tokenizer(os.urandom(32))
    store = PlaceholderStore()
    events = redact_in_place(body, tokenizer=tok, store=store, scanner=scan_string)
    assert any(e.type_label == "AWS_ACCESS_KEY" for e in events)
    assert "AKIAIOSFODNN7EXAMPLE" not in body["messages"][0]["content"]
    assert "<pl:AWS_ACCESS_KEY:" in body["messages"][0]["content"]


def test_redact_records_store_entry():
    body = {"messages": [{"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}]}
    tok = Tokenizer(os.urandom(32))
    store = PlaceholderStore()
    events = redact_in_place(body, tokenizer=tok, store=store, scanner=scan_string)
    placeholder = body["messages"][0]["content"]
    hmac8 = placeholder.removeprefix("<pl:AWS_ACCESS_KEY:").removesuffix(">")
    assert store.get(hmac8) == "AKIAIOSFODNN7EXAMPLE"


def test_redact_escapes_literal_pl_first():
    """Spec §4.6: literal `<pl:` in user input must be escaped before scanning."""
    body = {"messages": [{"role": "user", "content": "see <pl:fake:1234567890abcdef> docs"}]}
    tok = Tokenizer(os.urandom(32))
    store = PlaceholderStore()
    redact_in_place(body, tokenizer=tok, store=store, scanner=scan_string)
    assert "<pl-esc:" in body["messages"][0]["content"]
    assert "<pl:" not in body["messages"][0]["content"].replace("<pl-esc:", "")
