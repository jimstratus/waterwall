# tests/test_addon_outbound.py
"""Integration test: addon redacts outbound JSON request bodies."""

import json
import os
from pathlib import Path

import pytest
from mitmproxy.test import tflow, taddons

from waterwall.proxy.addon import WaterwallAddon


@pytest.fixture
def addon(tmp_path: Path):
    chain_path = tmp_path / "proxy.jsonl"
    a = WaterwallAddon(chain_path=chain_path, session_key=os.urandom(32))
    # v2 §4.2: addon gates on _sse_handlers (populated by running() in production).
    # Unit tests seed Anthropic-only handler to preserve v1 behavior.
    from waterwall.proxy.sse import SseStreamRewriter
    a._sse_handlers["api.anthropic.com"] = SseStreamRewriter(store=a._store)
    return a


def test_addon_redacts_aws_key_in_messages(addon):
    flow = tflow.tflow(
        req=tflow.treq(
            host="api.anthropic.com",
            port=443,
            scheme=b"https",
            method=b"POST",
            path=b"/v1/messages",
            headers=(
                (b"content-type", b"application/json"),
                (b"x-api-key", b"sk-ant-api03-redactedauthtoken"),
            ),
            content=json.dumps({
                "model": "claude-3-5-sonnet",
                "messages": [{"role": "user", "content": "leak AKIAIOSFODNN7EXAMPLE"}],
                "max_tokens": 100,
            }).encode(),
        )
    )

    with taddons.context(addon) as _:
        addon.request(flow)

    body = json.loads(flow.request.content)
    assert "AKIAIOSFODNN7EXAMPLE" not in body["messages"][0]["content"]
    assert "<pl:AWS_ACCESS_KEY:" in body["messages"][0]["content"]


def test_addon_does_not_modify_x_api_key_header(addon):
    flow = tflow.tflow(
        req=tflow.treq(
            host="api.anthropic.com",
            port=443,
            scheme=b"https",
            method=b"POST",
            path=b"/v1/messages",
            headers=(
                (b"content-type", b"application/json"),
                (b"x-api-key", b"sk-ant-api03-realapikey-do-not-touch"),
            ),
            content=b'{"messages":[]}',
        )
    )
    with taddons.context(addon) as _:
        addon.request(flow)
    assert flow.request.headers["x-api-key"] == "sk-ant-api03-realapikey-do-not-touch"


def test_addon_skips_non_anthropic_hosts(addon):
    flow = tflow.tflow(
        req=tflow.treq(
            host="api.openai.com",
            port=443,
            scheme=b"https",
            method=b"POST",
            path=b"/v1/chat/completions",
            content=b'{"messages":[{"role":"user","content":"AKIAIOSFODNN7EXAMPLE"}]}',
        )
    )
    with taddons.context(addon) as _:
        addon.request(flow)
    body = json.loads(flow.request.content)
    assert "AKIAIOSFODNN7EXAMPLE" in body["messages"][0]["content"], \
        "addon must scope to api.anthropic.com only (spec ADR #7)"


def test_addon_escapes_literal_pl_when_no_secrets(addon):
    """Spec §4.6: literal `<pl:` in user input must be escaped to `<pl-esc:` even
    when no scanner matches fire — otherwise Phase 3 detok would misread it as a
    real placeholder. Wave-2 review (2.7) caught this as a Critical bypass."""
    flow = tflow.tflow(
        req=tflow.treq(
            host="api.anthropic.com", port=443, scheme=b"https",
            method=b"POST", path=b"/v1/messages",
            content=json.dumps({
                "messages": [{"role": "user", "content": "see <pl:fake:1234567890abcdef> docs"}]
            }).encode(),
        )
    )
    with taddons.context(addon) as _:
        addon.request(flow)
    body = json.loads(flow.request.content)
    assert "<pl-esc:" in body["messages"][0]["content"]
    assert "<pl:" not in body["messages"][0]["content"].replace("<pl-esc:", "")


def test_addon_processes_path_with_query_string(addon):
    """Spec ADR #7 + production safety: clients may add query params
    (e.g. /v1/messages?stream=true). Path scoping must strip the query before
    equality check, else addon silently bypasses. Wave-2 review (2.7) caught this."""
    flow = tflow.tflow(
        req=tflow.treq(
            host="api.anthropic.com", port=443, scheme=b"https",
            method=b"POST", path=b"/v1/messages?stream=true",
            content=json.dumps({
                "messages": [{"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}]
            }).encode(),
        )
    )
    with taddons.context(addon) as _:
        addon.request(flow)
    body = json.loads(flow.request.content)
    assert "AKIAIOSFODNN7EXAMPLE" not in body["messages"][0]["content"]
    assert "<pl:AWS_ACCESS_KEY:" in body["messages"][0]["content"]


def test_load_registers_addon_in_module_addons(tmp_path: Path, monkeypatch):
    """Phase 2 lab test (test-host) caught: load() returned the instance but never
    appended to module-level `addons` list. mitmproxy traverses module.addons
    after load(), so the hook chain was never registered and request() never
    fired in production. Tests that bypass mitmproxy lifecycle (calling
    addon.request(flow) directly) cannot catch this.

    Also asserts load() is IDEMPOTENT: calling it twice (mitmproxy hot-reload,
    config change, etc.) must not double-register, since two instances would
    both fire on every request and the second pass would re-escape already-
    escaped placeholders, corrupting Phase 3 detok."""
    from waterwall.proxy import addon as addon_module

    addon_module.addons.clear()
    monkeypatch.setenv("WATERWALL_CHAIN", str(tmp_path / "proxy.jsonl"))

    first = addon_module.load(loader=None)

    assert len(addon_module.addons) == 1, \
        "load() must append its instance to module.addons exactly once"
    assert isinstance(first, addon_module.WaterwallAddon)
    assert first in addon_module.addons

    # Idempotency: a second load() must NOT register a duplicate.
    second = addon_module.load(loader=None)
    assert len(addon_module.addons) == 1, \
        "load() must be idempotent — re-invocation must not double-register"
    assert second is first, "load() must return the existing instance on re-invocation"

    # Cleanup so other tests that import addon_module see a clean state.
    addon_module.addons.clear()
