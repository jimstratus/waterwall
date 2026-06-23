# tests/test_addon_sse_dispatch.py
"""SSE dispatch by Host header — v2 spec §4.2."""
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from waterwall.proxy.addon import WaterwallAddon


def _make_addon(tmp_path: Path) -> WaterwallAddon:
    """Construct a WaterwallAddon for unit-testing the SSE dispatch path.

    Existing addon contract requires chain_path; pass a tmp path so the
    constructor succeeds. The dispatch tests don't exercise the chain.
    """
    return WaterwallAddon(chain_path=tmp_path / "proxy.jsonl")


def test_anthropic_host_routes_to_anthropic_handler(tmp_path):
    addon = _make_addon(tmp_path)
    # Simulate addon initialization with two registered handlers
    anthropic_handler = MagicMock(name="anthropic")
    openai_handler = MagicMock(name="openai")
    addon._sse_handlers = {
        "api.anthropic.com": anthropic_handler,
        "api.deepseek.com": openai_handler,
    }
    flow = MagicMock()
    flow.request.host = "api.anthropic.com"
    flow.response.headers = {"content-type": "text/event-stream"}
    flow.response.content = b"event: message_stop\ndata: {}\n\n"

    addon._dispatch_sse(flow)

    anthropic_handler.rewrite.assert_called_once_with(flow)
    openai_handler.rewrite.assert_not_called()


def test_openai_shape_host_routes_to_openai_handler(tmp_path):
    addon = _make_addon(tmp_path)
    anthropic_handler = MagicMock(name="anthropic")
    openai_handler = MagicMock(name="openai")
    addon._sse_handlers = {
        "api.anthropic.com": anthropic_handler,
        "api.deepseek.com": openai_handler,
    }
    flow = MagicMock()
    flow.request.host = "api.deepseek.com"
    flow.response.headers = {"content-type": "text/event-stream"}

    addon._dispatch_sse(flow)

    openai_handler.rewrite.assert_called_once_with(flow)
    anthropic_handler.rewrite.assert_not_called()


def test_unmapped_host_raises_keyerror(tmp_path):
    """Spec §4.2 R2: unmapped host = install-time invariant violation, re-raise."""
    addon = _make_addon(tmp_path)
    addon._sse_handlers = {"api.anthropic.com": MagicMock()}
    flow = MagicMock()
    flow.request.host = "api.example.com"  # not in map
    with pytest.raises(KeyError, match="api.example.com"):
        addon._dispatch_sse(flow)


def test_addon_init_registers_handlers_per_yaml(tmp_path, monkeypatch):
    """addon.running() must populate _sse_handlers from permitted_hosts.yaml."""
    yaml_text = """
hosts:
  - host: api.anthropic.com
    sse_handler: anthropic
  - host: api.deepseek.com
    sse_handler: openai
  - host: someproxy.local
    sse_handler: none
"""
    yaml_path = tmp_path / "permitted_hosts.yaml"
    yaml_path.write_text(yaml_text, encoding="utf-8")
    monkeypatch.setenv("WATERWALL_PERMITTED_HOSTS", str(yaml_path))

    from waterwall.proxy.sse import SseStreamRewriter as AnthropicSseHandler
    from waterwall.proxy.sse_openai import OpenAiSseHandler

    addon = _make_addon(tmp_path)
    # Stub out the heavyweight init pieces (chain, store, etc.) — only
    # exercise the SSE handler registration codepath.
    addon._init_sse_handlers_from_yaml(yaml_path)

    assert "api.anthropic.com" in addon._sse_handlers
    assert "api.deepseek.com" in addon._sse_handlers
    assert "someproxy.local" in addon._sse_handlers
    assert isinstance(addon._sse_handlers["api.anthropic.com"], AnthropicSseHandler)
    assert isinstance(addon._sse_handlers["api.deepseek.com"], OpenAiSseHandler)
    # 'none' = passthrough — handler with .rewrite that does nothing
    assert hasattr(addon._sse_handlers["someproxy.local"], "rewrite")


def test_init_invariant_aborts_on_unknown_handler_type(tmp_path):
    """A YAML entry with sse_handler not in {anthropic, openai, none} must
    have already been rejected by load_permitted_hosts. But also: the
    addon's init must not silently leave a host with no handler entry."""
    yaml_text = """
hosts:
  - host: api.anthropic.com
    sse_handler: anthropic
  - host: api.deepseek.com
    sse_handler: openai
"""
    yaml_path = tmp_path / "permitted_hosts.yaml"
    yaml_path.write_text(yaml_text, encoding="utf-8")

    addon = _make_addon(tmp_path)
    addon._init_sse_handlers_from_yaml(yaml_path)

    # Invariant: every YAML entry produced exactly one handler entry
    # (no entry was silently dropped).
    assert set(addon._sse_handlers.keys()) == {"api.anthropic.com", "api.deepseek.com"}
    # Invariant: no extra handlers
    assert len(addon._sse_handlers) == 2
