# tests/test_walker.py
"""JSON walker yields scannable string leaves per spec §3.1 / §4.1."""

import pytest

from waterwall.proxy.walker import walk_request_body, SKIP_PATH_TAILS

OUT_PATHS = []  # let the test populate; just ensure invariants


def test_walker_yields_text_leaves():
    body = {
        "model": "claude-3-5-sonnet",
        "messages": [
            {"role": "user", "content": "hello AKIAIOSFODNN7EXAMPLE"}
        ],
    }
    pairs = list(walk_request_body(body))
    leaves = [(path, leaf) for path, leaf in pairs]
    assert ("messages.0.content", "hello AKIAIOSFODNN7EXAMPLE") in leaves


def test_walker_skips_protocol_metadata_keys():
    """Walker is body-only — Authorization headers never reach it (skipped at HTTP layer
    by addon). Within JSON body, protocol metadata (model, max_tokens, etc.) is skipped
    so its values are not scanned."""
    body = {
        "model": "claude-3-5-sonnet",     # value is a string but path is skipped
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "ok"}],
    }
    pairs = list(walk_request_body(body))
    leaves = [(path, leaf) for path, leaf in pairs]
    # The model value should NOT appear as a yielded leaf.
    assert not any(leaf == "claude-3-5-sonnet" for _, leaf in leaves)
    # The user content SHOULD appear.
    assert any(leaf == "ok" for _, leaf in leaves)


def test_walker_recurses_into_tool_use_input():
    body = {
        "messages": [{
            "role": "assistant",
            "content": [{
                "type": "tool_use",
                "name": "Read",
                "input": {"file_path": "/etc/secret-AKIAIOSFODNN7EXAMPLE.env"}
            }],
        }],
    }
    pairs = list(walk_request_body(body))
    leaves = [(path, leaf) for path, leaf in pairs]
    assert any("AKIAIOSFODNN7EXAMPLE" in v for _, v in leaves)


def test_walker_skips_signature_path():
    """ThinkingBlock signature must not be yielded (spec §3.1)."""
    body = {
        "messages": [{
            "role": "assistant",
            "content": [{
                "type": "thinking",
                "thinking": "I should check that key",
                "signature": "this-is-a-server-issued-signature-do-not-touch"
            }]
        }]
    }
    pairs = list(walk_request_body(body))
    leaves = [path for path, _ in pairs]
    assert any("thinking" in p for p in leaves)
    assert not any(p.endswith(".signature") for p in leaves)


def test_walker_yields_tools_description():
    body = {
        "tools": [{
            "name": "Read",
            "description": "Read a file. AKIAIOSFODNN7EXAMPLE in description body."
        }]
    }
    pairs = list(walk_request_body(body))
    leaves = [(path, leaf) for path, leaf in pairs]
    assert any("AKIAIOSFODNN7EXAMPLE" in v for _, v in leaves)


@pytest.mark.parametrize("key", [
    "max_completion_tokens", "n", "presence_penalty", "frequency_penalty",
    "logit_bias", "logprobs", "top_logprobs", "response_format", "seed",
    "parallel_tool_calls", "user",
])
def test_openai_protocol_keys_are_skipped(key):
    """v2 SKIP_PATH_TAILS extension: OpenAI Chat Completions protocol keys
    must be skipped so their (string-shaped) values never reach the scanner.
    Spec §4.3."""
    body = {key: "AKIAIOSFODNN7EXAMPLE", "messages": [{"role": "user", "content": "hi"}]}
    leaves = list(walk_request_body(body))
    yielded_keys = [path for path, _ in leaves]
    assert key not in yielded_keys, f"{key} should be skipped by walker"
    # Sanity: messages.0.content should still be scanned
    assert any(p == "messages.0.content" for p in yielded_keys), \
        "non-protocol body content must remain scannable"
