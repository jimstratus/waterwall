# src/waterwall/proxy/walker.py
"""JSON path-aware string-leaf walker for outbound request bodies.

Spec §3.1 (paths), §4.1 (skip rules).
Yields (dotted-path, string-leaf) pairs for each scannable leaf.
"""

from __future__ import annotations

from typing import Generator

# Paths whose string leaves should NEVER be scanned (skip list).
# Match by exact dotted path or path-tail.
# Spec §4.3 (v2): universal superset across Anthropic + OpenAI-shape endpoints.
SKIP_PATH_TAILS: frozenset[str] = frozenset({
    # ── Anthropic Messages protocol / metadata (v1) ──
    "model",
    "max_tokens",
    "temperature",
    "top_k",
    "top_p",
    "stream",
    "tool_choice",
    "container",
    "inference_geo",
    "anthropic_beta",
    "betas",
    # ── Anthropic server-issued / encrypted (v1) ──
    "signature",
    # NOTE: "data" is intentionally NOT in this set — it is skipped only on
    # RedactedThinkingBlock via _skip_key (argus issue #17).
    # ── Anthropic tool name (server-side regex enforced, v1) ──
    "name",
    # ── OpenAI Chat Completions protocol / metadata (v2) ──
    "max_completion_tokens",
    "n",
    "presence_penalty",
    "frequency_penalty",
    "logit_bias",
    "logprobs",
    "top_logprobs",
    "response_format",
    "seed",
    "parallel_tool_calls",
    "user",
})


def _skip_key(key: str, parent: dict, skip_set: frozenset[str] = SKIP_PATH_TAILS) -> bool:
    """Generic protocol keys skip; 'data' skips ONLY on RedactedThinkingBlock
    (argus issue #17 — the global skip hid secrets in tool_result payloads)."""
    if key == "data":
        return parent.get("type") == "redacted_thinking"
    return key in skip_set


def walk_request_body(
    obj: object,
    path: str = "",
) -> Generator[tuple[str, str], None, None]:
    """Recursively walk a parsed JSON request body, yielding (path, leaf) pairs
    for every string leaf that should be scanned.
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            if _skip_key(key, obj):
                continue
            child_path = f"{path}.{key}" if path else key
            yield from walk_request_body(value, child_path)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            child_path = f"{path}.{i}"
            yield from walk_request_body(item, child_path)
    elif isinstance(obj, str):
        yield (path, obj)
    # numbers / bool / None: not scannable


from dataclasses import dataclass
from typing import Callable, Protocol


@dataclass(frozen=True)
class RedactionEvent:
    path: str
    type_label: str
    hmac8: str


class _Scanner(Protocol):
    def __call__(self, s: str) -> list: ...  # noqa


def redact_in_place(
    body: dict,
    *,
    tokenizer,
    store,
    scanner: _Scanner,
) -> list[RedactionEvent]:
    """Walk body, scan each leaf, substitute matches with placeholders in-place.

    Returns the list of redactions performed.
    """
    from .tokenizer import escape_literal_placeholders

    events: list[RedactionEvent] = []

    def _process(obj, path):
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                if _skip_key(key, obj):
                    continue
                child_path = f"{path}.{key}" if path else key
                obj[key] = _process(obj[key], child_path)
            return obj
        if isinstance(obj, list):
            for i in range(len(obj)):
                child_path = f"{path}.{i}"
                obj[i] = _process(obj[i], child_path)
            return obj
        if isinstance(obj, str):
            escaped = escape_literal_placeholders(obj)
            matches = scanner(escaped)
            if not matches:
                return escaped
            # Substitute matches right-to-left so offsets stay valid. Disjoint
            # spans are scan_string's contract (issue #21) — overlapping
            # matches are merged at the producer, so every consumer is safe.
            out = escaped
            for m in sorted(matches, key=lambda x: x.start, reverse=True):
                placeholder = tokenizer.tokenize(m.text, m.type)
                hmac8 = placeholder.removeprefix(f"<pl:{m.type}:").removesuffix(">")
                store.put(hmac8, m.text)
                events.append(RedactionEvent(
                    path=path, type_label=m.type, hmac8=hmac8,
                ))
                out = out[:m.start] + placeholder + out[m.end:]
            return out
        return obj

    # `_process` mutates dicts/lists in place via `obj[key] = ...` / `obj[i] = ...`.
    # Caller's body reference is updated transitively; no clear/update dance.
    _process(body, "")
    return events


import re
from .tokenizer import PLACEHOLDER_REGEX, unescape_literal_placeholders


@dataclass(frozen=True)
class DetokResult:
    detok_count: int
    unknown_placeholders: int


# Response paths to skip: only server-issued opaque fields. Reusing the full
# outbound set created restore-failure paths (argus issue #17).
RESPONSE_SKIP_TAILS: frozenset[str] = frozenset({"signature"})


def detokenize_in_place(body: dict, *, store) -> DetokResult:
    detok_count = 0
    unknown = 0

    def _resolve_match(m: "re.Match") -> str:
        nonlocal detok_count, unknown
        hmac8 = m.group("hmac8")
        plaintext = store.get(hmac8)
        if plaintext is None:
            unknown += 1
            return m.group(0)
        detok_count += 1
        return plaintext

    def _process(obj, path):
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                if _skip_key(key, obj, skip_set=RESPONSE_SKIP_TAILS):
                    continue
                child_path = f"{path}.{key}" if path else key
                obj[key] = _process(obj[key], child_path)
            return obj
        if isinstance(obj, list):
            for i in range(len(obj)):
                obj[i] = _process(obj[i], f"{path}.{i}")
            return obj
        if isinstance(obj, str):
            substituted = PLACEHOLDER_REGEX.sub(_resolve_match, obj)
            return unescape_literal_placeholders(substituted)
        return obj

    _process(body, "")
    return DetokResult(detok_count=detok_count, unknown_placeholders=unknown)
