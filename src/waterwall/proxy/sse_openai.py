# src/waterwall/proxy/sse_openai.py
"""OpenAI Chat Completions SSE handler. Spec §4.2.

OpenAI streams use flat `data: {chunk}\\n\\n` framing with no event names.
Stream terminator: `data: [DONE]\\n\\n`. Each non-DONE chunk is a JSON
object whose content lives at `choices[0].delta.content` (string fragment).

Restoration runs on the JOINED per-choice content, not per chunk (argus
issue #9): at typical 1-5-token deltas a placeholder straddles chunk
boundaries, so per-chunk matching misses the common case. Audit
granularity is therefore one `line_type=detokenization` chain entry per
stream, carrying aggregate counts.
"""
from __future__ import annotations

import json as _json
import logging
import re
from datetime import datetime, timezone

from waterwall.proxy.tokenizer import (
    PLACEHOLDER_REGEX,
    unescape_literal_placeholders,
)

_log = logging.getLogger("waterwall.sse_openai")

_DONE_LINE = b"data: [DONE]"


class OpenAiSseHandler:
    """Implements the SseHandler Protocol for OpenAI-shape streams."""

    def __init__(self, store, chain) -> None:
        self._store = store
        self._chain = chain

    def rewrite(self, flow) -> None:
        """Buffer-then-detokenize for the full response (v2 buffers the whole
        body anyway). Two passes (argus issue #9):
          1. join all delta.content per choice index, restore placeholders +
             unescape on the JOINED text (placeholders straddle chunks at
             typical 1-5-token deltas);
          2. re-distribute: the first content-bearing chunk of each choice
             carries the full restored text, later ones carry "" — OpenAI
             clients accumulate deltas, so the concatenation is identical.
        """
        body = flow.response.content
        host = flow.request.host  # v2 §4.5 — propagate to chain entries
        raw_chunks = body.split(b"\n\n")

        # Pass 1: parse, and join content per choice index.
        parsed: list[dict | None] = []
        pieces: dict[int, list[str]] = {}
        for raw in raw_chunks:
            obj = self._parse_content_chunk(raw)
            parsed.append(obj)
            if obj is not None:
                idx = obj["choices"][0].get("index", 0)
                pieces.setdefault(idx, []).append(
                    obj["choices"][0]["delta"]["content"]
                )

        restored: dict[int, str] = {}
        detok_total = 0
        unknown_total = 0
        types_total: set[str] = set()
        for idx, parts in pieces.items():
            joined = "".join(parts)
            new_text, detok, unknown, types = self._restore(joined)
            # Spec §5.2: unescape AFTER placeholder substitution so an
            # unescaped literal `<pl:` cannot be re-substituted.
            new_text = unescape_literal_placeholders(new_text)
            restored[idx] = new_text
            detok_total += detok
            unknown_total += unknown
            types_total.update(types)

        # Pass 2: re-distribute — first content chunk per choice carries the
        # full restored text; subsequent content chunks carry "".
        emitted: set[int] = set()
        out_chunks: list[bytes] = []
        for raw, obj in zip(raw_chunks, parsed):
            if obj is None:
                out_chunks.append(raw)
                continue
            idx = obj["choices"][0].get("index", 0)
            obj["choices"][0]["delta"]["content"] = (
                restored[idx] if idx not in emitted else ""
            )
            emitted.add(idx)
            out_chunks.append(
                b"data: " + _json.dumps(obj, ensure_ascii=False).encode("utf-8")
            )
        flow.response.set_content(b"\n\n".join(out_chunks))

        # One aggregate chain entry per stream that touched any placeholder
        # (argus issue #9 — replaces v1-style per-chunk entries).
        if detok_total or unknown_total:
            try:
                self._chain.append({
                    "line_type": "detokenization",
                    "direction": "in",
                    "host": host,  # v2 §4.5 — per-host attribution
                    "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                    "detok_count": detok_total,
                    "unknown_placeholders": unknown_total,
                    "types": sorted(types_total),
                })
            except Exception as e:
                # Fail closed in BOTH directions (argus issue #17): without an
                # audit line the restored secrets must not be delivered. Same
                # contract as addon.response() and SseStreamRewriter.rewrite().
                from mitmproxy.http import Response as _Resp
                flow.response = _Resp.make(
                    502,
                    _json.dumps({"error": "waterwall-chain-append-failed",
                                 "reason": str(e)}).encode(),
                    {"content-type": "application/json"},
                )
                return

    def _parse_content_chunk(self, raw_chunk: bytes) -> dict | None:
        """Return the parsed JSON object if this chunk carries string content
        at choices[0].delta.content; None for [DONE]/comments/non-content.

        Pass-through cases (returned as None; emitted byte-for-byte):
          - empty bytes
          - terminator `data: [DONE]`
          - chunk with no `data:` prefix (e.g., heartbeat comment `: ping`)
          - chunk where JSON parse fails
          - chunk with empty/absent/non-string delta.content
        """
        if not raw_chunk or raw_chunk.startswith(_DONE_LINE):
            return None
        if not raw_chunk.startswith(b"data: "):
            return None
        try:
            obj = _json.loads(raw_chunk[len(b"data: "):])
        except _json.JSONDecodeError:
            _log.warning("openai_sse: malformed JSON chunk; passing through")
            return None
        try:
            content = obj["choices"][0]["delta"].get("content")
        except (KeyError, IndexError, TypeError):
            return None
        if not content or not isinstance(content, str):
            return None
        return obj

    def _restore(self, text: str) -> tuple[str, int, int, list[str]]:
        """Replace each <pl:TYPE:HMAC8> with the stored plaintext (or pass
        through unchanged if not in store; bump unknown_placeholders counter).
        Returns (new_text, detok_count, unknown_count, sorted_types).

        Uses the canonical PLACEHOLDER_REGEX from tokenizer.py — the previous
        local copy required 8 hex chars while real placeholders carry 16, so
        restore never matched (argus issue #9, first finding).
        """
        detok = 0
        unknown = 0
        types: set[str] = set()

        def _sub(m: re.Match[str]) -> str:
            nonlocal detok, unknown
            ptype, hmac8 = m.group("type"), m.group("hmac8")
            plaintext = self._store.get(hmac8)
            if plaintext is None:
                unknown += 1
                return m.group(0)
            detok += 1
            types.add(ptype)
            return plaintext

        new_text = PLACEHOLDER_REGEX.sub(_sub, text)
        return new_text, detok, unknown, sorted(types)
