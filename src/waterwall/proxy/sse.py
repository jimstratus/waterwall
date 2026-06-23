# src/waterwall/proxy/sse.py
"""SSE byte-stream parser + per-content-block buffering for strategy (b) finalize-on-content_block_stop.

Spec §5.3.
"""

from __future__ import annotations

from typing import Generator


class SseLineSplitter:
    """Splits incremental byte chunks into SSE events.

    SSE-format: blank-line-terminated blocks of `name: value` lines.
    For Anthropic's stream we expect at minimum `event:` and `data:` per block.
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> Generator[tuple[str, str], None, None]:
        self._buf.extend(chunk)
        while True:
            sep_lf = self._buf.find(b"\n\n")
            sep_crlf = self._buf.find(b"\r\n\r\n")
            if sep_crlf >= 0 and (sep_lf < 0 or sep_crlf < sep_lf):
                sep, sep_len = sep_crlf, 4
            elif sep_lf >= 0:
                sep, sep_len = sep_lf, 2
            else:
                return
            block = bytes(self._buf[:sep]).decode("utf-8", errors="replace")
            del self._buf[: sep + sep_len]
            event_name = ""
            data_lines: list[str] = []
            for line in block.replace("\r\n", "\n").split("\n"):
                if line.startswith("event:"):
                    event_name = line[len("event:") :].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[len("data:") :].lstrip())
            if event_name:
                yield (event_name, "\n".join(data_lines))

    def residue(self) -> bytes:
        """Unconsumed trailing bytes (no terminator seen). The rewriter appends
        these verbatim so a truncated upstream stream loses nothing (argus #14)."""
        return bytes(self._buf)


import json as _json
from typing import Iterator

from waterwall.proxy.tokenizer import (
    PLACEHOLDER_REGEX,
    unescape_literal_placeholders,
)


BUFFER_HARD_CAP_BYTES = 1 * 1024 * 1024  # 1 MiB per content block


class SseStreamRewriter:
    """Strategy (b): buffer per content-block index, finalize at content_block_stop.

    Spec §5.3 (v1) + §4.2 (v2: implements the SseHandler Protocol — exposes
    rewrite(flow) which owns the audit-log emission + state-aggregator wiring
    that v1's addon.response() did inline).
    """

    def __init__(
        self,
        store,
        chain=None,
        state_aggregator=None,
        policy_hash: str | None = None,
    ) -> None:
        self._store = store
        self._chain = chain
        self._state_aggregator = state_aggregator
        self._policy_hash = policy_hash
        self._splitter = SseLineSplitter()
        self._buffers: dict[int, str] = {}
        self._buffer_bytes: dict[int, int] = {}
        self._block_meta: dict[int, dict] = {}
        # Pending output bytes (re-serialized SSE events to forward to client)
        self._pending_out = bytearray()

    def rewrite(self, flow) -> None:
        """v2 SseHandler Protocol entry point.

        Buffer-then-detok the full SSE response (v1 limitation; v1.1 will
        swap to true per-chunk streaming). Run feed() over the entire
        response.content; set rewritten bytes back; emit a
        line_type=detokenization chain entry; record activity.

        chain / state_aggregator are optional — unit tests for byte-level
        rewriting construct without them.

        State reset at entry: a single SseStreamRewriter instance is registered
        per host in addon._sse_handlers (v2 §4.2), so it serves every flow
        targeting that host. v1 used to create a fresh rewriter per flow via
        responseheaders(); we collapse that lifetime by clearing per-stream
        state here so a malformed/truncated stream from flow A cannot leak
        bytes into flow B.
        """
        from datetime import datetime, timezone

        self._splitter = SseLineSplitter()
        self._buffers.clear()
        self._buffer_bytes.clear()
        self._block_meta.clear()
        self._pending_out.clear()

        rewritten = b"".join(self.feed(flow.response.content))
        residue = self._splitter.residue()
        if residue:
            import logging

            logging.getLogger("waterwall.sse").warning(
                "SSE stream ended without terminator; passing %d tail bytes through",
                len(residue),
            )
            rewritten += residue
        flow.response.content = rewritten

        if self._chain is not None:
            try:
                self._chain.append({
                    "line_type": "detokenization",
                    "direction": "in",
                    "host": flow.request.host,
                    "request_id": flow.request.headers.get("x-request-id"),
                    "session_id": flow.request.headers.get("x-claude-code-session-id"),
                    "streaming": True,
                    "policy_hash": self._policy_hash,
                })
            except Exception as e:
                # Fail closed in BOTH directions (argus issue #17, spec §14):
                # without an audit line the detokenized stream must not be
                # delivered. Replace the rewritten body with a 502.
                from mitmproxy.http import Response as _Resp

                flow.response = _Resp.make(
                    502,
                    _json.dumps({
                        "error": "waterwall-chain-append-failed",
                        "reason": str(e),
                    }).encode(),
                    {"content-type": "application/json"},
                )
                return

        if self._state_aggregator is not None:
            self._state_aggregator.record_activity({
                "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "direction": "in",
                "request_id": flow.request.headers.get("x-request-id", "—"),
                "detok_count": 0,  # streaming branch — buffered detok counts in v1.1
            })

    def feed(self, chunk: bytes) -> Iterator[bytes]:
        for event_name, data in self._splitter.feed(chunk):
            self._handle(event_name, data)
            if self._pending_out:
                out = bytes(self._pending_out)
                self._pending_out.clear()
                yield out

    def _emit(self, event_name: str, payload_obj: dict) -> None:
        self._pending_out.extend(
            f"event: {event_name}\ndata: {_json.dumps(payload_obj)}\n\n".encode()
        )

    def _handle(self, event_name: str, data: str) -> None:
        if event_name in {"message_start", "message_stop", "ping", "error"}:
            try:
                obj = _json.loads(data) if data else {}
            except _json.JSONDecodeError:
                self._pending_out.extend(
                    f"event: {event_name}\ndata: {data}\n\n".encode()
                )
                return
            self._emit(event_name, obj)
            return

        try:
            obj = _json.loads(data)
        except _json.JSONDecodeError:
            self._pending_out.extend(
                f"event: {event_name}\ndata: {data}\n\n".encode()
            )
            return

        if event_name == "content_block_start":
            idx = obj.get("index", 0)
            self._buffers[idx] = ""
            self._buffer_bytes[idx] = 0
            self._block_meta[idx] = obj.get("content_block", {})
            self._emit(event_name, obj)
            return

        if event_name == "content_block_delta":
            idx = obj.get("index", 0)
            delta = obj.get("delta", {})
            dtype = delta.get("type")

            if dtype == "signature_delta":
                # Pass through; do NOT buffer or substitute.
                self._emit(event_name, obj)
                return

            text_to_buffer = ""
            if dtype == "text_delta":
                text_to_buffer = delta.get("text", "")
            elif dtype == "input_json_delta":
                text_to_buffer = delta.get("partial_json", "")
            elif dtype == "thinking_delta":
                text_to_buffer = delta.get("thinking", "")
            elif dtype == "citations_delta":
                # Pass through; citation payloads are source-document quotes,
                # NOT block text. Buffering them spliced quotes into the
                # visible message body (argus issue #14).
                self._emit(event_name, obj)
                return
            else:
                # Unknown delta type: pass through unchanged
                self._emit(event_name, obj)
                return

            if idx in self._buffers:
                self._buffers[idx] += text_to_buffer
                self._buffer_bytes[idx] = self._buffer_bytes.get(idx, 0) + len(
                    text_to_buffer.encode()
                )
                if self._buffer_bytes[idx] > BUFFER_HARD_CAP_BYTES:
                    # Degraded mode (spec §5.3 risk row): FLUSH the buffer
                    # unsubstituted (it was replaced on the wire by heartbeats)
                    # then pass this and subsequent deltas through. Discarding
                    # the buffer destroyed up to 1 MiB of output (argus #14).
                    flushed = self._buffers[idx]
                    self._buffers.pop(idx, None)
                    self._buffer_bytes.pop(idx, None)
                    if flushed:
                        recovery = dict(obj)
                        recovery["delta"] = {"type": dtype, **{
                            {"text_delta": "text", "input_json_delta": "partial_json",
                             "thinking_delta": "thinking"}[dtype]: flushed
                        }}
                        self._emit(event_name, recovery)
                    if self._chain is not None:
                        try:
                            self._chain.append({
                                "line_type": "warn",
                                "warn": "sse_degraded_mode",
                                "block_idx": idx,
                                "reason": f"buffer exceeded {BUFFER_HARD_CAP_BYTES} bytes",
                            })
                        except Exception:
                            pass
                    return
            else:
                # Block previously entered degraded mode (or start was never
                # seen) — pass through unsubstituted.
                self._emit(event_name, obj)
                return
            # Heartbeat: emit empty same-shape delta to keep stream alive
            heartbeat = dict(obj)
            heartbeat["delta"] = dict(delta)
            if dtype == "text_delta":
                heartbeat["delta"]["text"] = ""
            elif dtype == "input_json_delta":
                heartbeat["delta"]["partial_json"] = ""
            elif dtype == "thinking_delta":
                heartbeat["delta"]["thinking"] = ""
            self._emit(event_name, heartbeat)
            return

        if event_name == "content_block_stop":
            idx = obj.get("index", 0)
            full = self._buffers.pop(idx, "")
            self._buffer_bytes.pop(idx, None)
            meta = self._block_meta.pop(idx, {})
            substituted = PLACEHOLDER_REGEX.sub(
                lambda m: self._store.get(m.group("hmac8")) or m.group(0),
                full,
            )
            substituted = unescape_literal_placeholders(substituted)
            block_type = meta.get("type")  # set at content_block_start
            if block_type in ("tool_use", "server_tool_use"):
                delta_payload = {"type": "input_json_delta", "partial_json": substituted}
            elif block_type == "thinking":
                delta_payload = {"type": "thinking_delta", "thinking": substituted}
            elif block_type == "text" or substituted:
                delta_payload = {"type": "text_delta", "text": substituted}
            else:
                # Unknown block type with empty buffer: no synthetic delta —
                # injecting empty text_delta into non-text blocks broke strict
                # SDK accumulators (argus issue #14).
                delta_payload = None

            if delta_payload is not None:
                self._emit("content_block_delta", {
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": delta_payload,
                })
            self._emit(event_name, obj)
            return

        if event_name == "message_delta":
            # stop_sequence may be a placeholder
            self._emit(event_name, obj)
            return

        # Default: pass through
        self._emit(event_name, obj)
