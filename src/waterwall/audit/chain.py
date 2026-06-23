# src/waterwall/audit/chain.py
"""Hash-chained JSONL writer with optional Ed25519 signing.

Spec §9.1 chain, §9.3 checkpoint canonicalization (RFC 8785-style: sorted keys,
no whitespace, ensure_ascii=False), §14 fail-closed on chain-append errors.

Phase 2 shipped the basic writer; Phase 5 (this task) adds:
- Optional signer for emit_checkpoint()
- ensure_ascii=False canonicalization (was True in Plan 1)
- Monotonic timestamp via _now_ms_monotonic
- ChainAppendError raised on OSError (caller fail-closes)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS_PREV_HASH = "0" * 64


def _canonical_json(obj: dict) -> str:
    """RFC 8785-style canonicalization: sorted keys, no whitespace, UTF-8 bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class ChainAppendError(Exception):
    """Raised when chain JSONL append fails (filesystem error). Spec §14."""


class ChainWriter:
    def __init__(
        self,
        path: Path,
        signer: "EdSigner | None" = None,
        signing_key_id: str = "waterwall-2026-05",
    ) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = GENESIS_PREV_HASH
        self._last_ts_ms: int = 0
        self._signer = signer
        self._signing_key_id = signing_key_id
        # Argus issue #13: surfaced on /healthz as health.chain_intact — set
        # False on any append/checkpoint OSError, True again on the next
        # successful write (self-heal when the disk recovers).
        self.healthy: bool = True
        path.parent.mkdir(parents=True, exist_ok=True)
        # Argus issue #8: resume from an existing log instead of forking a new
        # genesis-rooted segment on every restart. Unparseable trailing content
        # fails LOUD — silently resuming past a torn tail would fork the chain.
        if path.exists() and path.stat().st_size > 0:
            last_line: dict | None = None
            with open(path, "r", encoding="utf-8") as fp:
                for lineno, raw in enumerate(fp, start=1):
                    stripped = raw.rstrip("\n")
                    if not stripped:
                        continue
                    try:
                        last_line = json.loads(stripped)
                    except json.JSONDecodeError as e:
                        raise ChainAppendError(
                            f"unparseable chain line {lineno} in {path}: {e}. "
                            f"Run `waterwall verify-chain` and rotate before restarting."
                        ) from e
            if last_line is not None:
                self._seq = int(last_line.get("seq", 0))
                self._prev_hash = _sha256_hex(_canonical_json(last_line))
        self._fp = open(path, "a", encoding="utf-8")
        # v2 §5 (R5): write a PID-bearing .lock sibling so external tools
        # (rotate-chain) can detect a live writer and refuse destructive
        # operations — and detect a STALE lock (dead PID after SIGKILL/OOM)
        # so it doesn't wedge rotation forever (argus issue #8).
        self._lock_path = path.with_suffix(path.suffix + ".lock")
        self._lock_path.write_text(str(os.getpid()), encoding="utf-8")

    def _now_ms_monotonic(self) -> int:
        """Monotonic timestamp in milliseconds — never goes backward.
        Spec §14: clock-skew correction."""
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        if now_ms <= self._last_ts_ms:
            now_ms = self._last_ts_ms + 1
        self._last_ts_ms = now_ms
        return now_ms

    def _ts_iso(self, ms: int) -> str:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat(timespec="milliseconds")

    def append(self, payload: dict) -> dict:
        """Append a chain line with seq, ts, prev_hash. Returns the written line."""
        with self._lock:
            self._seq += 1
            ts_ms = self._now_ms_monotonic()
            line = {
                "v": 1,
                "ts": self._ts_iso(ts_ms),
                "seq": self._seq,
                "prev_hash": self._prev_hash,
                **payload,
            }
            try:
                serialized = _canonical_json(line)
                self._fp.write(serialized + "\n")
                self._fp.flush()
            except OSError as e:
                # Spec §14: chain-append failure → fail-closed via raised exception.
                # Caller (addon) catches and returns 502.
                self.healthy = False
                raise ChainAppendError(str(e)) from e
            self.healthy = True
            self._prev_hash = _sha256_hex(serialized)
            return line

    def emit_checkpoint(self) -> dict:
        """Emit a signed checkpoint with chain_root_hash per spec §9.3."""
        if self._signer is None:
            raise RuntimeError("emit_checkpoint requires a signer")
        with self._lock:
            self._seq += 1
            ts_ms = self._now_ms_monotonic()
            line = {
                "v": 1,
                "ts": self._ts_iso(ts_ms),
                "seq": self._seq,
                "prev_hash": self._prev_hash,
                "line_type": "checkpoint",
                "signing_key_id": self._signing_key_id,
                "chain_root_hash": "",
                "signature": "",
            }
            chain_root = _sha256_hex(_canonical_json(line))
            line["chain_root_hash"] = chain_root
            sig = self._signer.sign(bytes.fromhex(chain_root))
            line["signature"] = base64.b64encode(sig).decode("ascii")

            serialized = _canonical_json(line)
            try:
                self._fp.write(serialized + "\n")
                self._fp.flush()
                # Checkpoints are the durability anchor — fsync so a host power
                # loss cannot drop an acknowledged checkpoint (argus issue #8).
                os.fsync(self._fp.fileno())
            except OSError as e:
                self.healthy = False
                raise ChainAppendError(str(e)) from e
            self.healthy = True
            self._prev_hash = _sha256_hex(serialized)
            return line

    def close(self) -> None:
        with self._lock:
            try:
                self._fp.close()
            finally:
                if self._lock_path.exists():
                    self._lock_path.unlink()
