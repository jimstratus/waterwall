# src/waterwall/audit/manifest.py
"""Session Manifests. Spec §9.4.

Emitted on session-end (X-Claude-Code-Session-Id changes, 30-min idle, or proxy SIGTERM).
"""

from __future__ import annotations

import base64
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from waterwall.audit.frameworks import tags_for
from waterwall.audit.receipt import _canonical_payload, _safe_filename_part


@dataclass
class SessionTracker:
    session_id: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # first_seq: chain seq number at session start (set when tracker is created
    # in addon._track_session). Used for chain_seq_range[0] in the manifest.
    first_seq: int | None = None
    redaction_total: int = 0
    types_seen: Counter = field(default_factory=Counter)
    unknown_placeholder_count: int = 0
    request_count: int = 0

    def record_redaction(self, type_label: str) -> None:
        self.redaction_total += 1
        self.types_seen[type_label] += 1

    def record_request(self) -> None:
        self.request_count += 1

    def record_unknown_placeholders(self, n: int) -> None:
        self.unknown_placeholder_count += n

    @property
    def avg_redactions_per_request(self) -> float:
        return self.redaction_total / self.request_count if self.request_count else 0.0


def emit_manifest(
    out_dir: Path,
    tracker: SessionTracker,
    chain_seq_range: tuple[int, int],
    chain_root_hash: str,
    policy_hash: str,
    signer,
    signing_key_id: str,
) -> Path:
    ended = datetime.now(timezone.utc)
    body = {
        "v": 1,
        "manifest_type": "session",
        "session_id": tracker.session_id,
        "started_ts": tracker.started_at.isoformat(timespec="milliseconds"),
        "ended_ts": ended.isoformat(timespec="milliseconds"),
        "redaction_total": tracker.redaction_total,
        "types_seen": dict(tracker.types_seen),
        "chain_seq_range": list(chain_seq_range),
        "chain_root_hash": chain_root_hash,
        "policy_hash": policy_hash,
        # max_block_buffer_kib dropped (argus issue #17): it was never
        # measured anywhere — a signed zero is worse than absence.
        "behavioral_fingerprint": {
            "avg_redactions_per_request": tracker.avg_redactions_per_request,
            "unknown_placeholder_count": tracker.unknown_placeholder_count,
            "request_count": tracker.request_count,
        },
        "frameworks": tags_for("manifest"),
        "signing_key_id": signing_key_id,
        "signature": "",
    }
    sig = signer.sign(_canonical_payload(body).encode())
    body["signature"] = base64.b64encode(sig).decode("ascii")

    out_dir.mkdir(parents=True, exist_ok=True)
    fname = f"{ended.strftime('%Y%m%dT%H%M%S')}_{_safe_filename_part(tracker.session_id)}.json"
    path = out_dir / fname
    path.write_text(json.dumps(body, indent=2), encoding="utf-8")
    return path
