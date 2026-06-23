# src/waterwall/audit/receipt.py
"""Action Receipts. Spec §9.2.

Per-redaction Ed25519-signed payload. Independently verifiable via
`waterwall verify-receipt`.
"""

from __future__ import annotations

import base64
import json
import re as _re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from waterwall.audit.chain import _canonical_json
from waterwall.audit.frameworks import tags_for


@dataclass(frozen=True)
class ReceiptEvent:
    type: str
    hmac8: str


# Single canonicalization source: audit/chain.py. Receipt signing, MANIFEST
# signing (export_evidence), and all verifiers must stay byte-identical —
# argus R1 quality review flagged the triplicated copies as a sync hazard.
_canonical_payload = _canonical_json


def _safe_filename_part(value: str | None, fallback: str = "unknown") -> str:
    """Sanitize a client-controlled value for use in an artifact filename.

    Argus issue #17: x-request-id / session id flowed unsanitized into
    filesystem paths. Strips path separators and collapses dot-runs so no
    '..' sequence (even as a substring) survives.
    """
    if not value:
        return fallback
    value = _re.sub(r"\.{2,}", "_", value)
    value = _re.sub(r"[^A-Za-z0-9._-]", "_", value)[:120]
    # Strip edge dots: a trailing '.' re-forms '..' once the caller appends
    # '.json' (Copilot finding on PR #18); a leading '.' hides the file.
    value = value.strip(".")
    return value or fallback


def emit_receipt(
    out_dir: Path,
    request_id: str,
    session_id: str | None,
    events: list[ReceiptEvent],
    policy_hash: str,
    chain_seq: int,
    signer,
    signing_key_id: str,
) -> Path:
    ts = datetime.now(timezone.utc)
    ts_iso = ts.isoformat(timespec="milliseconds")
    ts_for_filename = ts.strftime("%Y%m%dT%H%M%S.%f")[:-3]

    body = {
        "v": 1,
        "receipt_type": "redaction",
        "ts": ts_iso,
        "request_id": request_id,
        "session_id": session_id,
        "redaction_count": len(events),
        "types": [e.type for e in events],
        "hmac8s": [e.hmac8 for e in events],
        "policy_hash": policy_hash,
        "chain_seq": chain_seq,
        "frameworks": tags_for("redaction"),
        "signing_key_id": signing_key_id,
        "signature": "",
    }
    sig = signer.sign(_canonical_payload(body).encode())
    body["signature"] = base64.b64encode(sig).decode("ascii")

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{ts_for_filename}_{_safe_filename_part(request_id)}.json"
    path.write_text(json.dumps(body, indent=2), encoding="utf-8")
    return path
