# src/waterwall/cli/verify_chain.py
"""verify-chain: walks a Flight Recorder JSONL log, verifies prev_hash links,
and verifies every checkpoint signature. Spec §12.2."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path

from waterwall.audit.chain import _canonical_json, _sha256_hex, GENESIS_PREV_HASH
from waterwall.audit.signer import EdVerifier


@dataclass
class ChainVerificationResult:
    ok: bool
    lines_verified: int
    checkpoints_verified: int
    first_failure_seq: int | None = None
    failure_reason: str = ""
    first_seq: int | None = None
    last_seq: int | None = None


def verify_chain_file(log_path: Path, pubkey_path: Path) -> ChainVerificationResult:
    verifier = EdVerifier.load(pubkey_path)
    expected_prev = GENESIS_PREV_HASH
    lines_verified = 0
    cp_verified = 0
    first_seq: int | None = None
    last_seq: int | None = None

    # Stream line-by-line — argus 2026-05-06 review (kimi-k2.6 conf 95) flagged
    # that read_text().splitlines() on a 500MB+ chain log would exhaust memory.
    # 14-day retention at homelab traffic levels stays well below that, but
    # streaming is the right default.
    with open(log_path, "r", encoding="utf-8") as fp:
        for raw in fp:
            raw = raw.rstrip("\n")
            if not raw:
                continue
            try:
                line = json.loads(raw)
            except json.JSONDecodeError as e:
                return ChainVerificationResult(
                    ok=False, lines_verified=lines_verified,
                    checkpoints_verified=cp_verified,
                    first_failure_seq=lines_verified + 1,
                    failure_reason=f"json decode failure: {e}",
                )
            if line.get("prev_hash") != expected_prev:
                return ChainVerificationResult(
                    ok=False, lines_verified=lines_verified,
                    checkpoints_verified=cp_verified,
                    first_failure_seq=line.get("seq"),
                    failure_reason=f"prev_hash mismatch at seq {line.get('seq')}",
                )
            # If checkpoint, recompute the root from THIS line's content, then
            # verify the signature over the recomputed root. Trusting the
            # embedded chain_root_hash lets an attacker replay a genuine
            # (root, signature) pair onto a fabricated chain (argus issue #6).
            if line.get("line_type") == "checkpoint":
                try:
                    sig = base64.b64decode(line["signature"])
                    claimed_root = line["chain_root_hash"]
                except Exception as e:
                    return ChainVerificationResult(
                        ok=False, lines_verified=lines_verified,
                        checkpoints_verified=cp_verified,
                        first_failure_seq=line.get("seq"),
                        failure_reason=f"checkpoint signature decode failure: {e}",
                    )
                unsigned = dict(line)
                unsigned["chain_root_hash"] = ""
                unsigned["signature"] = ""
                recomputed_root = _sha256_hex(_canonical_json(unsigned))
                if recomputed_root != claimed_root:
                    return ChainVerificationResult(
                        ok=False, lines_verified=lines_verified,
                        checkpoints_verified=cp_verified,
                        first_failure_seq=line.get("seq"),
                        failure_reason=(
                            f"checkpoint chain_root_hash mismatch at seq "
                            f"{line.get('seq')}: embedded root does not match "
                            f"recomputed line content"
                        ),
                    )
                if not verifier.verify(bytes.fromhex(recomputed_root), sig):
                    return ChainVerificationResult(
                        ok=False, lines_verified=lines_verified,
                        checkpoints_verified=cp_verified,
                        first_failure_seq=line.get("seq"),
                        failure_reason=f"checkpoint signature failed verification at seq {line.get('seq')}",
                    )
                cp_verified += 1

            expected_prev = _sha256_hex(_canonical_json(line))
            lines_verified += 1
            seq = line.get("seq")
            if isinstance(seq, int):
                if first_seq is None:
                    first_seq = seq
                last_seq = seq

    if lines_verified == 0:
        return ChainVerificationResult(
            ok=False, lines_verified=0, checkpoints_verified=0,
            failure_reason="empty chain log: 0 lines verified (possible truncation)",
        )
    return ChainVerificationResult(
        ok=True, lines_verified=lines_verified, checkpoints_verified=cp_verified,
        first_seq=first_seq, last_seq=last_seq,
    )


def main_cli() -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="waterwall verify-chain")
    ap.add_argument("log_path", type=Path)
    ap.add_argument("--pubkey", required=True, type=Path)
    args = ap.parse_args()
    r = verify_chain_file(args.log_path, args.pubkey)
    if r.ok:
        print(f"OK: {r.lines_verified} lines verified, {r.checkpoints_verified} checkpoints valid")
        return 0
    print(
        f"FAIL: first failure at seq {r.first_failure_seq}: {r.failure_reason}\n"
        f"verified up to {r.lines_verified} lines, {r.checkpoints_verified} checkpoints"
    )
    return 1
