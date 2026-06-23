# src/waterwall/cli/export_evidence.py
"""export-evidence: bundle chain + receipts + manifests into a portable tar.gz.

Spec §9.6, §12.4.

Bundle layout:
  bundle.tar.gz/
    MANIFEST.json
    chain/proxy.jsonl
    receipts/{ts}_{request_id}.json     (one per receipt in range)
    manifests/{ts}_{session_id}.json    (one per manifest in range)
    policy/patterns.py
    pubkey.pem

v1 note: the full chain log is always included as a single segment — chain
segmentation by date range is deferred to v1.1. since/until filtering applies
only to receipts and manifests (by filename timestamp prefix, first 15 chars
YYYYMMDDTHHMMSS).
"""

from __future__ import annotations

import hashlib
import json
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_ts_prefix(name: str) -> datetime | None:
    """Parse the first 15 chars of a filename as YYYYMMDDTHHMMSS.

    Receipts also have a microseconds suffix (.NNN) before the underscore,
    but we truncate to second granularity for since/until comparisons.
    Returns None if the name doesn't start with a recognisable timestamp.
    """
    try:
        return datetime.strptime(name[:15], "%Y%m%dT%H%M%S").replace(
            tzinfo=timezone.utc
        )
    except (ValueError, IndexError):
        return None


def _files_in_range(
    directory: Path,
    since: datetime | None,
    until: datetime | None,
) -> list[Path]:
    """Return sorted list of files in directory whose filename ts is in [since, until)."""
    result = []
    for p in sorted(directory.iterdir()):
        if not p.is_file():
            continue
        if since is None and until is None:
            result.append(p)
            continue
        ts = _parse_ts_prefix(p.name)
        if ts is None:
            result.append(p)  # include files whose names have no parseable ts
            continue
        if since is not None and ts < since:
            continue
        if until is not None and ts >= until:
            continue
        result.append(p)
    return result


def _scan_chain(chain_path: Path) -> tuple[int, int, int, int]:
    """Return (first_seq, last_seq, line_count, checkpoint_count) by streaming the log."""
    first_seq: int | None = None
    last_seq: int | None = None
    lines = 0
    checkpoints = 0
    with open(chain_path, "r", encoding="utf-8") as fp:
        for raw in fp:
            raw = raw.rstrip("\n")
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            seq = obj.get("seq")
            if seq is not None:
                if first_seq is None:
                    first_seq = seq
                last_seq = seq
            if obj.get("line_type") == "checkpoint":
                checkpoints += 1
            lines += 1
    return (
        first_seq if first_seq is not None else 0,
        last_seq if last_seq is not None else 0,
        lines,
        checkpoints,
    )


def export_evidence(
    *,
    chain_path: Path,
    receipts_dir: Path | None,
    manifests_dir: Path | None,
    policy_snapshot: Path,
    pubkey_path: Path,
    out: Path,
    signing_key_path: Path,
    since: datetime | None = None,
    until: datetime | None = None,
) -> None:
    """Build an evidence bundle tar.gz at *out*.

    Parameters
    ----------
    chain_path:      path to the JSONL chain log (always included in full for v1)
    receipts_dir:    directory of per-redaction receipt JSON files (or None)
    manifests_dir:   directory of per-session manifest JSON files (or None)
    policy_snapshot: patterns.py file to snapshot into policy/
    pubkey_path:     Ed25519 public key (PEM) to embed
    out:             destination .tar.gz path
    signing_key_path: Ed25519 private key (PEM) used to sign MANIFEST.json
                     (argus issue #12: bundle completeness must be authenticated)
    since/until:     optional datetime bounds for receipt/manifest filtering
                     (chain is always included in full — v1 limitation)
    """
    import shutil
    import tempfile

    now = datetime.now(timezone.utc)

    # Snapshot the chain ONCE — the live ChainWriter appends continuously and
    # hashing/tarring the moving file makes fresh bundles fail their own
    # verification (argus issue #12). Every chain read below (stats scan,
    # sha256, signing_key_id scan, tar member) uses this frozen copy.
    snap_dir = tempfile.mkdtemp(prefix="waterwall-export-")
    chain_snapshot = Path(snap_dir) / chain_path.name
    shutil.copy2(chain_path, chain_snapshot)
    try:
        receipt_files: list[Path] = []
        if receipts_dir is not None and receipts_dir.is_dir():
            receipt_files = _files_in_range(receipts_dir, since, until)

        manifest_files: list[Path] = []
        if manifests_dir is not None and manifests_dir.is_dir():
            manifest_files = _files_in_range(manifests_dir, since, until)

        # Compute chain stats (from the snapshot, never the live file)
        first_seq, last_seq, chain_lines, chain_cps = _scan_chain(chain_snapshot)
        chain_sha = _sha256_file(chain_snapshot)
        policy_sha = _sha256_file(policy_snapshot)
        pubkey_sha = _sha256_file(pubkey_path)

        receipt_entries = [
            {"file": f"receipts/{p.name}", "sha256": _sha256_file(p)}
            for p in receipt_files
        ]
        manifest_entries = [
            {"file": f"manifests/{p.name}", "sha256": _sha256_file(p)}
            for p in manifest_files
        ]

        # Determine signing_key_id from chain (first checkpoint or first line)
        signing_key_id = "waterwall-2026-05"
        with open(chain_snapshot, "r", encoding="utf-8") as fp:
            for raw in fp:
                raw = raw.rstrip("\n")
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                    kid = obj.get("signing_key_id")
                    if kid:
                        signing_key_id = kid
                        break
                except json.JSONDecodeError:
                    continue

        manifest = {
            "v": 1,
            "ts_exported": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
            "since": since.isoformat() if since else None,
            "until": until.isoformat() if until else None,
            "policy_hash": policy_sha,
            "signing_key_id": signing_key_id,
            "chain": {
                "file": "chain/proxy.jsonl",
                "sha256": chain_sha,
                "seq_range": [first_seq, last_seq],
                "lines": chain_lines,
                "checkpoints": chain_cps,
            },
            "receipts": receipt_entries,
            "manifests": manifest_entries,
            "policy_snapshot": {"file": "policy/patterns.py", "sha256": policy_sha},
            "pubkey": {"file": "pubkey.pem", "sha256": pubkey_sha},
        }

        # Sign the MANIFEST itself (argus issue #12). Same zeroed-signature
        # canonicalization scheme as Action Receipts: sign over the canonical
        # JSON with "signature" set to "".
        import base64

        from waterwall.audit.receipt import _canonical_payload
        from waterwall.audit.signer import EdSigner

        manifest["signature"] = ""
        signer = EdSigner.load(signing_key_path)
        sig = signer.sign(_canonical_payload(manifest).encode("utf-8"))
        manifest["signature"] = base64.b64encode(sig).decode("ascii")
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")

        with tarfile.open(out, "w:gz") as tf:
            # MANIFEST.json — from bytes
            import io
            m_info = tarfile.TarInfo(name="MANIFEST.json")
            m_info.size = len(manifest_bytes)
            tf.addfile(m_info, io.BytesIO(manifest_bytes))

            # chain/proxy.jsonl (the snapshot, under the canonical arcname)
            tf.add(chain_snapshot, arcname="chain/proxy.jsonl")

            # receipts/
            for p in receipt_files:
                tf.add(p, arcname=f"receipts/{p.name}")

            # manifests/
            for p in manifest_files:
                tf.add(p, arcname=f"manifests/{p.name}")

            # policy/patterns.py
            tf.add(policy_snapshot, arcname="policy/patterns.py")

            # pubkey.pem
            tf.add(pubkey_path, arcname="pubkey.pem")
    finally:
        shutil.rmtree(snap_dir, ignore_errors=True)


def main_cli() -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="waterwall export-evidence")
    ap.add_argument("--chain", required=True, type=Path, help="Path to chain JSONL log")
    ap.add_argument("--receipts-dir", type=Path, default=None, help="Receipts directory")
    ap.add_argument("--manifests-dir", type=Path, default=None, help="Manifests directory")
    ap.add_argument("--policy", required=True, type=Path, help="patterns.py snapshot")
    ap.add_argument("--pubkey", required=True, type=Path, help="Ed25519 public key (PEM)")
    ap.add_argument(
        "--signing-key", required=True, type=Path,
        help="Ed25519 private key (PEM) to sign MANIFEST.json",
    )
    ap.add_argument("-o", "--out", required=True, type=Path, help="Output .tar.gz path")
    ap.add_argument("--since", default=None, help="ISO datetime lower bound (inclusive)")
    ap.add_argument("--until", default=None, help="ISO datetime upper bound (exclusive)")
    args = ap.parse_args()

    since = datetime.fromisoformat(args.since) if args.since else None
    until = datetime.fromisoformat(args.until) if args.until else None

    export_evidence(
        chain_path=args.chain,
        receipts_dir=args.receipts_dir,
        manifests_dir=args.manifests_dir,
        policy_snapshot=args.policy,
        pubkey_path=args.pubkey,
        out=args.out,
        signing_key_path=args.signing_key,
        since=since,
        until=until,
    )
    print(f"OK: bundle written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main_cli())
