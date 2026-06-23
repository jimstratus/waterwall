# src/waterwall/cli/verify_evidence.py
"""verify-evidence: verify an evidence bundle produced by export-evidence.

Spec §9.6, §12.5.

Verification steps (in order):
1. Extract bundle to a temp dir.
2. Read MANIFEST.json.
3. For every listed file: recompute SHA-256, compare to MANIFEST. Any mismatch
   → fail with the file's basename in failure_reason.
4. Run verify_chain_file on chain/proxy.jsonl — propagate failure with "chain"
   or "seq" in reason.
5. Run verify_receipt_file on every receipt — propagate failure with the
   receipt's filename in reason.
6. Run _verify_manifest_file on every session manifest — propagate failure with
   the manifest's filename in reason.
7. Confirm pubkey.pem in bundle matches the supplied pubkey (SHA-256 compare).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from waterwall.cli.verify_chain import verify_chain_file
from waterwall.cli.verify_receipt import verify_receipt_file


@dataclass
class EvidenceVerificationResult:
    ok: bool
    failure_reason: str = ""


# ---------------------------------------------------------------------------
# Session-manifest verifier (mirrors verify_receipt_file; manifest.py has none)
# ---------------------------------------------------------------------------

# Single canonicalization source (see audit/receipt.py note): the verifier
# MUST use byte-identical canonicalization to the signing side.
from waterwall.audit.chain import _canonical_json


def _verify_manifest_file(manifest_path: Path, pubkey_path: Path) -> bool:
    """Return True iff the session manifest's Ed25519 signature is valid."""
    from waterwall.audit.signer import EdVerifier, SignerError
    import base64

    try:
        body = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return False

    sig_b64 = body.get("signature")
    if not sig_b64:
        return False

    try:
        sig_bytes = base64.b64decode(sig_b64)
    except Exception:
        return False

    unsigned = dict(body)
    unsigned["signature"] = ""
    canonical = _canonical_json(unsigned).encode("utf-8")

    try:
        verifier = EdVerifier.load(pubkey_path)
    except SignerError:
        return False

    return verifier.verify(canonical, sig_bytes)


# ---------------------------------------------------------------------------
# SHA-256 helper
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Safe tar extraction (no extractall — avoids path-traversal)
# ---------------------------------------------------------------------------

def _tar_extract(bundle: Path, extract_dir: Path) -> None:
    """Extract a tar.gz bundle member-by-member, guarding against path traversal."""
    with tarfile.open(bundle, "r:gz") as tf:
        for member in tf.getmembers():
            dest = (extract_dir / member.name).resolve()
            base = str(extract_dir.resolve())
            if not (str(dest) == base or str(dest).startswith(base + os.sep)):
                raise ValueError(f"Unsafe tar member: {member.name!r}")
            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                dest.parent.mkdir(parents=True, exist_ok=True)
                with tf.extractfile(member) as src, open(dest, "wb") as dst:
                    dst.write(src.read())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_evidence_bundle(
    bundle_path: Path,
    pubkey_path: Path,
) -> EvidenceVerificationResult:
    """Verify an evidence bundle.

    Returns EvidenceVerificationResult(ok=True) if every check passes.
    On first failure returns ok=False with a descriptive failure_reason that
    includes the filename of the offending artifact.
    """
    with tempfile.TemporaryDirectory() as _tmp:
        extract_dir = Path(_tmp)
        try:
            _tar_extract(bundle_path, extract_dir)
        except Exception as exc:
            return EvidenceVerificationResult(ok=False, failure_reason=f"extraction failed: {exc}")

        # -- 1. Read MANIFEST.json --
        manifest_path = extract_dir / "MANIFEST.json"
        if not manifest_path.exists():
            return EvidenceVerificationResult(ok=False, failure_reason="MANIFEST.json missing")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return EvidenceVerificationResult(ok=False, failure_reason=f"MANIFEST.json parse error: {exc}")

        # -- 1b. MANIFEST.json signature (argus issue #12: completeness must
        # be authenticated, not just per-file hashes). Same zeroed-signature
        # canonicalization scheme as receipts/session manifests: verify over
        # canonical JSON with "signature" set to "".
        sig_b64 = manifest.get("signature")
        if not sig_b64:
            return EvidenceVerificationResult(ok=False, failure_reason="MANIFEST.json is unsigned")
        import base64

        from waterwall.audit.signer import EdVerifier

        unsigned = dict(manifest)
        unsigned["signature"] = ""
        try:
            verifier = EdVerifier.load(pubkey_path)
            sig_ok = verifier.verify(
                _canonical_json(unsigned).encode("utf-8"), base64.b64decode(sig_b64)
            )
        except Exception:
            sig_ok = False
        if not sig_ok:
            return EvidenceVerificationResult(ok=False, failure_reason="MANIFEST.json signature invalid")

        # -- 2. SHA-256 integrity checks for every listed file --

        # chain
        chain_entry = manifest.get("chain", {})
        chain_rel = chain_entry.get("file", "chain/proxy.jsonl")
        chain_file = extract_dir / chain_rel
        if not chain_file.exists():
            return EvidenceVerificationResult(ok=False, failure_reason=f"{chain_rel} missing")
        actual_sha = _sha256_file(chain_file)
        if actual_sha != chain_entry.get("sha256", ""):
            return EvidenceVerificationResult(
                ok=False, failure_reason=f"sha256 mismatch on {chain_rel}"
            )

        # receipts
        for entry in manifest.get("receipts", []):
            rel = entry.get("file", "")
            p = extract_dir / rel
            if not p.exists():
                return EvidenceVerificationResult(ok=False, failure_reason=f"{rel} missing")
            if _sha256_file(p) != entry.get("sha256", ""):
                return EvidenceVerificationResult(
                    ok=False, failure_reason=f"sha256 mismatch on {p.name}"
                )

        # manifests
        for entry in manifest.get("manifests", []):
            rel = entry.get("file", "")
            p = extract_dir / rel
            if not p.exists():
                return EvidenceVerificationResult(ok=False, failure_reason=f"{rel} missing")
            if _sha256_file(p) != entry.get("sha256", ""):
                return EvidenceVerificationResult(
                    ok=False, failure_reason=f"sha256 mismatch on {p.name}"
                )

        # policy snapshot — fail-closed: if MANIFEST lists it, file MUST exist.
        # Silent-skip on missing file would let an attacker omit policy/patterns.py
        # to bypass policy-divergence detection (code-review-7-3 critical finding).
        policy_entry = manifest.get("policy_snapshot", {})
        if policy_entry:
            policy_rel = policy_entry.get("file", "policy/patterns.py")
            policy_file = extract_dir / policy_rel
            if not policy_file.exists():
                return EvidenceVerificationResult(
                    ok=False, failure_reason=f"{policy_rel} missing"
                )
            if _sha256_file(policy_file) != policy_entry.get("sha256", ""):
                return EvidenceVerificationResult(
                    ok=False, failure_reason=f"sha256 mismatch on {policy_rel}"
                )

        # pubkey — fail-closed: if MANIFEST lists it, file MUST exist.
        pubkey_entry = manifest.get("pubkey", {})
        bundled_pubkey = extract_dir / "pubkey.pem"
        if pubkey_entry:
            if not bundled_pubkey.exists():
                return EvidenceVerificationResult(
                    ok=False, failure_reason="pubkey.pem missing"
                )
            if _sha256_file(bundled_pubkey) != pubkey_entry.get("sha256", ""):
                return EvidenceVerificationResult(
                    ok=False, failure_reason=f"sha256 mismatch on pubkey.pem"
                )

        # -- 3. pubkey in bundle matches the supplied pubkey --
        if not bundled_pubkey.exists():
            return EvidenceVerificationResult(
                ok=False, failure_reason="pubkey.pem missing"
            )
        if _sha256_file(bundled_pubkey) != _sha256_file(pubkey_path):
            return EvidenceVerificationResult(
                ok=False, failure_reason="pubkey.pem in bundle does not match supplied pubkey"
            )

        # -- 4. Chain cryptographic verification --
        chain_result = verify_chain_file(chain_file, pubkey_path)
        if not chain_result.ok:
            return EvidenceVerificationResult(
                ok=False,
                failure_reason=f"chain verification failed: {chain_result.failure_reason}",
            )

        # -- 4b. Cross-check MANIFEST chain stats against observed values --
        # (argus issue #12: stats recorded at export time must match what the
        # verifier actually saw — truncation at a line boundary with a
        # recomputed sha256 would otherwise pass.)
        expected = manifest.get("chain", {})
        observed = {
            "lines": chain_result.lines_verified,
            "checkpoints": chain_result.checkpoints_verified,
            "seq_range": [chain_result.first_seq, chain_result.last_seq],
        }
        for key in ("lines", "checkpoints", "seq_range"):
            if expected.get(key) != observed[key]:
                return EvidenceVerificationResult(
                    ok=False,
                    failure_reason=(
                        f"MANIFEST chain stats mismatch on {key}: "
                        f"manifest={expected.get(key)} observed={observed[key]}"
                    ),
                )

        # -- 5. Receipt signature verification --
        for entry in manifest.get("receipts", []):
            rel = entry.get("file", "")
            p = extract_dir / rel
            if not verify_receipt_file(p, pubkey_path):
                return EvidenceVerificationResult(
                    ok=False, failure_reason=f"receipt signature invalid: {p.name}"
                )

        # -- 5b. Receipt -> chain cross-reference (spec §9.6, argus issue #12) --
        # A receipt whose chain_seq points at a line that does not exist (or is
        # not a redaction line) in the bundled chain is a dangling reference,
        # even if its own signature and sha256 are valid.
        redaction_seqs: set[int] = set()
        with open(chain_file, "r", encoding="utf-8") as fp:
            for raw in fp:
                raw = raw.rstrip("\n")
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if obj.get("line_type") == "redaction" and isinstance(obj.get("seq"), int):
                    redaction_seqs.add(obj["seq"])
        for entry in manifest.get("receipts", []):
            p = extract_dir / entry.get("file", "")
            try:
                receipt = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                return EvidenceVerificationResult(
                    ok=False, failure_reason=f"receipt unreadable: {p.name}"
                )
            if receipt.get("chain_seq") not in redaction_seqs:
                return EvidenceVerificationResult(
                    ok=False,
                    failure_reason=(
                        f"receipt {p.name} references chain_seq "
                        f"{receipt.get('chain_seq')} which is not a redaction "
                        f"line in the bundled chain"
                    ),
                )

        # -- 6. Session manifest signature verification --
        for entry in manifest.get("manifests", []):
            rel = entry.get("file", "")
            p = extract_dir / rel
            if not _verify_manifest_file(p, pubkey_path):
                return EvidenceVerificationResult(
                    ok=False, failure_reason=f"session manifest signature invalid: {p.name}"
                )

    return EvidenceVerificationResult(ok=True)


def main_cli() -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="waterwall verify-evidence")
    ap.add_argument("bundle_path", type=Path, help="Path to the evidence bundle (.tar.gz)")
    ap.add_argument("--pubkey", required=True, type=Path, help="Ed25519 public key (PEM)")
    args = ap.parse_args()

    result = verify_evidence_bundle(args.bundle_path, args.pubkey)
    if result.ok:
        print(json.dumps({"ok": True, "bundle": str(args.bundle_path)}))
        return 0
    print(json.dumps({
        "ok": False,
        "bundle": str(args.bundle_path),
        "failure_reason": result.failure_reason,
    }))
    return 1


if __name__ == "__main__":
    sys.exit(main_cli())
