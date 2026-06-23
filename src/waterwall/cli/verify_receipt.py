# src/waterwall/cli/verify_receipt.py
"""CLI: verify-receipt — independent Ed25519 signature check on an Action Receipt.

Spec §12.1.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from waterwall.audit.chain import _canonical_json
from waterwall.audit.signer import EdVerifier, SignerError


def verify_receipt_file(receipt_path: Path, pubkey_path: Path) -> bool:
    """Return True iff the receipt's Ed25519 signature is valid.

    Returns False (does not raise) on any structural or cryptographic failure.
    """
    try:
        body = json.loads(receipt_path.read_text(encoding="utf-8"))
    except Exception:
        return False

    sig_b64 = body.get("signature")
    if not isinstance(sig_b64, str) or not sig_b64:
        return False

    try:
        sig_bytes = base64.b64decode(sig_b64)
    except Exception:
        return False

    # Reconstruct the exact bytes that were signed: body with signature=""
    unsigned = dict(body)
    unsigned["signature"] = ""
    canonical = _canonical_json(unsigned).encode("utf-8")

    try:
        verifier = EdVerifier.load(pubkey_path)
    except SignerError:
        return False

    return verifier.verify(canonical, sig_bytes)


def main_cli() -> int:
    parser = argparse.ArgumentParser(
        description="Verify an Action Receipt Ed25519 signature."
    )
    parser.add_argument("receipt_path", type=Path, help="Path to the receipt JSON file")
    parser.add_argument(
        "--pubkey", required=True, type=Path, help="Path to the Ed25519 public key (PEM)"
    )
    args = parser.parse_args()

    ok = verify_receipt_file(args.receipt_path, args.pubkey)
    reason = "signature valid" if ok else "signature invalid or receipt malformed"
    result = {"ok": ok, "receipt": str(args.receipt_path), "reason": reason}
    print(json.dumps(result))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main_cli())
