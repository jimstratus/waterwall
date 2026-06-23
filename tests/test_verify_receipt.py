# tests/test_verify_receipt.py
import json
from pathlib import Path

from waterwall.cli.verify_receipt import verify_receipt_file
from waterwall.audit.signer import generate_keypair, EdSigner
from waterwall.audit.receipt import emit_receipt, ReceiptEvent


def test_genuine_receipt_verifies(tmp_path: Path):
    priv = tmp_path / "k.key"; pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    out_dir = tmp_path / "receipts"; out_dir.mkdir()
    path = emit_receipt(
        out_dir=out_dir, request_id="r", session_id="s",
        events=[ReceiptEvent(type="X", hmac8="0" * 16)],
        policy_hash="ph", chain_seq=1,
        signer=EdSigner.load(priv), signing_key_id="t",
    )
    assert verify_receipt_file(path, pub)


def test_tampered_receipt_fails(tmp_path: Path):
    priv = tmp_path / "k.key"; pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    out_dir = tmp_path / "receipts"; out_dir.mkdir()
    path = emit_receipt(
        out_dir=out_dir, request_id="r", session_id="s",
        events=[ReceiptEvent(type="X", hmac8="0" * 16)],
        policy_hash="ph", chain_seq=1,
        signer=EdSigner.load(priv), signing_key_id="t",
    )
    body = json.loads(path.read_text())
    body["redaction_count"] = 999
    path.write_text(json.dumps(body, indent=2))
    assert not verify_receipt_file(path, pub)
