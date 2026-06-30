# tests/test_verify_receipt.py
import json
from pathlib import Path

from waterwall.cli.verify_receipt import verify_receipt_file
from waterwall.audit.signer import generate_keypair, EdSigner
from waterwall.audit.receipt import emit_receipt, ReceiptEvent


def test_genuine_receipt_verifies(tmp_path: Path):
    priv = tmp_path / "k.key"
    pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    out_dir = tmp_path / "receipts"
    out_dir.mkdir()
    path = emit_receipt(
        out_dir=out_dir, request_id="r", session_id="s",
        events=[ReceiptEvent(type="X", hmac8="0" * 16)],
        policy_hash="ph", chain_seq=1,
        signer=EdSigner.load(priv), signing_key_id="t",
    )
    assert verify_receipt_file(path, pub)


def test_tampered_receipt_fails(tmp_path: Path):
    priv = tmp_path / "k.key"
    pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    out_dir = tmp_path / "receipts"
    out_dir.mkdir()
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


# --- Fail-closed False returns (BACKLOG phase-6, line 105 + structural paths) ---
# verify_receipt_file must return False (NEVER raise) on every structural or
# cryptographic failure, so `waterwall verify-receipt` exits 1 cleanly and a
# silent refactor dropping a guard is caught here.

def _good_receipt(tmp_path: Path):
    priv = tmp_path / "k.key"
    pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    rcpt = tmp_path / "receipts"
    rcpt.mkdir()
    path = emit_receipt(
        out_dir=rcpt, request_id="r", session_id="s",
        events=[ReceiptEvent(type="X", hmac8="0" * 16)],
        policy_hash="ph", chain_seq=1,
        signer=EdSigner.load(priv), signing_key_id="t",
    )
    return path, pub


def test_verify_receipt_missing_pubkey_path_returns_false(tmp_path: Path):
    """BACKLOG phase-6 line 105: a nonexistent pubkey path must fail-closed to
    False (EdVerifier.load wraps FileNotFoundError in SignerError -> caught)."""
    path, _ = _good_receipt(tmp_path)
    bogus = tmp_path / "does-not-exist.pub"
    assert not verify_receipt_file(path, bogus)


def test_verify_receipt_malformed_pubkey_returns_false(tmp_path: Path):
    """A pubkey file that is not an Ed25519 PEM must fail-closed to False."""
    path, _ = _good_receipt(tmp_path)
    garbage = tmp_path / "garbage.pub"
    garbage.write_text("not a public key at all")
    assert not verify_receipt_file(path, garbage)


def test_verify_receipt_corrupt_json_returns_false(tmp_path: Path):
    """A non-JSON / structurally-broken receipt file -> False (never raise)."""
    path, pub = _good_receipt(tmp_path)
    path.write_text("{ this is not json ")
    assert not verify_receipt_file(path, pub)


def test_verify_receipt_missing_or_empty_signature_returns_false(tmp_path: Path):
    """A receipt with no `signature` field (or empty) -> False."""
    path, pub = _good_receipt(tmp_path)
    body = json.loads(path.read_text())
    body["signature"] = ""
    path.write_text(json.dumps(body))
    assert not verify_receipt_file(path, pub)
    del body["signature"]
    path.write_text(json.dumps(body))
    assert not verify_receipt_file(path, pub)


def test_verify_receipt_bad_base64_signature_returns_false(tmp_path: Path):
    """A signature field that isn't valid base64 -> False."""
    path, pub = _good_receipt(tmp_path)
    body = json.loads(path.read_text())
    body["signature"] = "!!! not base64 !!!"
    path.write_text(json.dumps(body))
    assert not verify_receipt_file(path, pub)
