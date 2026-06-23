# tests/test_receipt.py
import base64
import json
from pathlib import Path

from waterwall.audit.receipt import emit_receipt, ReceiptEvent, _canonical_payload
from waterwall.audit.signer import EdSigner, EdVerifier, generate_keypair


def _setup(tmp_path: Path):
    priv = tmp_path / "k.key"
    pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    return priv, pub, EdSigner.load(priv), EdVerifier.load(pub)


def test_receipt_writes_to_file_with_expected_schema(tmp_path: Path):
    priv, pub, signer, verifier = _setup(tmp_path)
    out_dir = tmp_path / "receipts"
    out_dir.mkdir()

    events = [
        ReceiptEvent(type="AWS_ACCESS_KEY", hmac8="aaaaaaaaaaaaaaaa"),
        ReceiptEvent(type="ANTHROPIC_KEY", hmac8="bbbbbbbbbbbbbbbb"),
    ]
    path = emit_receipt(
        out_dir=out_dir,
        request_id="req_test",
        session_id="sess_test",
        events=events,
        policy_hash="pol_hash",
        chain_seq=42,
        signer=signer,
        signing_key_id="test-1",
    )
    body = json.loads(path.read_text())
    assert body["v"] == 1
    assert body["receipt_type"] == "redaction"
    assert body["request_id"] == "req_test"
    assert body["redaction_count"] == 2
    assert body["types"] == ["AWS_ACCESS_KEY", "ANTHROPIC_KEY"]
    assert body["hmac8s"] == ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"]
    assert body["chain_seq"] == 42
    assert body["signing_key_id"] == "test-1"
    assert "signature" in body


def test_receipt_signature_verifies(tmp_path: Path):
    priv, pub, signer, verifier = _setup(tmp_path)
    out_dir = tmp_path / "receipts"
    out_dir.mkdir()

    events = [ReceiptEvent(type="AWS_ACCESS_KEY", hmac8="0123456789abcdef")]
    path = emit_receipt(
        out_dir=out_dir, request_id="r", session_id="s",
        events=events, policy_hash="ph", chain_seq=1,
        signer=signer, signing_key_id="t",
    )
    body = json.loads(path.read_text())
    sig = base64.b64decode(body["signature"])
    canon_body = dict(body)
    canon_body["signature"] = ""
    canonical = _canonical_payload(canon_body).encode()
    assert verifier.verify(canonical, sig)


def test_receipt_filename_format(tmp_path: Path):
    priv, pub, signer, _ = _setup(tmp_path)
    out_dir = tmp_path / "receipts"
    out_dir.mkdir()
    events = [ReceiptEvent(type="X", hmac8="0" * 16)]
    path = emit_receipt(
        out_dir=out_dir, request_id="req_xyz", session_id="s",
        events=events, policy_hash="ph", chain_seq=1,
        signer=signer, signing_key_id="t",
    )
    # File pattern: {ts}_{request_id}.json
    assert path.name.endswith("_req_xyz.json")


def test_receipt_filename_sanitizes_hostile_request_id(tmp_path: Path):
    """Argus issue #17: x-request-id flowed unsanitized into the filename."""
    priv, pub, signer, _ = _setup(tmp_path)
    path = emit_receipt(
        out_dir=tmp_path, request_id="../../../etc/evil", session_id=None,
        events=[], policy_hash="p", chain_seq=1,
        signer=signer, signing_key_id="k",
    )
    assert path.parent == tmp_path
    assert ".." not in path.name and "/" not in path.name


def test_receipt_filename_trailing_dot_does_not_reform_dotdot(tmp_path: Path):
    """Copilot finding on PR #18: a sanitized value ending in '.' re-formed a
    '..' substring once the caller appended '.json' (request_id 'foo.' ->
    '..._foo..json'). Trailing/leading dots must be stripped."""
    priv, pub, signer, _ = _setup(tmp_path)
    path = emit_receipt(
        out_dir=tmp_path, request_id="foo.", session_id=None,
        events=[], policy_hash="p", chain_seq=1,
        signer=signer, signing_key_id="k",
    )
    assert ".." not in path.name, path.name

    # degenerate: all dots -> fallback, not empty
    path = emit_receipt(
        out_dir=tmp_path, request_id=".", session_id=None,
        events=[], policy_hash="p", chain_seq=1,
        signer=signer, signing_key_id="k",
    )
    assert "unknown" in path.name and ".." not in path.name, path.name
