# tests/test_verify_chain.py
import json
from pathlib import Path

import pytest
from waterwall.audit.chain import ChainWriter
from waterwall.audit.signer import EdSigner, generate_keypair
from waterwall.cli.verify_chain import verify_chain_file, ChainVerificationResult


def _setup(tmp_path: Path):
    priv = tmp_path / "k.key"; pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    return priv, pub


def test_verify_chain_passes_on_clean_log(tmp_path: Path):
    priv, pub = _setup(tmp_path)
    signer = EdSigner.load(priv)
    log = tmp_path / "p.jsonl"
    cw = ChainWriter(log, signer=signer, signing_key_id="test-1")
    for _ in range(50):
        cw.append({"line_type": "redaction"})
    cw.emit_checkpoint()
    cw.close()
    result = verify_chain_file(log, pub)
    assert result.ok
    assert result.lines_verified == 51
    assert result.checkpoints_verified == 1


def test_verify_chain_detects_tampered_line(tmp_path: Path):
    priv, pub = _setup(tmp_path)
    signer = EdSigner.load(priv)
    log = tmp_path / "p.jsonl"
    cw = ChainWriter(log, signer=signer, signing_key_id="test-1")
    for _ in range(10):
        cw.append({"line_type": "redaction"})
    cw.emit_checkpoint()
    cw.close()
    lines = log.read_text().splitlines()
    obj = json.loads(lines[4])
    obj["redactions"] = [{"type": "AWS_ACCESS_KEY", "hmac8": "tampered00000000"}]
    lines[4] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n")
    result = verify_chain_file(log, pub)
    assert not result.ok
    assert result.first_failure_seq == 6  # next line's prev_hash mismatch


def test_relocated_valid_checkpoint_signature_fails(tmp_path):
    """A fabricated chain that splices in a genuine (chain_root_hash, signature)
    pair from a real checkpoint must FAIL verification. Argus issue #6:
    the signature must bind to THIS line's content, not be trusted at face value."""
    from waterwall.audit.chain import _canonical_json, _sha256_hex, GENESIS_PREV_HASH

    key_path = tmp_path / "signing.key"
    pub_path = tmp_path / "signing.pub"
    generate_keypair(key_path, pub_path)

    # 1. Build a genuine chain with one checkpoint.
    real_log = tmp_path / "real.jsonl"
    w = ChainWriter(real_log, signer=EdSigner.load(key_path))
    w.append({"line_type": "redaction", "redactions": [{"type": "AWS_ACCESS_KEY", "hmac8": "a" * 16}]})
    genuine_cp = w.emit_checkpoint()
    w.close()

    # 2. Fabricate a totally different chain, re-linking prev_hash by hand,
    #    and splice the genuine (root, signature) pair into a forged checkpoint.
    forged_log = tmp_path / "forged.jsonl"
    lines = []
    prev = GENESIS_PREV_HASH
    fake1 = {"v": 1, "ts": "2026-01-01T00:00:00.000+00:00", "seq": 1,
             "prev_hash": prev, "line_type": "redaction",
             "redactions": [{"type": "GITHUB_TOKEN", "hmac8": "b" * 16}]}
    s1 = _canonical_json(fake1)
    lines.append(s1)
    prev = _sha256_hex(s1)
    forged_cp = {"v": 1, "ts": "2026-01-01T00:00:01.000+00:00", "seq": 2,
                 "prev_hash": prev, "line_type": "checkpoint",
                 "signing_key_id": genuine_cp["signing_key_id"],
                 "chain_root_hash": genuine_cp["chain_root_hash"],   # replayed
                 "signature": genuine_cp["signature"]}                # replayed
    lines.append(_canonical_json(forged_cp))
    forged_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain_file(forged_log, pub_path)
    assert not result.ok
    assert "chain_root_hash" in result.failure_reason


def test_empty_chain_log_fails_verification(tmp_path):
    """A zero-byte (or blank-lines-only) chain log must NOT verify OK —
    truncation-to-empty is the crudest tampering. Argus issue #6."""
    key_path = tmp_path / "signing.key"
    pub_path = tmp_path / "signing.pub"
    generate_keypair(key_path, pub_path)

    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    result = verify_chain_file(empty, pub_path)
    assert not result.ok
    assert "empty" in result.failure_reason

    blanks = tmp_path / "blanks.jsonl"
    blanks.write_text("\n\n\n", encoding="utf-8")
    result = verify_chain_file(blanks, pub_path)
    assert not result.ok


def test_verify_chain_detects_forged_checkpoint_signature(tmp_path: Path):
    priv, pub = _setup(tmp_path)
    signer = EdSigner.load(priv)
    log = tmp_path / "p.jsonl"
    cw = ChainWriter(log, signer=signer, signing_key_id="test-1")
    cw.append({"line_type": "redaction"})
    cp = cw.emit_checkpoint()
    cw.close()
    # Replace signature with random bytes of valid length
    import base64
    lines = log.read_text().splitlines()
    cp_obj = json.loads(lines[1])
    cp_obj["signature"] = base64.b64encode(b"\x00" * 64).decode()
    lines[1] = json.dumps(cp_obj, sort_keys=True, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n")
    result = verify_chain_file(log, pub)
    assert not result.ok
    assert "checkpoint signature" in result.failure_reason.lower()
