# tests/test_chain_checkpoint.py
import base64
import hashlib
import json
from pathlib import Path

import pytest

from waterwall.audit.chain import ChainAppendError, ChainWriter, _canonical_json, _sha256_hex
from waterwall.audit.signer import EdSigner, EdVerifier, generate_keypair


def _setup(tmp_path: Path):
    priv = tmp_path / "k.key"
    pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    return priv, pub


def test_checkpoint_signature_verifies(tmp_path: Path):
    priv, pub = _setup(tmp_path)
    signer = EdSigner.load(priv)
    verifier = EdVerifier.load(pub)
    log = tmp_path / "p.jsonl"

    cw = ChainWriter(log, signer=signer, signing_key_id="test-1")
    cw.append({"line_type": "redaction"})
    cp = cw.emit_checkpoint()
    cw.close()

    assert cp["line_type"] == "checkpoint"
    assert "chain_root_hash" in cp
    assert "signature" in cp
    sig = base64.b64decode(cp["signature"])
    chain_root = bytes.fromhex(cp["chain_root_hash"])
    assert verifier.verify(chain_root, sig)


def test_chain_root_hash_canonical_construction(tmp_path: Path):
    """Spec §9.3: chain_root_hash = sha256(canonical_json(line with chain_root_hash="" and signature="")).
    Reconstruct the hash from the emitted checkpoint and assert exact match."""
    priv, pub = _setup(tmp_path)
    signer = EdSigner.load(priv)
    log = tmp_path / "p.jsonl"
    cw = ChainWriter(log, signer=signer, signing_key_id="test-1")
    cw.append({"line_type": "redaction"})
    cp = cw.emit_checkpoint()
    cw.close()

    rebuilt = dict(cp)
    rebuilt["chain_root_hash"] = ""
    rebuilt["signature"] = ""
    expected = hashlib.sha256(_canonical_json(rebuilt).encode()).hexdigest()
    assert cp["chain_root_hash"] == expected, \
        "chain_root_hash must use spec §9.3 canonicalization"


def test_subsequent_line_prev_hash_links_after_checkpoint(tmp_path: Path):
    priv, pub = _setup(tmp_path)
    signer = EdSigner.load(priv)
    log = tmp_path / "p.jsonl"
    cw = ChainWriter(log, signer=signer, signing_key_id="test-1")
    cw.append({"line_type": "redaction"})
    cp = cw.emit_checkpoint()
    line3 = cw.append({"line_type": "redaction"})
    cw.close()

    # Reconstruct prev_hash for line3 = sha256(canonical(line2/checkpoint))
    expected_prev = _sha256_hex(_canonical_json(cp))
    assert line3["prev_hash"] == expected_prev


def test_tampered_chain_root_fails_verification(tmp_path: Path):
    priv, pub = _setup(tmp_path)
    signer = EdSigner.load(priv)
    verifier = EdVerifier.load(pub)
    log = tmp_path / "p.jsonl"
    cw = ChainWriter(log, signer=signer, signing_key_id="test-1")
    cw.append({"line_type": "redaction"})
    cp = cw.emit_checkpoint()
    cw.close()

    sig = base64.b64decode(cp["signature"])
    bad_root = bytes.fromhex(cp["chain_root_hash"][::-1])  # reverse hex chars
    assert not verifier.verify(bad_root, sig)


def test_checkpoint_oserror_raises_chain_append_error(tmp_path: Path, monkeypatch):
    """Argus issue #8: emit_checkpoint must wrap OSError in ChainAppendError
    like append() does (module contract: caller fail-closes)."""
    priv, pub = _setup(tmp_path)
    w = ChainWriter(tmp_path / "chain.jsonl", signer=EdSigner.load(priv))

    def _boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(w._fp, "write", _boom)

    with pytest.raises(ChainAppendError):
        w.emit_checkpoint()
