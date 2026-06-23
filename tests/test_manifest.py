# tests/test_manifest.py
import base64
import json
from pathlib import Path
from datetime import datetime, timezone

from waterwall.audit.manifest import emit_manifest, SessionTracker
from waterwall.audit.signer import EdSigner, EdVerifier, generate_keypair


def _setup(tmp_path: Path):
    priv = tmp_path / "k.key"; pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    return EdSigner.load(priv), EdVerifier.load(pub)


def test_session_tracker_aggregates_redactions():
    t = SessionTracker(session_id="sess_xyz")
    t.record_redaction("AWS_ACCESS_KEY")
    t.record_redaction("AWS_ACCESS_KEY")
    t.record_redaction("ANTHROPIC_KEY")
    assert t.redaction_total == 3
    assert t.types_seen == {"AWS_ACCESS_KEY": 2, "ANTHROPIC_KEY": 1}


def test_emit_manifest_signature_verifies(tmp_path: Path):
    signer, verifier = _setup(tmp_path)
    t = SessionTracker(session_id="sess_xyz")
    t.record_redaction("AWS_ACCESS_KEY")

    out = tmp_path / "manifests"
    path = emit_manifest(
        out_dir=out,
        tracker=t,
        chain_seq_range=(1000, 1140),
        chain_root_hash="aabbccdd",
        policy_hash="phash",
        signer=signer,
        signing_key_id="test-1",
    )
    body = json.loads(path.read_text())
    assert body["v"] == 1
    assert body["manifest_type"] == "session"
    assert body["session_id"] == "sess_xyz"
    assert body["redaction_total"] == 1
    assert body["chain_root_hash"] == "aabbccdd"
    sig = base64.b64decode(body["signature"])
    canon = dict(body); canon["signature"] = ""
    from waterwall.audit.receipt import _canonical_payload
    assert verifier.verify(_canonical_payload(canon).encode(), sig)


def test_manifest_filename_sanitizes_hostile_session_id(tmp_path: Path):
    """Argus issue #17: client-controlled session id flowed unsanitized into the filename."""
    signer, _ = _setup(tmp_path)
    t = SessionTracker(session_id="../../evil")
    path = emit_manifest(
        out_dir=tmp_path,
        tracker=t,
        chain_seq_range=(1, 2),
        chain_root_hash="aabbccdd",
        policy_hash="phash",
        signer=signer,
        signing_key_id="test-1",
    )
    assert path.parent == tmp_path
    assert ".." not in path.name and "/" not in path.name


def test_fingerprint_reflects_request_counts(tmp_path: Path):
    """Argus issue #17: fingerprint fields were declared, never updated —
    every signed manifest reported zeros."""
    signer, _ = _setup(tmp_path)
    t = SessionTracker(session_id="s1")
    t.record_request()
    t.record_redaction("AWS_ACCESS_KEY")
    t.record_request()
    t.record_unknown_placeholders(2)
    path = emit_manifest(
        out_dir=tmp_path,
        tracker=t,
        chain_seq_range=(1, 2),
        chain_root_hash="r",
        policy_hash="p",
        signer=signer,
        signing_key_id="k",
    )
    body = json.loads(path.read_text())
    fp = body["behavioral_fingerprint"]
    assert fp["avg_redactions_per_request"] == 0.5
    assert fp["unknown_placeholder_count"] == 2
    assert fp["request_count"] == 2
    assert "max_block_buffer_kib" not in fp  # dropped: never measured (issue #17)
