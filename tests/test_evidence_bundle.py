# tests/test_evidence_bundle.py
import json
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from waterwall.cli.export_evidence import export_evidence
from waterwall.cli.verify_evidence import verify_evidence_bundle
from waterwall.audit.signer import generate_keypair, EdSigner
from waterwall.audit.chain import ChainWriter
from waterwall.audit.receipt import emit_receipt, ReceiptEvent


def _tar_extract(bundle: Path, extract_dir: Path) -> None:
    """Extract a tar.gz bundle member-by-member, guarding against path traversal."""
    with tarfile.open(bundle, "r:gz") as tf:
        for member in tf.getmembers():
            # Normalise and reject any path that escapes the target dir
            dest = (extract_dir / member.name).resolve()
            if not str(dest).startswith(str(extract_dir.resolve())):
                raise ValueError(f"Unsafe tar member: {member.name!r}")
            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                dest.parent.mkdir(parents=True, exist_ok=True)
                with tf.extractfile(member) as src, open(dest, "wb") as dst:
                    dst.write(src.read())


def test_export_and_verify_round_trip(tmp_path: Path):
    priv = tmp_path / "k.key"; pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    signer = EdSigner.load(priv)

    chain_path = tmp_path / "proxy.jsonl"
    cw = ChainWriter(chain_path, signer=signer, signing_key_id="t")
    for _ in range(5):
        cw.append({"line_type": "redaction"})
    cw.emit_checkpoint()
    cw.close()

    receipts_dir = tmp_path / "receipts"; receipts_dir.mkdir()
    emit_receipt(
        out_dir=receipts_dir, request_id="r1", session_id="s1",
        events=[ReceiptEvent(type="X", hmac8="0" * 16)],
        policy_hash="ph", chain_seq=1, signer=signer, signing_key_id="t",
    )

    bundle = tmp_path / "evidence.tar.gz"
    policy_snapshot = tmp_path / "patterns.py"
    policy_snapshot.write_text("PATTERNS = []")

    export_evidence(
        chain_path=chain_path,
        receipts_dir=receipts_dir,
        manifests_dir=None,
        policy_snapshot=policy_snapshot,
        pubkey_path=pub,
        out=bundle,
        signing_key_path=priv,
    )
    assert bundle.exists()

    result = verify_evidence_bundle(bundle, pub)
    assert result.ok


def _build_bundle(tmp_path: Path) -> Path:
    """Helper: build a clean evidence bundle for the tamper tests below.
    Returns the path to evidence.tar.gz; signing pubkey at tmp_path/k.pub."""
    priv = tmp_path / "k.key"; pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    signer = EdSigner.load(priv)

    chain_path = tmp_path / "proxy.jsonl"
    cw = ChainWriter(chain_path, signer=signer, signing_key_id="t")
    for _ in range(5):
        cw.append({"line_type": "redaction"})
    cw.emit_checkpoint()
    cw.close()

    receipts_dir = tmp_path / "receipts"; receipts_dir.mkdir()
    emit_receipt(
        out_dir=receipts_dir, request_id="r1", session_id="s1",
        events=[ReceiptEvent(type="X", hmac8="0" * 16)],
        policy_hash="ph", chain_seq=1, signer=signer, signing_key_id="t",
    )

    bundle = tmp_path / "evidence.tar.gz"
    policy_snapshot = tmp_path / "patterns.py"
    policy_snapshot.write_text("PATTERNS = []")
    export_evidence(
        chain_path=chain_path, receipts_dir=receipts_dir,
        manifests_dir=None, policy_snapshot=policy_snapshot,
        pubkey_path=pub, out=bundle,
        signing_key_path=priv,
    )
    return bundle


@dataclass
class _EvidenceSetup:
    bundle_path: Path
    pubkey_path: Path
    privkey_path: Path
    chain_path: Path

    def export(self, *, out: Path) -> Path:
        """Re-run export_evidence against the same on-disk chain/receipts/policy
        that _build_bundle created (used by the snapshot-race test below).
        Returns the new bundle path."""
        base = self.chain_path.parent
        export_evidence(
            chain_path=self.chain_path,
            receipts_dir=base / "receipts",
            manifests_dir=None,
            policy_snapshot=base / "patterns.py",
            pubkey_path=self.pubkey_path,
            out=out,
            signing_key_path=self.privkey_path,
        )
        return out

    def rebuild_with_receipt_chain_seq(self, chain_seq: int) -> Path:
        """Rebuild the bundle after editing ONE receipt's chain_seq, re-signing
        that receipt with the real key, updating its sha256 in MANIFEST.json,
        and re-signing MANIFEST — a deliberate full re-forge so that ONLY a
        receipt->chain cross-reference check can catch the dangling pointer."""
        import base64
        import hashlib

        from waterwall.audit.receipt import _canonical_payload

        signer = EdSigner.load(self.privkey_path)
        extract_dir = self.bundle_path.parent / "rebuild_chain_seq"
        extract_dir.mkdir()
        _tar_extract(self.bundle_path, extract_dir)

        # Edit + re-sign one receipt
        receipt_path = sorted((extract_dir / "receipts").iterdir())[0]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["chain_seq"] = chain_seq
        receipt["signature"] = ""
        sig = signer.sign(_canonical_payload(receipt).encode())
        receipt["signature"] = base64.b64encode(sig).decode("ascii")
        receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")

        # Update that receipt's sha256 in MANIFEST.json, then re-sign MANIFEST
        manifest_path = extract_dir / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        receipt_rel = str(receipt_path.relative_to(extract_dir)).replace(os.sep, "/")
        for entry in manifest["receipts"]:
            if entry["file"] == receipt_rel:
                entry["sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        manifest["signature"] = ""
        msig = signer.sign(_canonical_payload(manifest).encode())
        manifest["signature"] = base64.b64encode(msig).decode("ascii")
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        # Re-tar to a new path
        rebuilt = self.bundle_path.parent / "rebuilt_chain_seq.tar.gz"
        with tarfile.open(rebuilt, "w:gz") as tf:
            for f in extract_dir.rglob("*"):
                if f.is_file():
                    tf.add(f, arcname=str(f.relative_to(extract_dir)).replace(os.sep, "/"))
        return rebuilt


@pytest.fixture
def evidence_setup(tmp_path: Path) -> _EvidenceSetup:
    """A clean signed evidence bundle plus the paths the tamper tests need."""
    bundle = _build_bundle(tmp_path)
    return _EvidenceSetup(
        bundle_path=bundle,
        pubkey_path=tmp_path / "k.pub",
        privkey_path=tmp_path / "k.key",
        chain_path=tmp_path / "proxy.jsonl",
    )


def test_tampered_receipt_in_bundle_fails(tmp_path: Path):
    """Mutate one receipt's redaction_count; verify-evidence must fail with that receipt's name."""
    bundle = _build_bundle(tmp_path)
    pub = tmp_path / "k.pub"

    # Extract, mutate, repack
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()
    _tar_extract(bundle, extract_dir)
    receipts = list((extract_dir / "receipts").iterdir())
    target = receipts[0]
    body = json.loads(target.read_text())
    body["redaction_count"] = 999
    target.write_text(json.dumps(body, indent=2))
    bundle.unlink()
    with tarfile.open(bundle, "w:gz") as tf:
        for f in extract_dir.rglob("*"):
            if f.is_file():
                tf.add(f, arcname=str(f.relative_to(extract_dir)).replace(os.sep, "/"))

    result = verify_evidence_bundle(bundle, pub)
    assert not result.ok
    assert target.name in result.failure_reason


def test_tampered_chain_in_bundle_fails(tmp_path: Path):
    """Flip a byte mid-chain. verify-evidence reports the seq pointer."""
    bundle = _build_bundle(tmp_path)
    pub = tmp_path / "k.pub"

    extract_dir = tmp_path / "extract2"
    extract_dir.mkdir()
    _tar_extract(bundle, extract_dir)
    chain_file = extract_dir / "chain" / "proxy.jsonl"
    lines = chain_file.read_text().splitlines()
    obj = json.loads(lines[2])
    obj["redactions"] = [{"type": "AWS_ACCESS_KEY", "hmac8": "tampered00000000"}]
    lines[2] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    chain_file.write_text("\n".join(lines) + "\n")
    bundle.unlink()
    with tarfile.open(bundle, "w:gz") as tf:
        for f in extract_dir.rglob("*"):
            if f.is_file():
                tf.add(f, arcname=str(f.relative_to(extract_dir)).replace(os.sep, "/"))

    result = verify_evidence_bundle(bundle, pub)
    assert not result.ok
    assert "chain" in result.failure_reason.lower() or "seq" in result.failure_reason.lower()


def test_swapped_pubkey_fails(tmp_path: Path):
    """Replace bundle's pubkey.pem with a different key. All signatures fail."""
    bundle = _build_bundle(tmp_path)
    real_pub = tmp_path / "k.pub"

    other_priv = tmp_path / "other.key"
    other_pub = tmp_path / "other.pub"
    generate_keypair(other_priv, other_pub)

    extract_dir = tmp_path / "extract3"
    extract_dir.mkdir()
    _tar_extract(bundle, extract_dir)
    (extract_dir / "pubkey.pem").write_bytes(other_pub.read_bytes())
    bundle.unlink()
    with tarfile.open(bundle, "w:gz") as tf:
        for f in extract_dir.rglob("*"):
            if f.is_file():
                tf.add(f, arcname=str(f.relative_to(extract_dir)).replace(os.sep, "/"))

    # Verify against the REAL pub (not the swapped one) — manifest sha256 of pubkey.pem
    # mismatches; or signatures fail
    result = verify_evidence_bundle(bundle, real_pub)
    assert not result.ok


def _rebuild_bundle_without(extract_dir: Path, bundle: Path, exclude_relative: str) -> None:
    """Repack extract_dir into bundle, omitting one file (relative path)."""
    bundle.unlink()
    excluded = (extract_dir / exclude_relative).resolve()
    with tarfile.open(bundle, "w:gz") as tf:
        for f in extract_dir.rglob("*"):
            if f.is_file() and f.resolve() != excluded:
                tf.add(f, arcname=str(f.relative_to(extract_dir)).replace(os.sep, "/"))


def test_missing_policy_snapshot_fails(tmp_path: Path):
    """Policy snapshot listed in MANIFEST but file removed from bundle → fail-closed.
    Regression test for code-review-7-3 critical: silent skip on missing policy."""
    bundle = _build_bundle(tmp_path)
    pub = tmp_path / "k.pub"
    extract_dir = tmp_path / "extract_no_policy"
    extract_dir.mkdir()
    _tar_extract(bundle, extract_dir)
    _rebuild_bundle_without(extract_dir, bundle, "policy/patterns.py")
    result = verify_evidence_bundle(bundle, pub)
    assert not result.ok
    assert "policy" in result.failure_reason.lower() or "patterns.py" in result.failure_reason


def test_missing_pubkey_fails(tmp_path: Path):
    """Pubkey listed in MANIFEST but pubkey.pem removed from bundle → fail-closed.
    Regression test for code-review-7-3 critical: silent skip on missing pubkey."""
    bundle = _build_bundle(tmp_path)
    pub = tmp_path / "k.pub"
    extract_dir = tmp_path / "extract_no_pubkey"
    extract_dir.mkdir()
    _tar_extract(bundle, extract_dir)
    _rebuild_bundle_without(extract_dir, bundle, "pubkey.pem")
    result = verify_evidence_bundle(bundle, pub)
    assert not result.ok
    assert "pubkey" in result.failure_reason.lower()


def test_truncated_chain_with_recomputed_manifest_fails(tmp_path, evidence_setup):
    """Argus issue #12: truncate the bundled chain at a line boundary, recompute
    the (previously unsigned) MANIFEST sha — verification must now FAIL because
    the MANIFEST is signed and its stats are cross-checked."""
    import io
    import hashlib

    bundle, pubkey = evidence_setup.bundle_path, evidence_setup.pubkey_path
    tampered = bundle.parent / "tampered.tar.gz"

    with tarfile.open(bundle, "r:gz") as tf:
        members = {
            m.name: tf.extractfile(m).read() if m.isfile() else None
            for m in tf.getmembers()
        }

    chain_lines = members["chain/proxy.jsonl"].decode().strip().split("\n")
    truncated = ("\n".join(chain_lines[:-1]) + "\n").encode()
    manifest = json.loads(members["MANIFEST.json"])
    manifest["chain"]["sha256"] = hashlib.sha256(truncated).hexdigest()
    members["chain/proxy.jsonl"] = truncated
    members["MANIFEST.json"] = json.dumps(manifest, indent=2).encode()

    with tarfile.open(tampered, "w:gz") as tf:
        for name, data in members.items():
            if data is None:
                continue
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

    result = verify_evidence_bundle(tampered, pubkey)
    assert not result.ok
    assert (
        "manifest" in result.failure_reason.lower()
        or "stats" in result.failure_reason.lower()
    )


def test_fresh_signed_bundle_verifies(tmp_path, evidence_setup):
    result = verify_evidence_bundle(evidence_setup.bundle_path, evidence_setup.pubkey_path)
    assert result.ok, result.failure_reason


def test_receipt_with_bogus_chain_seq_fails(tmp_path, evidence_setup):
    """Argus issue #12 / spec §9.6: every receipt's chain_seq must reference a
    redaction line that actually exists in the bundled chain."""
    # Rebuild the bundle after editing ONE receipt's chain_seq to 9999 and
    # re-signing that receipt with the same key (so only the cross-ref catches it),
    # then recompute its sha in MANIFEST and re-sign MANIFEST.
    rebuilt = evidence_setup.rebuild_with_receipt_chain_seq(9999)
    from waterwall.cli.verify_evidence import verify_evidence_bundle
    result = verify_evidence_bundle(rebuilt, evidence_setup.pubkey_path)
    assert not result.ok
    assert "chain_seq" in result.failure_reason


def test_export_uses_chain_snapshot_not_live_file(tmp_path, evidence_setup, monkeypatch):
    """Argus issue #12: a line appended mid-export must not make the fresh
    bundle fail its own verification. Export must hash/tar a snapshot copy."""
    from waterwall.cli import export_evidence as ee

    appended = {"done": False}
    orig_sha256 = ee._sha256_file

    def sha_then_append(path):
        digest = orig_sha256(path)
        if path.name == evidence_setup.chain_path.name and not appended["done"]:
            # simulate the live proxy appending AFTER the hash is computed
            with open(evidence_setup.chain_path, "a", encoding="utf-8") as fp:
                fp.write(json.dumps({"v": 1, "seq": 999, "prev_hash": "x", "line_type": "redaction"}) + "\n")
            appended["done"] = True
        return digest

    monkeypatch.setattr(ee, "_sha256_file", sha_then_append)
    bundle = evidence_setup.export(out=tmp_path / "race.tar.gz")

    result = verify_evidence_bundle(bundle, evidence_setup.pubkey_path)
    assert result.ok, f"export raced the live writer: {result.failure_reason}"
