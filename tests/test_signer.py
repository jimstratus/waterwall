# tests/test_signer.py
from pathlib import Path
import os
import stat

import pytest
from waterwall.audit.signer import EdSigner, generate_keypair, SignerError


def test_generate_keypair_writes_files(tmp_path: Path):
    priv = tmp_path / "signing.key"
    pub = tmp_path / "signing.pub"
    generate_keypair(priv, pub)
    assert priv.exists() and pub.exists()
    assert priv.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    assert pub.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")


def test_generate_keypair_sets_priv_mode_0400(tmp_path: Path):
    if os.name != "posix":
        pytest.skip("POSIX permissions only")
    priv = tmp_path / "signing.key"
    pub = tmp_path / "signing.pub"
    generate_keypair(priv, pub)
    mode = stat.S_IMODE(priv.stat().st_mode)
    assert mode == 0o400, f"priv key must be 0400, got {oct(mode)}"


def test_sign_verify_round_trip(tmp_path: Path):
    priv = tmp_path / "signing.key"
    pub = tmp_path / "signing.pub"
    generate_keypair(priv, pub)
    signer = EdSigner.load(priv)
    sig = signer.sign(b"hello")
    assert signer.verify(b"hello", sig)
    assert not signer.verify(b"goodbye", sig)


def test_load_rejects_non_ed25519_key(tmp_path: Path):
    """RSA key path must be rejected. The RSA fixture is built with the
    cryptography lib — tests never shell out to openssl (repo convention;
    this was the one violation, flagged by Copilot on PR #18)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_path = tmp_path / "rsa.key"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    with pytest.raises(SignerError):
        EdSigner.load(rsa_path)


def test_verify_with_pubkey_only(tmp_path: Path):
    priv = tmp_path / "signing.key"
    pub = tmp_path / "signing.pub"
    generate_keypair(priv, pub)
    signer = EdSigner.load(priv)
    sig = signer.sign(b"hello")
    # Reload with pubkey only and verify
    from waterwall.audit.signer import EdVerifier
    verifier = EdVerifier.load(pub)
    assert verifier.verify(b"hello", sig)
    assert not verifier.verify(b"hello", b"\x00" * 64)
