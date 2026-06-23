# src/waterwall/audit/signer.py
"""Ed25519 signing.

Spec §9. v1: in-proxy key (tamper-evidence, NOT non-repudiation per §9.7).
v1.1 will move signing to a separate process over Unix socket.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


class SignerError(Exception):
    """Raised when key load or signing fails."""


def generate_keypair(priv_path: Path, pub_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    priv_path.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    if os.name == "posix":
        os.chmod(priv_path, 0o400)
    pub_path.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


class EdSigner:
    def __init__(self, priv: Ed25519PrivateKey) -> None:
        self._priv = priv

    @classmethod
    def load(cls, priv_path: Path) -> "EdSigner":
        try:
            priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        except Exception as e:
            raise SignerError(f"failed to load private key {priv_path}: {e}") from e
        if not isinstance(priv, Ed25519PrivateKey):
            raise SignerError(f"{priv_path} is not an Ed25519 private key")
        return cls(priv)

    def sign(self, message: bytes) -> bytes:
        return self._priv.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._priv.public_key().verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False


class EdVerifier:
    def __init__(self, pub: Ed25519PublicKey) -> None:
        self._pub = pub

    @classmethod
    def load(cls, pub_path: Path) -> "EdVerifier":
        try:
            pub = serialization.load_pem_public_key(pub_path.read_bytes())
        except Exception as e:
            raise SignerError(f"failed to load public key {pub_path}: {e}") from e
        if not isinstance(pub, Ed25519PublicKey):
            raise SignerError(f"{pub_path} is not an Ed25519 public key")
        return cls(pub)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._pub.verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
