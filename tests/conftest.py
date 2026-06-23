# tests/conftest.py
import pytest


@pytest.fixture(scope="session")
def rsa_4096_pem() -> str:
    """A real RSA-4096 private key in traditional PEM form (~3.2 KB).
    Generated once per session (keygen costs ~1.4 s); no key material in repo."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return pem.rstrip("\n")  # text leaf form, no trailing newline
