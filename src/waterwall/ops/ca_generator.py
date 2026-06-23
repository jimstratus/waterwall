# src/waterwall/ops/ca_generator.py
"""X.509 CA generator with multi-permittedSubtree NameConstraints.

Spec §4.1. Replaces v1's bash `deploy/ca/generate_ca.sh` for in-process generation.
Bash script remains for one-shot install scenarios; this module is the
canonical generator used by `waterwall regen-ca`.
"""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from waterwall.ops.permitted_hosts import PermittedHost


def generate_ca(
    *,
    hosts: list[PermittedHost],
    out_dir: Path,
    days: int = 365 * 10,
    common_name: str = "Waterwall Operator CA",
) -> None:
    """Generate an RSA-4096 CA with NameConstraints permittedSubtrees=hosts.

    Writes:
        out_dir/ca.pem            — cert (PEM, ≥ 1 line `BEGIN CERTIFICATE`)
        out_dir/ca.key            — private key (PEM, mode 0o440 root:waterwall on POSIX)
        out_dir/mitmproxy-ca.pem  — key + cert concatenated (mitmproxy 12.x format)

    Raises:
        ValueError if hosts is empty.
    """
    if not hosts:
        raise ValueError("hosts must be non-empty")

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)

    permitted = [x509.DNSName(h.host) for h in hosts]
    name_constraints = x509.NameConstraints(
        permitted_subtrees=permitted,
        excluded_subtrees=None,
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(seconds=60))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(name_constraints, critical=True)
    )
    cert = builder.sign(key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "ca.pem").write_bytes(cert_pem)
    (out_dir / "ca.key").write_bytes(key_pem)
    (out_dir / "mitmproxy-ca.pem").write_bytes(key_pem + cert_pem)

    if os.name == "posix":
        import shutil

        for name in ("ca.key", "mitmproxy-ca.pem"):
            p = out_dir / name
            p.chmod(0o440)  # root:waterwall read-only — service user needs group read
            try:
                shutil.chown(p, group="waterwall")
            except (LookupError, PermissionError, OSError):
                # dev boxes have no waterwall group; install.sh fixes ownership
                pass
