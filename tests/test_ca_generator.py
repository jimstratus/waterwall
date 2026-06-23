# tests/test_ca_generator.py
import pytest
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

from waterwall.ops.ca_generator import generate_ca
from waterwall.ops.permitted_hosts import PermittedHost


def test_ca_has_all_permitted_subtrees(tmp_path):
    """Spec §4.1: CA must be Name-Constrained to the union of permitted hosts."""
    hosts = [
        PermittedHost(host="api.anthropic.com", sse_handler="anthropic"),
        PermittedHost(host="api.deepseek.com", sse_handler="openai"),
        PermittedHost(host="api.openai.com", sse_handler="openai"),
    ]
    out_dir = tmp_path / "ca"
    out_dir.mkdir()
    generate_ca(hosts=hosts, out_dir=out_dir, days=30, common_name="Waterwall Test CA")

    cert_pem = (out_dir / "ca.pem").read_bytes()
    cert = x509.load_pem_x509_certificate(cert_pem)
    nc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
    permitted_dns = sorted(
        gn.value for gn in nc_ext.value.permitted_subtrees if isinstance(gn, x509.DNSName)
    )
    assert permitted_dns == ["api.anthropic.com", "api.deepseek.com", "api.openai.com"]
    # nameconstraints must be marked critical for RFC 5280 enforcement
    assert nc_ext.critical


def test_ca_writes_three_files(tmp_path):
    """generate_ca writes ca.pem, ca.key, mitmproxy-ca.pem (key+cert concatenated)."""
    hosts = [PermittedHost(host="api.anthropic.com", sse_handler="anthropic")]
    out_dir = tmp_path / "ca"
    out_dir.mkdir()
    generate_ca(hosts=hosts, out_dir=out_dir, days=30, common_name="t")
    assert (out_dir / "ca.pem").exists()
    assert (out_dir / "ca.key").exists()
    assert (out_dir / "mitmproxy-ca.pem").exists()
    mitm_pem = (out_dir / "mitmproxy-ca.pem").read_text(encoding="utf-8")
    assert "BEGIN PRIVATE KEY" in mitm_pem or "BEGIN RSA PRIVATE KEY" in mitm_pem
    assert "BEGIN CERTIFICATE" in mitm_pem


def test_ca_key_is_4096_bits(tmp_path):
    """Argus issue #11: spec + generate_ca.sh use rsa:4096; the in-process
    generator silently downgraded to 2048 (found by gemini AND minimax-m2.7)."""
    hosts = [PermittedHost(host="api.anthropic.com", sse_handler="anthropic")]
    out_dir = tmp_path / "ca"
    out_dir.mkdir()
    generate_ca(hosts=hosts, out_dir=out_dir, days=30, common_name="t")
    key = serialization.load_pem_private_key((out_dir / "ca.key").read_bytes(), password=None)
    assert key.key_size == 4096


def test_ca_files_group_readable_on_posix(tmp_path):
    import os, stat
    if os.name != "posix":
        pytest.skip("POSIX modes not enforced on Windows")
    hosts = [PermittedHost(host="api.anthropic.com", sse_handler="anthropic")]
    out_dir = tmp_path / "ca"
    out_dir.mkdir()
    generate_ca(hosts=hosts, out_dir=out_dir, days=30, common_name="t")
    for name in ("ca.key", "mitmproxy-ca.pem"):
        mode = stat.S_IMODE((out_dir / name).stat().st_mode)
        assert mode == 0o440, f"{name} is {oct(mode)}; service user needs group read (issue #11)"
