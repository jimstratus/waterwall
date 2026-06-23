"""Tests for verify-install startup + runtime modes.

Spec §11.4.  All CA fixtures are built via the cryptography library (no
shell-outs to openssl/bash) — same pattern as tests/test_ca_validator.py.
"""

from __future__ import annotations

import datetime as dt
import os
import socket
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from waterwall.ops.verify_install import CheckResult, run_runtime_checks, run_startup_checks


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _build_constrained_ca_pem() -> bytes:
    """Build a self-signed Name-Constrained CA cert (api.anthropic.com) in memory."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Waterwall Test CA")])
    now = dt.datetime.now(dt.timezone.utc)
    nc = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName("api.anthropic.com")],
        excluded_subtrees=None,
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(nc, critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _make_valid_ca(tmp_path: Path) -> Path:
    """Write a valid Name-Constrained CA to tmp_path/ca.pem."""
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(_build_constrained_ca_pem())
    return ca_path


def _make_valid_signing_key(tmp_path: Path) -> Path:
    """Generate an Ed25519 keypair; return path to private key."""
    from waterwall.audit.signer import generate_keypair

    priv = tmp_path / "signing.key"
    pub = tmp_path / "signing.pub"
    generate_keypair(priv, pub)
    return priv


def _make_mitmproxy_ca_pem(tmp_path: Path, include_key: bool = True, include_cert: bool = True) -> Path:
    """Write a fake mitmproxy-ca.pem with the requested PEM blocks present."""
    # Use real crypto objects so the PEM headers are correct
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mitmproxy")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    parts: list[bytes] = []
    if include_key:
        parts.append(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    if include_cert:
        parts.append(cert.public_bytes(serialization.Encoding.PEM))

    mca = tmp_path / "mitmproxy-ca.pem"
    mca.write_bytes(b"".join(parts))
    return mca


def _make_permitted_hosts_yaml(tmp_path: Path) -> Path:
    """Write a permitted_hosts.yaml matching the fixture CA (api.anthropic.com)."""
    hosts_path = tmp_path / "permitted_hosts.yaml"
    hosts_path.write_text(
        "hosts:\n  - host: api.anthropic.com\n    sse_handler: anthropic\n",
        encoding="utf-8",
    )
    return hosts_path


def _full_startup_kwargs(tmp_path: Path) -> dict:
    """Return a full valid set of keyword args for run_startup_checks."""
    _make_mitmproxy_ca_pem(tmp_path)  # writes tmp_path/mitmproxy-ca.pem
    return dict(
        ca_path=_make_valid_ca(tmp_path),
        permitted_hosts_path=_make_permitted_hosts_yaml(tmp_path),
        signer_path=_make_valid_signing_key(tmp_path),
        patterns_path=None,
        chain_log_dir=tmp_path,
        sentinel_dir=tmp_path,
        listen_port=0,
        admin_port=0,
        upstream_host="127.0.0.1",  # avoid real network in CI
    )


def _full_fake_state() -> dict:
    """Return a fake StateAggregator snapshot suitable for runtime checks."""
    return {
        "ca_mode": "NODE_EXTRA_CA_CERTS",
        "health": {
            "signer_key_readable": True,
            "upstream_reachable": True,
            "chain_intact": True,
            "patterns_loaded": 33,
            "patterns_min_required": 16,
        },
        "patterns": {"count": 33},
        "map": {"size": 1, "capacity": 10000},
        "verify_install": {"checks_passed": 0, "checks_total": 10, "last_run_ts": None},
        "_runtime_listener_bound": True,
        "_runtime_admin_bound_loopback": True,
        "session_key_age_seconds": 60,
    }


# ---------------------------------------------------------------------------
# Startup mode tests
# ---------------------------------------------------------------------------


def test_startup_check_1_ca_constrained(tmp_path: Path):
    """Check #1: CA file must be Name-Constrained to api.anthropic.com."""
    kwargs = _full_startup_kwargs(tmp_path)
    results = run_startup_checks(**kwargs)
    ca_check = next(r for r in results if r.name == "ca_file")
    assert ca_check.ok


def test_startup_check_1_ca_unconstrained_fails(tmp_path: Path):
    """Check #1: unconstrained CA must fail."""
    kwargs = _full_startup_kwargs(tmp_path)
    # overwrite with an unconstrained CA
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Bad CA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    kwargs["ca_path"].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    results = run_startup_checks(**kwargs)
    ca_check = next(r for r in results if r.name == "ca_file")
    assert not ca_check.ok


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits not enforced on Windows")
def test_startup_check_2_signing_key_mode_0400(tmp_path: Path):
    """Check #2: signing key must be mode 0o400 and Ed25519-loadable (POSIX only)."""
    kwargs = _full_startup_kwargs(tmp_path)
    results = run_startup_checks(**kwargs)
    sk_check = next(r for r in results if r.name == "signing_key")
    assert sk_check.ok


def test_startup_check_3_patterns_complete(tmp_path: Path):
    """Check #3: canonical patterns module satisfies >=16 count + REQUIRED_BASE_LABELS."""
    kwargs = _full_startup_kwargs(tmp_path)
    results = run_startup_checks(**kwargs)
    pc_check = next(r for r in results if r.name == "patterns_complete")
    assert pc_check.ok, pc_check.detail


def test_startup_check_3_flags_extension_duplicating_builtin(tmp_path: Path):
    """Check #3: a deployed extensions file that re-declares a built-in label
    or regex must fail the gate — this is the exact misconfiguration that
    shipped on prod-host (issue #21) and previously passed all 10 checks."""
    kwargs = _full_startup_kwargs(tmp_path)
    ext = tmp_path / "patterns.py"
    ext.write_text(
        'PATTERNS = [\n    ("AWS_ACCESS_KEY", r"\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b"),\n]\n',
        encoding="utf-8",
    )
    kwargs["patterns_path"] = ext
    results = run_startup_checks(**kwargs)
    pc_check = next(r for r in results if r.name == "patterns_complete")
    assert not pc_check.ok
    assert "AWS_ACCESS_KEY" in (pc_check.detail or "")


def test_startup_check_3_accepts_novel_extension(tmp_path: Path):
    """Check #3: a genuinely new extension pattern still passes."""
    kwargs = _full_startup_kwargs(tmp_path)
    ext = tmp_path / "patterns.py"
    ext.write_text(
        'PATTERNS = [\n    ("MY_INTERNAL_TOKEN", r"\\bmytok_[A-Za-z0-9]{32}\\b"),\n]\n',
        encoding="utf-8",
    )
    kwargs["patterns_path"] = ext
    results = run_startup_checks(**kwargs)
    pc_check = next(r for r in results if r.name == "patterns_complete")
    assert pc_check.ok, pc_check.detail


def test_startup_check_7_mitmproxy_ca_happy(tmp_path: Path):
    """Check #7: mitmproxy-ca.pem with both key + cert blocks passes."""
    _make_mitmproxy_ca_pem(tmp_path, include_key=True, include_cert=True)
    kwargs = _full_startup_kwargs(tmp_path)
    # _full_startup_kwargs already wrote the file; we regenerated it above (idempotent)
    results = run_startup_checks(**kwargs)
    mc_check = next(r for r in results if r.name == "mitmproxy_ca_file")
    assert mc_check.ok, mc_check.detail


def test_startup_check_7_mitmproxy_ca_missing_key_fails(tmp_path: Path):
    """Check #7: mitmproxy-ca.pem with only CERTIFICATE block (no key) fails."""
    kwargs = _full_startup_kwargs(tmp_path)
    # overwrite mitmproxy-ca.pem: cert only, no private key
    _make_mitmproxy_ca_pem(tmp_path, include_key=False, include_cert=True)
    results = run_startup_checks(**kwargs)
    mc_check = next(r for r in results if r.name == "mitmproxy_ca_file")
    assert not mc_check.ok
    assert "private key" in mc_check.detail.lower()


def test_startup_check_7_mitmproxy_ca_missing_cert_fails(tmp_path: Path):
    """Check #7: mitmproxy-ca.pem with only key block (no cert) fails."""
    kwargs = _full_startup_kwargs(tmp_path)
    _make_mitmproxy_ca_pem(tmp_path, include_key=True, include_cert=False)
    results = run_startup_checks(**kwargs)
    mc_check = next(r for r in results if r.name == "mitmproxy_ca_file")
    assert not mc_check.ok
    assert "certificate" in mc_check.detail.lower()


def test_startup_returns_10_checks(tmp_path: Path):
    """run_startup_checks always returns exactly 10 CheckResult items."""
    kwargs = _full_startup_kwargs(tmp_path)
    results = run_startup_checks(**kwargs)
    assert len(results) == 10


# ---------------------------------------------------------------------------
# Runtime mode tests
# ---------------------------------------------------------------------------


def test_runtime_check_5_listener_bound_state():
    """Check #5 runtime: reads _runtime_listener_bound from state, no bind attempt."""
    state = _full_fake_state()
    results = run_runtime_checks(state_provider=lambda: state)
    listener_check = next(r for r in results if r.name == "listener_bound")
    assert listener_check.ok


def test_runtime_check_5_listener_not_bound():
    """Check #5 runtime: _runtime_listener_bound=False → fail."""
    state = _full_fake_state()
    state["_runtime_listener_bound"] = False
    results = run_runtime_checks(state_provider=lambda: state)
    listener_check = next(r for r in results if r.name == "listener_bound")
    assert not listener_check.ok


def test_runtime_check_8_session_key_age_sane():
    """Check #8 runtime: session_key_age_seconds within 0–86400 → ok."""
    state = _full_fake_state()
    state["session_key_age_seconds"] = 60
    results = run_runtime_checks(state_provider=lambda: state)
    age_check = next(r for r in results if r.name == "session_key_age_sane")
    assert age_check.ok


def test_runtime_check_8_session_key_age_stale():
    """Check #8 runtime: session_key_age_seconds >= 86400 → fail (stale)."""
    state = _full_fake_state()
    state["session_key_age_seconds"] = 86400
    results = run_runtime_checks(state_provider=lambda: state)
    age_check = next(r for r in results if r.name == "session_key_age_sane")
    assert not age_check.ok


def test_runtime_returns_10_checks():
    """run_runtime_checks always returns exactly 10 CheckResult items."""
    state = _full_fake_state()
    results = run_runtime_checks(state_provider=lambda: state)
    assert len(results) == 10
    names = [r.name for r in results]
    expected = [
        "ca_file",
        "signing_key",
        "patterns_complete",
        "chain_dir_writable",
        "listener_bound",
        "admin_bound_loopback",
        "mitmproxy_ca_file",
        "session_key_age_sane",
        "sentinel_dir",
        "upstream_reachable",
    ]
    assert names == expected


def test_runtime_all_ok_on_healthy_state(tmp_path: Path):
    """All 10 runtime checks pass when the state snapshot is fully healthy
    AND the on-disk CA fixtures are valid — runtime checks #1/#7 re-validate
    the filesystem since argus issue #13 (they previously trusted the
    hardcoded ca_mode string, so a fake state alone passed vacuously)."""
    ca_path = _make_valid_ca(tmp_path)
    hosts_path = _make_permitted_hosts_yaml(tmp_path)
    _make_mitmproxy_ca_pem(tmp_path)
    state = _full_fake_state()
    results = run_runtime_checks(
        state_provider=lambda: state,
        ca_path=ca_path,
        permitted_hosts_path=hosts_path,
    )
    failures = [r for r in results if not r.ok]
    assert failures == [], [f"{r.name}: {r.detail}" for r in failures]
