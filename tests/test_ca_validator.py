"""Verify the CA validator rejects unconstrained CAs and accepts properly-constrained ones.

Plan 1 Task 1.2.

Tests use the `cryptography` library directly to generate test fixtures —
NOT shell-outs to openssl. This keeps tests portable across Windows and
Linux without git-bash + Windows-path translation grief. The openssl-based
shell scripts (deploy/ca/generate_ca.{sh,ps1}) are exercised separately by
Phase 1.1 + 1.3 lab-test procedures.
"""

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from waterwall.ops.ca_validator import (
    CaValidationError,
    validate_ca_for_waterwall,
)


def _build_ca_cert(
    name_constraints: x509.NameConstraints | None,
    cn: str = "Waterwall Test CA",
    days: int = 30,
    not_valid_after: dt.datetime | None = None,
    nc_critical: bool = True,
) -> bytes:
    """Build a self-signed CA cert for tests, with optional Name Constraints.

    Defaults (valid 30 days, critical NameConstraints) match the contract the
    pre-issue-#11 tests assumed, so they keep passing unchanged.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    if not_valid_after is None:
        not_valid_before = now
        not_valid_after = now + dt.timedelta(days=days)
    else:
        # keep before < after even when building an already-expired cert
        not_valid_before = not_valid_after - dt.timedelta(days=days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    if name_constraints is not None:
        builder = builder.add_extension(name_constraints, critical=nc_critical)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


def build_test_ca(
    tmp_path: Path,
    hosts: list[str],
    not_valid_after: dt.datetime | None = None,
    nc_critical: bool = True,
) -> Path:
    """Write a Name-Constrained test CA permitting `hosts`; return its path."""
    nc = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName(h) for h in hosts],
        excluded_subtrees=None,
    )
    pem = _build_ca_cert(
        name_constraints=nc, not_valid_after=not_valid_after, nc_critical=nc_critical
    )
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(pem)
    return ca_path


def test_validate_rejects_missing_file(tmp_path: Path):
    missing = tmp_path / "nope.pem"
    with pytest.raises(CaValidationError) as exc:
        validate_ca_for_waterwall(missing)
    assert "not found" in str(exc.value).lower()


def test_validate_accepts_constrained_ca(tmp_path: Path):
    """Build a Name-Constrained CA via cryptography and validate it."""
    nc = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName("api.anthropic.com")],
        excluded_subtrees=None,
    )
    pem = _build_ca_cert(name_constraints=nc)
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(pem)

    result = validate_ca_for_waterwall(ca_path)
    assert result.permits == frozenset({"api.anthropic.com"})
    assert result.is_critical


def test_validate_rejects_unconstrained_ca(tmp_path: Path):
    """A CA without a NameConstraints extension must be rejected."""
    pem = _build_ca_cert(name_constraints=None)
    ca_path = tmp_path / "bad.pem"
    ca_path.write_bytes(pem)

    with pytest.raises(CaValidationError) as exc:
        validate_ca_for_waterwall(ca_path)
    assert "name constraint" in str(exc.value).lower()


def test_validate_rejects_wrong_permitted_dns(tmp_path: Path):
    """A CA constrained to a different DNS name must be rejected."""
    nc = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName("api.openai.com")],
        excluded_subtrees=None,
    )
    pem = _build_ca_cert(name_constraints=nc)
    ca_path = tmp_path / "wrong.pem"
    ca_path.write_bytes(pem)

    with pytest.raises(CaValidationError) as exc:
        validate_ca_for_waterwall(ca_path)
    assert "mismatch" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# Issue #11 — expected_hosts from permitted_hosts.yaml, expiry, NC criticality
# ---------------------------------------------------------------------------


def test_validator_accepts_hosts_matching_expected_set(tmp_path: Path):
    ca = build_test_ca(tmp_path, hosts=["api.anthropic.com", "api.deepseek.com"])
    result = validate_ca_for_waterwall(
        ca, expected_hosts=frozenset({"api.anthropic.com", "api.deepseek.com"})
    )
    assert result.permits == frozenset({"api.anthropic.com", "api.deepseek.com"})


def test_validator_rejects_host_mismatch(tmp_path: Path):
    ca = build_test_ca(tmp_path, hosts=["api.anthropic.com"])
    with pytest.raises(CaValidationError, match="mismatch"):
        validate_ca_for_waterwall(
            ca, expected_hosts=frozenset({"api.anthropic.com", "api.openai.com"})
        )


def test_validator_rejects_expired_ca(tmp_path: Path):
    ca = build_test_ca(
        tmp_path,
        hosts=["api.anthropic.com"],
        not_valid_after=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1),
    )
    with pytest.raises(CaValidationError, match="expired"):
        validate_ca_for_waterwall(ca, expected_hosts=frozenset({"api.anthropic.com"}))


def test_validator_rejects_noncritical_name_constraints(tmp_path: Path):
    ca = build_test_ca(tmp_path, hosts=["api.anthropic.com"], nc_critical=False)
    with pytest.raises(CaValidationError, match="critical"):
        validate_ca_for_waterwall(ca, expected_hosts=frozenset({"api.anthropic.com"}))
