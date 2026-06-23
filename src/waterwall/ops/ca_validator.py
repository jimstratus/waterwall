"""Validate that a CA file is suitable for Waterwall.

Name-Constrained to exactly the permitted-hosts set, within its validity
window, with a CRITICAL NameConstraints extension.

Spec §3 / §11.4 Check #1.
Plan 1 Task 1.2; argus remediation Task 16 (issue #11).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtensionOID


class CaValidationError(Exception):
    """Raised when a CA fails Waterwall's validation rules."""


@dataclass(frozen=True)
class CaValidationResult:
    permits: frozenset[str]
    is_critical: bool
    not_after_iso: str


def validate_ca_for_waterwall(
    ca_path: Path,
    expected_hosts: frozenset[str] | None = None,
) -> CaValidationResult:
    """expected_hosts=None preserves the v1 anthropic-only contract for
    callers not yet migrated; verify-install passes the live yaml set
    (argus issue #11 — hardcode bricked the service after regen-ca)."""
    if expected_hosts is None:
        expected_hosts = frozenset({"api.anthropic.com"})

    if not ca_path.exists():
        raise CaValidationError(f"CA file not found: {ca_path}")

    pem = ca_path.read_bytes()
    cert = x509.load_pem_x509_certificate(pem)

    now = dt.datetime.now(dt.timezone.utc)
    if cert.not_valid_after_utc < now:
        raise CaValidationError(f"CA expired at {cert.not_valid_after_utc.isoformat()}")
    if cert.not_valid_before_utc > now:
        raise CaValidationError(
            f"CA not valid before {cert.not_valid_before_utc.isoformat()}"
        )

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
    except x509.ExtensionNotFound as e:
        raise CaValidationError(
            "CA missing required Name Constraints extension"
        ) from e

    if not ext.critical:
        raise CaValidationError(
            "CA NameConstraints must be critical (RFC 5280) — non-enforcing "
            "clients would ignore it, voiding the blast-radius guarantee"
        )

    nc: x509.NameConstraints = ext.value
    permitted = frozenset(
        gn.value
        for gn in (nc.permitted_subtrees or [])
        if isinstance(gn, x509.DNSName)
    )
    if permitted != expected_hosts:
        raise CaValidationError(
            f"CA Name Constraints mismatch: permits {sorted(permitted)}, "
            f"expected {sorted(expected_hosts)} (from permitted_hosts.yaml)"
        )

    return CaValidationResult(
        permits=permitted,
        is_critical=ext.critical,
        not_after_iso=cert.not_valid_after_utc.isoformat(),
    )
