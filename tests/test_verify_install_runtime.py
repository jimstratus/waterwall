# tests/test_verify_install_runtime.py
"""Argus issue #13: runtime checks 1/5/7 were vacuous (hardcoded literals).

The de-vacuoused CA checks (#1 ca_file, #7 mitmproxy_ca_file) read the
filesystem at runtime, resolved via WATERWALL_CA / WATERWALL_PERMITTED_HOSTS.
Tests that exercise them monkeypatch those env vars to tmp_path fixtures built
with tests/test_ca_validator.py's `build_test_ca` helper. Tests that target a
non-CA check assert ONLY their targeted check's result, since the CA checks
may legitimately fail on hosts without /etc/waterwall fixtures.
"""

from __future__ import annotations

from pathlib import Path

from waterwall.ops.verify_install import run_runtime_checks

from tests.test_ca_validator import build_test_ca


def _state(**over):
    base = {
        "ca_mode": "NODE_EXTRA_CA_CERTS",
        "health": {
            "signer_key_readable": True,
            "upstream_reachable": True,
            "chain_intact": True,
            "patterns_loaded": 30,
            "patterns_min_required": 16,
        },
        "session_key_age_seconds": 0,
        "_runtime_listener_bound": True,
        "_runtime_admin_bound_loopback": True,
    }
    base.update(over)
    return base


def _write_permitted_hosts(tmp_path: Path, hosts: list[str]) -> Path:
    hosts_path = tmp_path / "permitted_hosts.yaml"
    hosts_path.write_text(
        "hosts:\n"
        + "".join(f"  - host: {h}\n    sse_handler: anthropic\n" for h in hosts),
        encoding="utf-8",
    )
    return hosts_path


def _write_mitmproxy_ca(tmp_path: Path, key: bool = True, cert: bool = True) -> Path:
    """mitmproxy-ca.pem fixture — check #7 greps for PEM block markers."""
    parts = []
    if key:
        parts.append("-----BEGIN PRIVATE KEY-----\nMC4=\n-----END PRIVATE KEY-----\n")
    if cert:
        parts.append("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    mca = tmp_path / "mitmproxy-ca.pem"
    mca.write_text("".join(parts), encoding="ascii")
    return mca


def _ca_env(tmp_path: Path, monkeypatch, hosts: list[str] | None = None) -> None:
    """Point WATERWALL_CA / WATERWALL_PERMITTED_HOSTS at matching tmp fixtures."""
    hosts = hosts or ["api.anthropic.com"]
    ca_path = build_test_ca(tmp_path, hosts=hosts)
    _write_permitted_hosts(tmp_path, hosts)
    _write_mitmproxy_ca(tmp_path)
    monkeypatch.setenv("WATERWALL_CA", str(ca_path))
    monkeypatch.setenv("WATERWALL_PERMITTED_HOSTS", str(tmp_path / "permitted_hosts.yaml"))


# ---------------------------------------------------------------------------
# Check #5 — listener_bound reads the real probed value from state
# ---------------------------------------------------------------------------


def test_listener_bound_false_fails_check_5():
    results = {r.name: r for r in run_runtime_checks(lambda: _state(_runtime_listener_bound=False))}
    assert results["listener_bound"].ok is False


def test_listener_bound_true_passes_check_5():
    results = {r.name: r for r in run_runtime_checks(lambda: _state())}
    assert results["listener_bound"].ok is True


# ---------------------------------------------------------------------------
# Check #8 — session key age accepts 0 (was `0 < age`; argus issue #13)
# ---------------------------------------------------------------------------


def test_session_key_age_zero_passes():
    """0 < age rejected the first second after start (argus issue #13)."""
    results = {r.name: r for r in run_runtime_checks(lambda: _state(session_key_age_seconds=0))}
    assert results["session_key_age_sane"].ok is True


def test_session_key_age_stale_fails():
    results = {r.name: r for r in run_runtime_checks(lambda: _state(session_key_age_seconds=86400))}
    assert results["session_key_age_sane"].ok is False


# ---------------------------------------------------------------------------
# Check #1 — ca_file re-validates the CA on disk (was `ca_mode == literal`)
# ---------------------------------------------------------------------------


def test_runtime_ca_file_valid_on_disk_passes(tmp_path, monkeypatch):
    _ca_env(tmp_path, monkeypatch)
    results = {r.name: r for r in run_runtime_checks(lambda: _state())}
    assert results["ca_file"].ok is True, results["ca_file"].detail


def test_runtime_ca_file_missing_fails(tmp_path, monkeypatch):
    """A vanished/absent CA must fail at runtime even if state looks healthy —
    the old check trusted the hardcoded ca_mode string."""
    _ca_env(tmp_path, monkeypatch)
    monkeypatch.setenv("WATERWALL_CA", str(tmp_path / "absent-ca.pem"))
    results = {r.name: r for r in run_runtime_checks(lambda: _state())}
    assert results["ca_file"].ok is False


def test_runtime_ca_file_host_mismatch_fails(tmp_path, monkeypatch):
    """CA constrained to fewer hosts than permitted_hosts.yaml expects → fail."""
    _ca_env(tmp_path, monkeypatch)
    _write_permitted_hosts(tmp_path, ["api.anthropic.com", "api.openai.com"])
    results = {r.name: r for r in run_runtime_checks(lambda: _state())}
    assert results["ca_file"].ok is False
    assert "mismatch" in results["ca_file"].detail.lower()


def test_runtime_ca_file_missing_permitted_hosts_fails(tmp_path, monkeypatch):
    """Missing permitted_hosts.yaml fails closed — no anthropic-only fallback."""
    _ca_env(tmp_path, monkeypatch)
    monkeypatch.setenv("WATERWALL_PERMITTED_HOSTS", str(tmp_path / "absent.yaml"))
    results = {r.name: r for r in run_runtime_checks(lambda: _state())}
    assert results["ca_file"].ok is False


# ---------------------------------------------------------------------------
# Check #7 — mitmproxy_ca_file re-checked on disk (was delegated to ca_mode)
# ---------------------------------------------------------------------------


def test_runtime_mitmproxy_ca_present_passes(tmp_path, monkeypatch):
    _ca_env(tmp_path, monkeypatch)
    results = {r.name: r for r in run_runtime_checks(lambda: _state())}
    assert results["mitmproxy_ca_file"].ok is True, results["mitmproxy_ca_file"].detail


def test_runtime_mitmproxy_ca_missing_fails(tmp_path, monkeypatch):
    _ca_env(tmp_path, monkeypatch)
    (tmp_path / "mitmproxy-ca.pem").unlink()
    results = {r.name: r for r in run_runtime_checks(lambda: _state())}
    assert results["mitmproxy_ca_file"].ok is False
    assert "missing" in results["mitmproxy_ca_file"].detail.lower()


def test_runtime_mitmproxy_ca_missing_key_block_fails(tmp_path, monkeypatch):
    _ca_env(tmp_path, monkeypatch)
    _write_mitmproxy_ca(tmp_path, key=False, cert=True)
    results = {r.name: r for r in run_runtime_checks(lambda: _state())}
    assert results["mitmproxy_ca_file"].ok is False
    assert "private key" in results["mitmproxy_ca_file"].detail.lower()


# ---------------------------------------------------------------------------
# Startup check #3 — the deployed patterns file must actually be validated
# ---------------------------------------------------------------------------


def test_startup_check3_validates_deployed_patterns_file(tmp_path):
    """Argus issue #10: the patterns_path parameter was dead — a syntactically
    broken DEPLOYED patterns file must fail check #3."""
    from waterwall.ops.verify_install import run_startup_checks
    bad = tmp_path / "patterns.py"
    bad.write_text("PATTERNS = [unclosed", encoding="utf-8")
    results = {r.name: r for r in run_startup_checks(
        ca_path=tmp_path / "absent-ca.pem",
        signer_path=tmp_path / "absent.key",
        patterns_path=bad,
        chain_log_dir=tmp_path,
        sentinel_dir=tmp_path / "run",
        listen_port=0, admin_port=0,
        upstream_host="localhost",
        permitted_hosts_path=tmp_path / "absent.yaml",
    )}
    assert results["patterns_complete"].ok is False
    assert "patterns" in results["patterns_complete"].detail.lower() or \
           "syntax" in results["patterns_complete"].detail.lower()


def test_startup_check3_passes_with_valid_deployed_patterns_file(tmp_path):
    """A parseable deployed extensions file keeps check #3 green."""
    from waterwall.ops.verify_install import run_startup_checks
    good = tmp_path / "patterns.py"
    good.write_text('PATTERNS = [("MY_TOKEN", r"tok_[a-z0-9]{8}")]\n', encoding="utf-8")
    results = {r.name: r for r in run_startup_checks(
        ca_path=tmp_path / "absent-ca.pem",
        signer_path=tmp_path / "absent.key",
        patterns_path=good,
        chain_log_dir=tmp_path,
        sentinel_dir=tmp_path / "run",
        listen_port=0, admin_port=0,
        upstream_host="localhost",
        permitted_hosts_path=tmp_path / "absent.yaml",
    )}
    assert results["patterns_complete"].ok is True, results["patterns_complete"].detail


def test_startup_check3_absent_patterns_file_still_passes(tmp_path):
    """No deployed extensions file is a legitimate state — built-ins suffice."""
    from waterwall.ops.verify_install import run_startup_checks
    results = {r.name: r for r in run_startup_checks(
        ca_path=tmp_path / "absent-ca.pem",
        signer_path=tmp_path / "absent.key",
        patterns_path=tmp_path / "absent-patterns.py",
        chain_log_dir=tmp_path,
        sentinel_dir=tmp_path / "run",
        listen_port=0, admin_port=0,
        upstream_host="localhost",
        permitted_hosts_path=tmp_path / "absent.yaml",
    )}
    assert results["patterns_complete"].ok is True, results["patterns_complete"].detail


# ---------------------------------------------------------------------------
# Shape invariant — still exactly 10 checks with stable names
# ---------------------------------------------------------------------------


def test_runtime_still_returns_10_checks(tmp_path, monkeypatch):
    _ca_env(tmp_path, monkeypatch)
    results = run_runtime_checks(lambda: _state())
    assert [r.name for r in results] == [
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
    failures = [r.name for r in results if not r.ok]
    assert failures == []


def test_runtime_cli_respects_admin_port_env(monkeypatch, capsys):
    """The runtime-mode /admin/state URL hardcoded port 8889 — the same
    'hardcoded literal' class as the issue #13 findings. Found live in the
    remediation lab (proxy on 18889, CLI probed 8889)."""
    import sys
    import httpx
    from waterwall.ops import verify_install as vi

    seen = {}

    def fake_get(url, timeout):
        seen["url"] = url
        raise httpx.ConnectError("lab")

    monkeypatch.setenv("WATERWALL_ADMIN_PORT", "18889")
    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(sys, "argv", ["waterwall verify-install", "--runtime"])
    assert vi.main_cli() == 1
    assert "18889" in seen["url"], f"runtime mode ignored WATERWALL_ADMIN_PORT: {seen['url']}"
