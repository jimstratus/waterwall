"""Static regression tests for the Windows NSSM deployment scripts."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_PATH = REPO_ROOT / "deploy" / "nssm" / "install.ps1"
UNINSTALL_PATH = REPO_ROOT / "deploy" / "nssm" / "uninstall.ps1"
README_PATH = REPO_ROOT / "deploy" / "nssm" / "README.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_install_script_exists_and_is_no_longer_deferred():
    assert INSTALL_PATH.exists()
    text = _read(INSTALL_PATH)
    assert "DEFERRED TO v1.1" not in text


def test_install_script_downloads_nssm_when_missing():
    text = _read(INSTALL_PATH)
    assert "nssm-2.24.zip" in text
    assert "Invoke-WebRequest" in text
    assert "Expand-Archive" in text


def test_install_script_configures_service_supervision():
    text = _read(INSTALL_PATH)
    assert "waterwall-proxy" in text
    assert "SERVICE_DELAYED_AUTO_START" in text
    assert "AppExit" in text and "Restart" in text
    assert "AppRestartDelay" in text and "5000" in text
    assert "AppStdout" in text
    assert "AppStderr" in text


def test_install_script_preserves_load_bearing_mitmdump_flags():
    text = _read(INSTALL_PATH)
    assert "--listen-host" in text and "127.0.0.1" in text
    assert "--set" in text and "upstream_cert=false" in text
    assert "script_reloader=false" in text
    assert "confdir=" in text
    # issue #17: api.openrouter.ai has no public DNS records; the API lives on
    # the apex (openrouter.ai) — the wrong name means unintercepted egress.
    assert "$AllowHostsPattern = 'api\\.anthropic\\.com|api\\.deepseek\\.com|api\\.openai\\.com|openrouter\\.ai'" in text
    assert "'--allow-hosts', $AllowHostsPattern" in text


def test_install_script_sets_expected_environment_variables():
    text = _read(INSTALL_PATH)
    for name in (
        "HTTPS_PROXY=",
        "NO_PROXY=127.0.0.1,localhost",
        "WATERWALL_CHAIN=",
        "WATERWALL_SIGNING_KEY=",
        "WATERWALL_PATTERNS=",
        "WATERWALL_CONFIG=",
        "WATERWALL_PERMITTED_HOSTS=",
        "WATERWALL_ADMIN_PORT=8889",
    ):
        assert name in text


def test_install_script_restricts_private_key_acls_to_admin_and_system():
    text = _read(INSTALL_PATH)
    assert "function Set-PrivateKeyAcl" in text
    assert "SetAccessRuleProtection($true, $false)" in text
    assert "S-1-5-18" in text
    assert "S-1-5-32-544" in text
    assert "Join-Path $DataRoot 'ca.key'" in text
    assert "Join-Path $DataRoot 'mitmproxy-ca.pem'" in text
    assert "$signingKey" in text
    assert "Set-PrivateKeyAcl -Path $privateMaterialPath" in text


def test_uninstall_script_stops_and_removes_service_but_preserves_data():
    text = _read(UNINSTALL_PATH)
    assert UNINSTALL_PATH.exists()
    assert "waterwall-proxy" in text
    assert "Stop-Service" in text
    assert "nssm" in text and "remove" in text
    assert "-RemoveData" in text
    assert "Preserving" in text or "preserve" in text.lower()


def test_readme_documents_install_usage_and_limitations():
    text = _read(README_PATH)
    assert ".\\deploy\\nssm\\install.ps1" in text
    assert "auto-download" in text.lower()
    assert "nssm start waterwall-proxy" in text
    assert "nssm stop waterwall-proxy" in text
    assert "nssm status waterwall-proxy" in text
    assert "http://127.0.0.1:8889/healthz" in text
    assert "hardening provided by systemd" in text
    assert "LocalSystem" in text
