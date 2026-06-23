# tests/test_cli_regen_ca.py
"""CLI integration tests for `waterwall regen-ca`."""
from pathlib import Path
import subprocess
import sys


def test_regen_ca_writes_files(tmp_path):
    yaml_text = """
hosts:
  - host: api.anthropic.com
    sse_handler: anthropic
  - host: api.deepseek.com
    sse_handler: openai
"""
    yaml_path = tmp_path / "permitted_hosts.yaml"
    yaml_path.write_text(yaml_text, encoding="utf-8")
    out_dir = tmp_path / "ca"

    result = subprocess.run(
        [sys.executable, "-m", "waterwall.cli", "regen-ca",
         "--hosts-file", str(yaml_path),
         "--out-dir", str(out_dir)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert (out_dir / "ca.pem").exists()
    assert (out_dir / "ca.key").exists()
    assert (out_dir / "mitmproxy-ca.pem").exists()


def test_regen_ca_backs_up_existing(tmp_path):
    """Re-running over an existing CA dir should rename old files to *.bak-<ts>."""
    yaml_text = """
hosts:
  - host: api.anthropic.com
    sse_handler: anthropic
"""
    yaml_path = tmp_path / "permitted_hosts.yaml"
    yaml_path.write_text(yaml_text, encoding="utf-8")
    out_dir = tmp_path / "ca"

    # First run
    subprocess.run(
        [sys.executable, "-m", "waterwall.cli", "regen-ca",
         "--hosts-file", str(yaml_path), "--out-dir", str(out_dir)],
        check=True, timeout=30, capture_output=True,
    )
    first_ca_bytes = (out_dir / "ca.pem").read_bytes()

    # Second run — should back up old, write new
    subprocess.run(
        [sys.executable, "-m", "waterwall.cli", "regen-ca",
         "--hosts-file", str(yaml_path), "--out-dir", str(out_dir)],
        check=True, timeout=30, capture_output=True,
    )
    backups = list(out_dir.glob("ca.pem.bak-*"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == first_ca_bytes
    # New ca.pem differs (different serial number even with same hosts)
    assert (out_dir / "ca.pem").read_bytes() != first_ca_bytes


def test_regen_ca_failure_leaves_existing_ca_intact(tmp_path, monkeypatch):
    """Argus issue #11: backups were rename()d away BEFORE generation; a
    generation failure left /etc/waterwall with no CA at all."""
    import waterwall.cli.regen_ca as rc
    # seed an existing CA + valid hosts file
    (tmp_path / "ca.pem").write_text("OLD", encoding="utf-8")
    (tmp_path / "ca.key").write_text("OLD", encoding="utf-8")
    (tmp_path / "mitmproxy-ca.pem").write_text("OLD", encoding="utf-8")
    hosts = tmp_path / "permitted_hosts.yaml"
    hosts.write_text('hosts:\n  - host: api.anthropic.com\n    sse_handler: anthropic\n', encoding="utf-8")

    def boom(**kwargs):
        raise RuntimeError("generation exploded")
    monkeypatch.setattr(rc, "generate_ca", boom)
    monkeypatch.setattr(sys, "argv",
        ["waterwall regen-ca", "--hosts-file", str(hosts), "--out-dir", str(tmp_path)])
    assert rc.main_cli() != 0
    assert (tmp_path / "ca.pem").read_text() == "OLD"
    assert (tmp_path / "mitmproxy-ca.pem").read_text() == "OLD"


def test_regen_ca_rejects_invalid_yaml(tmp_path):
    yaml_path = tmp_path / "permitted_hosts.yaml"
    yaml_path.write_text("hosts: []\n", encoding="utf-8")
    out_dir = tmp_path / "ca"
    result = subprocess.run(
        [sys.executable, "-m", "waterwall.cli", "regen-ca",
         "--hosts-file", str(yaml_path), "--out-dir", str(out_dir)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    assert "at least one host" in (result.stdout + result.stderr)
