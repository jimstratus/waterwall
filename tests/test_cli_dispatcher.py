# tests/test_cli_dispatcher.py
from __future__ import annotations

import subprocess
import sys


def test_waterwall_cli_help_runs():
    """Smoke test: `python -m waterwall.cli --help` prints help and exits 0."""
    result = subprocess.run(
        [sys.executable, "-m", "waterwall.cli", "--help"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "verify-install" in result.stdout
    assert "verify-receipt" in result.stdout
    assert "pre-launch-hook" in result.stdout


def test_waterwall_cli_no_subcommand_fails():
    result = subprocess.run(
        [sys.executable, "-m", "waterwall.cli"],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
