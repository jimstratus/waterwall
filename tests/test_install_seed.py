# tests/test_install_seed.py
"""The default patterns.py seeded by BOTH installers (systemd install.sh and
Windows nssm install.ps1) must stay loader-valid and must not duplicate
built-in patterns (issue #21 — the seeded AWS_ACCESS_KEY dup produced
overlapping scan spans)."""
import re
from pathlib import Path

import pytest

from waterwall.proxy.pattern_loader import PatternLoader
from waterwall.proxy.patterns import SINGLE_LINE_PATTERNS

DEPLOY = Path(__file__).parent.parent / "deploy"


def _seed_from_install_sh() -> str:
    text = (DEPLOY / "systemd" / "install.sh").read_text(encoding="utf-8")
    m = re.search(
        r"cat > /etc/waterwall/patterns\.py <<'EOF'\n(.*?)\nEOF\n",
        text,
        re.DOTALL,
    )
    assert m, "patterns.py seed heredoc not found in install.sh"
    return m.group(1)


def _seed_from_install_ps1() -> str:
    text = (DEPLOY / "nssm" / "install.ps1").read_text(encoding="utf-8")
    m = re.search(
        r"\$patternsPath -Content @'\n(.*?)\n'@\n",
        text,
        re.DOTALL,
    )
    assert m, "patterns.py seed here-string not found in install.ps1"
    return m.group(1)


@pytest.fixture(params=["install.sh", "install.ps1"])
def seed_loader(request, tmp_path: Path) -> PatternLoader:
    seed = (
        _seed_from_install_sh()
        if request.param == "install.sh"
        else _seed_from_install_ps1()
    )
    seed_file = tmp_path / "patterns.py"
    seed_file.write_text(seed + "\n", encoding="utf-8")
    return PatternLoader(seed_file)  # raises ValueError on bad file


def test_seed_parses_with_pattern_loader(seed_loader):
    assert isinstance(seed_loader.compiled(), list)


def test_seed_does_not_duplicate_builtins(seed_loader):
    builtin_labels = {label for label, _ in SINGLE_LINE_PATTERNS}
    builtin_regexes = {pattern for _, pattern in SINGLE_LINE_PATTERNS}
    for label, compiled in seed_loader.compiled():
        assert label not in builtin_labels, f"seed re-introduces built-in label {label}"
        assert compiled.pattern not in builtin_regexes, (
            f"seed re-introduces built-in regex for {label}"
        )
