# tests/test_pattern_hot_reload.py
"""Argus issue #10: a reloaded pattern must change ACTUAL scan behavior,
emit a policy_change chain event, and update the reported policy hash."""

import json

from waterwall.proxy import patterns
from waterwall.proxy.addon import WaterwallAddon


# File on disk must contain r"\bhl_[a-f0-9]{32}\b" (single backslashes inside
# the raw-string literal that ast.literal_eval evaluates).
CUSTOM = 'PATTERNS = [("HOMELAB_TOKEN", r"\\bhl_[a-f0-9]{32}\\b")]\n'


def test_reload_changes_scan_behavior_and_chains_policy_change(tmp_path, monkeypatch):
    pfile = tmp_path / "patterns.py"
    pfile.write_text(CUSTOM, encoding="utf-8")
    monkeypatch.setenv("WATERWALL_PATTERNS", str(pfile))
    monkeypatch.setenv("WATERWALL_PERMITTED_HOSTS", str(tmp_path / "absent.yaml"))
    monkeypatch.setenv("WATERWALL_ADMIN_PORT", "0")

    addon = WaterwallAddon(chain_path=tmp_path / "chain.jsonl")
    old_hash = addon._policy_hash
    try:
        addon.running()          # starts PatternLoader, applies extensions
        secret = "hl_" + "a" * 32
        matches = patterns.scan_string(f"token {secret} here")
        assert any(m.type == "HOMELAB_TOKEN" for m in matches), \
            "extension pattern not active after running()"
        # built-ins must survive (extensions APPEND, not replace)
        builtin = patterns.scan_string("AKIAIOSFODNN7EXAMPLE")
        assert any(m.type == "AWS_ACCESS_KEY" for m in builtin)
        assert addon._policy_hash != old_hash
        # policy_change chain event emitted
        lines = [json.loads(l) for l in
                 (tmp_path / "chain.jsonl").read_text().strip().splitlines()]
        assert any(l.get("line_type") == "policy_change" for l in lines)
    finally:
        addon.done()
        patterns.reset_active_patterns()   # restore module state for other tests


def test_reset_restores_builtin_set():
    patterns.reset_active_patterns()
    assert patterns.pattern_count() == 31   # 30 single-line + PEM
