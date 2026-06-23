# tests/test_pattern_loader.py
"""Tests for PatternLoader — inotify/watchdog hot-reload of a PATTERNS file.

Inotify-based tests skip on Windows (inotify_simple is Linux only).
The Windows watchdog path is exercised on test-host in Task 6.6.
"""

import os
import time
from pathlib import Path

import pytest
from waterwall.proxy.pattern_loader import PatternLoader


@pytest.mark.skipif(os.name != "posix", reason="inotify_simple is Linux only; Windows path uses watchdog")
def test_pattern_reload_picks_up_change(tmp_path: Path):
    pattern_file = tmp_path / "patterns.py"
    pattern_file.write_text("PATTERNS = [('FOO', r'\\bfoo\\b')]")
    loader = PatternLoader(pattern_file)
    loader.start()
    initial_hash = loader.policy_hash()
    pattern_file.write_text("PATTERNS = [('FOO', r'\\bfoo\\b'), ('BAR', r'\\bbar\\b')]")
    # Allow inotify event to fire
    for _ in range(20):
        time.sleep(0.05)
        if loader.policy_hash() != initial_hash:
            break
    assert loader.policy_hash() != initial_hash, "loader should pick up file change"
    loader.stop()


@pytest.mark.skipif(os.name != "posix", reason="inotify_simple is Linux only; Windows path uses watchdog")
def test_pattern_reload_refused_on_parse_failure(tmp_path: Path):
    pattern_file = tmp_path / "patterns.py"
    pattern_file.write_text("PATTERNS = [('FOO', r'\\bfoo\\b')]")
    loader = PatternLoader(pattern_file)
    loader.start()
    initial_hash = loader.policy_hash()
    pattern_file.write_text("PATTERNS = [(broken syntax")
    time.sleep(0.2)
    # Invariant: policy hash unchanged on parse failure
    assert loader.policy_hash() == initial_hash
    loader.stop()


@pytest.mark.skipif(os.name != "posix", reason="inotify_simple is Linux only; Windows path uses watchdog")
def test_pattern_reload_refused_on_bad_regex(tmp_path: Path):
    pattern_file = tmp_path / "patterns.py"
    pattern_file.write_text("PATTERNS = [('FOO', r'\\bfoo\\b')]")
    loader = PatternLoader(pattern_file)
    loader.start()
    initial_hash = loader.policy_hash()
    # Invalid regex (unclosed group)
    pattern_file.write_text("PATTERNS = [('BAD', r'(unclosed')]")
    time.sleep(0.2)
    # Hash must be unchanged on compile failure
    assert loader.policy_hash() == initial_hash
    loader.stop()


@pytest.mark.skipif(os.name != "posix", reason="inotify_simple is Linux only; Windows path uses watchdog")
def test_pattern_loader_stop_cleans_up(tmp_path: Path):
    pattern_file = tmp_path / "patterns.py"
    pattern_file.write_text("PATTERNS = [('FOO', r'\\bfoo\\b')]")
    loader = PatternLoader(pattern_file)
    loader.start()
    loader.stop()
    # After stop, thread must not be alive
    assert not loader._thread.is_alive()
