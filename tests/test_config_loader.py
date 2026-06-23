# tests/test_config_loader.py
"""Tests for ConfigLoader — inotify/watchdog hot-reload of config.yaml.

Inotify-based tests skip on Windows (inotify_simple is Linux only).
The Windows watchdog path is exercised on test-host in Task 6.6.
"""

import os
import time
from pathlib import Path

import pytest
from waterwall.proxy.config_loader import ConfigLoader
from waterwall.proxy.killswitch import KillSwitch


@pytest.mark.skipif(os.name != "posix", reason="inotify_simple is Linux only; Windows path uses watchdog")
def test_config_loader_toggles_killswitch(tmp_path: Path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("kill_switch: false\n")
    ks = KillSwitch()
    ks.arm_http("operator")  # other source pre-armed
    loader = ConfigLoader(cfg, killswitch=ks)
    loader.start()
    cfg.write_text("kill_switch: true\n")
    for _ in range(20):
        time.sleep(0.05)
        if ks.status()["config"]:
            break
    assert ks.status()["config"] is True
    assert ks.status()["http"] is True  # preserved
    loader.stop()


@pytest.mark.skipif(os.name != "posix", reason="inotify_simple is Linux only; Windows path uses watchdog")
def test_config_loader_toggles_off(tmp_path: Path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("kill_switch: true\n")
    ks = KillSwitch()
    loader = ConfigLoader(cfg, killswitch=ks)
    loader.start()
    # Initial load — wait for first parse
    for _ in range(20):
        time.sleep(0.05)
        if ks.status()["config"]:
            break
    assert ks.status()["config"] is True
    cfg.write_text("kill_switch: false\n")
    for _ in range(20):
        time.sleep(0.05)
        if not ks.status()["config"]:
            break
    assert ks.status()["config"] is False
    loader.stop()


def test_config_loader_refuses_invalid_yaml(tmp_path: Path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("kill_switch: false\n")
    ks = KillSwitch()
    loader = ConfigLoader(cfg, killswitch=ks)
    loader.start()
    cfg.write_text("not: valid: yaml: [")
    time.sleep(0.2)
    # State unchanged on parse failure
    assert ks.status()["config"] is False
    loader.stop()


def test_config_loader_stop_cleans_up(tmp_path: Path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("kill_switch: false\n")
    ks = KillSwitch()
    loader = ConfigLoader(cfg, killswitch=ks)
    loader.start()
    loader.stop()
    assert not loader._thread.is_alive()
