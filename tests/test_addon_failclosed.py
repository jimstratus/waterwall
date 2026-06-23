# tests/test_addon_failclosed.py
"""Argus issue #7: missing/corrupt permitted_hosts.yaml must fail CLOSED,
and an armed killswitch must 502 before the host gate."""
import json
import os
from pathlib import Path

import pytest
from mitmproxy.test import tflow, taddons

from waterwall.proxy.addon import WaterwallAddon


def _mk_addon(tmp_path: Path) -> WaterwallAddon:
    return WaterwallAddon(chain_path=tmp_path / "chain.jsonl", session_key=os.urandom(32))


def _mk_flow(host: str, content: bytes):
    return tflow.tflow(
        req=tflow.treq(
            host=host, port=443, scheme=b"https",
            method=b"POST", path=b"/v1/messages",
            headers=((b"content-type", b"application/json"),),
            content=content,
        )
    )


def _isolate_running_env(tmp_path, monkeypatch):
    """Point running()'s other env-gated loaders at nonexistent paths so the
    test stays hermetic on hosts where /etc/waterwall/* really exists."""
    monkeypatch.setenv("WATERWALL_PATTERNS", str(tmp_path / "no-patterns.py"))
    monkeypatch.setenv("WATERWALL_CONFIG", str(tmp_path / "no-config.yaml"))
    monkeypatch.setenv("WATERWALL_ADMIN_PORT", "0")


def test_missing_permitted_hosts_502s_everything(tmp_path, monkeypatch):
    _isolate_running_env(tmp_path, monkeypatch)
    monkeypatch.setenv("WATERWALL_PERMITTED_HOSTS", str(tmp_path / "nonexistent.yaml"))
    addon = _mk_addon(tmp_path)
    addon.running()
    assert addon._config_error is not None

    flow = _mk_flow(host="api.anthropic.com", content=b'{"messages": []}')
    with taddons.context(addon) as _:
        addon.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 502
    body = json.loads(flow.response.content)
    assert body["error"] == "waterwall-config-error"
    addon.done()


def test_corrupt_permitted_hosts_502s_everything(tmp_path, monkeypatch):
    _isolate_running_env(tmp_path, monkeypatch)
    bad = tmp_path / "permitted_hosts.yaml"
    bad.write_text("hosts: [unclosed", encoding="utf-8")
    monkeypatch.setenv("WATERWALL_PERMITTED_HOSTS", str(bad))
    addon = _mk_addon(tmp_path)
    addon.running()
    assert addon._config_error is not None

    flow = _mk_flow(host="api.anthropic.com", content=b'{"messages": []}')
    with taddons.context(addon) as _:
        addon.request(flow)
    assert flow.response is not None and flow.response.status_code == 502
    addon.done()


def test_armed_killswitch_blocks_unregistered_host(tmp_path):
    """Killswitch check must run BEFORE the host gate (addon.py had it inverted)."""
    addon = _mk_addon(tmp_path)
    addon._killswitch.arm_http("test")
    flow = _mk_flow(host="api.example-not-registered.com", content=b"{}")
    with taddons.context(addon) as _:
        addon.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 502
    body = json.loads(flow.response.content)
    assert body["error"] == "waterwall-killswitch-engaged"
    addon.done()


def test_unit_test_construction_unaffected(tmp_path):
    """Addon built directly without running() keeps Plan-1 unit-test behavior:
    unregistered host + no config error -> pass through untouched."""
    addon = _mk_addon(tmp_path)
    assert addon._config_error is None
    flow = _mk_flow(host="api.anthropic.com", content=b'{"messages": []}')
    with taddons.context(addon) as _:
        addon.request(flow)
    assert flow.response is None
    addon.done()
