# tests/test_killswitch.py
import os
import signal
from pathlib import Path

import pytest
from waterwall.proxy.killswitch import KillSwitch


def test_initially_inactive(tmp_path: Path):
    ks = KillSwitch(sentinel_path=tmp_path / "kill")
    assert not ks.is_active()
    assert ks.active_sources() == []


def test_config_flag_arms_independently(tmp_path: Path):
    ks = KillSwitch(sentinel_path=tmp_path / "kill")
    ks.set_config_flag(True)
    assert ks.is_active()
    assert "config" in ks.active_sources()


def test_sentinel_file_arms_independently(tmp_path: Path):
    ks = KillSwitch(sentinel_path=tmp_path / "kill")
    (tmp_path / "kill").touch()
    assert ks.is_active()
    assert "sentinel" in ks.active_sources()


def test_http_arm_disarm(tmp_path: Path):
    ks = KillSwitch(sentinel_path=tmp_path / "kill")
    ks.arm_http("operator request")
    assert ks.is_active()
    assert "http" in ks.active_sources()
    ks.disarm_http()
    assert not ks.is_active()


@pytest.mark.skipif(os.name != "posix", reason="SIGUSR1 only on POSIX")
def test_sigusr1_toggles_latch(tmp_path: Path):
    ks = KillSwitch(sentinel_path=tmp_path / "kill")
    ks.install_sigusr1_handler()
    os.kill(os.getpid(), signal.SIGUSR1)
    # Allow signal delivery
    import time; time.sleep(0.05)
    assert ks.is_active()
    assert "sigusr1" in ks.active_sources()
    os.kill(os.getpid(), signal.SIGUSR1)
    time.sleep(0.05)
    assert not ks.is_active()


def test_or_composition(tmp_path: Path):
    ks = KillSwitch(sentinel_path=tmp_path / "kill")
    ks.set_config_flag(True)
    ks.arm_http("test")
    ks.set_config_flag(False)  # config off
    assert ks.is_active(), "http source still active should keep ks active"
    ks.disarm_http()
    assert not ks.is_active()


# Integration: addon returns 502 + writes killswitch chain entry when armed
def test_addon_killswitch_blocks_request(tmp_path: Path):
    import json
    import os as _os
    from mitmproxy.test import tflow, taddons
    from waterwall.proxy.addon import WaterwallAddon

    chain_path = tmp_path / "proxy.jsonl"
    addon = WaterwallAddon(chain_path=chain_path, session_key=_os.urandom(32))
    # v2 §4.2: gate on _sse_handlers; seed Anthropic for v1 killswitch path.
    from waterwall.proxy.sse import SseStreamRewriter
    addon._sse_handlers["api.anthropic.com"] = SseStreamRewriter(store=addon._store)
    addon._killswitch.arm_http("test")

    flow = tflow.tflow(req=tflow.treq(
        host="api.anthropic.com", port=443, scheme=b"https",
        method=b"POST", path=b"/v1/messages",
        content=json.dumps({"messages": [{"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}]}).encode(),
    ))
    with taddons.context(addon) as _:
        addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 502
    body = json.loads(flow.response.content)
    assert body["error"] == "waterwall-killswitch-engaged"
    assert "http" in body["sources_active"]

    # Chain log should have killswitch entry
    chain_lines = chain_path.read_text().strip().splitlines()
    types = [json.loads(l).get("line_type") for l in chain_lines]
    assert "killswitch" in types

    # Body should NOT have been redacted (killswitch fired before redaction)
    assert b"AKIAIOSFODNN7EXAMPLE" in flow.request.content


def test_sigusr1_handler_does_not_take_lock():
    """Argus issue #15: signal handlers run on the main thread; taking the
    same non-reentrant lock active_sources() holds deadlocks the proxy.
    The toggle must be a bare GIL-atomic flip."""
    ks = KillSwitch()
    with ks._lock:                      # simulate main thread inside active_sources()
        ks._toggle_sigusr1(None, None)  # must NOT block
    assert ks._sigusr1_latch is True
