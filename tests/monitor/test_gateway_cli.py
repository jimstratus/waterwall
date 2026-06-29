"""Tests for the `waterwall monitor-gateway` CLI entrypoint (gateway/__main__.py).

Covers two Kilocode hardening fixes that live in main_cli:
  - d938d5f: refuse to start without gateway.token (return 1, no server)
  - 77e41be: run an initial dead-man's-switch sweep BEFORE the first sleep,
             so a host that went stale while the gateway was down is alerted
             promptly on restart rather than after a full threshold delay.
"""
import importlib
import threading

import pytest

gwmain = importlib.import_module("waterwall.monitor.gateway.__main__")
appmod = importlib.import_module("waterwall.monitor.gateway.app")


def _cfg(tmp_path, monkeypatch, body):
    p = tmp_path / "config.yaml"
    p.write_text(body)
    monkeypatch.setenv("WATERWALL_CONFIG", str(p))


# --- d938d5f: gateway.token is required ---

@pytest.mark.parametrize("body", [
    "gateway:\n  db: ':memory:'\n",   # gateway block present, token missing
    "gateway:\n  token: ''\n",        # explicitly empty token
    "other: {}\n",                    # no gateway block at all
])
def test_gateway_cli_refuses_without_token(tmp_path, monkeypatch, body):
    _cfg(tmp_path, monkeypatch, body)
    # Must return 1 before ever building the app or binding a socket.
    monkeypatch.setattr(appmod, "build_gateway_app",
                        lambda **kw: pytest.fail("app built despite missing token"))
    assert gwmain.main_cli() == 1


# --- 77e41be: initial sweep runs before the gateway starts serving ---

def test_gateway_cli_runs_initial_sweep_before_serving(tmp_path, monkeypatch):
    # threshold = interval * miss_factor = 3600 → the loop's first real time.sleep
    # parks for an hour, so sweep_stale can only be called by the pre-loop initial sweep.
    _cfg(tmp_path, monkeypatch, "gateway:\n  token: t\n  interval: 3600\n  miss_factor: 1\n")

    calls = []
    swept = threading.Event()

    def fake_sweep(*a, **k):
        calls.append(a)
        swept.set()

    def fake_run(app, **kw):
        # uvicorn.run stands in for "now serving" — by the time we'd start the
        # server, the initial sweep must already have happened.
        assert swept.wait(10.0), "initial sweep did not run before serving"

    monkeypatch.setattr(appmod, "build_gateway_app", lambda **kw: object())
    monkeypatch.setattr(appmod, "sweep_stale", fake_sweep)
    monkeypatch.setattr("uvicorn.run", fake_run)

    assert gwmain.main_cli() == 0
    assert len(calls) == 1   # exactly the pre-loop initial sweep
