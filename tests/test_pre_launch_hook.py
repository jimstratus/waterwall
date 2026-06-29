# tests/test_pre_launch_hook.py
import json
import sys
import pytest
from waterwall.cli.pre_launch_hook import run


@pytest.fixture(autouse=True)
def _isolate_gate_config(tmp_path, monkeypatch):
    # On edge-host /etc/waterwall/config.yaml exists; default every test to a
    # nonexistent config so the gate is OFF unless a test opts in explicitly.
    monkeypatch.setenv("WATERWALL_CONFIG", str(tmp_path / "absent-config.yaml"))


def test_hook_exits_0_on_healthy(httpx_mock):
    httpx_mock.add_response(
        url="http://127.0.0.1:8889/healthz", status_code=200,
        json={"status": "ok", "killswitch_active": False},
    )
    code = run()
    assert code == 0


def test_hook_exits_nonzero_on_unhealthy(httpx_mock, capsys):
    httpx_mock.add_response(
        url="http://127.0.0.1:8889/healthz", status_code=503,
        json={"status": "fail", "reason": "patterns_loaded < 16"},
    )
    code = run()
    assert code != 0
    captured = capsys.readouterr()
    # spec §11.5 as amended by argus issue #17: SessionStart hooks have no
    # "decision" field — emit hookSpecificOutput.additionalContext instead;
    # the nonzero exit code is the wrapper-enforced block signal.
    parsed = json.loads(captured.out.strip())
    ctx = parsed["hookSpecificOutput"]
    assert ctx["hookEventName"] == "SessionStart"
    assert "patterns_loaded" in ctx["additionalContext"]


def test_hook_exits_nonzero_on_killswitch_active(httpx_mock, capsys):
    httpx_mock.add_response(
        url="http://127.0.0.1:8889/healthz", status_code=200,
        json={"status": "ok", "killswitch_active": True},
    )
    code = run()
    assert code != 0
    # issue #17: block surfaces via additionalContext + exit code, not "decision"
    parsed = json.loads(capsys.readouterr().out.strip())
    assert "kill switch" in parsed["hookSpecificOutput"]["additionalContext"]


@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
def test_hook_exits_nonzero_on_proxy_unreachable(httpx_mock, capsys):
    # No mock added → pytest-httpx raises a "no response" error (subclass of HTTPError)
    code = run()
    assert code != 0
    parsed = json.loads(capsys.readouterr().out.strip())
    assert "proxy unreachable" in parsed["hookSpecificOutput"]["additionalContext"]


def test_block_emits_session_start_additional_context(monkeypatch, capsys):
    """Argus issue #17: SessionStart hooks have no 'decision' field and exit
    codes don't block. The hook's stdout must use additionalContext so the
    operator at least SEES the warning in-session; enforcement lives in the
    waterwall-launch wrapper (which checks the exit code)."""
    import json
    from waterwall.cli.pre_launch_hook import _block
    rc = _block("proxy down")
    assert rc == 1                      # wrapper enforcement contract unchanged
    out = json.loads(capsys.readouterr().out)
    ctx = out["hookSpecificOutput"]
    assert ctx["hookEventName"] == "SessionStart"
    assert "proxy down" in ctx["additionalContext"]


# --- Phase 4: launch hard-gate on canary EXPOSED ---

from waterwall.cli.pre_launch_hook import gate_decision


@pytest.mark.parametrize("on_error", ["warn", "block", "anything"])
def test_gate_decision_exposed_always_blocks(on_error):
    action, reason = gate_decision("exposed", on_error)
    assert action == "block"
    assert "EXPOSED" in reason


@pytest.mark.parametrize("on_error", ["warn", "block", "anything"])
def test_gate_decision_pass_always_allows(on_error):
    assert gate_decision("pass", on_error) == ("allow", None)


def test_gate_decision_error_blocks_when_on_error_block():
    action, reason = gate_decision("error", "block")
    assert action == "block"
    assert "unverifiable" in reason


def test_gate_decision_error_warns_when_on_error_warn():
    action, reason = gate_decision("error", "warn")
    assert action == "warn"
    assert "unverifiable" in reason


def test_gate_decision_error_unknown_policy_fails_open_to_warn():
    # A config typo in on_error must not silently fail closed and strand launches.
    action, _ = gate_decision("error", "blok")
    assert action == "warn"


from waterwall.cli.pre_launch_hook import _load_gate_config


def _write_cfg(tmp_path, monkeypatch, body):
    p = tmp_path / "config.yaml"
    p.write_text(body)
    monkeypatch.setenv("WATERWALL_CONFIG", str(p))
    return p


def test_load_gate_config_none_when_file_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("WATERWALL_CONFIG", str(tmp_path / "nope.yaml"))
    assert _load_gate_config() is None


def test_load_gate_config_none_when_gate_absent(tmp_path, monkeypatch):
    _write_cfg(tmp_path, monkeypatch, "monitor:\n  canary_url: https://c/canary\n")
    assert _load_gate_config() is None


def test_load_gate_config_none_when_gate_disabled(tmp_path, monkeypatch):
    _write_cfg(tmp_path, monkeypatch, "monitor:\n  gate:\n    enabled: false\n")
    assert _load_gate_config() is None


def test_load_gate_config_returns_defaults_when_enabled(tmp_path, monkeypatch):
    _write_cfg(tmp_path, monkeypatch, "monitor:\n  gate:\n    enabled: true\n")
    canary_url, synthetic, client_env, on_error = _load_gate_config()
    assert canary_url == "https://canary.waterwall.local/canary"
    assert synthetic == "AKIAIOSFODNN7EXAMPLE"
    assert client_env == "/etc/waterwall/client.env"
    assert on_error == "warn"


def test_load_gate_config_honors_overrides(tmp_path, monkeypatch):
    _write_cfg(tmp_path, monkeypatch,
               "monitor:\n"
               "  canary_url: https://echo/canary\n"
               "  synthetic: SECRET123\n"
               "  client_env: /tmp/c.env\n"
               "  gate:\n    enabled: true\n    on_error: block\n")
    assert _load_gate_config() == ("https://echo/canary", "SECRET123", "/tmp/c.env", "block")


# --- Phase 4: run() integration (canary gate) ---

import json as _json


def _healthy(httpx_mock):
    httpx_mock.add_response(
        url="http://127.0.0.1:8889/healthz", status_code=200,
        json={"status": "ok", "killswitch_active": False})


def _enable_gate(tmp_path, monkeypatch, on_error="warn"):
    env = tmp_path / "client.env"
    env.write_text("export HTTPS_PROXY=http://127.0.0.1:8888\n")
    p = tmp_path / "config.yaml"
    p.write_text(
        "monitor:\n"
        f"  client_env: {env}\n"
        "  gate:\n    enabled: true\n"
        f"    on_error: {on_error}\n")
    monkeypatch.setenv("WATERWALL_CONFIG", str(p))


def test_run_blocks_when_canary_exposed(httpx_mock, monkeypatch, tmp_path, capsys):
    _healthy(httpx_mock)
    _enable_gate(tmp_path, monkeypatch)
    monkeypatch.setattr("waterwall.cli.pre_launch_hook.run_canary", lambda *a, **k: "exposed")
    assert run() == 1
    ctx = _json.loads(capsys.readouterr().out.strip())["hookSpecificOutput"]
    assert "EXPOSED" in ctx["additionalContext"]


def test_run_allows_when_canary_pass(httpx_mock, monkeypatch, tmp_path):
    _healthy(httpx_mock)
    _enable_gate(tmp_path, monkeypatch)
    monkeypatch.setattr("waterwall.cli.pre_launch_hook.run_canary", lambda *a, **k: "pass")
    assert run() == 0


def test_run_warns_but_allows_on_error_default(httpx_mock, monkeypatch, tmp_path, capsys):
    _healthy(httpx_mock)
    _enable_gate(tmp_path, monkeypatch, on_error="warn")
    monkeypatch.setattr("waterwall.cli.pre_launch_hook.run_canary", lambda *a, **k: "error")
    assert run() == 0
    err = capsys.readouterr().err
    assert "WARN" in err and "unverifiable" in err


def test_run_blocks_on_error_when_fail_closed(httpx_mock, monkeypatch, tmp_path):
    _healthy(httpx_mock)
    _enable_gate(tmp_path, monkeypatch, on_error="block")
    monkeypatch.setattr("waterwall.cli.pre_launch_hook.run_canary", lambda *a, **k: "error")
    assert run() == 1


def test_run_treats_unreadable_client_env_as_error(httpx_mock, monkeypatch, tmp_path):
    # client.env points nowhere -> can't verify the path -> 'error' policy, no crash.
    _healthy(httpx_mock)
    p = tmp_path / "config.yaml"
    p.write_text("monitor:\n  client_env: /no/such/client.env\n"
                 "  gate:\n    enabled: true\n    on_error: block\n")
    monkeypatch.setenv("WATERWALL_CONFIG", str(p))
    monkeypatch.setattr("waterwall.cli.pre_launch_hook.run_canary",
                        lambda *a, **k: pytest.fail("canary ran despite unreadable client.env"))
    assert run() == 1


def test_run_skips_canary_when_gate_disabled(httpx_mock, monkeypatch):
    # The autouse fixture leaves the gate OFF -> run_canary must never be called.
    _healthy(httpx_mock)
    monkeypatch.setattr("waterwall.cli.pre_launch_hook.run_canary",
                        lambda *a, **k: pytest.fail("canary ran while gate disabled"))
    assert run() == 0


def test_load_gate_config_none_on_malformed_yaml(tmp_path, monkeypatch):
    # argus HIGH: unparseable config must DISABLE the gate (the documented
    # fail-safe), not raise and crash the hook on every launch.
    _write_cfg(tmp_path, monkeypatch, "monitor: foo: [1, 2\n  bad")
    assert _load_gate_config() is None


def test_load_gate_config_none_on_non_mapping_top_level(tmp_path, monkeypatch):
    # A bare scalar/list at the top level is not a config mapping -> gate disabled.
    _write_cfg(tmp_path, monkeypatch, "just a bare string\n")
    assert _load_gate_config() is None


def _raise(exc):
    def _f(*a, **k):
        raise exc
    return _f


def test_load_gate_config_coerces_null_client_env_to_default(tmp_path, monkeypatch):
    # kilocode CRITICAL: client_env: null must not pass None through (load_proxy_env(None)
    # -> open(None) -> TypeError, uncaught). A non-string value falls back to the default.
    _write_cfg(tmp_path, monkeypatch,
               "monitor:\n  client_env: null\n  gate:\n    enabled: true\n")
    _, _, client_env, _ = _load_gate_config()
    assert client_env == "/etc/waterwall/client.env"


def test_load_gate_config_coerces_nonstring_values_to_defaults(tmp_path, monkeypatch):
    _write_cfg(tmp_path, monkeypatch,
               "monitor:\n  canary_url: 123\n  synthetic: [1, 2]\n"
               "  client_env: null\n  gate:\n    enabled: true\n    on_error: 5\n")
    assert _load_gate_config() == (
        "https://canary.waterwall.local/canary", "AKIAIOSFODNN7EXAMPLE",
        "/etc/waterwall/client.env", "warn")


def test_run_does_not_crash_when_client_env_read_raises_non_oserror(httpx_mock, monkeypatch, tmp_path):
    # kilocode CRITICAL: a non-OSError from reading client.env (TypeError/ValueError,
    # e.g. a binary file -> UnicodeDecodeError) must be treated as 'error', not crash.
    _healthy(httpx_mock)
    _enable_gate(tmp_path, monkeypatch, on_error="block")
    monkeypatch.setattr("waterwall.cli.pre_launch_hook.load_proxy_env", _raise(ValueError("bad bytes")))
    monkeypatch.setattr("waterwall.cli.pre_launch_hook.run_canary",
                        _raise(AssertionError("canary ran despite client.env read error")))
    assert run() == 1   # error -> block (on_error=block); no crash
