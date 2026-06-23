# tests/test_pre_launch_hook.py
import json
import sys
import pytest
from waterwall.cli.pre_launch_hook import run


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
