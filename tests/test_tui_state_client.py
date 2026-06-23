# tests/test_tui_state_client.py
import pytest
from waterwall.tui.state_client import StateClient, StateUnavailable


def test_state_client_returns_dict_on_success(httpx_mock):
    httpx_mock.add_response(
        url="http://127.0.0.1:8889/admin/state",
        json={"v": 1, "status": "ok", "uptime_seconds": 100},
    )
    client = StateClient(base_url="http://127.0.0.1:8889")
    state = client.fetch()
    assert state["v"] == 1
    assert state["status"] == "ok"


@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
def test_state_client_raises_when_proxy_offline(httpx_mock):
    """No mock added → connection refused → StateUnavailable."""
    client = StateClient(base_url="http://127.0.0.1:8889")
    with pytest.raises(StateUnavailable):
        client.fetch()


def test_state_client_raises_when_500(httpx_mock):
    httpx_mock.add_response(
        url="http://127.0.0.1:8889/admin/state", status_code=500,
    )
    client = StateClient(base_url="http://127.0.0.1:8889")
    with pytest.raises(StateUnavailable):
        client.fetch()


def test_state_client_rejects_non_dict_json(httpx_mock):
    """Argus issue #16: a non-dict JSON body must raise StateUnavailable,
    not propagate into the TUI poll loop."""
    httpx_mock.add_response(
        url="http://127.0.0.1:8889/admin/state", json=[1, 2, 3],
    )
    client = StateClient(base_url="http://127.0.0.1:8889")
    with pytest.raises(StateUnavailable, match="non-object"):
        client.fetch()
