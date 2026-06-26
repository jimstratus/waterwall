import httpx

from waterwall.monitor.canary import run_canary

SECRET = "AKIAIOSFODNN7EXAMPLE"
URL = "https://canary.waterwall.local/canary"


def _transport(verdict):
    def handler(request: httpx.Request) -> httpx.Response:
        assert SECRET.encode() in request.content  # client really sends the secret
        return httpx.Response(200, json={"verdict": verdict})
    return httpx.MockTransport(handler)


def test_run_canary_returns_pass():
    assert run_canary(URL, SECRET, transport=_transport("pass")) == "pass"


def test_run_canary_returns_exposed():
    assert run_canary(URL, SECRET, transport=_transport("exposed")) == "exposed"


def test_run_canary_error_on_transport_failure():
    def boom(request):
        raise httpx.ConnectError("refused")
    assert run_canary(URL, SECRET, transport=httpx.MockTransport(boom)) == "error"


def test_run_canary_error_on_missing_verdict():
    def no_verdict(request):
        return httpx.Response(200, json={})
    assert run_canary(URL, SECRET, transport=httpx.MockTransport(no_verdict)) == "error"
