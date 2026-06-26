from starlette.testclient import TestClient

from waterwall.monitor.echo import build_echo_app, classify_body

SECRET = "AKIAIOSFODNN7EXAMPLE"


def test_classify_exposed_when_raw_secret_present():
    assert classify_body(b'{"q":"AKIAIOSFODNN7EXAMPLE"}', SECRET) == "exposed"


def test_classify_pass_when_placeholder_present():
    assert classify_body(b'{"q":"<pl:AWS_ACCESS_KEY:d7d27033>"}', SECRET) == "pass"


def test_classify_error_when_neither():
    assert classify_body(b'{"q":"nothing here"}', SECRET) == "error"


def test_exposed_wins_if_both_present():
    # raw secret leaking is exposure even if some other field is tokenized
    assert classify_body(b'AKIAIOSFODNN7EXAMPLE <pl:X:1>', SECRET) == "exposed"


def test_echo_returns_exposed_verdict_for_raw_secret():
    client = TestClient(build_echo_app(SECRET))
    r = client.post("/canary", content=b'{"q":"AKIAIOSFODNN7EXAMPLE"}')
    assert r.status_code == 200
    assert r.json()["verdict"] == "exposed"


def test_echo_returns_pass_verdict_for_placeholder():
    app = build_echo_app(SECRET)
    client = TestClient(app)
    r = client.post("/canary", content=b'<pl:AWS_ACCESS_KEY:abcd1234>')
    assert r.json()["verdict"] == "pass"
    assert app.state.last_verdict == "pass"
