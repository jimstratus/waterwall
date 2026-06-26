import httpx

from waterwall.monitor.health import load_proxy_env, read_health
from waterwall.monitor.reporter import build_report


def _t(status_code, payload=None):
    return httpx.MockTransport(lambda req: httpx.Response(status_code, json=payload or {}))


def test_health_ok():
    assert read_health("http://x/healthz", transport=_t(200, {"status": "ok"})) == "ok"


def test_health_degraded():
    assert read_health("http://x/healthz", transport=_t(200, {"status": "degraded"})) == "degraded"


def test_health_down_on_503():
    assert read_health("http://x/healthz", transport=_t(503, {"status": "fail"})) == "down"


def test_health_down_on_unreachable():
    def boom(req):
        raise httpx.ConnectError("refused")
    assert read_health("http://x/healthz", transport=httpx.MockTransport(boom)) == "down"


def test_load_proxy_env(tmp_path):
    p = tmp_path / "client.env"
    p.write_text("# comment\nexport HTTPS_PROXY=http://127.0.0.1:8888\n"
                 "NODE_EXTRA_CA_CERTS=/etc/waterwall/ca.pem\n")
    env = load_proxy_env(str(p))
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:8888"
    assert env["NODE_EXTRA_CA_CERTS"] == "/etc/waterwall/ca.pem"


def test_build_report_shape():
    r = build_report("vector", "pass", "ok", "v2", 1000.0)
    assert r == {"host": "vector", "canary": "pass", "health": "ok",
                 "version": "v2", "ts": 1000.0}


def test_report_once_posts_bearer_payload():
    import waterwall.monitor.reporter as rep
    sent = {}

    def fake_post(url, json, headers):
        sent["url"] = url
        sent["json"] = json
        sent["headers"] = headers
        return True

    cfg = {"host": "vector", "version": "v2",
           "gateway_url": "https://gw/api/report", "token": "secret-token",
           "canary_url": "https://canary.waterwall.local/canary",
           "healthz_url": "http://127.0.0.1:8889/healthz",
           "synthetic": "AKIAIOSFODNN7EXAMPLE", "proxy": None, "ca_path": None}
    rep.run_canary = lambda *a, **k: "pass"
    rep.read_health = lambda *a, **k: "ok"
    out = rep.report_once(cfg, post=fake_post, clock=lambda: 1234.0)
    assert out["canary"] == "pass" and out["health"] == "ok" and out["ts"] == 1234.0
    assert sent["url"] == "https://gw/api/report"
    assert sent["headers"]["Authorization"] == "Bearer secret-token"
    assert sent["json"]["host"] == "vector"


def test_report_once_returns_none_when_post_fails():
    import waterwall.monitor.reporter as rep
    rep.run_canary = lambda *a, **k: "exposed"
    rep.read_health = lambda *a, **k: "ok"
    cfg = {"host": "h", "version": "v", "gateway_url": "u", "token": "t",
           "canary_url": "c", "healthz_url": "z", "synthetic": "s", "proxy": None, "ca_path": None}
    assert rep.report_once(cfg, post=lambda *a, **k: False, clock=lambda: 1.0) is None


def test_report_once_rereads_client_env_each_cycle(tmp_path):
    # Argus #1 (HIGH): the reporter must re-read client.env every cycle so post-startup
    # proxy drift is reflected in the canary path — not snapshotted once at startup.
    import waterwall.monitor.reporter as rep
    captured = []
    rep.run_canary = lambda url, syn, **k: (captured.append(k.get("proxy")) or "pass")
    rep.read_health = lambda *a, **k: "ok"
    envf = tmp_path / "client.env"
    cfg = {"host": "h", "version": "v", "gateway_url": "u", "token": "t",
           "canary_url": "c", "healthz_url": "z", "synthetic": "s", "client_env": str(envf)}
    envf.write_text("export HTTPS_PROXY=http://A\n")
    rep.report_once(cfg, post=lambda *a, **k: True, clock=lambda: 1.0)
    envf.write_text("export HTTPS_PROXY=http://B\n")   # drift after the first cycle
    rep.report_once(cfg, post=lambda *a, **k: True, clock=lambda: 1.0)
    assert captured == ["http://A", "http://B"]        # re-read each cycle, not cached


def test_report_once_unreadable_client_env_yields_error_not_crash(tmp_path):
    # Argus v2 #1 (HIGH): a missing/unreadable client.env must NOT crash the loop —
    # it can't determine the path, so the canary is 'error' and the heartbeat continues.
    import waterwall.monitor.reporter as rep
    rep.read_health = lambda *a, **k: "ok"
    called = []
    rep.run_canary = lambda *a, **k: called.append(1) or "pass"
    cfg = {"host": "h", "version": "v", "gateway_url": "u", "token": "t",
           "canary_url": "c", "healthz_url": "z", "synthetic": "s",
           "client_env": str(tmp_path / "does-not-exist.env")}
    out = rep.report_once(cfg, post=lambda *a, **k: True, clock=lambda: 1.0)
    assert out["canary"] == "error"   # can't verify the path
    assert called == []               # canary skipped, no false EXPOSED
