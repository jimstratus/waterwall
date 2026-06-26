from starlette.testclient import TestClient

from waterwall.monitor.gateway.app import build_gateway_app, sweep_stale
from waterwall.monitor.gateway.store import record_report


def _client(sent):
    app = build_gateway_app(db_path=":memory:", token="t0ken", discord_webhook="https://d",
                            notifier=lambda url, ev: sent.append(ev) or True)
    return app, TestClient(app)


def _rep(canary="pass", health="ok", ts=1.0):
    return {"host": "vector", "canary": canary, "health": health, "version": "v", "ts": ts}


def test_report_requires_bearer():
    _, c = _client([])
    assert c.post("/api/report", json=_rep()).status_code == 401
    assert c.post("/api/report", json=_rep(),
                  headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_report_stored_and_transition_notified():
    sent = []
    _, c = _client(sent)
    h = {"Authorization": "Bearer t0ken"}
    assert c.post("/api/report", json=_rep(canary="pass", ts=1.0), headers=h).status_code == 200
    assert sent == []                                            # good first sighting: silent
    c.post("/api/report", json=_rep(canary="exposed", ts=2.0), headers=h)
    assert any(e.severity == "alert" for e in sent)             # transition alert fired
    fleet = c.get("/api/fleet", headers=h).json()["fleet"]
    assert fleet[0]["host"] == "vector" and fleet[0]["canary"] == "exposed"


def test_fleet_requires_bearer():
    _, c = _client([])
    assert c.get("/api/fleet").status_code == 401
    assert c.get("/api/fleet", headers={"Authorization": "Bearer t0ken"}).status_code == 200


def test_sweep_stale_edge_triggered_and_recovers():
    sent = []
    app, _ = _client(sent)
    record_report(app.state.conn,
                  {"host": "h", "canary": "pass", "health": "ok", "version": "v", "ts": 100.0})
    # 1) host crosses into stale -> exactly one alert
    evs1 = sweep_stale(app, now=300.0, threshold=90.0, webhook="https://d")
    assert [e.severity for e in evs1] == ["alert"]
    assert "dead man" in evs1[0].message.lower()
    # 2) still stale -> no re-alert (edge-triggered, not per-sweep)
    assert sweep_stale(app, now=400.0, threshold=90.0, webhook="https://d") == []
    # 3) host reports fresh again -> recovery emitted once
    record_report(app.state.conn,
                  {"host": "h", "canary": "pass", "health": "ok", "version": "v", "ts": 500.0})
    evs3 = sweep_stale(app, now=505.0, threshold=90.0, webhook="https://d")
    assert [e.severity for e in evs3] == ["recovery"]
    assert [e.severity for e in sent] == ["alert", "recovery"]
