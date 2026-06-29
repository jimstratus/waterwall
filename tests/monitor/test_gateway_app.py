from starlette.testclient import TestClient

from waterwall.monitor.gateway.app import build_gateway_app, sweep_stale
from waterwall.monitor.gateway.store import record_report


def _client(sent, **kw):
    app = build_gateway_app(db_path=":memory:", token="t0ken", discord_webhook="https://d",
                            notifier=lambda url, ev: sent.append(ev) or True, **kw)
    return app, TestClient(app)


def _rep(canary="pass", health="ok", ts=1.0):
    return {"host": "edge-host", "canary": canary, "health": health, "version": "v", "ts": ts}


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
    assert fleet[0]["host"] == "edge-host" and fleet[0]["canary"] == "exposed"


def test_fleet_requires_bearer():
    _, c = _client([])
    assert c.get("/api/fleet").status_code == 401
    assert c.get("/api/fleet", headers={"Authorization": "Bearer t0ken"}).status_code == 200


# --- Kilocode fix: return 400 (not 500) on malformed/incomplete reports (9c79a3d) ---

def test_report_400_on_non_json_body():
    sent = []
    _, c = _client(sent)
    h = {"Authorization": "Bearer t0ken", "Content-Type": "application/json"}
    r = c.post("/api/report", content="not json at all", headers=h)
    assert r.status_code == 400
    assert sent == []                       # nothing recorded, no alert fired


def test_report_400_on_missing_keys():
    # An authed but incomplete payload (missing host/canary/...) must be a clean 400,
    # not an unhandled KeyError surfacing as a 500.
    sent = []
    _, c = _client(sent)
    h = {"Authorization": "Bearer t0ken"}
    assert c.post("/api/report", json={"host": "edge-host"}, headers=h).status_code == 400
    assert sent == []


def test_report_malformed_still_requires_auth_first():
    # Auth is checked before the body is parsed: a bad body without a token is 401, not 400.
    _, c = _client([])
    assert c.post("/api/report", content="garbage").status_code == 401


# --- Kilocode fix: expose stale_seconds from the fleet API for the dashboard (8b3bc31) ---

def test_fleet_exposes_default_stale_seconds():
    import inspect
    default = inspect.signature(build_gateway_app).parameters["stale_seconds"].default
    _, c = _client([])
    body = c.get("/api/fleet", headers={"Authorization": "Bearer t0ken"}).json()
    assert body["stale_seconds"] == default   # tracks the build default, not a literal


def test_fleet_exposes_configured_stale_seconds():
    _, c = _client([], stale_seconds=270.0)
    body = c.get("/api/fleet", headers={"Authorization": "Bearer t0ken"}).json()
    assert body["stale_seconds"] == 270.0


# --- Kilocode fix: reload persisted stale_hosts on startup (878f504) ---

def test_stale_hosts_reloaded_from_db_on_restart(tmp_path):
    sent = []
    db = str(tmp_path / "monitor.db")
    notifier = lambda url, ev: sent.append(ev) or True
    # First gateway: a host goes stale and is persisted as alerted.
    app1 = build_gateway_app(db_path=db, token="t", notifier=notifier)
    record_report(app1.state.conn,
                  {"host": "h", "canary": "pass", "health": "ok", "version": "v", "ts": 100.0})
    assert [e.severity for e in sweep_stale(app1, now=300.0, threshold=90.0)] == ["alert"]
    # Restart: a fresh app on the same DB must reload the alerted-stale set...
    app2 = build_gateway_app(db_path=db, token="t", notifier=notifier)
    assert app2.state.stale_hosts == {"h"}
    # ...so the next sweep does NOT re-alert the still-stale host.
    assert sweep_stale(app2, now=400.0, threshold=90.0) == []


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
