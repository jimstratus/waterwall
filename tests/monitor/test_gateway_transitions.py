from waterwall.monitor.gateway.transitions import (
    Event,
    detect_stale,
    detect_transitions,
)


def _r(canary="pass", health="ok", ts=1.0):
    return {"host": "vector", "canary": canary, "health": health, "version": "v", "ts": ts}


def test_canary_pass_to_exposed_emits_alert():
    evs = detect_transitions(_r(), _r(canary="exposed"))
    assert any(e.severity == "alert" and "EXPOSED" in e.message for e in evs)


def test_exposed_to_pass_emits_recovery():
    evs = detect_transitions(_r(canary="exposed"), _r(canary="pass"))
    assert any(e.severity == "recovery" for e in evs)


def test_steady_state_no_events():
    assert detect_transitions(_r(), _r()) == []


def test_first_sighting_bad_alerts():
    assert any(e.severity == "alert" for e in detect_transitions(None, _r(canary="exposed")))


def test_first_sighting_good_silent():
    assert detect_transitions(None, _r()) == []


def test_health_down_then_up():
    assert any(e.severity == "alert" for e in detect_transitions(_r(), _r(health="down")))
    assert any(e.severity == "recovery" for e in detect_transitions(_r(health="down"), _r()))


def test_detect_stale_returns_stale_hostnames():
    # detect_stale is now a pure host-name list; the edge lives in sweep_stale.
    fleet = [{"host": "vector", "canary": "pass", "health": "ok", "version": "v", "ts": 100.0}]
    assert detect_stale(fleet, now=200.0, threshold=90.0) == ["vector"]
    assert detect_stale(fleet, now=150.0, threshold=90.0) == []


def test_event_is_frozen_dataclass():
    e = Event("h", "alert", "m")
    assert (e.host, e.severity, e.message) == ("h", "alert", "m")
