from waterwall.monitor.gateway.store import (
    get_fleet,
    get_state,
    open_store,
    record_report,
)


def _rep(host, canary="pass", health="ok", ts=1.0):
    return {"host": host, "canary": canary, "health": health, "version": "v2", "ts": ts}


def test_record_returns_prev_then_upserts():
    conn = open_store(":memory:")
    assert record_report(conn, _rep("vector", ts=1.0)) is None      # first sighting
    prev = record_report(conn, _rep("vector", canary="exposed", ts=2.0))
    assert prev["canary"] == "pass"                                  # previous state
    assert get_state(conn, "vector")["canary"] == "exposed"         # current state


def test_get_state_none_for_unknown_host():
    conn = open_store(":memory:")
    assert get_state(conn, "nope") is None


def test_get_fleet_lists_all_hosts_sorted():
    conn = open_store(":memory:")
    record_report(conn, _rep("vector"))
    record_report(conn, _rep("prod-host"))
    hosts = [r["host"] for r in get_fleet(conn)]
    assert hosts == ["prod-host", "vector"]
