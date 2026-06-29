from waterwall.monitor.gateway.store import (
    get_fleet,
    get_stale_alerted,
    get_state,
    open_store,
    record_report,
    set_stale_alerted,
)


def _rep(host, canary="pass", health="ok", ts=1.0):
    return {"host": host, "canary": canary, "health": health, "version": "v2", "ts": ts}


def test_record_returns_prev_then_upserts():
    conn = open_store(":memory:")
    assert record_report(conn, _rep("edge-host", ts=1.0)) is None      # first sighting
    prev = record_report(conn, _rep("edge-host", canary="exposed", ts=2.0))
    assert prev["canary"] == "pass"                                  # previous state
    assert get_state(conn, "edge-host")["canary"] == "exposed"         # current state


def test_get_state_none_for_unknown_host():
    conn = open_store(":memory:")
    assert get_state(conn, "nope") is None


def test_get_fleet_lists_all_hosts_sorted():
    conn = open_store(":memory:")
    record_report(conn, _rep("edge-host"))
    record_report(conn, _rep("prod-host-control"))
    hosts = [r["host"] for r in get_fleet(conn)]
    assert hosts == ["edge-host", "prod-host-control"]


# --- Kilocode fix: persist the alerted-stale set across restarts (878f504) ---

def test_stale_alerted_empty_by_default():
    conn = open_store(":memory:")
    assert get_stale_alerted(conn) == set()


def test_set_and_get_stale_alerted_roundtrip():
    conn = open_store(":memory:")
    set_stale_alerted(conn, {"edge-host", "prod-host-control"})
    assert get_stale_alerted(conn) == {"edge-host", "prod-host-control"}


def test_set_stale_alerted_replaces_whole_set_atomically():
    # set_stale_alerted is a full replace (DELETE then re-insert), not a merge:
    # a host that recovered must drop out of the persisted set, not linger.
    conn = open_store(":memory:")
    set_stale_alerted(conn, {"a", "b"})
    set_stale_alerted(conn, {"b", "c"})
    assert get_stale_alerted(conn) == {"b", "c"}


def test_set_stale_alerted_empty_clears():
    conn = open_store(":memory:")
    set_stale_alerted(conn, {"a"})
    set_stale_alerted(conn, set())
    assert get_stale_alerted(conn) == set()


def test_stale_alerted_persists_across_reopen(tmp_path):
    # The whole point of the fix: a fresh connection to the same DB file (a gateway
    # restart) sees the previously-persisted stale set — so no spurious re-alert.
    db = str(tmp_path / "monitor.db")
    set_stale_alerted(open_store(db), {"edge-host"})
    assert get_stale_alerted(open_store(db)) == {"edge-host"}
