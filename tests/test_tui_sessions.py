from waterwall.tui.panes.sessions import render_sessions


def test_renders_active_sessions_with_uptime():
    state = {
        "ts": "2026-05-05T13:35:00Z",
        "sessions": [
            {"session_id": "sess_xyz", "redactions": 142, "started_ts": "2026-05-05T09:27:00Z"},
            {"session_id": "sess_pqr", "redactions": 23,  "started_ts": "2026-05-05T12:48:00Z"},
        ],
    }
    out = render_sessions(state)
    assert "sess_xyz" in out
    assert "142" in out
    assert "4h" in out and "8m" in out  # 13:35 - 09:27 = 4h 8m
    assert "sess_pqr" in out
    assert "47m" in out                    # 13:35 - 12:48 = 47m


def test_no_sessions_renders_em_dash():
    out = render_sessions({"sessions": []})
    assert "—" in out
