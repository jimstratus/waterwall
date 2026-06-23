"""Activity pane snapshot — render given state and assert key fields appear."""

from waterwall.tui.panes.activity import render_activity


def test_activity_renders_recent_redactions():
    state = {
        "ts": "2026-05-05T13:35:00.000Z",
        "recent_activity": [
            {"ts": "13:35:00", "direction": "out", "request_id": "req_abc",
             "redactions": 3, "types": ["AWS_ACCESS_KEY", "ANTHROPIC_KEY", "JWT_TOKEN"]},
            {"ts": "13:35:01", "direction": "in",  "request_id": "req_abc",
             "detok_count": 0},
        ],
    }
    out = render_activity(state)
    assert "13:35:00" in out
    assert "OUT" in out
    assert "req_abc" in out
    assert "AWS_ACCESS_KEY" in out


def test_activity_handles_missing_field():
    state = {"ts": "2026-05-05T13:35:00.000Z"}  # no recent_activity key
    out = render_activity(state)
    assert "—" in out or "no activity" in out.lower()
