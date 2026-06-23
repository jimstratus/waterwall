from waterwall.tui.panes.counters import render_counters


def test_renders_redactions_per_min_and_top_types():
    state = {
        "counters_5m": {
            "redactions_per_min": 12,
            "top_types": [
                {"type": "AWS_ACCESS_KEY", "count": 8},
                {"type": "ANTHROPIC_KEY", "count": 3},
            ],
            "latency_p50_ms": 4,
            "latency_p99_ms": 21,
            "unknown_placeholders": 0,
        },
    }
    out = render_counters(state)
    assert "12" in out
    assert "AWS_ACCESS_KEY" in out
    assert "8" in out
    assert "p50" in out
    assert "p99" in out
    assert "21" in out


def test_em_dash_when_no_top_types():
    out = render_counters({"counters_5m": {"redactions_per_min": 0, "top_types": []}})
    assert "—" in out
