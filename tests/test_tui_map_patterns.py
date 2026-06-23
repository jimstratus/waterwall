from waterwall.tui.panes.map_patterns import render_map_patterns


def test_renders_map_size_and_pattern_breakdown():
    state = {
        "map": {"size": 142, "capacity": 10000, "ttl_seconds": 14400},
        "patterns": {"count": 33, "breakdown": {"base": 16, "ext": 16, "pem": 1},
                     "hash": "a1b2c3d4e5f60011223344556677889900aabbccddeeff",
                     "last_reload_ts": "2026-05-05T13:00:14Z"},
    }
    out = render_map_patterns(state)
    assert "142" in out and "10000" in out
    assert "16" in out and "1" in out  # breakdown numbers
    assert "33" in out                   # total
    assert "a1b2c3d4" in out             # short hash
    assert "13:00:14" in out             # last_reload_ts (time portion)


def test_em_dash_for_missing_field():
    out = render_map_patterns({})
    assert "—" in out
