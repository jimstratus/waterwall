from waterwall.tui.panes.killswitch import render_killswitch


def test_renders_disarmed_state():
    state = {"killswitch": {"config": False, "sigusr1": False, "sentinel": False, "http": False, "active": False}}
    out = render_killswitch(state)
    assert "DISARMED" in out
    assert "passing" in out.lower()
    assert "✗" in out  # disarmed glyph for each source


def test_renders_active_state_with_sources():
    state = {"killswitch": {"config": True, "sigusr1": False, "sentinel": False, "http": True, "active": True}}
    out = render_killswitch(state)
    assert "ARMED" in out
    assert "BLOCKING" in out  # plain-English "you're cut off" message
    assert "config" in out.lower()
    assert "http" in out.lower()


def test_indicates_partial_disarm_when_other_sources_active():
    """Spec issue 11: TUI must surface that disarming via HTTP doesn't clear other sources.
    The pane should show which non-HTTP sources are still asserted."""
    state = {"killswitch": {"config": True, "sigusr1": False, "sentinel": False, "http": False, "active": True}}
    out = render_killswitch(state)
    assert "ARMED" in out
    assert "config" in out.lower()
