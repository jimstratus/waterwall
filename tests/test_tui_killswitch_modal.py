"""When the user disarms via HTTP but other sources remain active, the modal
must clearly say so."""

from waterwall.tui.modals.killswitch_modal import build_disarm_message


def test_disarm_message_clean():
    """No other sources active → simple confirmation."""
    msg = build_disarm_message(remaining_sources=[])
    assert "disarmed" in msg.lower()
    assert "still active" not in msg.lower()


def test_disarm_message_with_remaining_sources():
    """Other sources still active → modal must list them."""
    msg = build_disarm_message(remaining_sources=["sigusr1", "config"])
    assert "still active" in msg.lower()
    assert "sigusr1" in msg
    assert "config" in msg


def test_arm_message_reflects_non_2xx():
    """Argus issue #15: arm ignored HTTP status; claiming armed-when-not is
    the worst-case message for an emergency stop."""
    from waterwall.tui.modals.killswitch_modal import build_arm_message
    assert "FAILED" in build_arm_message(500)
    assert "armed" in build_arm_message(200).lower()


def test_disarm_message_includes_stuck_http_source():
    """Argus issue #15: the disarm worker excluded the http source from the
    remaining-sources check, so a stuck http arm was invisible."""
    msg = build_disarm_message(remaining_sources=["http"])
    assert "http" in msg
