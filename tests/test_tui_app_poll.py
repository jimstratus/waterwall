"""Argus issue #16: offline flag must clear only after panels actually cleared."""


def test_offline_flag_only_clears_after_panel_classes_cleared():
    """offline was set False even when NoMatches aborted the class-removal,
    leaving all panels red forever after a modal closed."""
    from waterwall.tui.app import WaterwallTUI
    assert WaterwallTUI._should_clear_offline(panels_cleared=True) is True
    assert WaterwallTUI._should_clear_offline(panels_cleared=False) is False
