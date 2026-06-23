from waterwall.tui.modals.verify_install_modal import render_check_table


def test_render_check_table_all_pass():
    payload = {
        "ok": True,
        "checks": [
            {"name": "ca_file", "ok": True, "detail": ""},
            {"name": "signing_key", "ok": True, "detail": ""},
        ],
    }
    out = render_check_table(payload)
    assert "ca_file" in out
    assert "10/10" in out or "2/2" in out
    assert "PASS" in out or "✓" in out


def test_render_check_table_with_failures():
    payload = {
        "ok": False,
        "checks": [
            {"name": "ca_file", "ok": True},
            {"name": "signing_key", "ok": False, "detail": "mode 0644 != 0o400"},
        ],
    }
    out = render_check_table(payload)
    assert "FAIL" in out or "✗" in out
    assert "mode 0644" in out


def test_render_check_table_surfaces_error_payload():
    """Argus issue #16: {ok:false, error:...} rendered as '0/0 passing'."""
    out = render_check_table({"ok": False, "error": "proxy unreachable at :8889"})
    assert "proxy unreachable" in out
    assert "0/0" not in out
