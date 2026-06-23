from waterwall.tui.panes.chain import render_chain


def test_split_cadence_renders_both_hashes():
    """Spec §10.2: chain pane must distinguish Checkpoint root (signed, slow)
    from Live chain head (unsigned, every line). Both rendered with distinct
    labels per spec §13.2 mockup."""
    state = {
        "chain": {"lines": 14201, "checkpoints": 142,
                  "last_signed_ts": "2026-05-05T13:34:00Z",
                  "last_checkpoint_root_hash": "f7e6d5c4b3a2010203040506070809",
                  "current_head_prev_hash":   "9a8b7c6d5e4f0a0b0c0d0e0f0a0b0c0d",
                  "verify_status": "ok"},
    }
    out = render_chain(state)
    assert "Checkpoint root" in out
    assert "Live chain head" in out
    assert "f7e6d5c4" in out
    assert "9a8b7c6d" in out
    assert "f7e6d5c4" != "9a8b7c6d"  # sanity: distinct values rendered
    assert "OK" in out or "●" in out


def test_em_dash_when_no_signed_checkpoint_yet():
    state = {"chain": {"lines": 5, "checkpoints": 0,
                       "last_signed_ts": None,
                       "last_checkpoint_root_hash": "",
                       "current_head_prev_hash": "00aa11bb",
                       "verify_status": "ok"}}
    out = render_chain(state)
    assert "—" in out
