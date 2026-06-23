# tests/test_idle_watcher.py
"""Idle watcher fires manifest emit on 30-min idle, and on SIGTERM."""

import time
from waterwall.audit.idle_watcher import IdleWatcher
from waterwall.audit.manifest import SessionTracker


def test_idle_watcher_fires_callback_on_timeout():
    fired: list[str] = []
    watcher = IdleWatcher(
        idle_timeout_seconds=0.1,
        on_idle=lambda sid: fired.append(sid),
    )
    watcher.touch("sess_a")
    time.sleep(0.05)
    watcher.tick()
    assert fired == []
    time.sleep(0.1)
    watcher.tick()
    assert fired == ["sess_a"]


def test_idle_watcher_resets_on_touch():
    fired: list[str] = []
    watcher = IdleWatcher(idle_timeout_seconds=0.1, on_idle=lambda sid: fired.append(sid))
    watcher.touch("sess_a")
    time.sleep(0.05)
    watcher.touch("sess_a")  # reset
    time.sleep(0.06)
    watcher.tick()
    assert fired == []  # not yet — second touch reset the clock


def test_one_failing_callback_does_not_starve_the_rest():
    """Argus issue #17: sids were deleted before callbacks ran; one raise
    lost every remaining session's manifest."""
    seen: list[str] = []

    def cb(sid: str) -> None:
        if sid == "bad":
            raise RuntimeError("boom")
        seen.append(sid)

    watcher = IdleWatcher(idle_timeout_seconds=0.0, on_idle=cb)
    for sid in ("bad", "good-1", "good-2"):
        watcher.touch(sid)
    time.sleep(0.01)
    watcher.tick()
    assert sorted(seen) == ["good-1", "good-2"]
