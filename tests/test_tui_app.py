import pytest
from textual.widgets import Static

from waterwall.tui.app import WaterwallTUI
from waterwall.tui.state_client import StateClient, StateUnavailable


class _FakeClient(StateClient):
    def __init__(self, state):
        self._state = state

    def fetch(self):
        return self._state


def _full_minimal_state() -> dict:
    """Minimal state shape the renderers ALL accept without KeyError."""
    return {
        "v": 1, "status": "ok", "uptime_seconds": 1,
        "ts": "2026-05-05T13:35:00.000Z",
        "killswitch": {"config": False, "sigusr1": False, "sentinel": False, "http": False, "active": False},
        "patterns": {"count": 33, "breakdown": {"base": 16, "ext": 16, "pem": 1}, "hash": "abc", "last_reload_ts": "13:00"},
        "map": {"size": 1, "capacity": 10000, "ttl_seconds": 14400},
        "chain": {"lines": 1, "checkpoints": 0, "last_signed_ts": None,
                  "last_checkpoint_root_hash": "", "current_head_prev_hash": "00",
                  "verify_status": "ok"},
        "counters_5m": {"redactions_per_min": 0, "top_types": [], "latency_p50_ms": 0, "latency_p99_ms": 0, "unknown_placeholders": 0},
        "sessions": [],
        "recent_activity": [],
    }


@pytest.mark.asyncio
async def test_app_renders_initial_state():
    fake = _FakeClient({
        "v": 1, "ts": "2026-05-05T13:35:00.000Z", "status": "ok",
        "uptime_seconds": 100,
        "killswitch": {"config": False, "sigusr1": False, "sentinel": False, "http": False, "active": False},
        "patterns": {"count": 33, "breakdown": {"base": 16, "ext": 16, "pem": 1}, "hash": "abc", "last_reload_ts": "13:00:00"},
        "map": {"size": 142, "capacity": 10000, "ttl_seconds": 14400},
        "chain": {"lines": 14201, "checkpoints": 142, "last_signed_ts": "13:34:00",
                  "last_checkpoint_root_hash": "f7e6", "current_head_prev_hash": "9a8b", "verify_status": "ok"},
        "counters_5m": {"redactions_per_min": 24, "top_types": [], "latency_p50_ms": 14, "latency_p99_ms": 87, "unknown_placeholders": 0},
        "sessions": [],
        "recent_activity": [],
    })
    app = WaterwallTUI(state_client=fake)
    async with app.run_test() as pilot:
        await pilot.pause()
        offline_banner = app.query_one("#offline-banner", Static)
        assert str(offline_banner.renderable).strip() == ""
        status = app.query_one("#status-indicator", Static)
        assert "UP" in str(status.renderable)


@pytest.mark.asyncio
async def test_app_flips_panels_red_when_offline():
    class _OfflineClient(StateClient):
        def fetch(self):
            raise StateUnavailable("test offline")

    app = WaterwallTUI(state_client=_OfflineClient())
    async with app.run_test() as pilot:
        await pilot.pause()
        for pid in WaterwallTUI.PANEL_IDS:
            assert app.query_one(pid, Static).has_class("status-fail"), \
                f"{pid} must have status-fail class when /admin/state unreachable"
        banner = app.query_one("#offline-banner", Static)
        assert "PROXY OFFLINE" in str(banner.renderable)


@pytest.mark.asyncio
async def test_app_displays_hostname_chip():
    fake = _FakeClient(_full_minimal_state())
    app = WaterwallTUI(state_client=fake, hostname="prod-host.lan.example.com")
    async with app.run_test() as pilot:
        await pilot.pause()
        chip = app.query_one("#hostname", Static)
        # FQDN is collapsed to short name and uppercased for prominence.
        assert "PROD-HOST" in str(chip.renderable)
        assert "lan.example.com" not in str(chip.renderable)
        assert chip.has_class("hostname-chip")


@pytest.mark.asyncio
async def test_hostname_stays_lit_when_proxy_offline():
    class _OfflineClient(StateClient):
        def fetch(self):
            raise StateUnavailable("test offline")

    app = WaterwallTUI(state_client=_OfflineClient(), hostname="test-host")
    async with app.run_test() as pilot:
        await pilot.pause()
        chip = app.query_one("#hostname", Static)
        # The hostname identifies the box, not the proxy — it must NOT flip
        # to status-fail when /admin/state is unreachable.
        assert not chip.has_class("status-fail")
        assert chip.has_class("hostname-chip")
        assert "TEST-HOST" in str(chip.renderable)
        # Pin the full class set: protects against a future refactor that
        # paints the whole header strip (e.g. `query("#header-strip Static")
        # .add_class("status-fail")`) — the negative assertion above wouldn't
        # catch a benign-looking class added alongside hostname-chip.
        assert set(chip.classes) == {"hostname-chip"}


@pytest.mark.asyncio
async def test_hostname_chip_resolves_from_socket():
    """Exercises the socket.gethostname() branch (the constructor's default
    path, not the hostname= override). Without this, a refactor that broke
    the .split(".")[0] FQDN-strip or dropped the `or "UNKNOWN"` fallback
    would not trip the suite."""
    fake = _FakeClient(_full_minimal_state())
    app = WaterwallTUI(state_client=fake)  # no hostname= override
    async with app.run_test() as pilot:
        await pilot.pause()
        chip = app.query_one("#hostname", Static)
        rendered = str(chip.renderable)
        assert "⌂" in rendered
        assert rendered == rendered.upper()   # .upper() chain wired
        assert "." not in rendered            # FQDN suffix stripped


@pytest.mark.asyncio
async def test_app_quits_on_q():
    fake = _FakeClient(_full_minimal_state())
    app = WaterwallTUI(state_client=fake)
    async with app.run_test() as pilot:
        await pilot.press("q")
        await pilot.pause()
    # If we exit cleanly the test passes; pilot.pause() after q ensures exit ran
