# tests/test_admin.py
import tempfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from waterwall.ops.admin import build_admin_app


@pytest.fixture
def client():
    # Use a stub state-provider: returns canned /admin/state JSON.
    state = {
        "v": 1, "ts": "2026-05-05T13:35:00.000Z", "status": "ok",
        "uptime_seconds": 100,
        "killswitch": {"config": False, "sigusr1": False, "sentinel": False, "http": False, "active": False},
    }
    arm_calls = []
    reload_calls = []
    app = build_admin_app(
        state_provider=lambda: state,
        killswitch_arm=lambda reason: arm_calls.append(reason),
        killswitch_disarm=lambda: arm_calls.append("disarm"),
        reload_patterns=lambda: reload_calls.append("reload"),
    )
    return TestClient(app), state, arm_calls, reload_calls


def test_healthz_returns_200(client):
    c, _, _, _ = client
    r = c.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"


def test_healthz_returns_503_when_status_not_ok():
    """Spec §10.1: /healthz returns 503 when state.status != 'ok'."""
    fail_state = {"status": "fail", "reason": "patterns_loaded < 16"}
    app = build_admin_app(
        state_provider=lambda: fail_state,
        killswitch_arm=lambda reason: None,
        killswitch_disarm=lambda: None,
        reload_patterns=lambda: None,
    )
    r = TestClient(app).get("/healthz")
    assert r.status_code == 503
    assert r.json() == fail_state


def test_admin_state_returns_full_schema(client):
    c, state, _, _ = client
    r = c.get("/admin/state")
    assert r.status_code == 200
    assert r.json() == state


def test_admin_killswitch_arm(client):
    c, _, arm_calls, _ = client
    r = c.post("/admin/killswitch", json={"action": "arm", "reason": "operator"})
    assert r.status_code == 200
    assert arm_calls == ["operator"]


def test_admin_killswitch_disarm(client):
    c, _, arm_calls, _ = client
    r = c.post("/admin/killswitch", json={"action": "disarm"})
    assert r.status_code == 200
    assert arm_calls == ["disarm"]


def test_admin_killswitch_unknown_action(client):
    c, _, _, _ = client
    r = c.post("/admin/killswitch", json={"action": "explode"})
    assert r.status_code == 400
    assert "error" in r.json()


def test_admin_reload_calls_callback(client):
    c, _, _, reload_calls = client
    r = c.post("/admin/reload")
    assert r.status_code == 200
    assert reload_calls == ["reload"]


def test_admin_reload_500s_when_reload_refused():
    """Argus issue #10: a refused reload (parse error) must surface as 500,
    not 200 {"status": "reloaded"}."""
    def failing_reload():
        raise RuntimeError("PATTERNS parse error: bad regex")
    app = build_admin_app(
        state_provider=lambda: {"status": "ok"},
        killswitch_arm=lambda reason: None,
        killswitch_disarm=lambda: None,
        reload_patterns=failing_reload,
    )
    r = TestClient(app).post("/admin/reload")
    assert r.status_code == 500
    assert "parse error" in r.json()["error"]


def test_admin_reload_500s_when_loader_absent():
    def no_loader():
        raise RuntimeError("pattern hot-reload not enabled (no loader)")
    app = build_admin_app(
        state_provider=lambda: {"status": "ok"},
        killswitch_arm=lambda reason: None,
        killswitch_disarm=lambda: None,
        reload_patterns=no_loader,
    )
    assert TestClient(app).post("/admin/reload").status_code == 500


# ---------------------------------------------------------------- CORS --

def _stub_state() -> dict:
    return {"status": "ok", "killswitch": {
        "config": False, "sigusr1": False, "sentinel": False, "http": False, "active": False,
    }}


def _stub_app(**kw):
    return build_admin_app(
        state_provider=_stub_state,
        killswitch_arm=lambda r: None,
        killswitch_disarm=lambda: None,
        reload_patterns=lambda: None,
        **kw,
    )


def test_admin_no_cors_headers_by_default():
    """Default has no CORS middleware (safe loopback-only default)."""
    c = TestClient(_stub_app())
    r = c.get("/admin/state", headers={"Origin": "http://anywhere.example"})
    assert "access-control-allow-origin" not in r.headers


def test_admin_cors_specific_origin_matches():
    c = TestClient(_stub_app(cors_origins=["http://kiosk.lan"]))
    r = c.get("/admin/state", headers={"Origin": "http://kiosk.lan"})
    assert r.headers.get("access-control-allow-origin") == "http://kiosk.lan"


def test_admin_cors_specific_origin_does_not_match():
    c = TestClient(_stub_app(cors_origins=["http://kiosk.lan"]))
    r = c.get("/admin/state", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_admin_cors_wildcard_matches_any():
    c = TestClient(_stub_app(cors_origins=["*"]))
    r = c.get("/admin/state", headers={"Origin": "http://anywhere.example"})
    assert r.headers.get("access-control-allow-origin") == "*"


def test_admin_cors_preflight_returns_200():
    c = TestClient(_stub_app(cors_origins=["http://kiosk.lan"]))
    r = c.options(
        "/admin/state",
        headers={
            "Origin": "http://kiosk.lan",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "http://kiosk.lan"
    assert "GET" in r.headers.get("access-control-allow-methods", "")


# ------------------------------------------------------ static mount --

def test_admin_static_dir_default_uses_shipped_webgui():
    """The shipped webgui/ lives at src/waterwall/webgui/. When the
    package is editable-installed the default static_dir must resolve
    to it; a fresh build_admin_app() should serve / and /app.js."""
    c = TestClient(_stub_app())
    r = c.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    assert "WATERWALL" in r.text or "reversible egress firewall" in r.text
    assert c.get("/app.js").status_code == 200
    assert c.get("/styles.css").status_code == 200


def test_admin_static_dir_explicit_real_dir(tmp_path):
    page = tmp_path / "index.html"
    page.write_text("<html>EXPLICIT</html>")
    c = TestClient(_stub_app(static_dir=tmp_path))
    assert c.get("/").text == "<html>EXPLICIT</html>"


def test_admin_static_dir_explicit_bogus_path_does_not_crash(caplog):
    """If the caller passes a path that doesn't exist, the admin server
    must still work in JSON-only mode (no static mount) — and log a
    warning so the misconfiguration is visible."""
    with caplog.at_level("WARNING", logger="waterwall.ops.admin"):
        # Activate caplog BEFORE constructing the app — the warning
        # is emitted at startup, not on request.
        c = TestClient(_stub_app(static_dir="/nonexistent/never-here"))
        r = c.get("/")
    assert r.status_code == 404
    # API endpoints still work
    assert c.get("/healthz").status_code == 200
    assert c.get("/admin/state").status_code == 200
    # Warning was logged
    assert any("static_dir" in rec.message for rec in caplog.records)


def test_admin_static_dir_explicit_file_not_dir_does_not_crash(caplog, tmp_path):
    not_a_dir = tmp_path / "i-am-a-file.txt"
    not_a_dir.write_text("not a directory")
    with caplog.at_level("WARNING", logger="waterwall.ops.admin"):
        c = TestClient(_stub_app(static_dir=not_a_dir))
        r = c.get("/")
    assert r.status_code == 404
    assert c.get("/healthz").status_code == 200
    assert any("static_dir" in rec.message for rec in caplog.records)


def test_admin_api_routes_take_precedence_over_static():
    """Explicit API routes (e.g. /admin/state) must be matched first;
    the StaticFiles mount at / should not shadow them."""
    c = TestClient(_stub_app())
    r = c.get("/admin/state")
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("application/json")
    # And /admin/state never returns an HTML index
    assert "<html" not in r.text.lower()


def test_admin_static_mount_blocks_non_page_assets():
    """Test files, README, and other non-page assets in the webgui
    directory must NOT be served through the static mount. Only
    index.html, app.js, and styles.css are web-accessible."""
    c = TestClient(_stub_app())
    # Page assets are served
    assert c.get("/app.js").status_code == 200
    assert c.get("/styles.css").status_code == 200
    assert c.get("/").status_code == 200
    # Non-page assets are 404
    assert c.get("/test_render.cjs").status_code == 404
    assert c.get("/test_states.cjs").status_code == 404
    assert c.get("/README.md").status_code == 404


# ----------------------------------------------------- mount_prefix --

def test_admin_mount_prefix_default_routes_at_root():
    """Default (no prefix) keeps /healthz, /admin/state, / at root."""
    c = TestClient(_stub_app())
    assert c.get("/healthz").status_code == 200
    assert c.get("/admin/state").status_code == 200
    # Static mount at / serves the shipped webgui
    assert c.get("/").status_code == 200
    assert "WATERWALL" in c.get("/").text or "reversible egress firewall" in c.get("/").text


def test_admin_mount_prefix_scopes_api_routes():
    """With mount_prefix='/waterwall', the API is under /waterwall/* and
    the root / is no longer the admin."""
    c = TestClient(_stub_app(mount_prefix="/waterwall"))
    # /waterwall/admin/state works
    r = c.get("/waterwall/admin/state")
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("application/json")
    # /waterwall/healthz works
    assert c.get("/waterwall/healthz").status_code == 200
    # Plain /admin/state does NOT exist
    assert c.get("/admin/state").status_code == 404
    # Plain /healthz does NOT exist
    assert c.get("/healthz").status_code == 404


def test_admin_mount_prefix_scopes_static_mount():
    """Static mount is at {prefix}/ — the webgui lives at /waterwall/."""
    c = TestClient(_stub_app(mount_prefix="/waterwall"))
    r = c.get("/waterwall/")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    assert "WATERWALL" in r.text or "reversible egress firewall" in r.text
    # Static assets too
    assert c.get("/waterwall/app.js").status_code == 200
    assert c.get("/waterwall/styles.css").status_code == 200
    # Plain / is NOT the webgui anymore — it 404s
    assert c.get("/").status_code == 404


def test_admin_mount_prefix_strips_trailing_slash():
    """`/waterwall/` and `/waterwall` both work; trailing slash is
    normalized on the way in."""
    c1 = TestClient(_stub_app(mount_prefix="/waterwall"))
    c2 = TestClient(_stub_app(mount_prefix="/waterwall/"))
    assert c1.get("/waterwall/admin/state").status_code == 200
    assert c2.get("/waterwall/admin/state").status_code == 200
    # Both static mounts work
    assert c1.get("/waterwall/").status_code == 200
    assert c2.get("/waterwall/").status_code == 200


def test_admin_mount_prefix_strips_surrounding_whitespace():
    """Templated env vars like ' /waterwall ' should not produce routes
    with spaces — the normalizer strips whitespace before slashes."""
    c = TestClient(_stub_app(mount_prefix=" /waterwall "))
    assert c.get("/waterwall/admin/state").status_code == 200
    assert c.get("/waterwall/").status_code == 200
    # A path with literal spaces should NOT match
    assert c.get("/ waterwall /admin/state").status_code == 404


def test_admin_mount_prefix_with_explicit_static_dir():
    """mount_prefix and explicit static_dir compose — the static dir
    is mounted at the prefixed path, not the root."""
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "index.html").write_text("<html>PREFIXED PAGE</html>")
        c = TestClient(_stub_app(mount_prefix="/ww", static_dir=td))
        assert c.get("/ww/").text == "<html>PREFIXED PAGE</html>"
        assert c.get("/ww/admin/state").status_code == 200
        # Root is not the webgui
        assert c.get("/").status_code == 404
