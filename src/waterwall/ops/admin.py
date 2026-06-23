# src/waterwall/ops/admin.py
"""Loopback-only admin HTTP server. Spec §10.

Refuses to bind to anything other than 127.0.0.1 / ::1.

When `static_dir` is not explicitly passed, `build_admin_app()`
auto-discovers and mounts the shipped `waterwall/webgui/` directory
if it exists (the default for installed packages). Pass
`static_dir=None` or a custom path to override. The `mount_prefix`
argument scopes all routes (API + static) under a path prefix, e.g.
`mount_prefix="/waterwall"` puts the page at `/waterwall/` and the
API at `/waterwall/admin/state`, leaving the rest of the URL
namespace free for other apps on the same host. Pass
`cors_origins=["*"]` (or a list of origins) to relax same-origin for
the case where the page is served from a different host than the
admin server.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles


_log = logging.getLogger(__name__)

# Only these files are served by the static mount. Prevents test files,
# README, and anything else in the webgui/ directory from being web-accessible
# via /waterwall/test_render.cjs etc.
_STATIC_ALLOWED_FILES = frozenset({"index.html", "app.js", "styles.css"})


class _FilteredStaticFiles(StaticFiles):
    """StaticFiles subclass that only serves whitelisted filenames.

    Prevents test files, README, and other non-page assets from being
    served through the admin's static mount — even in editable installs
    where the source directory contains everything.
    """

    async def get_response(self, path: str, scope):
        # Strip query string
        clean_path = path.split("?")[0].lstrip("/")
        # Mount passes '.' for directory-root requests (html=True serves
        # index.html from there). Allow it through; StaticFiles handles
        # the index.html lookup internally.
        if clean_path and clean_path != "." and clean_path not in _STATIC_ALLOWED_FILES:
            from starlette.responses import PlainTextResponse
            return PlainTextResponse("not found", status_code=404)
        return await super().get_response(path, scope)


def _resolve_static_dir(
    static_dir: str | os.PathLike[str] | None,
) -> Path | None:
    """Return the path to serve as the static mount, or None to skip.

    Resolution order:
      1. Explicit `static_dir` argument (caller-provided path)
      2. `<waterwall-package>/webgui/` (the shipped read-only webgui)
    Returns None if the resolved path does not exist or is not a directory.
    """
    if static_dir is not None:
        p = Path(static_dir).resolve()
        return p if p.is_dir() else None
    # admin.py lives in waterwall/ops/; the shipped webgui is the
    # sibling directory waterwall/webgui/.
    shipped = Path(__file__).resolve().parent.parent / "webgui"
    return shipped if shipped.is_dir() else None


def _normalize_prefix(mount_prefix: str) -> str:
    """Return the path prefix with no leading or trailing slashes.
    Empty string (default) means "no prefix, mount at root".
    Example: "/waterwall/" -> "waterwall", "/ww" -> "ww", "" -> "".
    Also strips surrounding whitespace so templated env vars like
    `' /waterwall '` don't produce routes containing spaces."""
    if not mount_prefix:
        return ""
    return mount_prefix.strip().strip("/")


def build_admin_app(
    *,
    state_provider: Callable[[], dict],
    killswitch_arm: Callable[[str], None],
    killswitch_disarm: Callable[[], None],
    reload_patterns: Callable[[], None],
    healthz_provider: Callable[[], dict] | None = None,
    cors_origins: list[str] | None = None,
    static_dir: str | os.PathLike[str] | None = None,
    mount_prefix: str = "",
) -> Starlette:
    """Build the loopback admin Starlette app.

    `state_provider` produces the full state snapshot.
    `healthz_provider` produces the flat healthz subset. When omitted, both
    endpoints use `state_provider` — convenient for tests where one stub dict
    serves both. Production wiring (addon.running) passes both.

    `cors_origins` — when non-empty, every response gets the
    `Access-Control-Allow-Origin` header for the matching origin. `"*"`
    is honored literally. Default: no CORS (same-origin only).

    `static_dir` — when the directory exists, mount it as the static
    handler. Default: the shipped `waterwall/webgui/` directory if it
    exists; None otherwise (admin-server-only mode).

    `mount_prefix` — when set, all routes (API + static) are scoped
    under this path prefix. Example: `mount_prefix="/waterwall"` puts
    the webgui at `/waterwall/` and the API at
    `/waterwall/admin/state`. The default is empty string (no prefix,
    routes at the URL root). The static mount, when present, is
    installed at `{prefix}/` (with html=True so the prefix root serves
    `index.html`).
    """
    healthz_source = healthz_provider or state_provider
    prefix = _normalize_prefix(mount_prefix)
    # Routes are built by prefixing the suffix with a single leading
    # slash. The empty-prefix case becomes "/suffix" naturally.
    p = f"/{prefix}" if prefix else ""

    async def healthz(request: Request) -> JSONResponse:
        body = healthz_source()
        if body.get("status") == "ok":
            return JSONResponse(body)
        return JSONResponse(body, status_code=503)

    async def admin_state(request: Request) -> JSONResponse:
        return JSONResponse(state_provider())

    async def admin_killswitch(request: Request) -> JSONResponse:
        body = await request.json()
        action = body.get("action")
        if action == "arm":
            killswitch_arm(body.get("reason", ""))
            return JSONResponse({"status": "armed"})
        if action == "disarm":
            killswitch_disarm()
            return JSONResponse({"status": "disarmed"})
        return JSONResponse({"error": "unknown action"}, status_code=400)

    async def admin_reload(request: Request) -> JSONResponse:
        try:
            reload_patterns()
            return JSONResponse({"status": "reloaded"})
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    routes: list = [
        Route(f"{p}/healthz", healthz, methods=["GET"]),
        Route(f"{p}/admin/state", admin_state, methods=["GET"]),
        Route(f"{p}/admin/killswitch", admin_killswitch, methods=["POST"]),
        Route(f"{p}/admin/reload", admin_reload, methods=["POST"]),
    ]

    # Static mount LAST so explicit API routes match first. The static
    # mount is rooted at `{prefix}/` with html=True, so a request to
    # `{prefix}/` serves the webgui's index.html. An empty prefix
    # mounts at `/`.
    resolved_static = _resolve_static_dir(static_dir)
    if resolved_static is not None:
        static_mount_path = f"/{prefix}" if prefix else "/"
        routes.append(Mount(static_mount_path, app=_FilteredStaticFiles(directory=resolved_static, html=True)))
    elif static_dir is not None:
        # Caller explicitly asked for static but the path was bogus.
        # Log it once at startup; don't crash the admin server.
        _log.warning("admin: static_dir %r is not a directory; skipping static mount",
                     str(static_dir))

    app = Starlette(routes=routes)

    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type"],
            allow_credentials=False,
        )

    return app


def serve_loopback(app: Starlette, port: int = 8889) -> None:
    """Run the admin server bound to 127.0.0.1 only."""
    import uvicorn
    config = uvicorn.Config(
        app, host="127.0.0.1", port=port,
        log_level="warning", access_log=False,
    )
    server = uvicorn.Server(config)
    server.run()
