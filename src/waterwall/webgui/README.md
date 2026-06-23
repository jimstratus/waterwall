# waterwall/webgui

A read-only browser status page for the Waterwall proxy, mirroring the
Textual TUI (`src/waterwall/tui/`) one-to-one in layout, data, and
visual feel.

This is a prototype. The page polls `GET admin/state` at 1 Hz and
renders six panels. It is **strictly observational** — no buttons, no
forms, no actions. The TUI on the box remains the source of truth for
arm/disarm, reload, verify-install, and evidence export.

## Run it (mock mode, no proxy required)

```bash
# from the repo root
cd src/waterwall/webgui
python3 -m http.server 8765
# open http://127.0.0.1:8765/
```

Then tick the **use mock** checkbox in the control strip at the
bottom of the page — the page defaults to `use mock = off` (live
data mode), and with no admin server running the fetch will fail
and show the OFFLINE state. Enabling mock mode switches to an
in-memory synthetic state generator that animates a realistic tail.

Use the `view` buttons to switch between `healthy`, `armed`, and
`offline`:

## Run it against a real waterwall instance

If the waterwall admin is running with the default config (root
mount, `mount_prefix=""`), the page is already served at the admin
URL:

```
http://127.0.0.1:8889/
```

Open it; the page renders, polls `/admin/state` at 1 Hz, shows live
data. No second static server to maintain.

### Path-prefix deployment (e.g. behind Caddy as `/waterwall/`)

For a reverse-proxy deployment where the admin lives under a path
prefix, start the waterwall process with the prefix exported:

```bash
export WATERWALL_MOUNT_PREFIX=/waterwall
# then start mitmdump with the waterwall addon as usual
```

The admin's API and static mount now live at `/waterwall/*`:

- `http://127.0.0.1:8889/waterwall/`              → the page
- `http://127.0.0.1:8889/waterwall/admin/state`  → JSON
- `http://127.0.0.1:8889/waterwall/healthz`      → health
- `http://127.0.0.1:8889/waterwall/app.js`       → webgui JS

A single Caddyfile in `deploy/caddy/` puts the page on a TLS-
terminating reverse proxy at `https://waterwall.example.com/waterwall/`
— same origin, no CORS needed. The page's default endpoint is
`admin/state` (relative), so it resolves against the page URL and
just works at both `/` and `/waterwall/`.

The Caddyfile in `deploy/caddy/` is written against the
`/waterwall/*` deployment. If you use the root-mount default, the
Caddyfile forwards to a 404 because the admin still serves the API
at `/admin/state` (not `/waterwall/admin/state`). Either set the
env var or change the Caddyfile's `@waterwall` matchers to `/`.

### Mock mode

The page defaults to `use mock = off` — opening it against a running
admin server shows live data. Tick the **use mock** checkbox in the
control strip to render with synthetic state instead (the page
ignores the endpoint field and uses an in-memory generator). The
three `view` buttons (healthy / armed / offline) drive the mock
generator's behavior. Useful for evaluating the page or taking
screenshots without a live proxy.

`mount_prefix` notes:
- Default is `""` (no prefix). The admin's API and the static
  mount are both at the URL root: `/healthz`, `/admin/state`,
  `/app.js`, `/`, etc.
- Setting `WATERWALL_MOUNT_PREFIX=/foo` puts everything under
  `/foo/*`. The admin doesn't change in any other way — the test
  suite calls it with `mount_prefix=""` (root) to keep its
  existing API surface.

For a production deploy behind a reverse proxy, see
`deploy/caddy/README.md` — covers Caddy, Tailscale, Cloudflare
Tunnel + Access, and Wireguard.

## Cross-origin: serve the page from a different host

If the page is served from a different host than the waterwall admin
(e.g. the operator uses a separate kiosk box that hosts the static
page, with the admin remaining on the waterwall host), the browser
will block the `admin/state` fetch unless the admin server sets the
right CORS headers. The admin server stays loopback-only by default,
so you typically also need to either (a) reverse-proxy
`/waterwall/admin/state` from the kiosk to the loopback admin, or
(b) bind the admin server to a LAN interface (spec says no by
default — only do this on a trusted LAN).

To enable CORS, set the `WATERWALL_CORS_ORIGINS` env var before
launching waterwall:

```bash
# Comma-separated list of allowed origins. Use * to allow any.
export WATERWALL_CORS_ORIGINS="http://kiosk.lan,http://localhost:8765"
# ... or for development only:
export WATERWALL_CORS_ORIGINS="*"
```

The admin app reads this env var once at startup, parses it as a
comma-separated list, and registers a `CORSMiddleware` with those
origins. Empty / unset means no CORS (same-origin only, which is the
safe loopback default).

Pre-flight `OPTIONS` requests are handled by the middleware and return
200 with the appropriate `Access-Control-Allow-*` headers, so the
browser's preflight check passes.

For the standard `https://waterwall.example.com/waterwall/` deployment
described in the previous section, CORS is not needed: the page
and the API share an origin, so the browser allows the fetch.

## What is shown (mirror of TUI spec §13.2)

| Panel            | Source field(s)                                       |
|------------------|-------------------------------------------------------|
| LIVE ACTIVITY    | `recent_activity` (tail-follows, last 50, pill on scroll-up) |
| COUNTERS (5m)    | `counters_5m` (rpm, top types, p50/p99, unknown)      |
| MAP / PATTERNS   | `map`, `patterns` (size, TTL, breakdown, hash, reload) |
| KILL SWITCH      | `killswitch` (4 sources, ARMED banner when active)    |
| CHAIN / AUDIT    | `chain` (lines, checkpoints, root, head, verify)      |
| ACTIVE SESSIONS  | `sessions` (id prefix, redactions, uptime)            |

Plus the top status chip (`UP` / `FAIL` / `OFFLINE`) and the
hostname chip pulled from `window.location.hostname`.

## Display rules (mirror of TUI spec §13.5)

- Missing/null/empty fields render as the em-dash `—`, never `0` or `""`.
- Hashes are shown as the first 8 chars + `…`.
- Session IDs are shown as the first 8 chars.
- ISO 8601 timestamps are shown as `HH:MM:SS.mmm` (top-level `ts` is
  used for session-uptime math, **not** `Date.now()`).
- If the poll fails (network, non-200, invalid JSON, non-object body),
  the page flips to the OFFLINE state: red frame, red banner with
  the failure reason, all panels blanked, no stale cache ever shown.

## File layout

```
src/waterwall/webgui/
  index.html        page shell + six panel sections + control strip
  styles.css        cyberpunk theme tokens, 2x3 grid, OFFLINE/ARMED states
  app.js            1 Hz poll loop, render functions, mock generator,
                    tail-follow with new-event pill
  test_render.cjs   node smoke test: loads app.js, renders all panels
                    against mock data, asserts content (16 checks).
                    Run: `node test_render.cjs`
  test_states.cjs   node smoke test: exercises ARMED + OFFLINE view
                    transitions (10 checks). Run: `node test_states.cjs`
  README.md         this file
```

No build step, no dependencies. The `webgui/` directory is shipped
inside the waterwall package as package data (see
`pyproject.toml`'s `[tool.setuptools.package-data]` block) so the
admin server can mount it from `site-packages/waterwall/webgui/`
without any extra deploy step.

The two test scripts are dependency-free — they build a minimal DOM
shim in pure node, load `app.js` via `vm`, and assert rendered output.

The Python-side integration (auto-mount + CORS) is tested in
`tests/test_admin.py` (10 new checks: 5 CORS, 5 static-mount).

## What is deliberately NOT in this page

The TUI's footer bindings — `[r] reload`, `[k] killswitch`,
`[v] verify-install`, `[e] export`, `[t] tail toggle`, `[q] quit` —
are not exposed. This is a glance-and-go status surface. The TUI on
the box itself remains the place for interactive operations. The web
page is for at-a-glance monitoring from another machine.

Also out of scope: time-series charts, history playback, per-user
state, auth, light theme. Those belong in a future v2 viewer (or
Grafana pointed at the chain JSONL); not in this live mirror.
