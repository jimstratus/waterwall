# deploy/caddy/APPS.md

Feasibility survey for hosting other applications on
`waterwall.example.com/<appname>/` (path-based) instead of separate ports,
all fronted by the same Caddyfile as the waterwall status page.

The waterwall status page itself is already wired at
`https://waterwall.example.com/waterwall/`. This doc is the next layer:
what else can ride the same plumbing?

## The pattern

For every app behind Caddy, the Caddyfile has a uniform three-line
block per app:

```caddyfile
@appname path /appname /appname/*
handle @appname {
    reverse_proxy 127.0.0.1:PORT
}
respond "not found" 404
```

Apps that natively know their mount prefix (like the waterwall
admin, via `mount_prefix="/waterwall"`) need only the bare
`reverse_proxy`. Apps that do not (mitmweb, plain StaticFiles dirs,
legacy apps) need `uri strip_prefix /appname` in between. Caddy
handles both shapes identically from the public URL's point of view.

To add a new app: copy the three lines, fill in `@appname` + the
upstream. No other change to Caddy.

## What lives in this repo

| App | HTTP? | Port | Feasibility | Pattern | Notes |
|---|---|---|---|---|---|
| waterwall admin + webgui | yes | 8889 | ✅ done | `reverse_proxy` (admin has `mount_prefix`) | shipped in this PR |
| mitmproxy web UI (mitmweb) | yes | 8081 | ✅ feasible | `uri strip_prefix` (mitmweb has no path-prefix support) | verified end-to-end; JS uses relative URLs so stripping works cleanly |
| mitmproxy (the proxy itself) | n/a | n/a | ❌ not applicable | — | it's a forward proxy, not a server you browse to. clients point their `HTTPS_PROXY` at it; no public URL makes sense |
| waterwall TUI | no | — | ❌ not applicable | — | terminal app (Textual). operator runs it on the box |
| waterwall CLI tools (`verify-*`, `export-evidence`, `pre-launch-hook`, `regen-ca`, `rotate-chain`) | no | — | ❌ not applicable | — | CLI subcommands. operator runs them on the box |
| `verify-install` (Python) | no | — | ❌ not applicable | — | runs at startup, prints PASS/FAIL summary; not HTTP |
| chain JSONL log | no | — | ❌ not applicable | — | append-only file, not HTTP. accessible via `scp` / `tail -f` on the box |

The realistic "in-repo" candidate beyond the waterwall admin is
**mitmweb**. Every other HTTP-servable thing in this repo *is* the
waterwall admin.

## Adjacent apps the operator might run on the same host

| App | HTTP? | Default port | Feasibility | Notes |
|---|---|---|---|---|
| Prometheus | yes | 9090 | ⚠️ requires config | needs `--web.route-prefix=/prom` or `--web.external-url` for subpath; UI is raw-path by default |
| Grafana | yes | 3000 | ✅ trivial | Grafana supports `root_url` for subpath deployments; Caddy matches `/grafana` and proxies |
| Loki / Promtail | yes | 3100 / 9080 | ✅ trivial | reverse-proxy with path stripping |
| node_exporter | yes | 9100 | ⚠️ limited | serves `/metrics` only — no UI. putting it under `/node_exporter` is fine for scraping but the path has to be reconfigured in Prometheus's scrape config too |
| cAdvisor | yes | 8080 | ✅ trivial | UI works under any prefix; `/metrics` likewise |
| filebrowser | yes | 8080 | ✅ trivial | supports `baseUrl` config for subpath |
| netdata | yes | 19999 | ⚠️ requires config | UI hardcodes `/api/v1/` fetch paths; subpath hosting needs reverse-proxy path rewriting or netdata's proxy mode. Not "just add a Caddy block" |
| Uptime Kuma | yes | 3001 | ✅ trivial | supports subpath via env var |
| caddy admin API | yes | 2019 | ✅ trivial | `reverse_proxy 127.0.0.1:2019` behind a tight ACL (not internet-exposed) |
| homer (static dashboard) | yes | 8080 | ✅ trivial | static site; Caddy `@homer` + `reverse_proxy` |

Out of scope for this PR but the Caddyfile template makes any of
these a 4-line addition.

## Apps that ARE NOT ideal for path-prefix hosting

These either can't be put under a subpath, or doing so breaks core
functionality:

- **WebSocket-heavy apps that hardcode the URL path** — most modern
  apps do this right, but legacy or niche ones sometimes have
  absolute WebSocket URLs in their JS. Verify before adding.
- **Apps that issue cookies scoped to `/`** — a path-prefixed
  reverse proxy still has the browser send cookies scoped to the
  proxied path (e.g. `/grafana/`) by default, so this usually works.
  But apps that explicitly set `Path=/` on their session cookies
  will leak the cookie to every other app on the same domain —
  potential cross-app auth issue. Watch for this in Grafana and
  similar.
- **Apps that download artifacts with absolute URLs in the
  response body** — e.g. some Prometheus exporters return
  `https://host:9090/graph?expr=...` links. Under a path-prefix
  proxy, those links are still correct as long as the operator
  configured the app with its public base URL (Grafana's
  `root_url`, etc.).
- **Apps that listen on privileged ports (<1024)** — Caddy itself
  has to be configured to bind those. Not a path-prefix problem
  per se, but worth knowing.
- **Apps with WebSocket subprotocols** that negotiate at the
  protocol level — rare, but the Caddy `reverse_proxy` directive
  passes WebSocket upgrades through transparently, so most
  subprotocols work. Verify the app supports `Connection: upgrade`
  tunneling if it's a non-standard upgrade.

## Mitmweb specifics (the verified candidate)

The mitmproxy web UI binds to `127.0.0.1:8081` by default (operator
can change with `--web-port` / `--web-host`). It does not natively
support a path prefix. The path-stripping pattern in Caddy is:

```caddyfile
@mitmweb path /mitmweb /mitmweb/*
handle @mitmweb {
    uri strip_prefix /mitmweb
    reverse_proxy 127.0.0.1:8081
}
```

Verified behavior:

- All paths under `/mitmweb/*` are forwarded to `127.0.0.1:8081/*`
  with the prefix stripped. The 403 auth gate from mitmweb is
  preserved (we get the same 403 from `/mitmweb/flows` as from
  `/flows`).
- The mitmweb JS bundle uses relative URLs internally — `ne()` in
  the bundle does `t.startsWith("/") && (t = "." + t)`, so every
  fetch like `/flows/123/request/content.data` becomes
  `./flows/123/request/content.data` and resolves against the
  current page URL. Under `/mitmweb/`, the fetch hits
  `/mitmweb/flows/123/...` which Caddy strips to
  `/flows/123/...` upstream.
- Static assets (`./static/images/favicon.ico`, the JS bundle,
  CSS) are all relative — same path-stripping pattern.
- CSRF: mitmweb uses an `_xsrf` cookie + `X-XSRFToken` header for
  non-GET requests. Cookies are path-scoped (browser default), so
  the cookie is set on `/mitmweb/` and sent on subsequent requests
  to that path. No cross-app leakage. The header is read by
  mitmweb's same-origin policy, which checks the request's Host
  header — and Caddy's reverse_proxy passes Host through (or
  rewrites it via the `header_up Host {host}` directive if you
  want to mask the upstream port).

  Recommendation: leave Host as-is. mitmweb compares it against
  the cookie's origin. The cookie is set by the response (so
  it's bound to the Caddy-served origin), and subsequent requests
  come back through Caddy (same Host). No mismatch.

- WebSocket: mitmweb uses EventSource (not raw WebSocket) for
  `/events`, so the reverse proxy just needs to pass through
  chunked transfer-encoding. Caddy does this by default.

Gotcha: **mitmweb requires authentication by default** (the 403 we
saw). The operator sets `web_password=...` (or runs without a
password for a homelab). For the path-prefixed case, the operator
also needs to decide whether the auth happens at Caddy (basic auth
in front of the proxy block) or at mitmweb (the existing form
login). Caddy basic auth is simpler for a single-operator setup.
