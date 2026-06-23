# RELEASE.md — Waterwall v0.2.0

**feat: read-only web status page + Caddy reverse-proxy configs**

PR: https://github.com/jimstratus/waterwall/pull/24
Branch: `feat/webgui` (7 commits)
Reviewed by: Copilot, Kimi-k2.7, Qwen 3.7, GLM-5.2, MiMo v2.5, DeepSeek v4

---

## What's new

### Read-only web status page (`/waterwall/`)

A dependency-free HTML/CSS/JS status dashboard that mirrors the Textual
TUI's six panels. Open `http://127.0.0.1:8889/waterwall/` (after
setting `WATERWALL_MOUNT_PREFIX=/waterwall`) and the page polls the
admin JSON at 1 Hz, showing:

- **Live Activity** (tail-follows, shows recent redaction events with
  auto-scroll and a "N new events" pill)
- **Counters (5m)** (redactions/min, top types, latency p50/p99,
  unknown placeholders)
- **Map / Patterns** (store size, TTL, pattern breakdown, policy hash,
  last reload)
- **Kill Switch** (4-source status; blinking ARMED banner + asserted-by
  list when fail-closed)
- **Chain / Audit** (log lines, checkpoints, checkpoint root, live head,
  verify status)
- **Active Sessions** (ID prefix, redactions, computed uptime)

The page is strictly observational — no arm/disarm, no reload, no
export, no verify-install. The TUI on the box remains the source of
truth for interactive operations.

Mock mode: tick the "use mock" checkbox to render synthetic state in
three views (healthy, armed, offline). Useful for evaluating the page
or taking screenshots without a running proxy.

Tested: two dependency-free node smoke tests (17 + 10 checks) built
against a minimal DOM shim in pure node (vm module + hand-rolled
Element/ClassList). No jsdom, no npm install.

### Admin server additions

`build_admin_app()` gains three optional kwargs:

- **`static_dir`**: mounts the shipped webgui at a configurable path.
  Defaults to the package's `waterwall/webgui/` directory. Bogus paths
  log a warning and degrade to JSON-only mode.

- **`cors_origins`**: registers a starlette `CORSMiddleware` when
  non-empty. Default is no CORS (same-origin only — the safe loopback
  default). `WATERWALL_CORS_ORIGINS` env var (comma-separated, `*` for
  wildcard) is read once at startup.

- **`mount_prefix`**: scopes all API routes and the static mount under
  a path prefix (e.g., `/waterwall/`). Default is `""` (no prefix,
  backward-compatible with the TUI's `state_client.py` and
  `verify_install.py`). `WATERWALL_MOUNT_PREFIX` env var sets it.

### Caddy + mesh reverse-proxy configs (`deploy/caddy/`)

A Caddyfile and per-access-path configs for exposing the waterwall
status page through a reverse proxy while keeping the admin on
`127.0.0.1`:

- **Caddyfile**: two listeners (loopback :8443 for cloudflared/tailscale
  serve, `https://waterwall.example.com` on the wg interface IP at :443).
  Path matchers (`@waterwall`) route only `/waterwall/*`; everything
  else returns 404. Commented-out mitmweb block as a template.

- **cloudflared.yml.example**: Cloudflare Tunnel ingress with
  `warp-routing.enabled` for WARP-to-WARP mesh. Includes a comment
  block walking through the Cloudflare Access policy setup on
  `/waterwall*`.

- **wg0.conf.example**: wg-quick format Wireguard config (server + 2
  example peers, each /32).

- **tailscale.md**: `tailscale serve` and `tailscale funnel` setup
  with path-preserving forwarding.

- **README.md**: Architecture diagram, per-path quickstart, security
  caveats for each access path, and an explicit list of what this
  directory does NOT do (no account provisioning, no key rotation, no
  widening of the loopback bind).

- **APPS.md**: Feasibility survey for putting other apps
  (Prometheus, Grafana, mitmweb, netdata, cAdvisor, etc.) behind the
  same Caddy reverse proxy under path prefixes. Covers which apps are
  trivial, which need config, and which are not ideal.

### Test additions

- `tests/test_admin.py`: 9 → 24 checks. CORS (5 tests: no headers by
  default, specific origin match, non-match, wildcard, preflight).
  Static mount (5 tests: default, explicit dir, bogus path, file path,
  precedence over API routes). Mount prefix (5 tests: default root,
  scoped API, scoped static, trailing slash, explicit dir + prefix).
  No regressions.

- Full suite: 377 passed, 2 skipped.

---

## Display rules (webgui, mirror of TUI spec §13.5)

- Missing/null/empty fields render as the em-dash `—`, never `0` or `""`.
- Hashes are shown as the first 8 chars + `…`.
- Session IDs are shown as the first 8 chars.
- ISO 8601 timestamps are shown as `HH:MM:SS.mmm`.
- If the poll fails (network, non-200, invalid JSON, non-object body),
  the page flips to the OFFLINE state: red frame, red banner with the
  failure reason, all panels blanked. No stale cache ever shown.

## Security notes

- The waterwall admin still binds 127.0.0.1:8889 only. Spec §10's
  loopback-only stance is preserved; nothing in this release widens
  the bind.
- The page is read-only and exposes operational state. Exposing the URL
  publicly is a deliberate operator decision; each access path's
  README section documents the trade-offs.
- CORS is opt-in and defaults to off (same-origin only).
- mount_prefix defaults to `""` (root mount), preserving backward
  compatibility with the TUI and verify-install.

## Breaking changes

None. All new features are additive and default to the existing
behavior.
