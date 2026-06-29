# Tailscale access for the waterwall status page

Tailscale is the cleanest of the three access paths. The waterwall
host runs `tailscaled` (the Tailscale daemon) and joins your tailnet.
The user-facing URL is `https://waterwall.example.com/waterwall/`, served
by Caddy's loopback listener (port 8443) via `tailscale serve`.

## Architecture

```
Phone/laptop (Tailscale client)
        │
        │  Tailscale Wireguard tunnel
        ▼
tailscaled on waterwall host
        │
        │  tailscale serve (TLS, tailnet)
        ▼
http://127.0.0.1:8443/waterwall/   (Caddy, loopback block in Caddyfile)
        │
        │  reverse_proxy (no path rewrite)
        ▼
http://127.0.0.1:8889/waterwall/   (waterwall admin, mount_prefix)
```

`tailscale serve` terminates TLS at the tailnet IP and forwards the
full request path to Caddy on loopback. Caddy matches `/waterwall/*`
and reverse-proxies to the admin, which handles routing via
`mount_prefix="/waterwall"`.
The admin is built with `mount_prefix="/waterwall"`, so the page and
JSON live at `/waterwall/` and `/waterwall/admin/state` respectively.

## Setup

1. Install Tailscale on the waterwall host:

   ```bash
   curl -fsSL https://tailscale.com/install.sh | sh
   tailscale up
   ```

2. Make sure Caddy is running and listening on `127.0.0.1:8443` (the
   loopback block of `deploy/caddy/Caddyfile`).

3. Register the page with `tailscale serve`:

   ```bash
   # Tailnet-only (your devices on the tailnet can reach it)
   # Do NOT use --set-path: it strips the path prefix before forwarding,
   # which breaks the admin's mount_prefix routing. Without --set-path,
   # the full path is preserved and Caddy matches /waterwall/*.
   tailscale serve --bg --https=443 http://127.0.0.1:8443
   ```

   ```bash
   # Public via Tailscale Funnel (anyone on the internet can reach
   # it at https://<host>.<tailnet>.ts.net/waterwall/ — Tailscale's
   # edge handles TLS, your tailnet auth is the gate). Treat as a public
   # surface; combine with Tailscale ACLs that require your devices
   # to be tagged/approved.
   tailscale funnel --bg --https=443 http://127.0.0.1:8443
   ```

   The `--bg` flag persists the rule across reboots. Run `tailscale
   serve status` to see what's currently registered, and `tailscale
   serve reset` to clear it.

4. From any device on the tailnet, open:

   ```
   https://waterwall.example.com/waterwall/
   ```

   The page renders, polls `/waterwall/admin/state` at 1 Hz, shows
   live data.

   For the Tailscale-named URL, use:
   ```
   https://<host>.<tailnet>.ts.net/waterwall/
   ```
   Tailscale MagicDNS resolves this to the tailnet IP, and the cert
   matches the host. Both URLs work; pick whichever is convenient.

## Path handling

`tailscale serve` without `--set-path` forwards the full request path
to Caddy unchanged. Caddy matches `/waterwall/*` and reverse-proxies
to the admin on loopback. The admin's `mount_prefix="/waterwall"`
handles the final routing.

**Do NOT use `--set-path=/waterwall`** — it strips the path prefix before
forwarding, which breaks the admin's mount_prefix routing (the admin
receives `/` instead of `/waterwall/` and returns 404).

If you want to drop Caddy from the Tailscale path entirely, point
`tailscale serve` directly at the admin:

```bash
tailscale serve --bg --https=443 --set-path=/waterwall http://127.0.0.1:8889
```

The admin already serves at `/waterwall/*` thanks to `mount_prefix`.
The downside is no Caddy in this path means no shared TLS config
across access paths — but for a Tailscale-only deploy that's fine.

## Why Caddy is still in the path

`tailscale serve` can forward directly to the waterwall admin
(`http://127.0.0.1:8889`) and skip Caddy entirely. Reasons to keep
Caddy in the loop:

- Single config across all three access paths (Tailscale, CF Tunnel,
  wg). One Caddyfile to maintain.
- cloudflared (`http://127.0.0.1:8443`) needs a local HTTP upstream
  anyway, so the loopback listener is there.

## Security caveats

- `tailscale serve` is tailnet-scoped by default. Only devices
  authenticated to your tailnet can reach the URL. No public DNS,
  no open internet exposure.
- `tailscale funnel` *is* public. Tailscale's edge handles TLS, but
  the URL is discoverable. Combine with Tailscale ACLs that require
  device approval.
- The waterwall admin binds 127.0.0.1 only. Tailscale's daemon
  connects to it on loopback; the page is never exposed on a public
  IP directly.
- No CORS is needed for this path: tailscale serve and the
  waterwall page share the same origin, and the page's default
  endpoint is the relative `admin/state` which resolves against the
  page URL automatically.
