# deploy/caddy — exposing the waterwall status page

The waterwall status page (shipped under `src/waterwall/webgui/`) and
the JSON API are served by the waterwall admin server, which binds to
`127.0.0.1:8889` and refuses any other bind address. This directory
holds the configs for putting a reverse proxy in front of that
loopback listener so the page is reachable from:

- a **Tailscale** tailnet (or, with `tailscale funnel`, the public
  internet at `<host>.<tailnet>.ts.net/waterwall`),
- a **Cloudflare Tunnel** (or Cloudflare WARP-to-WARP mesh) — the
  public URL `https://waterwall.example.com/waterwall/`, gated by a
  Cloudflare Access policy,
- a **Wireguard** peer (your phone or laptop on your own VPN).

The page lives at a single path: `/waterwall/*`. The waterwall admin
must be built with `mount_prefix="/waterwall"` for the reverse-proxy
rules below to forward correctly — start mitmdump with
`WATERWALL_MOUNT_PREFIX=/waterwall` in its environment. With the
env var unset, the admin uses the legacy root mount (the API lives
at `/admin/state`) and these Caddyfile rules forward to a 404; set
the env var or change the matchers to `/`.

## File layout

```
deploy/caddy/
├── Caddyfile                # the Caddyfile (Caddy)
├── cloudflared.yml.example  # Cloudflare Tunnel config (cloudflared)
├── wg0.conf.example         # Wireguard interface (wg-quick)
├── tailscale.md             # Tailscale Serve / Funnel setup
└── README.md                # this file
```

## Architecture

```
                       ┌──────────────────────────────────────┐
   Tailscale client    │   tailscaled                         │
       (phone) ────────┤   tailscale serve --set-path=/waterwall
                       │            │                        │
                       │            ▼                        │
                       │   http://127.0.0.1:8443/waterwall/  │
   Cloudflare edge     │   cloudflared tunnel ──▶ Caddy ─────┤
   (waterwall.example.com   │   /waterwall/* path matched by Caddy
    .com  or  WARP     │            │                        │
    client)            │            ▼                        │
                       │   https://waterwall.example.com:443      │
   Wireguard peer      │   (Caddy on wg IP, /waterwall/*     │
   (laptop)  ──────────┤    match)                            │
                       │            │                        │
                       │            ▼                        │
                       │   http://127.0.0.1:8889/waterwall/  │
                       │   waterwall admin (mount_prefix)    │
                       │   page + JSON at /waterwall/*       │
                       └──────────────────────────────────────┘
```

Three access paths converge on the same loopback admin. The
`/waterwall/*` prefix is the contract: it's how the operator keeps the
waterwall surface out of the root URL namespace, leaving room for
other apps on the same host.

The waterwall admin is always the same loopback service. The three
access paths differ only in how they reach Caddy (Tailscale's
loopback, cloudflared's loopback, or the wg interface IP directly).

## Quick start

### Tailscale (easiest, tailnet-only)

```bash
# 1. install + bring up tailscale on the waterwall host
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up

# 2. point Tailscale's HTTPS at the loopback Caddy listener
#    (do NOT use --set-path: it strips the path prefix)
tailscale serve --bg --https=443 http://127.0.0.1:8443

# 3. open from any tailnet device
#    https://<host>.<tailnet>.ts.net/waterwall/
```

See `tailscale.md` for the full setup, including the public-funnel
variant.

### Cloudflare Tunnel (public, gated by Cloudflare Access)

```bash
# 1. one-time: log in and create a named tunnel
cloudflared tunnel login
cloudflared tunnel create waterwall-status
# (creates /etc/cloudflared/<UUID>.json)

# 2. copy the example config
cp deploy/caddy/cloudflared.yml.example /etc/cloudflared/config.yml
#    edit it: set the tunnel name, credentials-file, and hostname

# 3. route DNS
cloudflared tunnel route dns waterwall-status waterwall.example.com

# 4. configure the Access policy in the Cloudflare Zero Trust dashboard
#    (see the comment block in cloudflared.yml.example)

# 5. run (or enable the systemd unit that ships with cloudflared)
cloudflared tunnel --config /etc/cloudflared/config.yml run
```

The public URL is `https://waterwall.example.com/waterwall/`. Cloudflare
Access prompts for the configured IdP (email OTP, GitHub OAuth, etc.)
before serving the page.

### Wireguard (no third party, single-operator VPN)

```bash
# 1. generate the server keypair
wg genkey | sudo tee /etc/wireguard/wg0.key | wg pubkey | \
    sudo tee /etc/wireguard/wg0.pub

# 2. install the example config
sudo cp deploy/caddy/wg0.conf.example /etc/wireguard/wg0.conf
sudo chmod 600 /etc/wireguard/wg0.conf
sudo sed -i "s|REPLACE_WITH_SERVER_PRIVATE_KEY|$(sudo cat /etc/wireguard/wg0.key)|" /etc/wireguard/wg0.conf

# 3. for each peer, generate a keypair on the peer and add the
#    peer's public key to /etc/wireguard/wg0.conf as a [Peer] block

# 4. bring up the interface
sudo systemctl enable --now wg-quick@wg0

# 5. on the peer, add waterwall.example.com -> 10.0.0.1 to /etc/hosts
#    (or use the wireguard app's "DNS" field on iOS/Android)

# 6. open from the peer
#    https://waterwall.example.com/waterwall/
```

The Caddyfile signs the cert with Caddy's internal CA. Export the
CA from `/var/lib/caddy/pki/authorities/local/root.crt` on the
waterwall host and install it on the peer device to skip the
browser's cert warning.

## Caddyfile details

The shipped Caddyfile has two listeners, each with a `@waterwall`
path matcher and a 404 catch-all:

1. `http://127.0.0.1:8443` — loopback, used by `cloudflared tunnel`
   and (via `tailscale serve`) by the Tailscale path. HTTP only;
   TLS is handled at the upstream tunnel.
2. `https://waterwall.example.com` on the wg interface IP — the
   Wireguard peer listener. `tls internal` gives you a self-signed
   cert and an internal CA at
   `/var/lib/caddy/pki/authorities/local/root.crt` that you can
   export to peers.

Tailscale is configured out of band via `tailscale serve`, not in
the Caddyfile. The `tailscale serve` invocation hits the loopback
listener at `127.0.0.1:8443` with the path `/waterwall/...`; Caddy
matches and forwards to the admin.

The admin's `mount_prefix="/waterwall"` keeps everything scoped.
Edit the Caddyfile `bind` line for your wg interface IP, and
`caddy validate --config /etc/caddy/Caddyfile` to confirm.

## What this directory does NOT do

- It does not provision a Cloudflare account, a Tailscale account,
  or a DNS zone. Each needs an account and (for Cloudflare) a
  domain.
- It does not generate or rotate keys. Use `wg genkey`, `wg pubkey`,
  `tailscale up`, and the Cloudflare Zero Trust dashboard for those.
- It does not bind the waterwall admin to anything other than
  `127.0.0.1`. The spec's hard stance on loopback-only is preserved.
  The Caddyfile + tunnels are how you get from loopback to the
  world.
- It does not change the read-only nature of the page. The page is
  observational regardless of access path. The TUI on the box
  remains the source of truth for arm/disarm, reload,
  verify-install, and evidence export.

## Security caveats

The page exposes operational state (kill-switch position, session
counts, chain line count, recent redactions). For a single-operator
homelab this is fine and useful. Be aware of it when deciding how
publicly to expose the URL.

- **Tailscale**: tailnet-scoped by default. The safest of the three.
  No public DNS, no open internet.
- **Cloudflare Tunnel + Access**: scope via Cloudflare Access
  policies. The default config requires the operator's email OTP /
  GitHub OAuth; everyone else gets a 403. Tightening further (device
  posture, geo restrictions) is straightforward in the dashboard.
- **Cloudflare Tunnel + WARP-to-WARP mesh**: WARP clients only. Same
  caveats as the public path minus the DNS discoverability.
- **Wireguard**: as safe as your peer list. Hold the keys to a high
  standard; rotate on device loss. The wg interface is the only
  ingress; the loopback Caddy listener isn't reachable from outside
  the host.
