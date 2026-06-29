# Waterwall fleet monitoring (Phase 1)

Know — fast — when a Waterwall instance stops protecting you, so you stop sending secrets
through your agent the moment protection lapses. The primary signal is an **in-path redaction
canary** (not a passive health ping), because the genuinely silent failure is an agent that
*bypasses* the proxy, which a `/healthz` check can't see.

## How it works

```
each host:  agent ─┐
                   ├─ client.env (HTTPS_PROXY, NODE_EXTRA_CA_CERTS)
   reporter ───────┘  every ~45s: send a synthetic secret down THIS path
        │                          to the canary echo (provider stand-in)
        │   echo verdict:  PASS = tokenized   |   EXPOSED = raw secret leaked
        │   + /healthz:    ok | degraded | down
        ▼
   POST (bearer) ──►  gateway (edge-host)  ──►  Discord on transition only
                          │                  (EXPOSED / RECOVERED / dead-man's-switch)
                          └──►  /  fleet dashboard
```

- **Canary** catches all three failures: daemon down, engine broken, **and silent bypass**.
- **Heartbeat cadence** is a dead-man's-switch — if a reporter goes silent for `interval ×
  miss_factor`, the gateway alerts (host/agent/proxy is gone).
- **Edge-triggered:** Discord fires only on state *changes*, never per poll.

## Reporter config (`/etc/waterwall/config.yaml`, per host) — off by default

```yaml
monitor:
  enabled: true
  gateway_url: "https://waterwall-monitor.example.com/api/report"
  token: "<shared-bearer-token>"        # 0400 root; never commit
  interval: 45
  client_env: "/etc/waterwall/client.env"
  canary_url: "https://canary.waterwall.local/canary"
  healthz_url: "http://127.0.0.1:8889/healthz"
  # host: <override hostname>   # defaults to socket.gethostname()
```

`client.env` is the **single source of truth** for the agent's proxy settings (see
`deploy/monitor/client.env.template`). The agent sources it via shell profile AND the reporter
sources it — so the canary travels the same path as the agent, and a broken agent env makes the
canary report `EXPOSED`.

## Gateway config (edge-host only)

```yaml
gateway:
  token: "<same-shared-bearer-token>"
  discord_webhook: "https://discord.com/api/webhooks/…"   # channel is your choice
  db: "/var/log/waterwall/monitor.db"
  interval: 45
  miss_factor: 3            # dead-man's-switch fires after interval × miss_factor
  bind: "127.0.0.1"         # keep loopback; publish via CF tunnel
  port: 8890
```

## Endpoints & auth

| Path | Method | Auth |
|---|---|---|
| `/api/report` | POST | `Authorization: Bearer <token>` (reporters) |
| `/api/fleet` | GET | `Authorization: Bearer <token>` (the dashboard sends it) |
| `/` | GET | HTML shell (no data); **publish behind CF Access** for the human layer |

The dashboard reads its token from the URL fragment `#token=<token>` once (stored in
`localStorage`; a fragment is never sent to the server, so the token stays out of access logs), then sends
it on every `/api/fleet` fetch. Keep `bind: 127.0.0.1` and expose only through the CF tunnel +
CF Access — the bearer protects the data API even behind Access.

## Install (systemd units in `deploy/monitor/`)

- `waterwall-canary-echo.service` — the loopback TLS echo (needs a `canary.waterwall.local`
  leaf cert signed by the waterwall CA; add the canary host to `permitted_hosts.yaml` + regen CA).
- `waterwall-reporter.service` — runs `waterwall report` (every host you want monitored).
- `waterwall-monitor-gateway.service` — runs `waterwall monitor-gateway` (edge-host only).

## Reading the dashboard

- canary **PASS** (green) = secrets are tokenized in-path.
- canary **EXPOSED** (red) = secrets are bypassing Waterwall — **act now** (stop the agent /
  fix `client.env`).
- health **degraded/down** = the proxy daemon itself is unhealthy.
- **⛔ stale** = no heartbeat past the threshold (dead-man's-switch).

## Status

Phase 1 ships the reporter + gateway + canary echo + Discord alerts + dashboard. Phase 2 adds the
per-host backup local notifier and Phase 4 the session-launch hard-gate on `EXPOSED` (both below;
opt-in, code complete). Deferred: fleet rollout to additional hosts (Phase 3).

## Launch hard-gate (Phase 4)

The pre-launch hook (`waterwall pre-launch-hook`, enforced by the
`waterwall-launch` wrapper) can refuse to start an agent when a fresh canary,
fired at launch through the agent's own proxy/CA, returns `EXPOSED`. Opt in per
host:

```yaml
monitor:
  gate:
    enabled: true        # default false
    on_error: warn       # warn (default, fail-open) | block (fail-closed)
  canary_url: https://canary.waterwall.local/canary
  synthetic: AKIAIOSFODNN7EXAMPLE
  client_env: /etc/waterwall/client.env
```

- `pass` → agent starts.
- `exposed` → agent blocked (exit 1).
- `error` (echo unreachable / unverifiable) → `warn` starts with a loud
  warning; `block` refuses to start.

Designated first host: **canary-host**, internal homelab. Requires the local
canary echo + canary host trusted on that box (step-3 wiring). `edge-host` remains
the public routing edge. See
`docs/superpowers/specs/2026-06-29-waterwall-monitor-launch-gate-design.md`.

## Backup local notifier (Phase 2)

A per-host, gateway-independent alert path so a single host can still warn you when
the central gateway/Discord path is down. The reporter edge-detects locally and
fans each alert to an independent Discord webhook plus a local log + the systemd
journal. Opt in per host:

```yaml
monitor:
  backup:
    enabled: true        # default false
    webhook: "https://discord.com/api/webhooks/…"   # SEPARATE from the gateway's
    log_path: "/var/log/waterwall/backup-alerts.log"
    gateway_miss_threshold: 2    # consecutive failed gateway POSTs before alerting
```

Fires (edge-triggered) on:
- local canary **EXPOSED** — immediately (no debounce; redundant with the gateway's
  alert, so you're never blind on the critical signal);
- **gateway unreachable** for `gateway_miss_threshold` consecutive cycles (the central
  path is blind), with a recovery when it returns.

The journal is captured automatically (the reporter runs under systemd); `journalctl
-u waterwall-reporter` shows the alerts even with no network. See
`docs/superpowers/specs/2026-06-29-waterwall-monitor-backup-notifier-design.md`.
