# Fleet deploy helpers (`deploy/fleet/`)

Operator-run scripts for the **ops steps** the code can't do for you: wiring the
in-path redaction canary on a host, rolling Waterwall + the reporter across the
fleet, enabling the per-host backup notifier, and a read-only drift/health check.

These run **on the target hosts** (the gate host, the fleet, a connectivity host)
— not on the edge/gateway host, which has no outbound fleet connectivity. Every
script is idempotent and shellcheck-clean; state-changing scripts default to a
dry-run.

> The generic names below (`canary-host` = the Step-1 gate host, `fleet-host-1/2`
> = Step-2 targets, `edge-host` = the monitor-gateway/edge host) are placeholders;
> substitute your real host names when you run these.

> References: `docs/monitor.md` (config + design), and the proven mechanism in
> `docs/superpowers/lab-notes/monitor-phase1-acceptance.md`.

| Script | Runs where | What |
|---|---|---|
| `bootstrap-host.sh` | each fleet target | venv + `systemd/install.sh` + monitor units; enabled-not-started |
| `deploy-fleet.sh` | a connectivity host (SSH to fleet) | Step 2: pull REF + run `bootstrap-host.sh` on each target |
| `wire-canary.sh` | the gate host | Step 1: canary echo + `--allow-hosts` + `regen-ca` + leaf cert + launch gate |
| `enable-backup-notifier.sh` | any monitored host | Step 3: turn on the Phase-2 backup local notifier |
| `verify-monitor.sh` | any host | read-only drift + health (8 checks); exits 1 on any `✗` |
| `_config-merge.py` | internal | deep-merge a YAML snippet into `/etc/waterwall/config.yaml` (used by the two config-editing scripts) |

## Runbook (steps 1–3)

### Step 1 — Canary wiring + launch gate (on the gate host)

```bash
# plan first (no changes):
sudo bash /opt/waterwall/deploy/fleet/wire-canary.sh
# execute:
sudo bash /opt/waterwall/deploy/fleet/wire-canary.sh --apply
# then enable + start the reporter (after setting monitor.* in config.yaml):
sudo systemctl enable --now waterwall-reporter.service
```

`wire-canary.sh` is idempotent and safe to re-run. It leaves `monitor.gate.on_error:
warn` (fail-open) for first enablement; switch to `block` once the canary is trusted.

**Upstream trust note:** mitmproxy does not verify upstream certs by default, so the
proxy forwards to the loopback echo with no extra flag. Do **not** add a global
`ssl_verify_upstream_trusted_ca=/etc/waterwall/ca.pem` — real providers are not
signed by the waterwall CA and would break.

### Step 2 — Fleet deploy (from a connectivity host)

```bash
# on a host with SSH to the fleet (a connectivity host, not the edge host):
bash deploy/fleet/deploy-fleet.sh --ref master --refresh canary-host fleet-host-1 fleet-host-2
```

`--refresh` hard-resets each target to `origin/<ref>` (use for clean rollouts); omit
it for a plain checkout. Each target ends enabled-but-not-started so you can wire
config before going live.

### Step 3 — Backup notifier (per host)

The Discord webhook is a secret — read it from a 0400 root file or stdin, never the
command line:

```bash
echo "https://discord.com/api/webhooks/…" | \
  sudo bash deploy/fleet/enable-backup-notifier.sh
# or:
sudo bash deploy/fleet/enable-backup-notifier.sh --from-file /etc/waterwall/backup-webhook \
     --log-path /var/log/waterwall/backup-alerts.log --miss-threshold 2
```

Use a **separate** per-host webhook (independent of the gateway's), per `docs/monitor.md`.

### Verify (any time, read-only)

```bash
sudo bash deploy/fleet/verify-monitor.sh     # exits 1 if any check fails (✗)
```

Checks proxy health, `permitted_hosts` ↔ `--allow-hosts` drift, CA permittedSubtrees
↔ `permitted_hosts` (regen-ca needed?), the canary leaf cert (presence/SAN/expiry),
launch-gate + reporter + backup-notifier config, and the `/etc/hosts` loopback entry.

## Public-snapshot note

These scripts are sanitized for the public mirror by `deploy/prepare-public-snapshot.sh`
(host names → generic placeholders). `tests/test_public_snapshot.py` regression-guards
that no real infra token survives.