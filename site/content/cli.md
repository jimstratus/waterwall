# CLI Reference

The `waterwall` command is the venv console script (`/opt/waterwall/.venv/bin/waterwall`, shim
at `/opt/waterwall/bin/waterwall`). Symlink it onto `PATH` for convenience — see the
[Runbook](runbook.html). Commands that read protected paths (`signing.key`, `/var/log/waterwall`)
need root.

## Commands

```bash
waterwall verify-install [--runtime]
waterwall verify-chain   <log>  --pubkey <pub>
waterwall verify-receipt <file> --pubkey <pub>
waterwall export-evidence --chain <log> --policy <patterns.py> \
    --pubkey <pub> --signing-key <key> -o <out.tar.gz> \
    [--receipts-dir D] [--manifests-dir D] [--since YYYY-MM-DD] [--until YYYY-MM-DD]
waterwall verify-evidence <bundle.tar.gz> --pubkey <pub>
waterwall regen-ca [--hosts-file permitted_hosts.yaml] [--out-dir /etc/waterwall]
waterwall rotate-chain [--chain-path <log>]
waterwall pre-launch-hook
waterwall dashboard
```

| Command | What it does |
|---|---|
| `verify-install [--runtime]` | 10 health checks. Startup mode binds the ports; `--runtime` reads the live admin state and re-validates the on-disk CA + listener. |
| `verify-chain` | Walks the chain log: `prev_hash` continuity plus, for each checkpoint, **recomputes the root from the line's own content** before verifying its Ed25519 signature. An empty log fails (not a vacuous OK). |
| `verify-receipt` | Verifies a single Ed25519 action receipt against the public key. |
| `export-evidence` | Produces a tarball of chain + receipts + manifests + policy + pubkey with an **Ed25519-signed MANIFEST**. `--signing-key` is required. `--since/--until` filter receipts/manifests by date; the chain is always included in full. |
| `verify-evidence` | Full bundle audit: per-file SHA-256 → MANIFEST signature → chain crypto → MANIFEST chain-stats cross-check → per-receipt signatures → receipt-to-chain cross-reference → bundled-pubkey identity. Any failure short-circuits with a reason. |
| `regen-ca` | Regenerates the Name-Constrained RSA-4096 CA so its `permittedSubtrees` match the current host list. Generates into a temp dir and swaps only on success. |
| `rotate-chain` | Archives the current chain with a properly-chained terminal entry and starts fresh. Proxy must be stopped. |
| `pre-launch-hook` | Reads `/healthz`; emits a SessionStart warning and exits non-zero when the proxy is down or kill-switched. Used by the launch wrapper. |
| `dashboard` | Launches the [TUI](tui.html). |

## Verifying a running deployment

```bash
sudo waterwall verify-install --runtime
sudo waterwall verify-chain    /var/log/waterwall/proxy.jsonl --pubkey /etc/waterwall/signing.pub
sudo waterwall export-evidence --chain /var/log/waterwall/proxy.jsonl --policy /etc/waterwall/patterns.py \
    --pubkey /etc/waterwall/signing.pub --signing-key /etc/waterwall/signing.key -o /tmp/evidence.tar.gz
sudo waterwall verify-evidence /tmp/evidence.tar.gz --pubkey /etc/waterwall/signing.pub
```

Anyone holding only the **public** key can run `verify-chain`, `verify-receipt`, and
`verify-evidence` to independently audit the evidence — that is the point of the signed,
hash-chained design.
