# Waterwall — deployment guide

End-to-end procedure for installing Waterwall on a fresh host, written so you (or a teammate, or future-you in six months) can follow it cold. Validated path: Debian 13 LXC on Proxmox. Adjacent Debian/Ubuntu releases work unchanged; other distros need package-name swaps.

Already deployed and just need day-to-day commands? See **`docs/runbook.md`**.

## Deployment at a glance

```mermaid
flowchart TD
    A[1. clone to /opt/waterwall] --> B["2. venv + pip install -e .[dev]"]
    B --> C[3. install.sh<br/>user · permitted_hosts · 4-host CA · signing key · unit]
    C --> D[4. BACK UP keys out-of-band]
    D --> E[5. systemctl start<br/>ExecStartPre: verify-install]
    E --> F{verify-install<br/>passes?}
    F -- no --> E2[fix CA / keys / patterns<br/>journalctl -u waterwall-proxy]
    E2 --> E
    F -- yes --> G[6. claude /login<br/>BEFORE setting proxy env]
    G --> H[7. set HTTPS_PROXY + NODE_EXTRA_CA_CERTS + NO_PROXY]
    H --> I[8. tools/verify-deploy.sh<br/>full acceptance gate]
    I --> J[9. SessionStart hook]
    J --> K[operate · docs/runbook.md]
```

## 0. Prerequisites

The target host needs:

- Debian 13 (or Ubuntu 24.04+), 64-bit
- Python 3.12 or newer (`python3 --version`)
- Network egress to the upstream API hosts on :443 (`api.anthropic.com`, `api.openai.com`, `api.deepseek.com`, `openrouter.ai`), plus `console.anthropic.com:443` for Claude OAuth and your package mirror
- Root / `sudo` for the install step (the service drops to a `waterwall` system user at runtime)
- ~500 MB disk for venv + audit logs; budget for ~14-day log retention

Tools the install script assumes: `bash`, `python3`, `python3-venv`, `git`, `curl`, `systemctl`, `chown`/`chmod` — standard Debian. The CA and signing key are generated in-process via the `cryptography` library (no `openssl` shell-out). Run `apt-get install -y python3 python3-venv git curl` if any are missing.

For the operator workstation that drives a client through the proxy, you also need that client installed and authenticated (e.g. `claude`, Claude Code CLI 2.1.131+).

## 1. Get the source

```bash
sudo git clone https://github.com/jimstratus/waterwall.git /opt/waterwall
cd /opt/waterwall
```

No git access to the private repo? Transfer a tarball: on a reachable host `git archive HEAD --format=tar -o waterwall.tar`, then `scp` it over and `mkdir /opt/waterwall && tar xf waterwall.tar -C /opt/waterwall`.

## 2. Create the venv + install dependencies

```bash
cd /opt/waterwall
sudo python3 -m venv .venv
sudo .venv/bin/pip install -e ".[dev]"
```

The `[dev]` extras pull in pytest + ruff + mypy. Drop `[dev]` for a slimmer prod-only install if disk is tight.

Quick sanity — run the suite:

```bash
sudo .venv/bin/python -m pytest 2>&1 | tail -3
```

Expect the suite to pass (at time of writing ~326 passed, 2 skipped — the 2 skips are Windows-only PowerShell smoke tests; the exact count drifts as tests are added). What matters is **0 failed**. Any failure here means the venv didn't pick something up cleanly — fix before proceeding.

## 3. Run the installer

```bash
sudo ./deploy/systemd/install.sh
```

The install script is idempotent. It:

- Creates the `waterwall` system user/group if missing
- Seeds `/etc/waterwall/permitted_hosts.yaml` with the default four hosts (only if absent):
  `api.anthropic.com` (handler `anthropic`), `api.openai.com`, `api.deepseek.com`, `openrouter.ai` (handler `openai`)
- Generates a Name-Constrained **RSA-4096** CA at `/etc/waterwall/{ca.pem,ca.key,mitmproxy-ca.pem}` whose `permittedSubtrees` match `permitted_hosts.yaml` (only if not present)
- Generates the Ed25519 signing keypair at `/etc/waterwall/{signing.key,signing.pub}` (only if absent; `signing.key` mode `0440 root:waterwall`)
- Writes default `/etc/waterwall/patterns.py` (extensions appended to the built-in set) and `/etc/waterwall/config.yaml` (`kill_switch: false`)
- Creates `/var/log/waterwall/{,receipts,manifests}` and `/run/waterwall`
- Installs the systemd unit + weekly restart timer to `/etc/systemd/system/`
- Runs `systemctl daemon-reload` and `systemctl enable` (does **not** start)

Verify afterward:

```bash
sudo systemctl is-enabled waterwall-proxy.service           # → enabled
sudo systemctl is-enabled waterwall-proxy-restart.timer     # → enabled
ls -la /etc/waterwall/                                      # CA + signing key + permitted_hosts.yaml present
cat /etc/waterwall/permitted_hosts.yaml                     # the 4-host set
```

To add a provider host later: append a `{host, sse_handler}` entry to `permitted_hosts.yaml`, run `sudo /opt/waterwall/bin/waterwall regen-ca` (full shim path — `sudo`'s `secure_path` doesn't include the venv), re-import the regenerated `ca.pem` on any client, then restart the service. `regen-ca` generates into a temp dir and only swaps on success, so a failed regen leaves the live CA untouched.

## 4. Backup the keys (CRITICAL)

Before starting, copy these out-of-band:

- `/etc/waterwall/signing.key` — **Ed25519 private key. Lose it and all historical chain logs become unverifiable forever.** Treat like a CA root: encrypt at rest, store in a separate system, restrict to operators who rotate it.
- `/etc/waterwall/signing.pub` — public key. Distribute to anyone who verifies receipts/chain/evidence. Safe to share.
- `/etc/waterwall/ca.{pem,key}` — the Name-Constrained CA. Needed to re-issue clients' `NODE_EXTRA_CA_CERTS` after a wipe/reinstall.

Skip this and a disk failure means you cannot reconstruct prior audit evidence. Don't skip.

## 5. Start the service

```bash
sudo systemctl start waterwall-proxy.service
sudo systemctl status waterwall-proxy.service               # → active (running)
sudo journalctl -u waterwall-proxy -n 20
```

`ExecStartPre` runs `waterwall verify-install` (10 startup checks) before mitmdump launches — a failing check blocks start and the unit retries (`Restart=on-failure`, `RestartSec=5`). Two ports should now listen on loopback:

```bash
ss -tlnp | grep -E '8888|8889'
# 127.0.0.1:8888 — proxy (mitmdump)
# 127.0.0.1:8889 — admin / healthz
```

Health probe:

```bash
curl -sf http://127.0.0.1:8889/healthz | python3 -m json.tool
```

Expect `"status": "ok"`, `"signer_key_readable": true`, `"chain_intact": true`, `"patterns_loaded": 30`. Note `"upstream_reachable"` is legitimately `false` right after a fresh start — it only flips `true` once the proxy relays its first upstream response, and it does **not** gate `status`/the 503. Drive one request through the proxy, then re-probe to see it go `true`.

## 6. Authenticate the client (do this BEFORE setting the proxy env)

The Name-Constrained CA permits only the configured API hosts — **not** `console.anthropic.com`, which Claude Code's OAuth callback uses. `claude /login` with `HTTPS_PROXY` set fails with `OAuth error: permitted subtree violation`. Correct order:

```bash
# 1. Make sure proxy env vars are NOT set
unset HTTPS_PROXY NODE_EXTRA_CA_CERTS CLAUDE_CODE_CERT_STORE NO_PROXY
env | grep -iE 'proxy|cert' || echo "(env clean)"

# 2. Login (interactive — opens auth URL, paste back the code)
claude /login

# 3. Smoke-test
claude --print "ping" | head -3   # should respond, NOT 401

# 4. Now enable the proxy for session traffic
export HTTPS_PROXY=http://127.0.0.1:8888
export NODE_EXTRA_CA_CERTS=/etc/waterwall/ca.pem
export CLAUDE_CODE_CERT_STORE=bundled,system
export NO_PROXY="127.0.0.1,localhost,downloads.claude.ai,statsig.anthropic.com,http-intake.logs.us5.datadoghq.com"
```

The `NO_PROXY` exclusions are required: the client touches `downloads.claude.ai` (updates) and telemetry endpoints the Name-Constrained CA refuses to MITM; without them you get `Client TLS handshake failed`. Add them to your shell profile so every new session inherits them.

For OpenAI / DeepSeek / OpenRouter clients, point that client's base URL through `http://127.0.0.1:8888` with the same `NODE_EXTRA_CA_CERTS` and confirm its host is in `permitted_hosts.yaml`.

## 7. Install the placeholder-preservation protocol (for agent workflows)

Without this, the model paraphrases tokenized secrets in its responses ("your AWS key", `<your_key>`, etc.) and the local detokenizer can't substitute the real value back. For agent workflows where the response must contain the actual secret to be executable, append the protocol to `~/.claude/CLAUDE.md` (or a per-project `./CLAUDE.md`):

```bash
cat /opt/waterwall/docs/claude-md-insert.md   # read it first, then append the marked block
cat >> ~/.claude/CLAUDE.md <<'EOF'

## Waterwall placeholder protocol

When you receive input containing strings of the form `<pl:TYPE:HEX>` (e.g.
`<pl:AWS_ACCESS_KEY:abc12345>`, `<pl:ANTHROPIC_KEY:def67890>`,
`<pl:GITHUB_TOKEN:0011223344556677>`), they are opaque references to a real
secret held by a local egress proxy. **Never** paraphrase, abbreviate, elide,
or replace these with descriptive placeholders like `<your_key>`, `<API_KEY>`,
`<...>`, or "the AWS key". Reproduce each placeholder string byte-for-byte
in your output if you reference it.

When generating commands or code that includes such a placeholder, treat it
exactly like a literal string variable — quote it where the shell needs
quoting, but never alter its content.
EOF
```

Skip this and simple Q&A about secrets still works (the model reasons over the placeholder), but operational outputs that *use* the secret (vault, sops, etc.) silently break because the placeholder gets paraphrased.

## 8. Validate the deploy with the automated gate

```bash
sudo bash /opt/waterwall/tools/verify-deploy.sh
```

This runs every acceptance gate end-to-end: `/healthz` 200 · `verify-install --runtime` 10/10 · a redaction round-trip (`AKIAIOSFODNN7EXAMPLE` → placeholder → upstream → restored) · the agent roundtrip (vault command preserves the placeholder; substitution restores) · kill-switch arm/502/disarm cycle · `verify-chain` on the resulting log. PASS on all = production-ready; any FAIL prints which gate failed and the next diagnostic.

## 9. Configure the SessionStart hook (recommended)

The pre-launch hook surfaces a warning when the proxy is down or kill-switched. Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "*",
        "hooks": [{ "type": "command", "command": "/opt/waterwall/.venv/bin/waterwall pre-launch-hook" }]
      }
    ]
  }
}
```

Note SessionStart hooks **cannot hard-block** a Claude Code session — the hook emits a SessionStart `additionalContext` warning and exits 1, and the warning shows in-session. For a hard refusal-to-launch, use the `deploy/wrappers/waterwall-launch` wrapper, which gates `exec claude` on that exit code. Test it: stop the proxy and confirm the warning appears (wrapper refuses); restart and confirm normal launch.

## 10. Operate

Day-to-day commands, diagnostics, recovery: **`docs/runbook.md`**. The TUI dashboard gives live visibility — `/opt/waterwall/deploy/waterwall-tui` runs it always-on in tmux (create-or-attach, respawns on quit).

## Migration to a new host

1. Stop and disable the old service: `sudo systemctl stop waterwall-proxy && sudo systemctl disable waterwall-proxy`
2. Rsync persistent state to the new host:
   - `/etc/waterwall/` (CA, signing key, patterns, config, `permitted_hosts.yaml`) — **keep `signing.key` mode 0440 root:waterwall**
   - `/var/log/waterwall/` (chain log, receipts, manifests) — for evidence continuity
3. Install through steps 1–5. `install.sh` is idempotent — it leaves an existing `signing.key`/CA/`permitted_hosts.yaml` alone.
4. Start: `sudo systemctl start waterwall-proxy`
5. Run the gate: `sudo bash /opt/waterwall/tools/verify-deploy.sh`
6. Update each client's `HTTPS_PROXY` if the new host has a different IP/hostname.

The chain log now **resumes `seq`/`prev_hash` across restarts** (Argus #8), so a copied chain continues verifiably on the new host without a manual rotate. If you *want* a clean break (e.g. a major version cutover), stop the proxy and run `sudo /opt/waterwall/bin/waterwall rotate-chain` (full shim path, since `sudo` won't find the venv on PATH) — it appends a properly-chained terminal rotation entry and archives the old log so the archive still passes `verify-chain`.

## Decommission

1. Stop and disable: `sudo systemctl stop waterwall-proxy && sudo systemctl disable waterwall-proxy`
2. Optionally export a final evidence bundle for archival:
   ```bash
   sudo /opt/waterwall/.venv/bin/waterwall export-evidence \
     --chain /var/log/waterwall/proxy.jsonl \
     --receipts-dir /var/log/waterwall/receipts \
     --manifests-dir /var/log/waterwall/manifests \
     --policy /etc/waterwall/patterns.py \
     --pubkey /etc/waterwall/signing.pub \
     --signing-key /etc/waterwall/signing.key \
     --out /tmp/waterwall-final-evidence.tar.gz
   ```
3. Securely shred the signing key: `sudo shred -u /etc/waterwall/signing.key` (the public key can stay)
4. Remove the units: `sudo rm /etc/systemd/system/waterwall-proxy*.{service,timer}; sudo systemctl daemon-reload`
5. Optional: remove `/opt/waterwall`, `/var/log/waterwall`, `/run/waterwall`, `/etc/waterwall` once you've archived anything you want

## Troubleshooting deployment

| Symptom | Likely cause | Fix |
|---|---|---|
| `systemctl start` fails immediately | `ExecStartPre` `verify-install` failed (CA mismatch, missing signing key, unparseable patterns) | `journalctl -u waterwall-proxy` shows the failing check; fix it (often `regen-ca` after editing `permitted_hosts.yaml`) |
| `/healthz` returns 503 | A health probe failed (signer key unreadable, pattern count < 16, upstream unreachable, chain not intact) | `curl -s http://127.0.0.1:8889/healthz \| jq` shows which; fix the underlying issue |
| `verify-install` fails after `regen-ca` | CA permitted set no longer matches `permitted_hosts.yaml` | Re-run `regen-ca` against the current yaml; they must agree exactly |
| `claude /login` fails `permitted subtree violation` | `HTTPS_PROXY` was set during login | `unset HTTPS_PROXY` and retry |
| `claude --print "..."` returns 401 | No cached auth token | `claude /login` (without proxy) first |
| `claude --print` stalls 5–10 min when killswitch armed | Claude SDK's exponential backoff on 5xx | Expected; confirm with a direct `curl -x http://127.0.0.1:8888 …` (returns 502 immediately) |
| TLS handshake fails for a non-API host | That host isn't in `permitted_hosts.yaml` and isn't in `NO_PROXY` | Add it to `NO_PROXY` (telemetry/updates) — the CA is constrained by design |
| TUI panels show "proxy offline" but curl `/healthz` works | TUI started before the service | Quit the TUI (`[q]`) and relaunch |

If you hit something not in the table, `journalctl -u waterwall-proxy --since "1h ago"` is the first place to look. The runbook has more diagnostic recipes.
