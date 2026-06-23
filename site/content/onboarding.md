# Onboarding & Setup

A cold-start guide: from nothing to an agent whose secrets are tokenized on the wire. The
validated path is a Debian-family Linux host; adjacent releases work unchanged, other
distros may need package-name swaps.

!!! note "The golden rule of client auth"
    **Log your agent in _before_ you enable the proxy.** Waterwall's CA is name-constrained
    to your API hosts only — it deliberately refuses to intercept OAuth callback hosts like
    `console.anthropic.com`. Logging in with the proxy enabled fails with a
    `permitted subtree violation`. Authenticate first, then turn the proxy on.

## 1. Prerequisites

- A 64-bit Debian 13 / Ubuntu 24.04+ host (or similar)
- Python 3.12 or newer (`python3 --version`)
- Network egress on `:443` to your upstream API hosts, plus your OAuth/login host and package mirror
- Root / `sudo` for the install step (the service drops to an unprivileged `waterwall` user at runtime)
- ~500 MB disk for the venv + audit logs
- On your workstation: the agent client installed (e.g. Claude Code CLI)

## 2. Install

```bash
sudo git clone https://github.com/jimstratus/waterwall.git /opt/waterwall
cd /opt/waterwall
sudo python3 -m venv .venv
sudo .venv/bin/pip install -e ".[dev]"
sudo ./deploy/systemd/install.sh
```

The installer is **idempotent** — re-running never clobbers an existing CA, signing key,
config, or host list. It:

- creates the `waterwall` system user/group
- seeds `/etc/waterwall/permitted_hosts.yaml` with the default host set
- generates a **Name-Constrained RSA-4096 CA** at `/etc/waterwall/{ca.pem,ca.key,mitmproxy-ca.pem}`
- generates the **Ed25519 audit signing keypair** at `/etc/waterwall/{signing.key,signing.pub}`
- writes default `patterns.py` + `config.yaml`, creates the log dirs, installs the systemd unit + weekly restart timer, and enables (does not start) the service

## 3. Back up the keys (do not skip)

```text
/etc/waterwall/signing.key   Ed25519 private key — lose it and ALL past audit logs become
                             unverifiable forever. Treat it like a CA root.
/etc/waterwall/signing.pub   public key — safe to share with anyone who verifies evidence.
/etc/waterwall/ca.{pem,key}  the name-constrained CA — needed to re-issue clients after a wipe.
```

Copy these out-of-band **before** you start the service. A disk failure without a backup
means you cannot reconstruct prior audit evidence.

## 4. Start and health-check

```bash
sudo systemctl start waterwall-proxy.service
sudo systemctl status waterwall-proxy.service          # → active (running)
curl -sf http://127.0.0.1:8889/healthz | python3 -m json.tool
```

A startup check (`verify-install`, 10 checks) runs before the proxy launches; a failure
blocks start. A healthy probe shows `"status": "ok"`, `"chain_intact": true`, and a
`"patterns_loaded"` count.

!!! note "upstream_reachable starts false"
    `"upstream_reachable": false` right after a fresh start is normal — it only flips `true`
    once the proxy relays its first upstream response. It does not gate health. Drive one
    request through, then re-probe.

## 5. Authenticate the agent — then enable the proxy

```bash
# a. make sure proxy env vars are NOT set
unset HTTPS_PROXY NODE_EXTRA_CA_CERTS CLAUDE_CODE_CERT_STORE NO_PROXY

# b. log in directly (no proxy)
claude /login
claude --print "ping" | head -3        # should respond, not 401

# c. NOW enable the proxy for session traffic
export HTTPS_PROXY=http://127.0.0.1:8888
export NODE_EXTRA_CA_CERTS=/etc/waterwall/ca.pem
export CLAUDE_CODE_CERT_STORE=bundled,system
export NO_PROXY="127.0.0.1,localhost,downloads.claude.ai,statsig.anthropic.com"
```

The `NO_PROXY` exclusions matter: your client touches update and telemetry hosts that the
name-constrained CA refuses to intercept by design — without excluding them you get TLS
handshake failures. Add the exports to your shell profile so every new session inherits them.

For OpenAI / OpenRouter / other clients, point that client's base URL through
`http://127.0.0.1:8888` with the same `NODE_EXTRA_CA_CERTS`, and confirm its host is in
`permitted_hosts.yaml`.

## 6. (Recommended) the placeholder-preservation protocol

For agent workflows where a response must contain the **actual** secret to be executable
(generating a `vault`/`sops` command, say), append the protocol block from
`docs/claude-md-insert.md` to your `~/.claude/CLAUDE.md`. It tells the model to reproduce
`<pl:TYPE:HEX>` placeholders byte-for-byte instead of paraphrasing them as `<your_key>` —
which is what lets the local detokenizer substitute the real value back. Plain Q&A about
secrets works without it; operational outputs that *use* the secret need it.

## 7. (Recommended) the SessionStart health hook

Add to `~/.claude/settings.json` so each session warns you when the proxy is down or
kill-switched:

```json
{
  "hooks": {
    "SessionStart": [
      { "matcher": "*", "hooks": [{ "type": "command",
        "command": "/opt/waterwall/.venv/bin/waterwall pre-launch-hook" }] }
    ]
  }
}
```

SessionStart hooks can warn but cannot hard-block; for a hard refusal-to-launch, use the
`deploy/wrappers/waterwall-launch` wrapper which gates on the hook's exit code.

## You're done

Drive a request through the proxy and re-probe `/healthz` to watch `upstream_reachable`
flip `true`. From here: the **[Runbook](runbook.html)** for day-to-day operation, the
**[Deploy](deploy.html)** guide for the full production procedure, and the
**[TUI Dashboard](tui.html)** for live visibility.
