# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Waterwall is a Python explicit-HTTPS proxy for a single-operator homelab. It intercepts Claude Code → `api.anthropic.com` traffic and performs **reversible tokenization**: secrets matched by a curated regex set on outbound requests get replaced by deterministic HMAC-SHA256 placeholders `<pl:TYPE:HMAC8>`, then restored on inbound (including streaming SSE). Anthropic's servers never see plaintext.

Read these in order before doing anything substantive:

1. `docs/handoffs/HANDOFF.md` — current execution state (which phases are done, what's next, how to resume)
2. `docs/superpowers/specs/2026-05-05-waterwall-design.md` — design contract (~860 lines). The spec is authoritative; if a plan or test conflicts with it, the spec wins.
3. `docs/superpowers/plans/2026-05-05-waterwall.md` — Plan 1 (redaction core, Phases 0–4)
4. `docs/superpowers/plans/2026-05-05-waterwall-audit-ops.md` — Plan 2 (audit + ops + CLI, Phases 5–7)
5. `docs/superpowers/plans/2026-05-05-waterwall-tui.md` — Plan 3 (TUI + docs, Phases 8–9)
6. `docs/superpowers/lab-notes/phase-{0,1}.md` — Phase 0 and 1 GO verdicts; document the test-host test bed setup

## Build & test

This is a **Python 3.12 package** developed on Windows with the venv at `.venv/`. Use PowerShell, not git-bash.

```powershell
# fresh setup
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"

# run all tests
.\.venv\Scripts\python.exe -m pytest -v

# run a single test
.\.venv\Scripts\python.exe -m pytest tests/test_ca_validator.py::test_validate_accepts_constrained_ca -v

# the CA gen script (mostly used during install on a Linux target, but works locally)
bash deploy/ca/generate_ca.sh /tmp/test-ca 30
```

Tests **do not shell out to openssl** — they use the `cryptography` library directly to build test fixtures, so they run portably on Windows and Linux.

## Deployment targets

| Host | Role | OS | Notes |
|---|---|---|---|
| `test-host` | **Test bed** | Debian (Proxmox CT) | mitmproxy 12.2.2 already installed via pipx; CA at `/etc/waterwall/{ca.pem,ca.key,mitmproxy-ca.pem}`; Claude Code 2.1.131 authenticated. SSH as root. |
| `prod-host` | **Production** (Ansible IAM control-node) | Debian LXC | Final v1 deployment target. Spec §15 systemd hardening table applies here. |

`ssh test-host` and `ssh prod-host` work directly. Everything that touches the IAM control-node MUST go through SSH from this Windows host — never run infrastructure commands on Windows directly.

## Architecture (big picture)

The proxy is a **mitmproxy 12.2.2 addon** on `127.0.0.1:8888`. The addon (`src/waterwall/proxy/addon.py`, currently a skeleton) is loaded by mitmdump at startup and intercepts only `POST /v1/messages` to `api.anthropic.com`.

Outbound flow (designed in spec §5.1):
1. Walker recurses the JSON body, yielding scannable string leaves per the path-allowlist in spec §3.1.
2. Each leaf is regex-matched against the pattern set in spec §8 (16 base + 16 extensions + 1 multi-line PEM block).
3. Matches are replaced with `<pl:TYPE:HMAC8>` placeholders; the original plaintext is stored in a per-process LRU map keyed by HMAC8.
4. Modified body is forwarded to Anthropic.

Inbound flow:
- Non-streaming JSON: walker recurses response, substitutes `<pl:...>` placeholders with stored plaintext.
- Streaming SSE: per-content-block buffering, finalize at `content_block_stop` (spec §5.3 strategy b). Plan 1 ships this as **buffer-the-full-response** (a documented v1 limitation; v1.1 adds true per-chunk streaming via `flow.response.stream`).

Beyond redaction: v1 also ships a Pipelock-inspired audit layer (hash-chained tamper-evident JSONL log + Ed25519-signed checkpoints + per-redaction Action Receipts + per-session Manifests + framework-mapped compliance metadata), a four-source kill switch, hot-reloading patterns, a 10-check verify-install with startup vs runtime modes, a Claude-Code SessionStart pre-launch hook, and a cyberpunk-themed Textual TUI dashboard.

The codebase splits into:

| Package | Role |
|---|---|
| `src/waterwall/proxy/` | mitmproxy addon, walker, tokenizer, store, SSE handler, patterns, kill switch, hot-reload |
| `src/waterwall/audit/` | hash-chain writer, Ed25519 signer, Action Receipts, Session Manifests, framework tag table |
| `src/waterwall/ops/` | healthcheck + admin HTTP endpoints, verify-install, StateAggregator, CA validator |
| `src/waterwall/tui/` | Textual TUI app + 6 panes + modals + cyberpunk CSS |
| `src/waterwall/cli/` | `waterwall` CLI (verify-receipt, verify-chain, export-evidence, verify-evidence, dashboard, pre-launch-hook) |

## Critical operational notes

**mitmproxy 12.2.2 has no `ca_file` option** despite what the original RESEARCH.md said. Use `--set confdir=<dir>` where `<dir>` contains `mitmproxy-ca.pem` (key + cert concatenated). The `deploy/ca/generate_ca.sh` script writes that file alongside `ca.pem` and `ca.key`. The full Phase 1 lab note at `docs/superpowers/lab-notes/phase-1.md` documents this verified-on-test-host.

**verify before invoking** unfamiliar CLI flags inherited from research docs. The `ca_file` mistake above cost ~15 min of debugging that one `mitmdump --options | grep ca_` would have prevented.

**Single-operator threat model.** Don't treat this like a multi-tenant SaaS service — over-paranoid security tangents (long lectures about minimum-privilege keys, defense-in-depth threat-modeling on internal LAN traffic) are not welcome. Calibrate to the actual blast radius.

**v1 silent-failure surfaces.** Several v1.1-deferred items are silent-failure prone (StateAggregator private-attr coupling, escape function non-idempotency, encoded-payload coverage, etc.). Plan 2 has a "Argus external-model review findings" table that lists what's deferred and why; respect it when working on Phase 5+.

## Plan execution conventions

Plans use bite-sized TDD: failing test → run-fail → implement → run-pass → commit. **Each numbered task gets its own commit** (`feat(scope): …`, `test(scope): …`, etc., with the spec section reference in the body where appropriate).

When executing Phase 2+ via `superpowers:subagent-driven-development`, dispatch one named subagent per task. Per-subagent isolation prevents the "agents writing wrong attribute names" failure mode documented in `~/.claude/rules/ca-errors.md`.

**Don't skip argus.** After internal spec/plan reviews approve, run argus (multi-model external review) before locking. Argus already caught one corroborated silent-failure bug (verify-install Check #7 stub) that internal review missed. See `~/.claude/rules/argus-is-not-optional.md`.

## Project state

Current commit: `dcf0385` (the HANDOFF that captured Phase 0/1 GO). Phases 0 and 1 GO; Phases 2-9 pending. The plans were corrected for the mitmproxy 12.2.2 `confdir` discovery and patched per argus external-model review findings before pause.

Resume by reading `docs/handoffs/HANDOFF.md`, then opening Plan 1 at the Phase 2 section.
