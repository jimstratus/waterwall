# TUI Dashboard

`waterwall dashboard` launches a cyberpunk [Textual](https://textual.textualize.io/) TUI for
live operational visibility — Matrix-green for healthy, magenta-red for alarms. It is a
**read-only renderer** that polls `127.0.0.1:8889/admin/state` at 1 Hz on a worker thread, so
it must run on the proxy host and a slow admin endpoint never freezes the UI.

```bash
waterwall dashboard
# always-on in tmux (create-or-attach, respawns on quit):
/opt/waterwall/deploy/waterwall-tui
```

## The six panes

| Pane | Shows |
|---|---|
| **LIVE ACTIVITY** | streaming tail of intercepted flows (OUT magenta, IN green, warn amber, err red) |
| **COUNTERS (5-min)** | rolling redaction / detokenization / unknown-placeholder counts |
| **KILL SWITCH** | the four sources and whether each is asserted |
| **MAP / PATTERNS** | store occupancy and the live pattern count + policy hash |
| **CHAIN / AUDIT** | chain length, last checkpoint, `chain_intact` |
| **ACTIVE SESSIONS** | per-session redaction fingerprints |

## Keymap

| Key | Action |
|---|---|
| `[r]` | Reload patterns (POST `/admin/reload`; surfaces a 500 on refusal) |
| `[k]` | Killswitch arm/disarm modal |
| `[v]` | `verify-install --runtime` |
| `[e]` | Export evidence bundle (date-range pickers) |
| `[t]` | Toggle the live-activity tail |
| `[q]` | Quit |

## Pane status indicators

- `●UP` (green) — proxy healthy, accepting traffic
- `●FAIL` (red) — `/healthz` 503; check signer key, pattern count, chain
- `●ACTIVE` (kill-switch pane) — at least one source asserted
- `●OFFLINE` — admin endpoint unreachable; all panels go red rather than show stale data

## Theme

The dashboard requires 24-bit color, available in any modern terminal (Windows Terminal, tmux
on Linux, `xterm` with `TERM=xterm-256color`). The same palette — matrix green `#00ff41`, cyan
`#00ffff`, hot magenta `#ff00ff`, amber `#ffaa00`, alarm red `#ff003c` on near-black — is the
basis for **this documentation site**, so the docs and the dashboard read as one system.
