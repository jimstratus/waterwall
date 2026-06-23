# Waterwall pre-launch wrappers

For agents without a native session-start hook system (Hermes Agent, Codex CLI,
and OpenCode if its plugin API has no pre-startup event), use
`waterwall-launch` as a thin wrapper.

## How it works

`waterwall-launch <agent-binary> [args...]`:

1. Calls `waterwall pre-launch-hook` (existing CLI verb, spec §11.5).
2. Gates on its **exit code** — the enforcement contract (argus issue #17:
   Claude Code SessionStart hooks have no `decision` field, so the hook's JSON
   carries only an informational `hookSpecificOutput.additionalContext`
   warning; this wrapper is the actual enforcement point).
3. On nonzero exit: prints the additionalContext warning (best-effort, via jq
   or a grep fallback) to stderr, exits 1. The agent never starts.
4. On exit 0: `exec`s the target binary, forwarding all original args.

## Per-agent install

```bash
sudo cp deploy/wrappers/waterwall-launch /usr/local/bin/waterwall-launch
sudo chmod +x /usr/local/bin/waterwall-launch

# Symlink one wrapper per agent:
sudo ln -sf waterwall-launch /usr/local/bin/waterwall-hermes
sudo ln -sf waterwall-launch /usr/local/bin/waterwall-codex
```

Then update whatever launches the agent (systemd unit, cron, shell alias) to
invoke `waterwall-hermes <real-hermes-args>` instead of `hermes <args>`.

## Expected behavior

| Proxy state | Kill switch | Wrapper exit code | Agent invoked? |
|---|---|---|---|
| running, healthy | disarmed | 0 (then the agent's exit code) | yes |
| down | n/a | 1 | no |
| running | armed | 1 | no |

## Why a shell wrapper, not a Python module?

The wrapper must `exec` the target binary so the agent process replaces the
wrapper PID — process groups, signal handling, and stdin/stdout/stderr behave
exactly as if the user had run the agent directly. A Python wrapper that
`subprocess.run`s the agent would interpose an extra process layer, breaking
this transparency.
