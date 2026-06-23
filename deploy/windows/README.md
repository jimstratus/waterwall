# Windows client-side Waterwall helpers

These scripts address the Windows workstation follow-up items that sit alongside the Windows NSSM service install:

- use a **dedicated Waterwall proxy host** for client traffic instead of pointing the workstation at `prod-host`
- keep the SSH tunnel alive across reboot/logon with **Task Scheduler**
- install a **SessionStart** pre-launch hook that blocks Claude Code when Waterwall is unreachable or kill-switched

## 1. Dedicated Waterwall proxy host

Do not use `prod-host` as the long-term Windows client proxy target. Provision a separate Debian/LXC host and run the existing Linux installer there:

```bash
git clone <repo>
cd waterwall
python3 -m venv .venv && .venv/bin/pip install -e .[dev]
sudo ./deploy/systemd/install.sh
sudo systemctl start waterwall-proxy.service
```

Then export the dedicated host CA to Windows and point the client tunnel at that host. This keeps prod-host's audit chain limited to prod-host-originated traffic.

## 2. Persist the SSH tunnel across reboot

`install_tunnel_task.ps1` registers a **Task Scheduler** entry at logon. It forwards both the proxy port and the admin health port:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\deploy\windows\install_tunnel_task.ps1 -TunnelHost waterwall-client
```

The scheduled task uses:

- `ssh -N`
- `-o ExitOnForwardFailure=yes`
- `-o ServerAliveInterval=30`
- `-L 8888:127.0.0.1:8888`
- `-L 8889:127.0.0.1:8889`

Verify after logon:

```powershell
Test-NetConnection localhost -Port 8888
Test-NetConnection localhost -Port 8889
```

## 3. Install the Claude Code SessionStart hook

`waterwall-sessionstart.ps1` is a PowerShell shim for the spec §11.5 pre-launch contract. It:

- checks the local proxy listener with `Test-NetConnection`
- calls `http://127.0.0.1:8889/healthz`
- exits 0 with no output on success
- exits 1 and emits `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"WATERWALL BLOCK: ..."}}`
  when the proxy is unreachable or the kill switch is active (issue #17:
  SessionStart hooks have no `decision` field and cannot block — the JSON
  surfaces the warning in-session; exit-code gating is for wrapper installs)

Install it into `~/.claude/settings.json` without clobbering existing hooks:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\deploy\windows\install_claude_hook.ps1
```

The installer appends a `SessionStart` command entry for `deploy\windows\waterwall-sessionstart.ps1` and preserves any existing `hooks` entries already present in `settings.json`.

## 4. Windows Claude Code environment

```powershell
$env:HTTPS_PROXY = 'http://127.0.0.1:8888'
$env:NODE_EXTRA_CA_CERTS = 'C:\ProgramData\Waterwall\ca.pem'
$env:CLAUDE_CODE_CERT_STORE = 'bundled,system'
$env:NO_PROXY = '127.0.0.1,localhost,downloads.claude.ai,statsig.anthropic.com,http-intake.logs.us5.datadoghq.com'
```

If you are running Waterwall on the Windows host itself via NSSM, keep the same local env vars and install the hook anyway so `SessionStart` fails early when the service is unhealthy.
