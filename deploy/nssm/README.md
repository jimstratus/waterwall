# Windows NSSM service deployment

Waterwall can run as a Windows service via NSSM without changing the existing Debian/systemd deployment path.

## What this installs

- `waterwall-proxy` Windows service
- Delayed auto-start
- Restart-on-failure with a 5-second delay
- Logs under `C:\ProgramData\Waterwall\logs`
- Config, CA, signing keys, and audit artifacts under `C:\ProgramData\Waterwall`

If `nssm.exe` is not already on PATH, `install.ps1` will auto-download the official NSSM zip (`https://nssm.cc/release/nssm-2.24.zip`) into `C:\ProgramData\Waterwall\nssm`. The scripts are pinned to NSSM 2.24 CLI behavior.

## Prerequisites

- Windows PowerShell 5+ or PowerShell 7+
- Python 3.12
- Waterwall installed into the repo-local `.venv`
- Administrator shell
- Internet access for NSSM auto-download if NSSM is missing

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

## Install

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\deploy\nssm\install.ps1
```

The installer reuses repo-local `.venv\Scripts\mitmdump.exe`, `.venv\Scripts\waterwall.exe`, and `.venv\Scripts\python.exe`. It also ensures these files exist under `C:\ProgramData\Waterwall`:

- `ca.pem`
- `ca.key`
- `mitmproxy-ca.pem`
- `signing.key`
- `signing.pub`
- `patterns.py`
- `config.yaml`
- `permitted_hosts.yaml`

> **Warning**
> The installer leaves the service running as LocalSystem unless you reconfigure the service account after install.

## Start / stop / status

```powershell
nssm start waterwall-proxy
nssm stop waterwall-proxy
nssm status waterwall-proxy
Get-Service waterwall-proxy
```

## Verify

```powershell
curl.exe http://127.0.0.1:8889/healthz
.\.venv\Scripts\waterwall.exe verify-install --runtime
```

## Claude Code / Hermes environment on Windows

```powershell
$env:HTTPS_PROXY = 'http://127.0.0.1:8888'
$env:NODE_EXTRA_CA_CERTS = 'C:\ProgramData\Waterwall\ca.pem'
$env:CLAUDE_CODE_CERT_STORE = 'bundled,system'
$env:NO_PROXY = '127.0.0.1,localhost,downloads.claude.ai,statsig.anthropic.com,http-intake.logs.us5.datadoghq.com'
```

## Uninstall

```powershell
.\deploy\nssm\uninstall.ps1
```

By default the uninstall script preserves `C:\ProgramData\Waterwall` so CA material, signing keys, and audit logs are not destroyed accidentally. Use `-RemoveData` only for an intentional teardown.

## Limitations

- NSSM restart supervision is not equivalent to the hardening provided by systemd.
- The service runs under LocalSystem unless you change the service account after install.
- Audit/config files live under `C:\ProgramData\Waterwall`.
- The NSSM download is sourced from the official release zip URL; the installer does not currently verify a published checksum.
