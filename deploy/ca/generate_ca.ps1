# Generate a Name-Constrained CA permitting only api.anthropic.com.
# Spec §3 / Plan 1 Phase 1 / Plan 1 Task 1.1.
# PowerShell variant — Windows operators (Linux operators use generate_ca.sh).

[CmdletBinding()]
param(
    [string]$OutDir = "C:\waterwall\ca",
    [int]$Days = 3650
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$cnf = @'
[ req ]
distinguished_name = req_dn
prompt             = no
x509_extensions    = v3_ca

[ req_dn ]
CN = Waterwall Local CA

[ v3_ca ]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
nameConstraints        = critical, permitted;DNS:api.anthropic.com
'@

$cnfPath = Join-Path $OutDir 'ca.cnf'
$keyPath = Join-Path $OutDir 'ca.key'
$pemPath = Join-Path $OutDir 'ca.pem'

Set-Content -Path $cnfPath -Value $cnf -Encoding ASCII

# Use bundled openssl (Windows ships one with Git for Windows or available
# via `winget install ShiningLight.OpenSSL`). Caller's responsibility to
# have openssl on PATH.
& openssl req -x509 -newkey rsa:4096 -nodes `
    -days $Days `
    -keyout $keyPath `
    -out    $pemPath `
    -config $cnfPath

if ($LASTEXITCODE -ne 0) {
    throw "openssl failed with exit code $LASTEXITCODE"
}

# Restrict ACL on the private key — only the current user can read.
icacls $keyPath /inheritance:r /grant:r "$env:USERNAME:(R)" | Out-Null

Write-Host "CA written to $pemPath"
Write-Host "Private key at $keyPath (current-user read-only)"
