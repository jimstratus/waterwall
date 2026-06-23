[CmdletBinding()]
param(
    [string]$DataRoot = "C:\ProgramData\Waterwall",
    [string]$NssmPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'waterwall-proxy'
$NssmUrl = 'https://nssm.cc/release/nssm-2.24.zip'
$AllowHostsPattern = 'api\.anthropic\.com|api\.deepseek\.com|api\.openai\.com|openrouter\.ai'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Require-Administrator {
    if (-not (Test-IsAdministrator)) {
        throw 'Administrator privileges are required. Re-run this script from an elevated PowerShell session.'
    }
}

function Get-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path (Join-Path $scriptDir '..\..')).Path
}

function Get-RepoExecutable {
    param(
        [string]$RepoRoot,
        [string]$Name
    )

    $path = Join-Path $RepoRoot ".venv\Scripts\$Name"
    if (-not (Test-Path $path)) {
        throw "Required executable not found: $path`nRun: .\.venv\Scripts\python.exe -m pip install -e "".[dev]"""
    }
    return $path
}

function Write-FileIfMissing {
    param(
        [string]$Path,
        [string]$Content
    )

    if (-not (Test-Path $Path)) {
        Set-Content -Path $Path -Value $Content -Encoding utf8
    }
}

function Set-PrivateKeyAcl {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return
    }

    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    $existingRules = @($acl.Access)
    foreach ($rule in $existingRules) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
    }

    $fullControl = [Security.AccessControl.FileSystemRights]::FullControl
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $inheritance = [Security.AccessControl.InheritanceFlags]::None
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $systemSid = 'S-1-5-18'
    $administratorsSid = 'S-1-5-32-544'
    foreach ($sid in @(
            (New-Object Security.Principal.SecurityIdentifier $systemSid)
            (New-Object Security.Principal.SecurityIdentifier $administratorsSid)
        )) {
        $accessRule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            $fullControl,
            $inheritance,
            $propagation,
            $allow
        )
        [void]$acl.AddAccessRule($accessRule)
    }

    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Join-NssmArguments {
    param([string[]]$Arguments)

    $escaped = foreach ($argument in $Arguments) {
        if ($argument -match '[\s"]') {
            '"' + ($argument -replace '"', '""') + '"'
        }
        else {
            $argument
        }
    }
    return ($escaped -join ' ')
}

function Get-NssmExecutable {
    param(
        [string]$ToolRoot,
        [string]$SuppliedPath
    )

    if ($SuppliedPath) {
        if (-not (Test-Path $SuppliedPath)) {
            throw "Supplied NSSM path does not exist: $SuppliedPath"
        }
        $resolved = (Resolve-Path $SuppliedPath).Path
        return $resolved
    }

    $command = Get-Command nssm.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $zipPath = Join-Path $ToolRoot 'nssm-2.24.zip'
    $extractRoot = Join-Path $ToolRoot 'nssm-2.24'
    $archDir = if ([Environment]::Is64BitOperatingSystem) { 'win64' } else { 'win32' }
    $downloadedNssm = Join-Path $extractRoot "$archDir\nssm.exe"

    if (-not (Test-Path $downloadedNssm)) {
        Write-Host "nssm.exe not found on PATH; downloading NSSM from $NssmUrl"
        Invoke-WebRequest -Uri $NssmUrl -OutFile $zipPath
        if (Test-Path $extractRoot) {
            Remove-Item -Path $extractRoot -Recurse -Force
        }
        Expand-Archive -Path $zipPath -DestinationPath $ToolRoot -Force
    }

    if (-not (Test-Path $downloadedNssm)) {
        throw "Downloaded NSSM archive did not contain $archDir\nssm.exe"
    }

    return $downloadedNssm
}

function Invoke-Nssm {
    param(
        [string]$Executable,
        [string[]]$Arguments
    )

    & $Executable @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "nssm failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
}

function Ensure-WaterwallFiles {
    param(
        [string]$RepoRoot,
        [string]$PythonExe,
        [string]$WaterwallExe,
        [string]$DataRoot
    )

    $logsDir = Join-Path $DataRoot 'logs'
    $nssmDir = Join-Path $DataRoot 'nssm'
    foreach ($path in @($DataRoot, $logsDir, $nssmDir)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }

    $patternsPath = Join-Path $DataRoot 'patterns.py'
    $configPath = Join-Path $DataRoot 'config.yaml'
    $hostsPath = Join-Path $DataRoot 'permitted_hosts.yaml'

    Write-FileIfMissing -Path $patternsPath -Content @'
# Waterwall pattern EXTENSIONS — entries here are ADDED to the built-in
# patterns (src/waterwall/proxy/patterns.py); do NOT repeat a built-in.
# A duplicate produces overlapping scan spans for the same secret (issue #21).
# Each entry is a (TYPE, regex) tuple, e.g.:
#     ("MY_INTERNAL_TOKEN", r"\bmytok_[A-Za-z0-9]{32}\b"),
PATTERNS = [
]
'@

    Write-FileIfMissing -Path $configPath -Content @'
kill_switch: false
'@

    Write-FileIfMissing -Path $hostsPath -Content @'
hosts:
  - host: api.anthropic.com
    sse_handler: anthropic
  - host: api.deepseek.com
    sse_handler: openai
  - host: api.openai.com
    sse_handler: openai
  - host: openrouter.ai
    sse_handler: openai
'@

    $requiredCaFiles = @(
        Join-Path $DataRoot 'ca.pem'
        Join-Path $DataRoot 'ca.key'
        Join-Path $DataRoot 'mitmproxy-ca.pem'
    )
    if ($requiredCaFiles.Where({ -not (Test-Path $_) }).Count -gt 0) {
        & $WaterwallExe regen-ca --hosts-file $hostsPath --out-dir $DataRoot
        if ($LASTEXITCODE -ne 0) {
            throw 'waterwall regen-ca failed.'
        }
    }

    $signingKey = Join-Path $DataRoot 'signing.key'
    $signingPub = Join-Path $DataRoot 'signing.pub'
    if ((-not (Test-Path $signingKey)) -or (-not (Test-Path $signingPub))) {
        & $PythonExe -c "from pathlib import Path; from waterwall.audit.signer import generate_keypair; generate_keypair(Path(r'$signingKey'), Path(r'$signingPub'))"
        if ($LASTEXITCODE -ne 0) {
            throw 'Waterwall signing-key generation failed.'
        }
    }

    $privateMaterialFiles = @(
        Join-Path $DataRoot 'ca.key'
        Join-Path $DataRoot 'mitmproxy-ca.pem'
        $signingKey
    )
    foreach ($privateMaterialPath in $privateMaterialFiles) {
        Set-PrivateKeyAcl -Path $privateMaterialPath
    }
}

Require-Administrator

$repoRoot = Get-RepoRoot
$mitmdumpExe = Get-RepoExecutable -RepoRoot $repoRoot -Name 'mitmdump.exe'
$waterwallExe = Get-RepoExecutable -RepoRoot $repoRoot -Name 'waterwall.exe'
$pythonExe = Get-RepoExecutable -RepoRoot $repoRoot -Name 'python.exe'

Ensure-WaterwallFiles -RepoRoot $repoRoot -PythonExe $pythonExe -WaterwallExe $waterwallExe -DataRoot $DataRoot

$logsDir = Join-Path $DataRoot 'logs'
$nssmDir = Join-Path $DataRoot 'nssm'
$nssmExe = Get-NssmExecutable -ToolRoot $nssmDir -SuppliedPath $NssmPath
$addonPath = Join-Path $repoRoot 'src\waterwall\proxy\addon.py'

$envPairs = @(
    'HTTPS_PROXY=',
    'NO_PROXY=127.0.0.1,localhost',
    "WATERWALL_CHAIN=$DataRoot\logs\proxy.jsonl",
    "WATERWALL_SIGNING_KEY=$DataRoot\signing.key",
    "WATERWALL_PATTERNS=$DataRoot\patterns.py",
    "WATERWALL_CONFIG=$DataRoot\config.yaml",
    "WATERWALL_PERMITTED_HOSTS=$DataRoot\permitted_hosts.yaml",
    'WATERWALL_ADMIN_PORT=8889'
)

$mitmArguments = @(
    '-s', $addonPath,
    '--allow-hosts', $AllowHostsPattern,
    '--listen-host', '127.0.0.1',
    '-p', '8888',
    '--set', 'stream_large_bodies=10m',
    '--set', "confdir=$DataRoot",
    '--set', 'script_reloader=false',
    '--set', 'upstream_cert=false'
)
$mitmArgumentLine = Join-NssmArguments -Arguments $mitmArguments

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Service $ServiceName already exists; replacing it."
    if ($existingService.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
    Invoke-Nssm -Executable $nssmExe -Arguments @('remove', $ServiceName, 'confirm')
}

Invoke-Nssm -Executable $nssmExe -Arguments @('install', $ServiceName, $mitmdumpExe)
Invoke-Nssm -Executable $nssmExe -Arguments @('set', $ServiceName, 'AppParameters', $mitmArgumentLine)
Invoke-Nssm -Executable $nssmExe -Arguments @('set', $ServiceName, 'AppDirectory', $repoRoot)
Invoke-Nssm -Executable $nssmExe -Arguments @('set', $ServiceName, 'Description', 'Waterwall reversible-tokenization egress proxy')
Invoke-Nssm -Executable $nssmExe -Arguments @('set', $ServiceName, 'AppEnvironmentExtra', ($envPairs -join "`n"))
Invoke-Nssm -Executable $nssmExe -Arguments @('set', $ServiceName, 'Start', 'SERVICE_DELAYED_AUTO_START')
Invoke-Nssm -Executable $nssmExe -Arguments @('set', $ServiceName, 'AppExit', 'Default', 'Restart')
Invoke-Nssm -Executable $nssmExe -Arguments @('set', $ServiceName, 'AppRestartDelay', '5000')
Invoke-Nssm -Executable $nssmExe -Arguments @('set', $ServiceName, 'AppStdout', (Join-Path $logsDir 'service.stdout.log'))
Invoke-Nssm -Executable $nssmExe -Arguments @('set', $ServiceName, 'AppStderr', (Join-Path $logsDir 'service.stderr.log'))
Invoke-Nssm -Executable $nssmExe -Arguments @('set', $ServiceName, 'AppRotateFiles', '1')
Invoke-Nssm -Executable $nssmExe -Arguments @('set', $ServiceName, 'AppRotateOnline', '1')
Invoke-Nssm -Executable $nssmExe -Arguments @('set', $ServiceName, 'AppRotateBytes', '10485760')

Write-Host ''
Write-Host "Installed $ServiceName using $nssmExe"
Write-Host 'The service runs as LocalSystem unless you reconfigure the service account.'
Write-Host 'Start:   nssm start waterwall-proxy'
Write-Host 'Stop:    nssm stop waterwall-proxy'
Write-Host 'Status:  nssm status waterwall-proxy'
Write-Host 'Inspect: Get-Service waterwall-proxy'
Write-Host 'Health:  curl.exe http://127.0.0.1:8889/healthz'
