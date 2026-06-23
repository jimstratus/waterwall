[CmdletBinding()]
param(
    [switch]$RemoveData,
    [string]$DataRoot = "C:\ProgramData\Waterwall",
    [string]$NssmPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'waterwall-proxy'

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

function Get-NssmExecutable {
    param(
        [string]$DataRoot,
        [string]$SuppliedPath
    )

    if ($SuppliedPath) {
        return (Resolve-Path $SuppliedPath).Path
    }

    $command = Get-Command nssm.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    foreach ($candidate in @(
        (Join-Path $DataRoot 'nssm\nssm-2.24\win64\nssm.exe'),
        (Join-Path $DataRoot 'nssm\nssm-2.24\win32\nssm.exe')
    )) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw 'Unable to find nssm.exe. Supply -NssmPath or ensure it is on PATH.'
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

Require-Administrator

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
    $nssmExe = Get-NssmExecutable -DataRoot $DataRoot -SuppliedPath $NssmPath
    Invoke-Nssm -Executable $nssmExe -Arguments @('remove', $ServiceName, 'confirm')
    Write-Host "Removed service $ServiceName"
}
else {
    Write-Host "Service $ServiceName is not installed."
}

if ($RemoveData) {
    if (Test-Path $DataRoot) {
        Remove-Item -Path $DataRoot -Recurse -Force
        Write-Host "Removed $DataRoot"
    }
}
else {
    Write-Host "Preserving $DataRoot (CA, signing keys, config, and audit logs)."
    Write-Host 'Re-run with -RemoveData only if you intentionally want to delete operator data.'
}
