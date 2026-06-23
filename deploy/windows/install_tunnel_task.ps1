[CmdletBinding()]
param(
    [string]$TunnelHost = "waterwall-client",
    [string]$TaskName = "Waterwall SSH Tunnel",
    [int]$LocalProxyPort = 8888,
    [int]$LocalAdminPort = 8889,
    [string]$RemoteHost = "127.0.0.1",
    [int]$RemoteProxyPort = 8888,
    [int]$RemoteAdminPort = 8889
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Join-CommandArguments {
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

$ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue
if (-not $ssh) {
    throw "ssh.exe not found on PATH. Install the Windows OpenSSH client first."
}

$arguments = Join-CommandArguments -Arguments @(
    '-N',
    '-o', 'ExitOnForwardFailure=yes',
    '-o', 'ServerAliveInterval=30',
    '-L', "$LocalProxyPort`:$RemoteHost`:$RemoteProxyPort",
    '-L', "$LocalAdminPort`:$RemoteHost`:$RemoteAdminPort",
    $TunnelHost
)

$action = New-ScheduledTaskAction -Execute $ssh.Source -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Description "Waterwall SSH tunnel to $TunnelHost ($LocalProxyPort/$LocalAdminPort -> $RemoteHost)" `
    -Force | Out-Null

Write-Host "Registered scheduled task '$TaskName' for tunnel host $TunnelHost"
Write-Host "It forwards localhost:$LocalProxyPort and localhost:$LocalAdminPort at logon."
Write-Host "Verify with:"
Write-Host "  Test-NetConnection localhost -Port $LocalProxyPort"
Write-Host "  Test-NetConnection localhost -Port $LocalAdminPort"
