[CmdletBinding()]
param(
    [string]$SettingsPath = (Join-Path $env:USERPROFILE ".claude\settings.json"),
    [string]$HookScriptPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.x leaves $PSScriptRoot and $PSCommandPath empty inside
# param-default expressions when launched via `powershell.exe -File`. Resolve
# the default here in the body where both are reliably populated.
if ([string]::IsNullOrEmpty($HookScriptPath)) {
    $HookScriptPath = Join-Path $PSScriptRoot "waterwall-sessionstart.ps1"
}

$settingsDir = Split-Path -Parent $SettingsPath
New-Item -ItemType Directory -Path $settingsDir -Force | Out-Null

if (Test-Path $SettingsPath) {
    $settings = Get-Content -Raw -Path $SettingsPath | ConvertFrom-Json
}
else {
    $settings = [pscustomobject]@{}
}

if (-not $settings.PSObject.Properties['hooks']) {
    $settings | Add-Member -NotePropertyName hooks -NotePropertyValue ([pscustomobject]@{})
}

if (-not $settings.hooks.PSObject.Properties['SessionStart']) {
    $settings.hooks | Add-Member -NotePropertyName SessionStart -NotePropertyValue @()
}

$command = "powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$HookScriptPath`""
$existingEntries = @($settings.hooks.SessionStart)
$alreadyPresent = $false

foreach ($entry in $existingEntries) {
    if ($entry.matcher -ne '*') {
        continue
    }
    foreach ($hook in @($entry.hooks)) {
        if ($hook.type -eq 'command' -and $hook.command -eq $command) {
            $alreadyPresent = $true
            break
        }
    }
    if ($alreadyPresent) {
        break
    }
}

if (-not $alreadyPresent) {
    $newEntry = [pscustomobject]@{
        matcher = '*'
        hooks = @(
            [pscustomobject]@{
                type = 'command'
                command = $command
            }
        )
    }
    $settings.hooks.SessionStart = @($existingEntries) + $newEntry
}

$json = $settings | ConvertTo-Json -Depth 20
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($SettingsPath, $json, $utf8NoBom)

Write-Host "Updated $SettingsPath"
Write-Host "SessionStart hook command:"
Write-Host "  $command"
