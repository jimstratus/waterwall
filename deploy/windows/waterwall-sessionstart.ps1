[CmdletBinding()]
param(
    [string]$HealthzUrl = "http://127.0.0.1:8889/healthz",
    [string]$ProxyHost = "127.0.0.1",
    [int]$ProxyPort = 8888
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Block {
    param(
        [string]$Reason
    )

    # Argus issue #17: SessionStart hooks have no 'decision' field and exit
    # codes don't block the session. additionalContext is SessionStart's only
    # supported output channel, so the warning at least appears in-session;
    # the exit-1 contract remains for wrapper-style installs that gate on it.
    [Console]::Error.WriteLine("waterwall sessionstart hook: BLOCK - $Reason")
    $payload = [pscustomobject]@{
        hookSpecificOutput = [pscustomobject]@{
            hookEventName     = 'SessionStart'
            additionalContext = "WATERWALL BLOCK: $Reason. Outbound traffic may be UNREDACTED. Stop and fix the proxy before sending secrets."
        }
    }
    $json = $payload | ConvertTo-Json -Compress
    Write-Output $json
    exit 1
}

function Get-JsonResponse {
    param([string]$Url)

    $request = [System.Net.HttpWebRequest]::Create($Url)
    $request.Method = 'GET'
    $request.Timeout = 5000
    $request.ReadWriteTimeout = 5000

    try {
        $response = [System.Net.HttpWebResponse]$request.GetResponse()
        $statusCode = [int]$response.StatusCode
    }
    catch [System.Net.WebException] {
        if (-not $_.Exception.Response) {
            throw
        }
        $response = [System.Net.HttpWebResponse]$_.Exception.Response
        $statusCode = [int]$response.StatusCode
    }

    try {
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $bodyText = $reader.ReadToEnd()
    }
    finally {
        if ($reader) {
            $reader.Dispose()
        }
        $response.Dispose()
    }

    try {
        $body = $bodyText | ConvertFrom-Json
    }
    catch {
        throw "Waterwall /healthz returned non-JSON content."
    }

    return @{
        StatusCode = $statusCode
        Body = $body
    }
}

$proxyReachable = Test-NetConnection -ComputerName $ProxyHost -Port $ProxyPort -InformationLevel Quiet -WarningAction SilentlyContinue
if (-not $proxyReachable) {
    Write-Block -Reason "Waterwall proxy unreachable at $ProxyHost`:$ProxyPort"
}

try {
    $result = Get-JsonResponse -Url $HealthzUrl
}
catch {
    Write-Block -Reason "Waterwall health probe failed at $HealthzUrl`: $($_.Exception.Message)"
}

if ($result.StatusCode -ne 200) {
    Write-Block -Reason "Waterwall /healthz returned $($result.StatusCode)"
}

if ($result.Body.killswitch_active) {
    $sources = $result.Body.killswitch_sources -join ','
    Write-Block -Reason "Waterwall kill switch is active (sources: $sources)"
}

# Healthy: SessionStart has no "allow" payload — exit 0 with no output
# (issue #17), matching the Linux pre-launch-hook contract.
exit 0
