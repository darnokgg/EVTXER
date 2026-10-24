# tests/TlsPinning.Integration.Tests.ps1
#
# The unit tests call Test-PinnedCertificate directly, on a thread that has a
# PowerShell runspace. The TLS stack does not: it invokes the validation
# callback on a worker thread with no runspace, where a PowerShell scriptblock
# cannot run at all. Only a real handshake catches that, so it lives here.
#
# Set TEST_TLS_URL to an https:// URL this machine can reach, e.g.
#   $env:TEST_TLS_URL = 'https://example.com/'
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

if (-not $env:TEST_TLS_URL) {
    Write-Host "  [SKIP] TEST_TLS_URL not set - live TLS pinning test skipped" -ForegroundColor Yellow
} else {
    $uri      = [Uri]$env:TEST_TLS_URL
    $hostName = $uri.Host
    $port     = if ($uri.Port -gt 0) { $uri.Port } else { 443 }

    $tp = Get-ServerCertThumbprint $hostName $port
    Assert-True ($tp -match '^[0-9A-F]{64}$') "fetched a SHA-256 fingerprint from $hostName"

    # -DisableKeepAlive matters: a pooled, already-validated connection is
    # reused without re-running the validation callback, so without it the
    # later legs would pass on a stale verdict and the test would lie.
    function Test-Reaches {
        try {
            Invoke-WebRequest -Uri $env:TEST_TLS_URL -TimeoutSec 20 -UseBasicParsing -DisableKeepAlive | Out-Null
            return $true
        }
        catch {
            # Getting an HTTP response back - 401, 403, 404, anything - means
            # the TLS handshake completed, which is the only thing this test
            # is about. Without this, pointing TEST_TLS_URL at Security Onion
            # itself would report a pinning failure when all that happened was
            # an unauthenticated request being turned away.
            $resp = $null
            try { $resp = $_.Exception.Response } catch { }
            if ($resp) { return $true }
            return $false
        }
    }

    Set-TlsTrust -Mode 'Pin' -PinnedThumbprint $tp
    Assert-True (Test-Reaches) "the correct pin allows the connection"

    Set-TlsTrust -Mode 'Pin' -PinnedThumbprint ('A' * 64)
    Assert-True (-not (Test-Reaches)) "a wrong pin refuses the connection"

    Set-TlsTrust -Mode 'Skip'
    Assert-True (Test-Reaches) "Skip mode connects regardless"

    Set-TlsTrust -Mode 'System'
}
