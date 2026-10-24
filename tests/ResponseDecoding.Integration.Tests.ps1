# tests/ResponseDecoding.Integration.Tests.ps1
#
# The mirror of the _bulk request-encoding bug. Elasticsearch answers with
# "content-type: application/json" and NO charset, and PowerShell 5.1 then
# decodes the response body as Latin-1. Every non-ASCII character comes back
# mangled.
#
# Where that bites: the upload handler reads existing host names out of a terms
# aggregation and compares them to the batch's host names to decide skip /
# replace / upload. host.name is an ES keyword, matched case-sensitively and
# exactly. A host called "BÜRO-PC" read back as "BÃœRO-PC" matches nothing, so
# the tool would re-upload a host it already holds - or, with Replace ticked,
# fail to delete the old copy first and double it.
#
# Needs a live ES. Set:
#   $env:TEST_ES_BASE  $env:TEST_ES_USER  $env:TEST_ES_PASSWORD
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

if (-not $env:TEST_ES_BASE) {
    Write-Host "  [SKIP] TEST_ES_BASE not set - live response-decoding test skipped" -ForegroundColor Yellow
} else {
    $base = $env:TEST_ES_BASE
    $user = if ($env:TEST_ES_USER) { $env:TEST_ES_USER } else { 'admin' }
    Set-TlsTrust -Mode 'Skip'
    $h = Get-AuthHeader $user $env:TEST_ES_PASSWORD
    $idx = "hayabusa-test-decode-$(Get-Date -Format 'yyyyMMddHHmmss')"

    # U+00FC: 0xFC in Latin-1, 0xC3 0xBC in UTF-8. Decoding the UTF-8 bytes as
    # Latin-1 yields "BÃ¼RO-PC", which is nothing like the stored keyword.
    $hostName = 'B' + [char]0x00FC + 'RO-PC'

    try {
        $doc = @{ '@timestamp' = (Get-Date).ToString('o')
                  ecs = @{ version = '8.11.0' }
                  hayabusa = @{ details = @{}; extra = @{}; level = 'info' }
                  host = @{ name = $hostName } } | ConvertTo-Json -Depth 10 -Compress
        $body = '{"index":{"_index":"' + $idx + '"}}' + "`n" + $doc + "`n"
        $r = Invoke-RestMethod -Uri "$base/_bulk" -Method Post -Headers $h `
                -ContentType 'application/x-ndjson' -Body (ConvertTo-BulkBody $body) -TimeoutSec 60
        Assert-True (-not $r.errors) "the non-ASCII host name indexes cleanly"
        Invoke-RestMethod -Uri "$base/$idx/_refresh" -Method Post -Headers $h -TimeoutSec 30 | Out-Null

        # A host aggregation read back through Invoke-EsJson, the reader every
        # upload query uses.
        $aggBody = '{"size":0,"aggs":{"h":{"terms":{"field":"host.name","size":10000,"missing":"(unknown)"}}}}'
        $agg = Invoke-EsJson -Uri "$base/$idx/_search" -Method Post -Headers $h `
                    -ContentType 'application/json' -Body $aggBody -TimeoutSec 30
        $seen = @($agg.aggregations.h.buckets | ForEach-Object { $_.key })

        Assert-Equal $seen.Count 1                  "the aggregation returns one host bucket"
        Assert-Equal $seen[0] $hostName             "the host name survives the round trip unmangled"

    } finally {
        try { Invoke-RestMethod -Uri "$base/$idx" -Method Delete -Headers $h -TimeoutSec 30 | Out-Null } catch { }
        Set-TlsTrust -Mode 'System'
    }
}

# ---- the shipped read paths must not decode responses themselves ----
$src = Get-ToolSource
Assert-True ($src -notmatch 'aggregations\.h\.buckets[\s\S]{0,40}Invoke-RestMethod') `
    "the host aggregation is not read through Invoke-RestMethod"
Assert-True ($src -match 'Invoke-EsJson') "the tool uses the UTF-8 safe reader"
