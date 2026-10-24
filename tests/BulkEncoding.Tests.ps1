# tests/BulkEncoding.Tests.ps1
#
# PowerShell 5.1's Invoke-RestMethod encodes a *string* body as Latin-1 when
# the Content-Type carries no charset. Every non-ASCII character then reaches
# Elasticsearch as an invalid UTF-8 byte and the whole document is rejected
# with "Invalid UTF-8 start byte". Found for real: two Service Control Manager
# records naming "Intel(R) Graphics Software" with a U+00AE registered sign
# were dropped from a 936-document upload. The 599-file sample
# corpus has no non-ASCII in Details, which is why it never showed before.
#
# The fix is to hand Invoke-RestMethod a byte[], which bypasses its string
# encoding entirely.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$ascii    = '{"index":{"_index":"x"}}'
$nonAscii = '{"Svc":"Intel' + [char]0x00AE + ' Graphics Software"}'

# ---- ASCII is unchanged ----
$a = ConvertTo-BulkBody $ascii
Assert-True ($a -is [byte[]])              "returns a byte array, not a string"
Assert-Equal $a.Length $ascii.Length       "pure ASCII encodes one byte per character"

# ---- non-ASCII must be UTF-8, not Latin-1 ----
# U+00AE is 0xAE in Latin-1 (one byte) and 0xC2 0xAE in UTF-8 (two bytes).
# Length alone therefore distinguishes the correct encoding from the bug.
$b = ConvertTo-BulkBody $nonAscii
Assert-True ($b.Length -gt $nonAscii.Length) "a non-ASCII character encodes to more than one byte"

$hex = ($b | ForEach-Object { $_.ToString('X2') }) -join ''
Assert-True ($hex -match 'C2AE')  "U+00AE is encoded as the UTF-8 pair C2 AE"
Assert-True ($hex -notmatch '22AE') "the bare Latin-1 byte AE does not appear after the quote"

# ---- and it round-trips ----
Assert-Equal ([Text.Encoding]::UTF8.GetString($b)) $nonAscii "UTF-8 decoding returns the original text"

# ---- no BOM: a BOM would corrupt the first line of an ndjson body ----
Assert-True (-not ($a[0] -eq 0xEF -and $a[1] -eq 0xBB -and $a[2] -eq 0xBF)) "no byte-order mark is emitted"

# ---- the shipped upload paths must not pass a raw string any more ----
foreach ($f in 'code\HayabusaMissionTool.ps1') {
    $src = Get-Content (Join-Path $PSScriptRoot "..\$f") -Raw
    Assert-True ($src -notmatch '-Body \$sb\.ToString\(\)') "$f does not post the bulk body as a string"
}

# ---- live round-trip: the only thing that proves Elasticsearch accepts it ----
if (-not $env:TEST_ES_BASE) {
    Write-Host "  [SKIP] TEST_ES_BASE not set - live UTF-8 round-trip skipped" -ForegroundColor Yellow
} else {
    $base = $env:TEST_ES_BASE
    $user = if ($env:TEST_ES_USER) { $env:TEST_ES_USER } else { 'admin' }
    Set-TlsTrust -Mode 'Skip'
    $h = Get-AuthHeader $user $env:TEST_ES_PASSWORD
    $idx = "hayabusa-test-utf8-$(Get-Date -Format 'yyyyMMddHHmmss')"
    $svc = 'Intel' + [char]0x00AE + ' Graphics Software'
    try {
        # The tool's own template first, as the Upload tab does: it maps
        # hayabusa.details as flattened, so the exact-value term query below
        # can match. On a fresh cluster without it the field is analysed text
        # and the term never hits - found 2026-10-16 when this ran first
        # against a new Elasticsearch, before any other test had put it.
        Invoke-RestMethod -Uri "$base/_index_template/hayabusa-evtx" -Method Put -Headers $h -ContentType 'application/json' `
            -Body (Get-Content "$PSScriptRoot\..\code\index-template.json" -Raw) -TimeoutSec 60 | Out-Null
        $doc = @{ '@timestamp' = (Get-Date).ToString('o')
                  ecs = @{ version = '8.11.0' }
                  hayabusa = @{ details = @{ Svc = $svc }; extra = @{}; level = 'info' }
                  host = @{ name = 'ENCODING-TEST' } } | ConvertTo-Json -Depth 10 -Compress
        $body = '{"index":{"_index":"' + $idx + '"}}' + "`n" + $doc + "`n"
        $resp = Invoke-RestMethod -Uri "$base/_bulk" -Method Post -Headers $h `
                    -ContentType 'application/x-ndjson' -Body (ConvertTo-BulkBody $body) -TimeoutSec 60
        Assert-True (-not $resp.errors) "Elasticsearch accepts a document containing U+00AE"

        Invoke-RestMethod -Uri "$base/$idx/_refresh" -Method Post -Headers $h -TimeoutSec 30 | Out-Null

        # Asked server-side on purpose. PowerShell 5.1 also mis-decodes the
        # RESPONSE when Elasticsearch returns application/json without a
        # charset, so comparing a read-back string in PowerShell tests the
        # client's decoder rather than what was stored. Letting Elasticsearch
        # match the term means the index itself decides, and a hit can only
        # happen if the stored bytes equal the bytes we sent.
        $q = '{"size":0,"query":{"term":{"hayabusa.details.Svc":' + (ConvertTo-Json $svc) + '}}}'
        $found = Invoke-RestMethod -Uri "$base/$idx/_search" -Method Post -Headers $h `
                    -ContentType 'application/json' -Body (ConvertTo-BulkBody $q) -TimeoutSec 30
        Assert-Equal ([int]$found.hits.total.value) 1 "Elasticsearch matches the exact non-ASCII value it stored"
    } finally {
        try { Invoke-RestMethod -Uri "$base/$idx" -Method Delete -Headers $h -TimeoutSec 30 | Out-Null } catch { }
        Set-TlsTrust -Mode 'System'
    }
}
