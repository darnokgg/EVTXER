# tests/DedupUpload.Integration.Tests.ps1
#
# Live-ES integration test for per-detection duplicate handling: the upload
# sends "create" with each detection's fixed id (event.id) as _id, so
# Elasticsearch itself refuses a detection it already holds. Exercises the
# same New-BulkActionLine / Get-EcsLineId / Get-BulkTally path the upload
# handler uses, against a real Elasticsearch.
#
# Requires a reachable ES with creds in $env FOR THE TEST ONLY:
#   $env:TEST_ES_BASE      e.g. https://192.0.2.20:9200
#   $env:TEST_ES_USER      optional, defaults to 'admin'
#   $env:TEST_ES_PASSWORD
#
# Uses a scratch hayabusa-test-<timestamp> index and deletes it when done.
# Never touches the live mission index or logs-import-so.
#
# Skips cleanly (prints [SKIP], no failure) when TEST_ES_BASE is not set, so
# the normal offline test harness (run-tests.ps1) stays green without ES.

. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$base = $env:TEST_ES_BASE
if (-not $base) { Write-Host "  [SKIP] TEST_ES_BASE not set - live dedup integration test skipped" -ForegroundColor Yellow; return }

$user = if ($env:TEST_ES_USER) { $env:TEST_ES_USER } else { 'admin' }
$pass = $env:TEST_ES_PASSWORD
# -Mode 'Skip': TEST_ES_BASE may be any Elasticsearch instance, so there is
# no fingerprint to pin.
Set-TlsTrust -Mode 'Skip'
$h = Get-AuthHeader $user $pass
$idx = "hayabusa-test-$(Get-Date -Format 'yyyyMMddHHmmss')"

function ConvertTo-TestLine([int]$Record, [string]$ImportId) {
    $hit = @{ Computer = 'A'; Channel = 'Security'; RecordID = $Record; EventID = 4624
              Timestamp = '2026-10-01T10:00:00.000000Z'; RuleID = 'r1'; RuleTitle = 'Logon'; Level = 'low'
              Details = @{ TgtUser = 'bob' } } | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    ConvertTo-EcsDocument $hit $ImportId | ConvertTo-Json -Depth 12 -Compress
}
function Send-TestBatch([string[]]$Lines) {
    $sb = New-Object Text.StringBuilder
    foreach ($l in $Lines) { [void]$sb.AppendLine((New-BulkActionLine $idx (Get-EcsLineId $l))); [void]$sb.AppendLine($l) }
    $r = Invoke-RestMethod -Uri "$base/_bulk?$($script:BulkFilterPath)" -Method Post -Headers $h `
            -ContentType 'application/x-ndjson' -Body (ConvertTo-BulkBody $sb.ToString()) -TimeoutSec 60
    Invoke-RestMethod -Uri "$base/$idx/_refresh" -Method Post -Headers $h -TimeoutSec 30 | Out-Null
    Get-BulkTally $r
}
function Get-TestCount {
    [long](Invoke-EsJson -Uri "$base/$idx/_count" -Method Get -Headers $h -TimeoutSec 30).count
}

try {
    # First pull: records 1 and 2.
    $t = Send-TestBatch @((ConvertTo-TestLine 1 'first'), (ConvertTo-TestLine 2 'first'))
    Assert-Equal $t.Created 2 "first upload: both detections created"
    Assert-Equal (Get-TestCount) 2 "the index holds 2"

    # The same file again (forgot it was uploaded): nothing doubled.
    $t = Send-TestBatch @((ConvertTo-TestLine 1 'first'), (ConvertTo-TestLine 2 'first'))
    Assert-Equal $t.Created 0   "same batch again: nothing created"
    Assert-Equal $t.Duplicate 2 "both reported as already in the index"
    Assert-Equal $t.Failed 0    "and neither counted as a failure"
    Assert-Equal (Get-TestCount) 2 "the index still holds 2"

    # A re-pull two weeks later, converted again under a new import.id:
    # record 1 rolled out of the log, 2 overlaps, 3 is new.
    $t = Send-TestBatch @((ConvertTo-TestLine 2 'second'), (ConvertTo-TestLine 3 'second'))
    Assert-Equal $t.Created 1   "re-pull: only the new detection is created"
    Assert-Equal $t.Duplicate 1 "the overlap is recognised"
    Assert-Equal (Get-TestCount) 3 "the index holds 3 - the rolled-out record 1 is kept, nothing doubled"

    $firstBody = '{"query":{"term":{"import.id":"first"}}}'
    $kept = [long](Invoke-EsJson -Uri "$base/$idx/_count" -Method Post -Headers $h -ContentType 'application/json' -Body $firstBody -TimeoutSec 30).count
    Assert-Equal $kept 2 "an overlapping detection keeps the import.id of the upload that first brought it"
} finally {
    try { Invoke-RestMethod -Uri "$base/$idx" -Method Delete -Headers $h -TimeoutSec 30 | Out-Null } catch { }
    Set-TlsTrust -Mode 'System'
}

# ---- end to end: convert a timeline, then send the ECS file twice ----
# The same functions the Upload tab calls, on a file, with a small batch so
# the streaming loop crosses several requests.
$idx = "hayabusa-test-e2e-$(Get-Date -Format 'yyyyMMddHHmmss')"
$dir = Join-Path ([IO.Path]::GetTempPath()) ("e2e-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $dir -Force | Out-Null
try {
    $src = Join-Path $dir 'results.jsonl'
    $tpl = '{{"Timestamp":"2026-10-01T10:00:00.000000Z","RuleTitle":"Rule","Level":"high","Computer":"WS01","Channel":"Security","EventID":4624,"RecordID":{0},"RuleID":"r1","Details":{{"TgtUser":"u{0}"}}}}'
    [IO.File]::WriteAllLines($src, [string[]](1..250 | ForEach-Object { $tpl -f $_ }))
    $ecs = Join-Path $dir 'results.ecs.jsonl'
    $null = Convert-HayabusaJsonlToEcs -Source $src -Destination $ecs -ImportId 'e2e' -Workers 1
    Invoke-RestMethod -Uri "$base/_index_template/hayabusa-evtx" -Method Put -Headers $h -ContentType 'application/json' `
        -Body (Get-Content "$PSScriptRoot\..\code\index-template.json" -Raw) -TimeoutSec 60 | Out-Null

    $batches = 0
    $t = Send-EcsFile -Base $base -Headers $h -Index $idx -Path $ecs -BatchSize 100 -OnBatch { param($x) $script:batches++ }
    Invoke-RestMethod -Uri "$base/$idx/_refresh" -Method Post -Headers $h -TimeoutSec 30 | Out-Null
    Assert-Equal $script:batches 3 "250 documents went out as 3 requests of at most 100"
    Assert-Equal $t.Created 250 "every document created"
    Assert-Equal (Get-TestCount) 250 "the index holds 250"

    $t = Send-EcsFile -Base $base -Headers $h -Index $idx -Path $ecs -BatchSize 100
    Invoke-RestMethod -Uri "$base/$idx/_refresh" -Method Post -Headers $h -TimeoutSec 30 | Out-Null
    Assert-Equal "$($t.Created)/$($t.Duplicate)/$($t.Failed)" '0/250/0' "the same file again: all 250 already there, none failed"
    Assert-Equal (Get-TestCount) 250 "the index still holds 250"
    $one = Invoke-EsJson -Uri "$base/$idx/_search?size=1" -Headers $h -TimeoutSec 30
    Assert-Equal $one.hits.hits[0]._id $one.hits.hits[0]._source.event.id "the document's _id is its event.id"

    # "Update detections already in the index": overwritten, not doubled.
    $t = Send-EcsFile -Base $base -Headers $h -Index $idx -Path $ecs -BatchSize 100 -Overwrite
    Invoke-RestMethod -Uri "$base/$idx/_refresh" -Method Post -Headers $h -TimeoutSec 30 | Out-Null
    Assert-Equal "$($t.Created)/$($t.Updated)/$($t.Duplicate)/$($t.Failed)" '0/250/0/0' "Update: all 250 replaced in place"
    Assert-Equal (Get-TestCount) 250 "and the index still holds 250"

    # A damaged line (braces balance, not JSON) is a failure, not an abort.
    $bad = Join-Path $dir 'bad.ecs.jsonl'
    [IO.File]::WriteAllLines($bad, [string[]]@('{"event":{"id":"' + ('c' * 40) + '"},"broken": }'))
    $t = Send-EcsFile -Base $base -Headers $h -Index $idx -Path $bad
    Assert-Equal "$($t.Created)/$($t.Failed)" '0/1' "a line Elasticsearch cannot parse is counted as failed and the upload finishes"
} finally {
    try { Invoke-RestMethod -Uri "$base/$idx" -Method Delete -Headers $h -TimeoutSec 30 | Out-Null } catch { }
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    Set-TlsTrust -Mode 'System'
}

# ---- a detection refused for its event fields still lands ----
# winlog.event_data takes whatever fields the evidence has. If one clashes with
# the index (text in one event, an object in another) or the index is past its
# field limit, Elasticsearch refuses the whole document - the alert with it.
# Send-EcsFile sends such a detection again without its event fields, tagged.
$idx = "hayabusa-test-clash-$(Get-Date -Format 'yyyyMMddHHmmss')"
$dir = Join-Path ([IO.Path]::GetTempPath()) ("clash-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $dir -Force | Out-Null
try {
    Invoke-RestMethod -Uri "$base/_index_template/hayabusa-evtx" -Method Put -Headers $h -ContentType 'application/json' `
        -Body (Get-Content "$PSScriptRoot\..\code\index-template.json" -Raw) -TimeoutSec 60 | Out-Null
    $first  = '{"@timestamp":"2026-10-01T10:00:00Z","event":{"id":"' + ('a' * 40) + '","kind":"alert"},"rule":{"name":"one"},"winlog":{"event_data":{"Foo":"text"}}}'
    $second = '{"@timestamp":"2026-10-01T10:00:01Z","event":{"id":"' + ('b' * 40) + '","kind":"alert"},"rule":{"name":"two"},"winlog":{"event_data":{"Foo":{"nested":1},"Bar":"kept?"}}}'
    $f = Join-Path $dir 'clash.ecs.jsonl'
    [IO.File]::WriteAllLines($f, [string[]]@($first, $second))
    $t = Send-EcsFile -Base $base -Headers $h -Index $idx -Path $f
    Invoke-RestMethod -Uri "$base/$idx/_refresh" -Method Post -Headers $h -TimeoutSec 30 | Out-Null
    Assert-Equal "$($t.Created)/$($t.FieldsRefused)/$($t.Failed)" '2/1/0' "both detections land; the clashing one is counted as stored without its fields"
    $two = Invoke-EsJson -Uri "$base/$idx/_doc/$('b' * 40)" -Headers $h -TimeoutSec 30
    Assert-True ($null -eq $two._source.winlog.event_data) "it is stored without winlog.event_data"
    Assert-True (@($two._source.tags) -contains 'evtxer-fields-refused') "and tagged, so an analyst can find it"
    Assert-Equal $two._source.rule.name 'two' "the detection itself is intact"
} finally {
    try { Invoke-RestMethod -Uri "$base/$idx" -Method Delete -Headers $h -TimeoutSec 30 | Out-Null } catch { }
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    Set-TlsTrust -Mode 'System'
}

# ---- an index created before v37 learns the new mappings ----
$idx = "hayabusa-test-old-$(Get-Date -Format 'yyyyMMddHHmmss')"
try {
    # Old shape: strict root, no winlog.event_data, no dynamic templates.
    Invoke-RestMethod -Uri "$base/$idx" -Method Put -Headers $h -ContentType 'application/json' `
        -Body '{"settings":{"index":{"number_of_replicas":0}},"mappings":{"dynamic":false,"properties":{"winlog":{"properties":{"channel":{"type":"keyword"}}}}}}' -TimeoutSec 60 | Out-Null
    Invoke-EsJson -Uri "$base/$idx/_mapping" -Method Put -Headers $h -ContentType 'application/json' `
        -Body (Get-IndexMappingPatch (Get-Content "$PSScriptRoot\..\code\index-template.json" -Raw)) -TimeoutSec 60 | Out-Null
    $doc = '{"winlog":{"channel":"Security","event_data":{"TargetUserName":"bob","LogonType":3}}}'
    Invoke-RestMethod -Uri "$base/$idx/_doc?refresh=true" -Method Post -Headers $h -ContentType 'application/json' -Body $doc -TimeoutSec 30 | Out-Null
    $hit = Invoke-EsJson -Uri "$base/$idx/_count" -Method Post -Headers $h -ContentType 'application/json' `
        -Body '{"query":{"term":{"winlog.event_data.TargetUserName":"bob"}}}' -TimeoutSec 30
    Assert-Equal $hit.count 1 "after the mapping patch an old index makes winlog.event_data searchable"
} finally {
    try { Invoke-RestMethod -Uri "$base/$idx" -Method Delete -Headers $h -TimeoutSec 30 | Out-Null } catch { }
    Set-TlsTrust -Mode 'System'
}
