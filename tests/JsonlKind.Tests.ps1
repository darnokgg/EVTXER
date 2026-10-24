# tests/JsonlKind.Tests.ps1
#
# Get-JsonlKind decides whether a file may be uploaded. The mistake it exists
# to stop is selecting output/results.jsonl (raw Hayabusa) instead of
# output/ecs.jsonl (the ECS transform): both are .jsonl, both sit in the same
# folder, and uploading the raw one indexes Timestamp instead of @timestamp
# with no hayabusa.details object, disagreeing with the index template.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$tmp = Join-Path $env:TEMP ("jsonlkind-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

function New-Fixture($Name, $Lines) {
    $p = Join-Path $tmp $Name
    Set-Content -Path $p -Value $Lines -Encoding UTF8
    return $p
}

# Shapes taken from the real files: ecs.jsonl carries @timestamp / ecs.version
# / hayabusa; results.jsonl carries Timestamp / RuleTitle and none of those.
$ecsLine = '{"@timestamp":"2019-04-27T21:04:25.733401Z","ecs":{"version":"8.11.0"},"event":{"kind":"alert"},"hayabusa":{"level":"high","details":{},"extra":{}},"import":{"id":"20260908085437fa4c6679"},"host":{"name":"DC01"}}'
$rawLine = '{"Timestamp":"2019-04-27T21:04:25.733401Z","RuleTitle":"Sticky Key Like Backdoor Usage","Level":"crit","Computer":"DC01","Channel":"Security","EventID":4688,"Details":{},"ExtraFieldInfo":{}}'

try {
    # ---- the two kinds that matter ----
    Assert-Equal (Get-JsonlKind (New-Fixture 'ecs.jsonl' @($ecsLine, $ecsLine))).Kind 'Ecs' `
        "an ECS JSONL line is recognised as Ecs"
    Assert-Equal (Get-JsonlKind (New-Fixture 'results.jsonl' @($rawLine, $rawLine))).Kind 'RawHayabusa' `
        "a raw Hayabusa line is recognised as RawHayabusa, not Ecs"

    # ---- nothing usable ----
    Assert-Equal (Get-JsonlKind (Join-Path $tmp 'nope.jsonl')).Kind 'Missing' "a missing path is Missing"
    Assert-True ((Get-JsonlKind (Join-Path $tmp 'nope.jsonl')).Reason -match 'not found') `
        "a path that was given but does not exist says so, rather than 'no file selected'"
    Assert-True ((Get-JsonlKind '').Reason -match 'No file selected') `
        "an empty path says no file is selected"
    Assert-Equal (Get-JsonlKind (New-Fixture 'empty.jsonl' @())).Kind 'Empty'  "an empty file is Empty"
    Assert-Equal (Get-JsonlKind (New-Fixture 'blank.jsonl' @('', '   ', ''))).Kind 'Empty' `
        "a whitespace-only file is Empty"
    Assert-Equal (Get-JsonlKind (New-Fixture 'junk.jsonl' @('this is not json'))).Kind 'Unknown' `
        "unparseable content is Unknown"
    Assert-Equal (Get-JsonlKind (New-Fixture 'other.jsonl' @('{"alpha":1,"beta":2}'))).Kind 'Unknown' `
        "valid JSON of an unrelated shape is Unknown"

    # ---- the PS 5.1 empty-key hazard ----
    # ConvertFrom-Json cannot create a property with an empty name and rejects
    # the whole line. This is the bug that silently dropped 107 documents. One
    # unparseable sample line must not be allowed to decide the verdict.
    $emptyKeyFirst = @('{"":"C:\\Users\\IEUser\\AppData\\Roaming\\svchost.exe","@timestamp":"2019-04-27T21:04:25Z"}', $ecsLine)
    Assert-Equal (Get-JsonlKind (New-Fixture 'emptykey.jsonl' $emptyKeyFirst)).Kind 'Ecs' `
        "a leading unparseable line does not mask a valid ECS file"

    # ---- blank lines interleaved should not derail classification ----
    Assert-Equal (Get-JsonlKind (New-Fixture 'padded.jsonl' @('', $ecsLine, ''))).Kind 'Ecs' `
        "leading blank lines are skipped"

    # ---- every verdict explains itself, for the readiness strip ----
    foreach ($f in 'ecs.jsonl', 'results.jsonl', 'junk.jsonl', 'empty.jsonl') {
        $r = Get-JsonlKind (Join-Path $tmp $f)
        Assert-True ($r.Reason.Length -gt 0) "$f verdict carries a reason"
    }

    # ---- the import.id has to come back out of the file ----
    # A browsed ecs.jsonl already carries the import.id it was converted with.
    # The tool used to mint a fresh one at upload time and tell the operator to
    # filter on it - an id that appears nowhere in the data.
    Assert-Equal (Get-JsonlImportId (Join-Path $tmp 'ecs.jsonl')) '20260908085437fa4c6679' `
        "the import.id is read back from an ECS file"
    Assert-Equal (Get-JsonlImportId (Join-Path $tmp 'results.jsonl')) '' `
        "a raw Hayabusa file has no import.id to read"
    Assert-Equal (Get-JsonlImportId (Join-Path $tmp 'nope.jsonl')) '' `
        "a missing file yields no import.id"
    Assert-Equal (Get-JsonlImportId (Join-Path $tmp 'junk.jsonl')) '' `
        "an unparseable file yields no import.id"

    # ---- against the real corpus, when it is present ----
    # results.ecs.jsonl is what the tool writes now; ecs.jsonl is the older
    # Python pipeline's name and may still be lying around. Prefer the
    # current one, or this passes against a stale artifact and never sees
    # what the tool actually produces.
    $outDir  = Join-Path $PSScriptRoot '..\output'
    $realEcs = Join-Path $outDir 'results.ecs.jsonl'
    if (-not (Test-Path $realEcs)) { $realEcs = Join-Path $outDir 'ecs.jsonl' }
    $realRaw = Join-Path $outDir 'results.jsonl'
    if ((Test-Path $realEcs) -and (Test-Path $realRaw)) {
        Assert-Equal (Get-JsonlKind $realEcs).Kind 'Ecs'         "real $([IO.Path]::GetFileName($realEcs)) is Ecs"
        Assert-Equal (Get-JsonlKind $realRaw).Kind 'RawHayabusa' "real output/results.jsonl is RawHayabusa"
    } else {
        Write-Host "  [SKIP] output/ecs.jsonl or results.jsonl absent - real-corpus check skipped" -ForegroundColor Yellow
    }
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
