# tests/LargeRun.Tests.ps1
#
# Before a run over tens of GB from 30-40 machines (owner, 2026-10-26):
#   1. every detection says which EVTXER made it - agent.* beside
#      event.ingested (the conversion time, already there), so an index
#      with documents from several versions can be told apart;
#   2. a raw import warns when Security Onion's disk is running out - read
#      once per import on the SSH call that stages the files, never polled.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
$code = Join-Path $PSScriptRoot '..\code'

# ---- 1. the version stamp ----
$doc = @{ Computer = 'WS01'; Timestamp = '2026-10-20T08:00:00.000000Z'; Level = 'high'; RuleTitle = 'Net Conn'
          RuleID = 'r1'; EventID = 5156; Channel = 'Security'; RecordID = 7 } | ConvertTo-Json | ConvertFrom-Json
$had = $script:ToolVersion
try {
    $script:ToolVersion = '99'
    $e = ConvertTo-EcsDocument $doc 't'
    Assert-Equal $e.agent.name 'EVTXER' "agent.name says which tool shipped it"
    Assert-Equal $e.agent.type 'evtxer' "agent.type too"
    Assert-Equal $e.agent.version '99' "agent.version is the EVTXER version that converted it"
    Assert-True ($e.event.ingested -match '^\d{4}-\d\d-\d\dT') "and event.ingested is when"
    $script:ToolVersion = '100'
    Assert-Equal (ConvertTo-EcsDocument $doc 't').event.id $e.event.id "the version is not part of the detection id - a new version does not duplicate old detections"
} finally { $script:ToolVersion = $had }

$tpl = Get-Content (Join-Path $code 'index-template.json') -Raw | ConvertFrom-Json
$agent = $tpl.template.mappings.properties.agent.properties
foreach ($f in 'name', 'type', 'version') {
    Assert-Equal $agent.$f.type 'keyword' "agent.$f is mapped (the template is dynamic:false, so an unmapped field cannot be searched)"
}
$lib = Get-Content (Join-Path $code 'HayabusaLib.ps1') -Raw
# An index created by an older EVTXER only learns new fields from the patch
# the upload sends - the template applies only when an index is created.
$patch = Get-IndexMappingPatch (Get-Content (Join-Path $code 'index-template.json') -Raw) | ConvertFrom-Json
Assert-Equal $patch.properties.agent.properties.version.type 'keyword' "appending into an older index maps agent.* there too"
# The conversion workers are separate processes: a real run through two.
$dir = Join-Path ([IO.Path]::GetTempPath()) ("evtxer-stampw-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
$had = $script:ToolVersion
try {
    $script:ToolVersion = '77'
    [IO.File]::WriteAllLines("$dir\r.jsonl", [string[]]@(foreach ($i in 1..40) {
        (@{ Computer = 'WS01'; Timestamp = '2026-10-20T08:00:00.000000Z'; Level = 'low'; RuleTitle = 'R'; RuleID = 'r'
            EventID = 4624; Channel = 'Security'; RecordID = $i } | ConvertTo-Json -Compress) }))
    $c = Convert-HayabusaJsonlToEcs -Source "$dir\r.jsonl" -Destination "$dir\e.jsonl" -ImportId 'w' -EvtxDir $dir -HayabusaDir $dir -Workers 2
    $v = @(Get-Content "$dir\e.jsonl" | ForEach-Object { ($_ | ConvertFrom-Json).agent.version })
    Assert-Equal "$($c.Workers) workers, $($v.Count) docs, $(@($v | Sort-Object -Unique) -join ',')" '2 workers, 40 docs, 77' "every document from the worker processes carries the version"
} finally { $script:ToolVersion = $had; Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
# The hand-run conversion (Show command / README) runs in a fresh console.
$had = $script:ToolVersion
try {
    $script:ToolVersion = '77'
    Assert-True ((Get-ManualEcsCommand -LibPath 'C:\x\HayabusaLib.ps1' -Source 'C:\r.jsonl') -match "\`$script:ToolVersion = '77'") "a hand-run conversion stamps the version too"
} finally { $script:ToolVersion = $had }

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Write-Host "  [SKIP] python not found - twin stamp check skipped" -ForegroundColor Yellow }
else {
    $dir = Join-Path ([IO.Path]::GetTempPath()) ("evtxer-stamp-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    try {
        $in = Join-Path $dir 'in.jsonl'; $out = Join-Path $dir 'out.jsonl'
        [IO.File]::WriteAllLines($in, [string[]]@($doc | ConvertTo-Json -Compress))
        & { $ErrorActionPreference = 'Continue'; & $py.Source -I "$PSScriptRoot\..\scripts\hayabusa_to_ecs.py" $in -o $out --import-id t --hayabusa-dir $dir 2>$null }
        $p = Get-Content -LiteralPath $out -Encoding UTF8 | Select-Object -First 1 | ConvertFrom-Json
        $launcher = Get-Content (Join-Path $code 'HayabusaMissionTool.ps1') -Raw
        $v = [regex]::Match($launcher, "\`$script:ToolVersion = '([^']+)'").Groups[1].Value
        Assert-Equal "$($p.agent.name)|$($p.agent.type)|$($p.agent.version)" "EVTXER|evtxer|$v" "the Python twin stamps the same, with the launcher's version"
    } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
}

# ---- 2. a step's warning stays in sight ----
# Its own amber line in the window, and on the queue row (the raw step's:
# records of the export that could not be read).
$wq = Get-Content (Join-Path $code 'wpf-queue.ps1') -Raw
$done = [regex]::Match($wq, '(?s)function Complete-QueueStep.*?\n\}').Value
Assert-True ($done -match "\`$res\.Warning" -and $done -match "Write-Log -Background [^\n]*Warning[^\n]*'warn'" -and $done -match '\$job\.Note = \$res\.Warning') "a queued step's warning gets its own amber line and stays on the row"
Assert-True ([regex]::Match($lib, "(?s)'raw' \{.*?\n            \}").Value -match '\$r\.Warning = ') "the raw step hands its warning back"
