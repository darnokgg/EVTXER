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

# ---- 2. Security Onion's disk ----
$df = @('Filesystem         1024-blocks      Used Available Capacity Mounted on',
        '/dev/mapper/ol-root   52428800  41943040  10485760      80% /',
        '/dev/mapper/ol-nsm   209715200 167772160  41943040      80% /nsm')
$d = @(ConvertFrom-DfOutput $df)
Assert-Equal $d.Count 2 "df -Pk: one row per path asked, the header skipped"
Assert-Equal $d[0].AvailKB 10485760 "free space of the staging folder's file system"
Assert-Equal $d[1].Mount '/nsm' "and of /nsm, where Security Onion keeps the import and Elasticsearch its data"
Assert-Equal @(ConvertFrom-DfOutput @('EVTXER-STAGED', 'df: /nsm: No such file or directory')).Count 0 "anything else is ignored"

Assert-Equal @(Get-SoDiskWarning $d 1GB).Count 0 "plenty of room: no warning"
$w = @(Get-SoDiskWarning $d 5GB)
Assert-Equal $w.Count 1 "5 GB of EVTX would take /nsm past 85% (a copy plus the indexed events, ~3x)"
Assert-True ($w[0] -match '/nsm' -and $w[0] -match '95%') "the warning names /nsm and when Elasticsearch stops accepting data"
$w = @(Get-SoDiskWarning $d 12GB)
Assert-True (@($w | Where-Object { $_ -match '/tmp' }).Count -eq 1) "more than the staging file system holds: that is said too"
Assert-Equal @(Get-SoDiskWarning @() 50GB).Count 0 "free space that could not be read: no warning, nothing stops"

Assert-True ((Get-SoRemoteCommand Stage '/tmp/x') -match 'df -Pk /tmp /nsm') "read on the staging call already made - no extra connection, no polling"
$imp = [regex]::Match($lib, '(?s)function Invoke-SoImport.*?\n\}').Value
Assert-True ($imp -match 'Get-SoDiskWarning' -and $imp -match 'DiskWarning') "a raw import checks once and reports it"
Assert-True ($imp -notmatch 'throw[^\n]*DiskWarning') "a warning only - it never stops the import"
# In Detail, so it is there on success AND on the failure it predicted -
# the tab, the queue's summary or failure, and the activity log all read it.
Assert-True ($imp -match '(?s)if \(\$r\.DiskWarning\) \{ \$r\.Detail = [^\n]*LOW DISK on the manager[^\n]*\}\s*return \$r') "the warning goes into the result's Detail, last"
$soi = Get-Content (Join-Path $code 'wpf-soimport.ps1') -Raw
Assert-True ($soi -match 'Not imported: \$\(\$s\.Detail\)') "the Raw Events tab shows Detail when an import fails"

# ---- the low-disk path, run for real (review, 2026-10-26: was only a source grep) ----
# Invoke-SoImport against a stand-in for plink/pscp: the staging call answers
# with df rows for a nearly full /nsm, the import then fails - the failure a
# full disk causes. The warning must be logged amber and be in Detail.
$dir = Join-Path ([IO.Path]::GetTempPath()) ("evtxer-lowdisk-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
try {
    $f = Join-Path $dir 'Security.evtx'; [IO.File]::WriteAllBytes($f, (New-Object byte[] 4096))
    $logged = New-Object System.Collections.Generic.List[string]
    $fake = {
        param($p)
        if ($null -ne $p.Capture) {          # an EMPTY list is false in PowerShell
            if ($p.Label -like 'Stage*') {
                foreach ($l in 'EVTXER-STAGED', 'Filesystem 1024-blocks Used Available Capacity Mounted on',
                               '/dev/sda1 52428800 1048576 51380224 2% /',
                               '/dev/sdb1 1048576 1048000 576 99% /nsm') { $p.Capture.Add($l) }
            } elseif ($p.Label -like 'Clean*') { $p.Capture.Add('EVTXER-CLEANED') }
        }
        0
    }
    $r = Invoke-SoImport -Files @(Get-Item -LiteralPath $f) -HostName 'so1' -User 'u' -Password 'p' `
            -HostKey ('SHA256:' + ('A' * 43)) -Run $fake -IsCancelled { $false } -Log { param($t, $k) $logged.Add("$k|$t") }
    Assert-True ($r.DiskWarning -match '/nsm') "the staging call's free space gives a warning for a nearly full /nsm"
    Assert-True ($r.Outcome -ne 'Success' -and $r.Detail -match 'LOW DISK on the manager') "and a failed import carries it in Detail, beside its error"
    Assert-True (@($logged | Where-Object { $_ -like 'warn|LOW DISK ON THE MANAGER*' }).Count -eq 1) "logged once, amber"
} finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }

# The queue keeps it in sight: its own amber line in the window, and on the row.
$wq = Get-Content (Join-Path $code 'wpf-queue.ps1') -Raw
$done = [regex]::Match($wq, '(?s)function Complete-QueueStep.*?\n\}').Value
Assert-True ($done -match "\`$res\.Warning" -and $done -match "Write-Log -Background [^\n]*LOW DISK[^\n]*'warn'" -and $done -match '\$job\.Note = "LOW DISK') "a queued raw import's low-disk warning gets its own amber line and stays on the row"
Assert-True ([regex]::Match($lib, "(?s)'raw' \{.*?\n            \}").Value -match '\$r\.Warning = \$s\.DiskWarning') "the queue step hands the warning back"
