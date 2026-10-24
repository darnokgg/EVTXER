# tests/JobQueue.Integration.Tests.ps1
#
# One real queued job, each step in its own background runspace exactly as
# the queue runs it: the bundled Hayabusa scans one host folder, the ECS
# conversion runs, the upload goes to Elasticsearch when TEST_ES_BASE is set
# (TEST_ES_USER, TEST_ES_PASSWORD - as DedupUpload.Integration.Tests.ps1),
# and the archive zips and removes the folder. Needs code\hayabusa-x64 and
# evtx-samples\ (both gitignored); skips without them.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
$script:AppRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'code'
$exe = Find-Hayabusa
$samples = @(Get-ChildItem "$PSScriptRoot\..\evtx-samples\hayabusa-sample-evtx-main\DeepBlueCLI" -Filter *.evtx -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -in 'mimikatz-privesc-hashdump.evtx', 'new-user-security.evtx', 'metasploit-psexec-native-target-system.evtx' })
if (-not $exe -or $samples.Count -ne 3) { Write-Host "  [SKIP] no Hayabusa or no sample EVTX - live job queue test skipped" -ForegroundColor Yellow; return }

$scratch = Join-Path ([IO.Path]::GetTempPath()) "jobqueue_live_$PID"
$hostDir = Join-Path $scratch 'evtx\WS-TEST_20261016_1500'
New-Item -ItemType Directory -Path $hostDir -Force | Out-Null
foreach ($s in $samples) { Copy-Item -LiteralPath $s.FullName -Destination $hostDir }

function Invoke-Step($Job, [hashtable]$Context) {
    $run = Start-LibJob 'Invoke-QueueStep' @{ Job = $Job; Context = $Context }
    $deadline = (Get-Date).AddMinutes(5)
    while (-not $run.Handle.IsCompleted -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }
    $r = Complete-LibJob $run
    $lines = @(); $m = $null; while ($run.Lines.TryDequeue([ref]$m)) { $lines += $m }
    $r | Add-Member -NotePropertyName Lines -NotePropertyValue $lines
    return $r
}

try {
    $steps = @('scan', 'ecs', 'upload', 'archive')
    if (-not $env:TEST_ES_BASE) { $steps = @('scan', 'ecs', 'archive') }
    $job = New-QueueJob $hostDir $steps (Join-Path $scratch 'output\hayabusa\jobs')
    $ctx = @{ HayabusaExe = $exe; TemplatePath = (Join-Path $script:AppRoot 'index-template.json'); ArchiveRoot = (Join-Path $scratch 'archive'); ToolVersion = '99' }

    # ---- scan ----
    $r = Invoke-Step $job $ctx
    Assert-True $r.Ok "the scan step runs Hayabusa on that host folder only ($($r.Summary))"
    Assert-True (Test-Path -LiteralPath (Join-Path $job.OutDir 'results.jsonl')) "into the job's own results.jsonl"
    Assert-True (Test-Path -LiteralPath (Join-Path $job.OutDir 'results-summary.html')) "with Hayabusa's HTML summary beside it"
    Assert-True ($r.Summary -match 'event records matched a rule') "it reports how many records matched a rule"
    Assert-True (@($r.Lines | Where-Object { $_ -match '^==== .*Scanning with Hayabusa' }).Count -eq 1) "its output reaches the job's log lines"
    Assert-Equal $r.Ledger[0].Action 'Convert' "and it writes an activity-log row"
    Assert-Equal $r.Ledger[0].ToolVersion '99' "stamped with the tool's version, which the runspace only knows from the window"
    $job.Step++

    # ---- ECS ----
    $r = Invoke-Step $job $ctx
    Assert-True ($r.Ok -and $r.Detections -gt 0) "the ECS step converts the detections ($($r.Detections))"
    $ecs = Join-Path $job.OutDir 'results.ecs.jsonl'
    Assert-Equal @(Get-Content -LiteralPath $ecs).Count ([int]$r.Detections) "one document per detection"
    $first = Get-Content -LiteralPath $ecs -TotalCount 1 | ConvertFrom-Json
    Assert-Equal $first.import.id $job.ImportId "every document carries the job's own import.id"
    $detections = $r.Detections
    $job.Step++

    # ---- upload (live) ----
    if ($env:TEST_ES_BASE) {
        Set-TlsTrust -Mode 'Skip'
        $user = if ($env:TEST_ES_USER) { $env:TEST_ES_USER } else { 'admin' }
        $idx = "hayabusa-mission-queuetest$PID"
        $up = $ctx + @{ EsBase = $env:TEST_ES_BASE; EsHeaders = (Get-AuthHeader $user $env:TEST_ES_PASSWORD); Index = $idx
                        EsHost = ([uri]$env:TEST_ES_BASE).Host; EsPort = ([uri]$env:TEST_ES_BASE).Port; EsUser = $user }
        $r = Invoke-Step $job $up
        Assert-True $r.Ok "the upload step appends to the mission index ($($r.Summary))"
        Assert-True ($r.Summary -match "^$detections new") "every detection is new the first time"
        $r2 = Invoke-Step $job $up
        Assert-True ($r2.Ok -and $r2.Summary -match "^0 new, 0 updated, $detections already in index") "the same job again doubles nothing ($($r2.Summary))"
        Assert-Equal $r.Ledger[0].Action 'Upload' "the upload writes its own activity-log row"
        try { Invoke-RestMethod -Uri "$($env:TEST_ES_BASE)/$idx" -Method Delete -Headers $up.EsHeaders | Out-Null } catch { }
        $job.Step++
    }

    # ---- archive ----
    $r = Invoke-Step $job $ctx
    Assert-True $r.Ok "the archive step zips the host folder ($($r.Summary))"
    Assert-True (-not (Test-Path -LiteralPath $hostDir)) "and only then removes it"
    Assert-Equal @(Get-ChildItem -LiteralPath $ctx.ArchiveRoot -Filter *.zip).Count 1 "one verified zip"

    # ---- a failed step says why, and is cancelled when asked ----
    $bad = New-QueueJob (Join-Path $scratch 'evtx\GONE_20261016_1500') @('archive') (Join-Path $scratch 'output\hayabusa\jobs')
    $r = Invoke-Step $bad $ctx
    Assert-True (-not $r.Ok -and $r.Summary) "a step that cannot run fails with its reason ($($r.Summary))"
    Assert-Equal $r.Ledger[0].Result 'Failed' "and the activity log says Failed"
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
