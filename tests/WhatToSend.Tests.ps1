# tests/WhatToSend.Tests.ps1
#
# One "what to send" choice (v83, owner: raw events were "convoluted and
# not intuitive" - three checkboxes in three places, and raw events only
# meant unticking the Hayabusa scan). The Hayabusa tab picks Detections /
# Detections + raw events / Raw events only; the queue's Send picks the same
# plus Nothing. Raw events only never runs the rules scan.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$scratch = Join-Path ([IO.Path]::GetTempPath()) "whattosend_$PID"
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
$code = Join-Path $PSScriptRoot '..\code'

# ---- the Hayabusa tab's plan ----
$p = Get-ConvertPlan -Make 'det' -FromEvtx $true
Assert-True ($p.Scan -and $p.Ecs -and -not $p.Raw) "Detections: the rules scan and ECS, no raw events"
Assert-Equal $p.Button 'SCAN + CONVERT' "Detections: SCAN + CONVERT"
$p = Get-ConvertPlan -Make 'both' -FromEvtx $true
Assert-True ($p.Scan -and $p.Ecs -and $p.Raw) "Detections + raw events: all three"
Assert-Equal $p.Button 'SCAN + CONVERT' "Detections + raw events: SCAN + CONVERT"
$p = Get-ConvertPlan -Make 'raw' -FromEvtx $true
Assert-True ($p.Raw -and -not $p.Scan -and -not $p.Ecs) "Raw events only: NO rules scan, no detections"
Assert-Equal $p.Button 'EXPORT RAW EVENTS' "Raw events only: the button says what it does"
foreach ($m in 'det', 'both', 'raw') {
    $p = Get-ConvertPlan -Make $m -FromEvtx $false
    Assert-True ($p.Ecs -and -not $p.Scan -and -not $p.Raw -and $p.Make -eq 'det') "an existing JSONL ($m) holds only detections: ECS only"
    Assert-Equal $p.Button 'CONVERT' "an existing JSONL: CONVERT"
}
foreach ($m in 'det', 'both', 'raw') {
    Assert-True ([bool](Get-ConvertPlan -Make $m -FromEvtx $true).Hint) "'$m' says what it writes"
}
Assert-True ((Get-ConvertPlan -Make 'both' -FromEvtx $false).Hint -match 'EVTX') "a JSONL source says raw events need the EVTX folder"

# ---- the queue's Send setting, and the old switches it replaces ----
Assert-Equal (ConvertTo-AutoSend 'on' 'on') 'both' "Hayabusa scan + Raw events was Detections + raw events"
Assert-Equal (ConvertTo-AutoSend 'on' 'off') 'det' "Hayabusa scan alone was Detections"
Assert-Equal (ConvertTo-AutoSend 'off' 'on') 'raw' "Raw events alone was Raw events only"
Assert-Equal (ConvertTo-AutoSend 'off' 'off') 'none' "neither was Nothing"

$def = Read-ToolSettings (Join-Path $scratch 'missing.conf')
Assert-Equal $def.AutoSend 'det' "a fresh install sends the detections"
Assert-Equal $def.AutoUpload 'on' "and uploads them"

$old = Join-Path $scratch 'old.conf'
[IO.File]::WriteAllText($old, '{ "AutoConvert": "off", "AutoUpload": "on", "AutoRaw": "on", "AutoArchive": "off", "MissionName": "x" }')
$s = Read-ToolSettings $old
Assert-Equal $s.AutoSend 'raw' "a v82 settings.conf keeps its choice (raw events alone -> Raw events only)"
Assert-Equal $s.MissionName 'x' "and the rest of it"
Save-ToolSettings $s (Join-Path $scratch 'new.conf')
$saved = [IO.File]::ReadAllText((Join-Path $scratch 'new.conf'))
Assert-True ($saved -match '"AutoSend"' -and $saved -notmatch 'AutoConvert' -and $saved -notmatch 'AutoRaw') "saved again, it holds Send and not the old switches"
Assert-Equal (Read-ToolSettings (Join-Path $scratch 'new.conf')).AutoSend 'raw' "and reads back the same"
# v82 sent raw events even with Upload unticked when the scan was off (the
# box was greyed out then) - the migration must not stop them going out.
[IO.File]::WriteAllText($old, '{ "AutoConvert": "off", "AutoUpload": "off", "AutoRaw": "on" }')
$s = Read-ToolSettings $old
Assert-True ($s.AutoSend -eq 'raw' -and $s.AutoUpload -eq 'on') "v82 raw events alone with a greyed-out Upload off still go to the stack"
[IO.File]::WriteAllText($old, '{ "AutoConvert": "on", "AutoUpload": "off", "AutoRaw": "off" }')
Assert-Equal (Read-ToolSettings $old).AutoUpload 'off' "a v82 Upload off with the scan on stays off"
[IO.File]::WriteAllText($old, '{ "AutoSend": "bogus", "AutoConvert": "on", "AutoRaw": "on" }')
Assert-Equal (Read-ToolSettings $old).AutoSend 'both' "an unknown Send falls back to the old switches"

# ---- which steps a queued host gets ----
$q = { param($send, $up, $arch) (Get-QueueSteps ([pscustomobject]@{ AutoSend = $send; AutoUpload = $up; AutoArchive = $arch })) -join ',' }
Assert-Equal (& $q 'det' 'on' 'off') 'scan,ecs,upload' "Detections: scan, ECS, upload"
Assert-Equal (& $q 'both' 'on' 'on') 'scan,ecs,upload,raw,archive' "Detections + raw events, archive: every step, raw before the archive"
Assert-Equal (& $q 'raw' 'on' 'off') 'raw' "Raw events only: the raw step alone - no rules scan"
Assert-Equal (& $q 'raw' 'off' 'off') 'rawfile' "Raw events only, Upload off: exported and kept, never sent"
Assert-Equal (& $q 'both' 'off' 'off') 'scan,ecs,rawfile' "Upload off: nothing goes out, both files are kept"
Assert-Equal (& $q 'none' 'on' 'on') 'archive' "Nothing: only the archive"
Assert-Equal @(Get-QueueSteps ([pscustomobject]@{ AutoSend = 'none'; AutoUpload = 'on'; AutoArchive = 'off' })).Count 0 "Nothing and no archive: no job at all"
$t = $script:QueueStepText['rawfile']
Assert-True ($t.Short -and $t.Run -and $t.Wait -and $t.Colour) "the kept raw export has its own words and colour on a queue row"

# ---- Show command: both files of one run share an import.id, or the
# Upload tab never pairs them ----
$ecsCmd = Get-ManualEcsCommand -LibPath 'C:\x\HayabusaLib.ps1' -Source 'C:\o\results.jsonl' -WithImportId
$rawCmd = Get-ManualRawCommand -Exe 'C:\h\hayabusa.exe' -EvtxDir 'C:\e' -WorkDir 'C:\o' -LibPath 'C:\x\HayabusaLib.ps1'
foreach ($c in $ecsCmd, $rawCmd) {
    Assert-True ($c -match '-ImportId \$importId' -and $c -match 'if \(-not \$importId\)') "each manual conversion takes the one shared import.id"
}
Assert-True ((Get-ManualEcsCommand -LibPath 'C:\x\HayabusaLib.ps1' -Source 'C:\o\results.jsonl') -notmatch 'importId') "the plain ECS command is as before"

# ---- the windows use them ----
$cv = Get-Content (Join-Path $code 'wpf-convert.ps1') -Raw
foreach ($rb in 'rbMakeDet', 'rbMakeBoth', 'rbMakeRaw') {
    Assert-True ($cv -match "(?s)x:Name=`"$rb`"[^>]*ToolTip=`"") "the Hayabusa tab has $rb, explained"
}
Assert-True ($cv -notmatch 'chkRaw\b') "the old 'Also export every raw event' box is gone"
Assert-True ($cv -match 'Get-ConvertPlan') "the tab acts on Get-ConvertPlan"
Assert-True ($cv -match '(?s)if \(\$plan\.Scan\) \{\s*\$scanned = Invoke-HayabusaScan') "the rules scan runs only when the plan says so"

$qx = Get-Content (Join-Path $code 'wpf-queue.ps1') -Raw
Assert-True ($qx -notmatch 'chkAutoConvert' -and $qx -notmatch 'chkAutoRaw') "the queue's old Hayabusa scan and Raw events boxes are gone"
foreach ($tag in 'det', 'both', 'raw', 'none') {
    Assert-True ($qx -match "(?s)x:Name=`"cboAutoSend`".*?Tag=`"$tag`"") "Send offers '$tag'"
}
$blk = [regex]::Match($qx, '(?s)function Get-QueueBlockers.*?\n\}').Value
Assert-True ($blk -match '\$b\.rawfile') "the kept raw export waits for Hayabusa and a rules update like the others"
Assert-True ($blk -notmatch '\$b\.rawfile = \$send') "but never for the stack - it sends nothing"
Assert-True ($qx -match "-in 'scan', 'ecs', 'raw', 'rawfile'") "it reads the rules, so a rules update waits for it"
Assert-True ($qx -match "\`$network = \`$step -in 'upload', 'raw' -or") "and it is not a network step"

$lib = Get-Content (Join-Path $code 'HayabusaLib.ps1') -Raw
Assert-True ($lib -match "(?s)\{ \`$_ -in 'raw', 'rawfile' \} \{.*?if \(\`$step -eq 'rawfile'\)") "the queue step exports for both, and only 'raw' uploads"
Assert-True ($lib -match "(?s)if \(\`$step -eq 'rawfile'\) \{\s*if \(-not \`$x\.Converted\)") "a kept export of logs with no events says so, not 'send them'"
Assert-True ($cv -match '(?s)if \(\$raw\.Ok -and \$raw\.Converted -and -not \$raw\.Cancelled\)') "a raw-only export with a few unreadable records is still handed to the Upload tab"

Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
