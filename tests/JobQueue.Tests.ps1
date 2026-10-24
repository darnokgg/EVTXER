# tests/JobQueue.Tests.ps1
#
# The job queue (v48): each collected host folder becomes
# one job - scan -> ECS -> upload -> raw import -> archive - run one at a time
# off the window's thread, saved in logs\queue.json so it survives a restart.
# These pin the queue's own rules; JobQueue.Integration.Tests.ps1 runs a real
# job through Hayabusa.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$scratch = Join-Path ([IO.Path]::GetTempPath()) "jobqueue_$PID"
New-Item -ItemType Directory -Path $scratch -Force | Out-Null

# ---- which steps a job gets comes from the queue pane's switches ----
$on = [pscustomobject]@{ AutoConvert = 'on'; AutoUpload = 'on'; AutoRaw = 'on'; AutoArchive = 'on' }
Assert-Equal ((Get-QueueSteps $on) -join ',') 'scan,ecs,upload,raw,archive' "everything on: every step, raw import before the archive"
$def = Read-ToolSettings (Join-Path $scratch 'none.conf')
Assert-Equal ((Get-QueueSteps $def) -join ',') 'scan,ecs,upload' "by default: convert and upload; archive and raw import are the operator's choice"
$noConv = [pscustomobject]@{ AutoConvert = 'off'; AutoUpload = 'on'; AutoRaw = 'off'; AutoArchive = 'on' }
Assert-Equal ((Get-QueueSteps $noConv) -join ',') 'archive' "no upload without the conversion that makes its file"
$off = [pscustomobject]@{ AutoConvert = 'off'; AutoUpload = 'off'; AutoRaw = 'off'; AutoArchive = 'off' }
Assert-Equal @(Get-QueueSteps $off).Count 0 "everything off: no job at all"

# ---- a job ----
$out = Join-Path $scratch 'jobs'
$j1 = New-QueueJob -Folder 'D:\evtx\DC01_20261016_1412' -Steps @('scan', 'ecs', 'upload') -OutRoot $out -Now ([datetime]'2026-10-16 14:20:00')
Assert-Equal $j1.Name 'DC01_20261016_1412' "a job is named after its host folder"
Assert-Equal $j1.OutDir (Join-Path $out 'DC01_20261016_1412') "with its own results folder"
Assert-True (Test-Path -LiteralPath $j1.OutDir) "made at once, so a second job cannot claim it"
$j1b = New-QueueJob -Folder 'D:\evtx\DC01_20261016_1412' -Steps @('scan') -OutRoot $out
Assert-Equal $j1b.OutDir (Join-Path $out 'DC01_20261016_1412-2') "a second job for the same folder never writes over the first one's results"
Assert-True ($j1.ImportId -match '^20261016142000[0-9a-f]{8}$') "its import.id is minted once, for every retry"
Assert-Equal "$($j1.State)/$($j1.Step)" 'queued/0' "it starts queued at its first step"

# ---- saved and read back; a restart never loses it ----
$qf = Join-Path $scratch 'queue.json'
$j2 = New-QueueJob -Folder 'D:\evtx\FS03_20261016_1418' -Steps @('archive') -OutRoot $out
$j2.State = 'running'
Save-JobQueue @($j1, $j2) $qf
$back = Read-JobQueue $qf
Assert-Equal $back.Count 2 "both jobs come back"
Assert-Equal ($back[0].Steps -join ',') 'scan,ecs,upload' "with their steps"
Assert-Equal @($back[1].Steps).Count 1 "a one-step job keeps its step as a list"
Assert-Equal "$($back[1].State)/$($back[1].Step)" 'queued/0' "a job that was running when EVTXER closed goes back in the queue at the same step"
Assert-True ($back[1].Note -match "Interrupted .* 'Archiving'; it starts there again") "and says where it stopped"
Save-JobQueue @($j1) $qf
Assert-Equal @(Read-JobQueue $qf).Count 1 "a queue of one is still a list"
Save-JobQueue @() $qf
Assert-Equal @(Read-JobQueue $qf).Count 0 "an empty queue reads back empty"
Assert-True (-not (Test-Path -LiteralPath "$qf.new")) "the new copy is swapped in, not left beside it"
Assert-Equal @(Read-JobQueue (Join-Path $scratch 'missing.json')).Count 0 "no queue file is an empty queue"
[IO.File]::WriteAllText((Join-Path $scratch 'bad.json'), '{ not json')
Assert-Equal @(Read-JobQueue (Join-Path $scratch 'bad.json')).Count 0 "a damaged queue file does not stop the tool starting"
Assert-True ((Get-Content -LiteralPath $qf -Raw) -notmatch 'assword') "the queue file holds no password field"

# ---- order: the operator's order, then the finished ones ----
function New-J($n, $s) { [pscustomobject]@{ Id = $n; State = $s; Finished = ''; Steps = @('scan'); Step = 0; Note = '' } }
$a = New-J 'a' 'done'; $a.Finished = '2026-10-16T10:00:00'
$b = New-J 'b' 'queued'
$c = New-J 'c' 'running'
$d = New-J 'd' 'failed'
$e = New-J 'e' 'done'; $e.Finished = '2026-10-16T11:00:00'
$f = New-J 'f' 'waiting'
$o = Get-QueueOrder @($a, $b, $c, $d, $e, $f)
Assert-Equal (($o | ForEach-Object Id) -join '') 'bcdfea' "the operator's order - a running job keeps its place - then finished, newest first"
# Found driving the real window: putting the running job first was saved as
# the order, so two hosts swapped places every time one of them ran.
$c.State = 'queued'; $b.State = 'running'
Assert-Equal ((Get-QueueOrder $o | ForEach-Object Id) -join '') 'bcdfea' "a different job running does not reorder the queue"
$o = Move-QueueJob $o 'f' 'next'
Assert-Equal (($o | ForEach-Object Id) -join '') 'fbcdea' "Run next puts it at the top"
$o = Move-QueueJob $o 'f' 'up'
Assert-Equal (($o | ForEach-Object Id) -join '') 'fbcdea' "nothing moves above the top"
$o = Move-QueueJob $o 'c' 'down'
Assert-Equal (($o | ForEach-Object Id) -join '') 'fbdcea' "Move down"
$o = Move-QueueJob $o 'c' 'down'
Assert-Equal (($o | ForEach-Object Id) -join '') 'fbdcea' "nothing moves below the finished jobs"
$o = Move-QueueJob $o 'd' 'up'
Assert-Equal (($o | ForEach-Object Id) -join '') 'fdbcea' "Move up"
Assert-Equal ((Move-QueueJob $o 'e' 'up' | ForEach-Object Id) -join '') 'fdbcea' "a finished job never moves"
Assert-Equal ((Move-QueueJob $o 'zz' 'up' | ForEach-Object Id) -join '') 'fdbcea' "an unknown job changes nothing"

# ---- waiting for the operator ----
$q1 = New-J 'q1' 'queued'; $q1.Steps = @('scan', 'ecs', 'upload'); $q1.Step = 2
$q2 = New-J 'q2' 'queued'
$changed = Update-QueueBlockers @($q1, $q2) @{ upload = 'press VERIFY CONNECTIVITY on the Upload tab' }
Assert-True $changed "a newly blocked job is a change"
Assert-Equal "$($q1.State)|$($q1.Note)" 'waiting|press VERIFY CONNECTIVITY on the Upload tab' "a job whose next step is blocked waits, saying why"
Assert-Equal $q2.State 'queued' "the job behind it is not held up"
Assert-True (-not (Update-QueueBlockers @($q1, $q2) @{ upload = 'press VERIFY CONNECTIVITY on the Upload tab' })) "the same reason again is no change"
[void](Update-QueueBlockers @($q1, $q2) @{})
Assert-Equal "$($q1.State)|$($q1.Note)" 'queued|' "it goes back to the queue by itself once the reason is gone"
$q3 = New-J 'q3' 'failed'
[void](Update-QueueBlockers @($q3) @{ scan = 'x' })
Assert-Equal $q3.State 'failed' "a failed job stays failed until Retry"

# ---- what a row says, and its colour ----
$s = New-J 's' 'queued'; $s.Steps = @('scan', 'ecs', 'upload'); $s.Step = 1
Assert-Equal (Get-QueueStage $s).Text 'Waiting to convert to ECS' "a queued job says what it waits for"
$s.State = 'running'
Assert-Equal (Get-QueueStage $s).Text 'Converting to ECS' "a running one says what it is doing"
Assert-Equal (Get-QueueStage $s).Colour '#A98BD9' "in the colour of that step"
$s.Step = 2; $s.State = 'queued'
Assert-Equal (Get-QueueStage $s).Colour '#4FB8B0' "each step its own colour, so a glance shows how far a host has got"
$s.State = 'waiting'; $s.Note = 'set the mission name on the Settings tab'
Assert-Equal (Get-QueueStage $s).Text 'Waiting for you: set the mission name on the Settings tab' "waiting for the operator says so"
Assert-Equal (Get-QueueStage $s).Colour '#E8B04A' "in amber"
$s.State = 'failed'; $s.Note = 'Hayabusa exited with code 1'
Assert-Equal (Get-QueueStage $s).Text "Failed at 'Uploading': Hayabusa exited with code 1" "a failure names its step and its reason"
$s.Note = 'Cancelled'
Assert-Equal (Get-QueueStage $s).Text "Cancelled at 'Uploading' - Retry goes on from there" "a cancelled job says so, and how to go on"
$s.State = 'done'; $s.Step = 3; $s.Note = ''
Assert-Equal (Get-QueueStage $s).Text 'Done' "and done is done"

# ---- a bar on every row, moving when it works ----
$b = New-J 'b' 'queued'; $b.Steps = @('scan', 'ecs', 'upload', 'raw', 'archive'); $b.Step = 2
$p = Get-QueueJobProgress $b $null
Assert-Equal "$($p.Pct)/$($p.Busy)" '40/False' "a waiting job's bar stands still at how far it got (2 of 5 steps = 40%)"
$b.State = 'running'
$p = Get-QueueJobProgress $b @{ Total = 200; Done = 50 }
Assert-Equal "$($p.Pct)/$($p.Busy)/$($p.Detail)" '45/False/25%' "a step that measures itself fills its own share: 40% + a quarter of 20%"
$p = Get-QueueJobProgress $b @{ Total = 149; Done = 36; Note = 'copying file 37 of 149' }
Assert-Equal $p.Detail 'copying file 37 of 149' "and can say what it counts"
$b.Step = 0
$p = Get-QueueJobProgress $b @{ Total = 0; Cpu = 151 }
Assert-Equal "$($p.Pct)/$($p.Busy)/$($p.Detail)" '0/True/CPU 02:31' "the scan cannot measure itself: a moving bar, with its CPU time climbing"
$p = Get-QueueJobProgress $b @{ Total = 0; Cpu = 0.2 }
Assert-Equal $p.Detail '' "no CPU line before there is any"
$b.Step = 3
$p = Get-QueueJobProgress $b @{ Total = 0; Note = 'Security Onion is importing them'; Cpu = 4 }
Assert-True ($p.Busy -and $p.Detail -eq 'Security Onion is importing them') "nor can so-import-evtx on the manager - and plink's CPU time is not shown as if it were the import's"
$b.Step = 0
$b.State = 'done'
Assert-Equal (Get-QueueJobProgress $b $null).Pct 100.0 "done is a full bar"
$b.State = 'failed'; $b.Step = 3
Assert-Equal (Get-QueueJobProgress $b $null).Pct 60.0 "a failed job's bar stops where it failed"
$p = Get-QueueJobProgress ([pscustomobject]@{ State = 'running'; Steps = @('archive'); Step = 0 }) @{ Total = 10; Done = 99 }
Assert-Equal $p.Pct 100.0 "a count past its total never overfills the bar"

# ---- the manual Archive never takes a folder the queue still needs ----
$h = New-J 'h' 'queued'; $h | Add-Member Folder 'D:\evtx\A'
$k = New-J 'k' 'done';   $k | Add-Member Folder 'D:\evtx\B'
Assert-True (Test-QueueHoldsFolder @($h, $k) 'D:\evtx\A') "a folder a job still needs is held"
Assert-True (-not (Test-QueueHoldsFolder @($h, $k) 'D:\evtx\B')) "a finished job's folder is not"

# ---- the off-the-window runner ----
$lines = New-Object System.Collections.Generic.List[string]
$cap = New-Object System.Collections.Generic.List[string]
$code = Invoke-PumpedTool -Label 'echo' -Exe "$env:SystemRoot\System32\cmd.exe" -Arguments @('/c', 'echo', 'hello secret world', '&', 'exit', '3') `
            -Capture $cap -Mask @('secret') -LogWriter { param($m) $lines.Add($m) }
Assert-Equal $code 3 "it returns the program's exit code"
Assert-True (($cap -join '|') -match 'hello \*{8} world') "its output is captured, with the password masked"
Assert-True (-not ($lines -match 'secret')) "and the password never reaches the log"
$p = [hashtable]::Synchronized(@{ Cancel = $false })
$t0 = Get-Date
$job = Start-LibJob 'Invoke-PumpedTool' @{ Exe = "$env:SystemRoot\System32\ping.exe"; Arguments = @('-n', '30', '127.0.0.1') }
Start-Sleep -Milliseconds 1500
$job.Progress.Cancel = $true
$code = Complete-LibJob $job
Assert-Equal $code -1 "Cancel stops it and says so"
Assert-True (((Get-Date) - $t0).TotalSeconds -lt 15) "at once, not after the program's own 30 seconds"
Assert-True ($job.Lines.Count -gt 0) "and its lines came back from the background runspace"

Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue

# ---- the row's bar is wired to that progress ----
$qsrc = Get-Content "$PSScriptRoot\..\code\wpf-queue.ps1" -Raw
Assert-True ($qsrc -match '<ProgressBar[^>]*Value="\{Binding Pct, Mode=OneWay\}"[^>]*IsIndeterminate="\{Binding Busy, Mode=OneWay\}"') "every row has a bar: filling for a number, moving when it has none"
Assert-True ($qsrc -match 'class EvtxerQueueRow : INotifyPropertyChanged') "rows update in place, so a moving bar never restarts"
