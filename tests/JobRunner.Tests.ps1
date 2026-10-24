# tests/JobRunner.Tests.ps1
#
# Long jobs used to run on the window's own thread. Hayabusa prints nothing
# between "Scanning in progress" and its summary when its output is piped (it
# hides the progress bar without a console), so nothing pumped the dispatcher
# and the window froze for the whole scan - fifteen minutes of "is it dead?".
# These pin the pieces that keep it alive and say what it is doing.
. "$PSScriptRoot\..\code\EvtxCollector.ps1"

$scratch = Join-Path ([IO.Path]::GetTempPath()) "jobrunner_$PID"
New-Item -ItemType Directory -Path $scratch -Force | Out-Null

# ---- elapsed / status text ----
Assert-Equal (Format-JobDuration ([timespan]::FromSeconds(252)))  '04:12'   "minutes and seconds under an hour"
Assert-Equal (Format-JobDuration ([timespan]::FromSeconds(3725))) '1:02:05' "hours once past an hour"
Assert-Equal (Format-JobDuration ([timespan]::Zero))              '00:00'   "zero is 00:00"

$s = Get-JobStatusText -Label 'Hayabusa scan' -Elapsed ([timespan]::FromSeconds(252)) -Cpu ([timespan]::FromSeconds(230)) -Detail '42 files, 1.3 GB'
Assert-Equal $s 'Hayabusa scan - 04:12 elapsed - CPU 03:50 - 42 files, 1.3 GB' "the status names the job, the clock, the CPU and the detail"
$s = Get-JobStatusText -Label 'Collecting' -Elapsed ([timespan]::FromSeconds(5))
Assert-Equal $s 'Collecting - 00:05 elapsed' "no CPU and no detail are simply left out"

# ---- run logs ----
$p = Get-RunLogPath -LogsDir 'C:\x\logs' -Job 'Takajo automagic' -Now ([datetime]'2026-10-12 14:03:09')
Assert-Equal $p 'C:\x\logs\run_takajo-automagic_20261012_140309.txt' "a run log is named after the job and the time"

# ---- the log pane width survives a restart, but never a bad value ----
Assert-Equal (ConvertTo-LogPaneWidth '612') 612.0 "a saved width is used"
Assert-Equal (ConvertTo-LogPaneWidth '') 460.0 "no saved width means the default"
Assert-Equal (ConvertTo-LogPaneWidth 'garbage') 460.0 "a garbled file means the default"
Assert-Equal (ConvertTo-LogPaneWidth '40') 280.0 "too narrow is widened to the floor"
Assert-Equal (ConvertTo-LogPaneWidth '9000' -Max 900) 900.0 "too wide is capped"

# ---- Hayabusa arguments live in one place ----
$a = Get-HayabusaScanArgs -EvtxDir 'C:\e' -OutFile 'C:\o\results.jsonl' -HtmlReport 'C:\o\results-summary.html'
foreach ($flag in '-w', '-O', '-b', '-C') { Assert-True ($a -contains $flag) "the scan always passes $flag" }
Assert-Equal ($a[0]) 'dfir-timeline' "the scan uses dfir-timeline (Hayabusa 4)"
Assert-Equal ($a[$a.IndexOf('-t') + 1]) 'JSONL' "JSONL by default"
Assert-Equal ($a[$a.IndexOf('-H') + 1]) 'C:\o\results-summary.html' "the HTML results summary is requested"
Assert-True ($a -notcontains '-q') "the main pass keeps its banner and summary"
$c = Get-HayabusaScanArgs -EvtxDir 'C:\e' -OutFile 'C:\o\results.csv' -Format csv -Quiet
Assert-Equal ($c[$c.IndexOf('-t') + 1]) 'csv' "the CSV pass asks for csv"
Assert-True ($c -contains '-q' -and $c -contains '-N') "the CSV pass is quiet and skips the summary"
Assert-True ($c -notcontains '-H') "the CSV pass writes no second HTML report"

# ---- Takajo in a console keeps its progress bar ----
$t = Get-TakajoArgs -Command automagic -TakajoDir 'C:\t' -Timeline 'C:\r.jsonl' -OutDir 'C:\o' -ShowProgress
Assert-True ($t -notcontains '--skipProgressBar') "-ShowProgress lets Takajo draw its bar"
$t = Get-TakajoArgs -Command automagic -TakajoDir 'C:\t' -Timeline 'C:\r.jsonl' -OutDir 'C:\o'
Assert-True ($t -contains '--skipProgressBar') "captured runs still suppress it"

# ---- the process pump: output arrives while the program runs ----
Initialize-ProcessPump
$pump = New-Object EvtxerProcessPump('cmd.exe', '/c echo out-line& echo err-line 1>&2& exit 3', $scratch)
$lines = @()
$deadline = (Get-Date).AddSeconds(20)
while (-not $pump.IsDone -and (Get-Date) -lt $deadline) { $lines += $pump.Drain(); Start-Sleep -Milliseconds 50 }
$lines += $pump.Drain()
Assert-True $pump.IsDone "the pump reports the program finished"
Assert-True ($lines -contains 'out-line') "stdout is captured"
Assert-True (($lines | ForEach-Object { $_.Trim() }) -contains 'err-line') "stderr is captured"
Assert-Equal $pump.ExitCode 3 "the exit code comes through"
Assert-True ($pump.CpuTime -is [timespan]) "CPU time is readable"
$pump.Dispose()

# Kill ends a long runner promptly, and a prompt on stdin cannot block it.
$pump = New-Object EvtxerProcessPump('cmd.exe', '/c ping -n 30 127.0.0.1', $scratch)
Start-Sleep -Milliseconds 300
$pump.Kill()
$deadline = (Get-Date).AddSeconds(10)
while (-not $pump.IsDone -and (Get-Date) -lt $deadline) { [void]$pump.Drain(); Start-Sleep -Milliseconds 50 }
Assert-True $pump.IsDone "Kill ends the program"
$pump.Dispose()
$pump = New-Object EvtxerProcessPump('cmd.exe', '/c set /p x=type something: ', $scratch)
$deadline = (Get-Date).AddSeconds(10)
while (-not $pump.IsDone -and (Get-Date) -lt $deadline) { [void]$pump.Drain(); Start-Sleep -Milliseconds 50 }
Assert-True $pump.IsDone "a program waiting on stdin gets EOF instead of hanging the job"
$pump.Dispose()

# ---- console mode: the wrapper reports the exit code before the window closes ----
$rc = Join-Path $scratch 'rc.txt'
$wrapper = New-ConsoleRunScript -Exe 'cmd.exe' -Arguments @('/c', "exit 7") -ExitCodeFile $rc -Title "it's a test" -NoPause
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapper))
$proc = Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc) `
            -WindowStyle Hidden -PassThru -Wait
Assert-True (Test-Path $rc) "the wrapper writes the exit-code file"
Assert-Equal ((Get-Content $rc -Raw).Trim()) '7' "the file holds the program's exit code"
Assert-Equal $proc.ExitCode 7 "and the wrapper exits with it"
Assert-True ($wrapper -match "it''s a test") "single quotes in literals are escaped"
Assert-True (-not ($wrapper -match 'Read-Host')) "-NoPause leaves out the keypress"
Assert-True ((New-ConsoleRunScript -Exe 'x.exe' -Arguments @() -ExitCodeFile $rc -Title 't') -match 'Read-Host') `
    "a real console run waits for Enter so the summary can be read"

# The exit-code file is read as a number or not at all - never an empty 0.
$rcf = Join-Path $scratch 'rc2.txt'
Assert-Equal (Read-ExitCodeFile $rcf) $null "no file yet means not finished"
[IO.File]::WriteAllText($rcf, '')
Assert-Equal (Read-ExitCodeFile $rcf) -1 "an empty file is a failure, not success"
[IO.File]::WriteAllText($rcf, "0`r`n")
Assert-Equal (Read-ExitCodeFile $rcf) 0 "a written 0 is success"
$neverRan = New-ConsoleRunScript -Exe (Join-Path $scratch 'missing.exe') -Arguments @() -ExitCodeFile (Join-Path $scratch 'rc3.txt') -Title 't' -NoPause
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($neverRan))
Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc) -WindowStyle Hidden -Wait
Assert-Equal (Read-ExitCodeFile (Join-Path $scratch 'rc3.txt')) -1 "a program that never started reports -1, not 0"

# Arguments survive the console wrapper: curly quotes, and a trailing backslash
# after a space. cmd's echo shows exactly what the program received.
$echoOut = Join-Path $scratch 'echo.txt'
$odd = @("C:\Cases\O$([char]0x2019)Brien", 'C:\My Cases\')
$w2 = New-ConsoleRunScript -Exe 'cmd.exe' -Arguments (@('/c', 'echo') + $odd + @('>', $echoOut)) -ExitCodeFile (Join-Path $scratch 'rc4.txt') -Title 't' -NoPause
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($w2))
Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc) -WindowStyle Hidden -Wait
Assert-Equal (Read-ExitCodeFile (Join-Path $scratch 'rc4.txt')) 0 "a curly apostrophe no longer breaks the wrapper"
Assert-Equal (ConvertTo-PsLiteral "O$([char]0x2019)Brien") "'O$([char]0x2019)$([char]0x2019)Brien'" "typographic quotes are doubled like '"
Assert-Equal (Protect-NativeArgument 'C:\My Cases\') 'C:\My Cases\\' "a trailing backslash after a space is doubled for the native program"
Assert-Equal (Protect-NativeArgument 'C:\Cases\') 'C:\Cases\' "without a space it is passed as it is"

# ---- collection progress, as the operator sees it ----
$pr = @{ HostIndex = 2; HostCount = 5; Host = 'DC01'; Step = 'exporting'; LogIndex = 4; LogCount = 6; LogName = 'Security' }
$v = Get-CollectProgressView $pr 0
Assert-Equal $v.Text 'Host 2/5 DC01 - exporting log 4/6: Security' "exporting names the host and the log"
Assert-True ($v.Fraction -gt 0.2 -and $v.Fraction -lt 0.4) "and sits inside host 2 of 5 ($($v.Fraction))"

$pr = @{ HostIndex = 1; HostCount = 1; Host = 'WS1'; Step = 'downloading'; DownloadDone = 0; DownloadTotal = 880MB }
$v = Get-CollectProgressView $pr 312MB
Assert-Equal $v.Text 'Host 1/1 WS1 - downloading 312 / 880 MB' "downloading shows megabytes so far"
Assert-True ($v.Fraction -gt 0.6 -and $v.Fraction -lt 0.9) "a download is the back half of the host ($($v.Fraction))"

$pr = @{ HostIndex = 1; HostCount = 2; Host = 'WS1'; Step = 'copying'; LogIndex = 1; LogCount = 2; LogName = 'Security.evtx'; DownloadDone = 0; DownloadTotal = 20MB }
$v = Get-CollectProgressView $pr 10MB
Assert-Equal $v.Text 'Host 1/2 WS1 - copying 1/2: Security.evtx (10 / 20 MB)' "an SMB copy shows the file and its size"
Assert-Equal ([Math]::Round($v.Fraction, 3)) 0.125 "half of the first of two files on the first of two hosts"

$v = Get-CollectProgressView @{} 0
Assert-Equal $v.Fraction -1 "no progress yet means an animated bar, not 0%"

# Exporting and compressing run on the target; without these they showed
# nothing for minutes and looked frozen.
$t0 = [datetime]'2026-10-15T10:00:00Z'
$pr = @{ HostIndex = 1; HostCount = 1; Host = 'DC01'; Step = 'compressing'; StepStarted = $t0; RemoteBytes = 230MB }
$v = Get-CollectProgressView $pr 0 $t0.AddSeconds(75)
Assert-Equal $v.Text 'Host 1/1 DC01 - compressing the exports on the target - 230 MB written (01:15)' "compressing shows what the target has written and for how long"
$pr = @{ HostIndex = 1; HostCount = 1; Host = 'DC01'; Step = 'exporting'; LogIndex = 1; LogCount = 2; LogName = 'Security'; StepStarted = $t0; RemoteBytes = -1 }
$v = Get-CollectProgressView $pr 0 $t0.AddSeconds(9)
Assert-Equal $v.Text 'Host 1/1 DC01 - exporting log 1/2: Security (00:09)' "no size yet (or no second session): the clock alone"
$pr = @{ HostIndex = 1; HostCount = 1; Host = 'WS1'; Step = 'downloading'; DownloadDone = 0; DownloadTotal = 880MB; StepStarted = $t0; RemoteBytes = 5MB }
$v = Get-CollectProgressView $pr 312MB $t0.AddSeconds(3725)
Assert-Equal $v.Text 'Host 1/1 WS1 - downloading 312 / 880 MB (1:02:05)' "a download keeps its own byte count, plus the clock"

# ---- the collection runs off the UI thread, and still logs ----
# 203.0.113.1 is TEST-NET-3: never routed, so the port check fails fast and the
# real collector, the real lib and the real runspace plumbing all run with no
# target. SMB, because WinRM would need TrustedHosts (and Administrator).
$out = Join-Path $scratch 'evtx'
$job = Start-LibJob 'Invoke-EvtxCollection' -Script $script:EvtxCollectorPath -Parameters @{
    Targets = @('203.0.113.1'); Method = 'SMB'; Category = 'DFIR'
    Credential = (New-CollectCredential 'x\y' 'z'); OutRoot = $out
} -Progress ([hashtable]::Synchronized(@{ Cancel = $false; HostCount = 0
                 HostDone = (New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]') }))
$deadline = (Get-Date).AddSeconds(90)
$logged = @()
while (-not $job.Handle.IsCompleted -and (Get-Date) -lt $deadline) {
    $m = $null; while ($job.Lines.TryDequeue([ref]$m)) { $logged += $m }
    Start-Sleep -Milliseconds 100
}
$summary = Complete-LibJob $job
$m = $null; while ($job.Lines.TryDequeue([ref]$m)) { $logged += $m }
Assert-True ($job.Handle.IsCompleted) "the background collection finishes"
Assert-Equal $summary.Attempted 1 "it returns the collector's summary"
Assert-Equal $summary.Failed 1 "an unreachable host fails rather than hanging"
Assert-True (@($logged | Where-Object { $_ -like '==== Target: 203.0.113.1*' }).Count -eq 1) "its log lines reach the queue"
Assert-True (@($logged | Where-Object { $_ -like '*Credentials purged*' }).Count -eq 1) "the cleanup still runs and says so"
Assert-Equal $job.Progress.HostCount 1 "progress knows how many hosts there are"
Assert-Equal $job.Progress.HostDone.Count 0 "a failed host is not handed to the job queue"

# A cancel stops before the next host and offers every unvisited host for retry.
$job = Start-LibJob 'Invoke-EvtxCollection' -Script $script:EvtxCollectorPath -Progress ([hashtable]::Synchronized(@{ Cancel = $true; HostCount = 0 })) -Parameters @{
    Targets = @('203.0.113.1', '203.0.113.2'); Method = 'SMB'; Category = 'DFIR'
    Credential = (New-CollectCredential 'x\y' 'z'); OutRoot = $out
}
$deadline = (Get-Date).AddSeconds(60)
while (-not $job.Handle.IsCompleted -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 100 }
$summary = Complete-LibJob $job
Assert-Equal $summary.Attempted 0 "a cancel before the first host attempts nothing"
Assert-Equal (@($summary.Retry) -join ',') '203.0.113.1,203.0.113.2' "every host not visited is offered for retry"

Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
