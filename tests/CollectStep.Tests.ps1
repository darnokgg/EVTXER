# tests/CollectStep.Tests.ps1
#
# Cancel used to be checked only between collection steps, so one Copy-Item
# of a big archive kept going for five minutes after the click. Long steps now
# run through Invoke-CollectStep, which stops them in the middle.
#
# Against a REAL PSSession: one to a second local powershell.exe over the named
# pipe Enter-PSHostProcess uses, so neither WinRM nor admin is needed. PS 5.1
# has no public way to wrap that runspace as a PSSession, hence the reflection -
# test-only. Copy-Item -FromSession and Invoke-Command -Session do not care how
# the session is carried.
. "$PSScriptRoot\..\code\EvtxCollector.ps1"

function New-PipeSession {
    $p = Start-Process powershell -ArgumentList '-NoProfile', '-NoExit', '-Command', '$null' -PassThru -WindowStyle Hidden
    $ci = New-Object System.Management.Automation.Runspaces.NamedPipeConnectionInfo($p.Id)
    $rs = [runspacefactory]::CreateRunspace($ci)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ($true) {
        try { $rs.Open(); break }
        catch { if ([DateTime]::UtcNow -gt $deadline) { throw }; Start-Sleep -Milliseconds 300; $rs = [runspacefactory]::CreateRunspace($ci) }
    }
    $ctor = [System.Management.Automation.Runspaces.PSSession].GetConstructors('NonPublic,Instance') |
        Where-Object { $a = $_.GetParameters(); $a.Count -eq 1 -and $a[0].ParameterType.Name -eq 'RemoteRunspace' } |
        Select-Object -First 1
    [pscustomobject]@{ Session = $ctor.Invoke(@($rs)); Process = $p }
}

$pipe = $null
$dir = Join-Path ([IO.Path]::GetTempPath()) ("step-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $dir -Force | Out-Null
try {
    $pipe = New-PipeSession
    $session = $pipe.Session

    # ---- a session made here works from the step's own runspace ----
    $r = Invoke-CollectStep -Script { param($s) Invoke-Command -Session $s -ErrorAction Stop -ScriptBlock { $PID } } -ArgumentList $session
    Assert-Equal ([int](@($r) | Select-Object -Last 1)) $pipe.Process.Id "Invoke-Command through the step reaches the target"

    # ---- errors come back as themselves ----
    $msg = $null
    try { Invoke-CollectStep -Script { param($s) Invoke-Command -Session $s -ErrorAction Stop -ScriptBlock { throw 'remote boom' } } -ArgumentList $session }
    catch { $msg = $_.Exception.Message }
    Assert-Equal $msg 'remote boom' "a remote failure keeps its own message (Get-CollectErrorHint reads it)"
    $msg = $null
    try { Invoke-CollectStep -Script { throw 'local boom' } } catch { $msg = $_.Exception.Message }
    Assert-Equal $msg 'local boom' "a local failure keeps its own message"

    # ---- a whole small file arrives ----
    $small = Join-Path $dir 'small.bin'
    [IO.File]::WriteAllBytes($small, [byte[]](1..255))
    $v = Invoke-StagedCopy -Destination (Join-Path $dir 'small.copy') -Copy {
        param($to) Invoke-CollectStep -Script { param($s, $from, $to) Copy-Item -FromSession $s -Path $from -Destination $to -Force -ErrorAction Stop } `
                       -ArgumentList $session, $small, $to
    }
    Assert-True $v.Ok "Copy-Item -FromSession through the step delivers the file"
    Assert-Equal (Get-FileHash (Join-Path $dir 'small.copy')).Hash (Get-FileHash $small).Hash "byte for byte"

    # ---- Cancel stops a big download in the middle ----
    $big = Join-Path $dir 'big.bin'
    $f = [IO.File]::Create($big); $f.SetLength(400MB); $f.Close()
    $progress = [hashtable]::Synchronized(@{ Cancel = $false })
    $polls = 0
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $cancelAt = $null
    $msg = $null
    try {
        $null = Invoke-StagedCopy -Destination (Join-Path $dir 'big.copy') -Copy {
            param($to) Invoke-CollectStep -Script { param($s, $from, $to) Copy-Item -FromSession $s -Path $from -Destination $to -Force -ErrorAction Stop } `
                           -ArgumentList $session, $big, $to -Progress $progress -OnPoll {
                $script:polls++
                # The operator clicks Cancel about 2 s in.
                $script:cancelAt = $clock.Elapsed.TotalSeconds; $progress.Cancel = $true
            }
        }
    } catch { $msg = $_.Exception.Message }
    $stopTook = $clock.Elapsed.TotalSeconds - $cancelAt
    Assert-Equal $msg 'Cancelled by the operator.' "Cancel ends the step with the collector's own message"
    Assert-True ($stopTook -lt 5) ("the download stopped {0:N1} s after Cancel (a 400 MB copy takes ~35 s)" -f $stopTook)
    Assert-True (-not (Test-Path (Join-Path $dir 'big.copy')))         "no file under the real name"
    Assert-True (-not (Test-Path (Join-Path $dir 'big.copy.partial'))) "and the partial is removed"
    Assert-True ($polls -ge 1) "the step polled while it worked"

    # ---- the session survives, so the host's cleanup can still run ----
    $after = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock { 'still here' }
    Assert-Equal $after 'still here' "the session is usable after a cancelled step - the target's staging folder can still be removed"
    $sizeProgress = [hashtable]::Synchronized(@{ RemoteBytes = -1 })
    Update-RemoteSize @{ Session = $session; Tried = $true } $sizeProgress $big
    Assert-Equal $sizeProgress.RemoteBytes (400MB) "Update-RemoteSize reads the size of the file on the target"
    Update-RemoteSize @{ Session = $session; Tried = $true } $sizeProgress (Join-Path $dir 'nope.bin')
    Assert-Equal $sizeProgress.RemoteBytes 0 "a file not written yet is 0"
    $sizeProgress.RemoteBytes = -1
    Update-RemoteSize @{ Session = $null; Tried = $true } $sizeProgress $big
    Assert-Equal $sizeProgress.RemoteBytes -1 "no second session: no size, never a guess"
    $src = ${function:Update-RemoteSize}.ToString()
    Assert-True ($src -match 'OpenTimeout' -and $src -match 'OperationTimeout') "the probe session has short timeouts - a stalled target cannot hold up Cancel"
}
finally {
    if ($pipe) {
        try { Remove-PSSession $pipe.Session -ErrorAction SilentlyContinue } catch { }
        Stop-Process -Id $pipe.Process.Id -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- the step clock ----
$p = [hashtable]::Synchronized(@{})
Set-CollectProgress $p @{ Step = 'exporting'; LogName = 'Security' }
$t0 = $p.StepStarted
Assert-True ($t0 -is [datetime]) "a new step starts the step clock"
Assert-Equal $p.RemoteBytes -1 "and forgets the last step's remote size"
$p.RemoteBytes = 5
Set-CollectProgress $p @{ Step = 'exporting'; LogName = 'Security' }
Assert-Equal $p.StepStarted $t0 "the same step and log keeps its clock"
Assert-Equal $p.RemoteBytes 5 "and its size"
Set-CollectProgress $p @{ Step = 'exporting'; LogName = 'System' }
Assert-True ($p.StepStarted -ge $t0 -and $p.RemoteBytes -eq -1) "the next log of the same step restarts it"
