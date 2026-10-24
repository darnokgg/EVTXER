# EvtxCollector.ps1 — remote EVTX collection (SMB + WinRM), ported from the
# original standalone collector script.
# Dot-source HayabusaLib.ps1 for ConvertTo-HostList / Resolve-LogPreset / ConvertTo-EvtxFileName.
. "$PSScriptRoot\HayabusaLib.ps1"

function Remove-EvtxStaging {
    # Cleanup used to be a single Remove-Item at the BOTTOM of the per-host try
    # block, so any host that threw kept its exports on the target and leaked
    # its session. This runs from a finally instead, and removes two classes of
    # thing on two different rules:
    #
    #   1. THIS run's staging folder and its archive - ours beyond doubt, so
    #      they go whatever their age.
    #   2. anything else of ours still lying in the staging parent - per-run
    #      folders and archives orphaned by a hard kill, plus the fixed names
    #      older builds wrote to - but only once it is old enough that nobody
    #      can still be using it.
    #
    # The age decision is Test-StaleStagingItem, which is unit-tested: the
    # listing happens on the target and the judgement happens here.
    param(
        $Session,
        [string]$CurrentPath,
        [scriptblock]$LogWriter,
        # Whether this run built an archive beside the staging folder. Only
        # then can one be left behind - a lost session used to report a .zip
        # that was never written.
        [switch]$ZipAttempted,
        # Where to sweep. Only tests change it: C:\Windows\Temp cannot be
        # listed without administrator rights.
        [string[]]$KnownPaths = @(Get-EvtxStagingPaths)
    )
    $known  = @($KnownPaths)

    # This run's own artifacts are taken whatever their age - including the
    # archive, which Compress-Archive writes BESIDE the staging folder rather
    # than inside it. Nothing but this and the normal-path cleanup ever names
    # it, so a session that dropped after the archive was built used to strand
    # it on the target for good. Everything else is swept by age, never on
    # sight (Test-StaleStagingItem). The filters come from the library's list,
    # so the names still live in exactly one place.
    $current = @()
    if ($CurrentPath) { $current = @($CurrentPath, "$CurrentPath.zip") }
    $parent  = Split-Path -Parent $known[0]
    $leaves  = @($known | ForEach-Object { Split-Path -Leaf $_ })
    $filters = @("$($leaves[0])*") + @($leaves | Select-Object -Skip 1)

    # Look on the target, decide here, delete exactly that on the target - see
    # Get-StagingListing and Get-StagingDeletePlan for why it is three steps.
    $plan = [pscustomobject]@{ Files = @(); Dirs = @(); Left = @() }
    try {
        $rows = @(Invoke-Command -Session $Session -ErrorAction Stop -ScriptBlock ${function:Get-StagingListing} `
                    -ArgumentList $parent, ([string[]]$filters), ([string[]]$current))
        $plan = Get-StagingDeletePlan -Listing $rows -Current $current
        if ($LogWriter) {
            foreach ($l in $plan.Left) { & $LogWriter "  [--] Left alone (a link, a subfolder, or not made by an administrator): $l" }
        }
    }
    catch {
        if ($LogWriter) { & $LogWriter "  [--] Could not list the staging area: $($_.Exception.Message)" }
    }

    # Reports what is still there rather than assuming the delete worked: the
    # caller used to print "Remote temp cleaned" after a session that had died,
    # with the exports still sitting in C:\Windows\Temp on the target.
    $mine = @()
    if ($CurrentPath) { $mine += $CurrentPath; if ($ZipAttempted) { $mine += "$CurrentPath.zip" } }
    try {
        $left = @(Invoke-Command -Session $Session -ErrorAction Stop -ScriptBlock ${function:Remove-StagingPlan} `
                    -ArgumentList ([string[]]$plan.Files), ([string[]]$plan.Dirs), ([string[]]$mine))
        return [pscustomobject]@{ Clean = ($left.Count -eq 0); Left = $left; Reason = 'could not be deleted' }
    }
    catch {
        return [pscustomobject]@{
            Clean = ($mine.Count -eq 0); Left = $mine
            Reason = "the connection was lost before cleanup ($($_.Exception.Message))"
        }
    }
}

function Add-CollectTrustedHosts([string[]]$Targets) {
    # Only real host names and addresses: '*' would trust every host for the
    # run (Test-TargetName). The Collect tab refuses them first; this is the
    # second line.
    $Targets = @($Targets | ForEach-Object { "$_".Trim() } | Where-Object { Test-TargetName $_ })
    # A workgroup target has no Kerberos, so WinRM refuses it unless it is in
    # the client's TrustedHosts. Both Collect and Verify Access call this; only
    # Collect used to, so Verify failed on exactly the hosts that needed it.
    #
    # Returns the original list wrapped in an object, so an EMPTY original is
    # still truthy for the caller's "restore?" check. Throws before writing if
    # the read fails: restoring a value that was never read would wipe the
    # operator's own TrustedHosts.
    $path = 'WSMan:\localhost\Client\TrustedHosts'
    try   { $original = [string](Get-Item -Path $path -ErrorAction Stop).Value }
    catch {
        $fix = (Get-LocalWinRmProblems 'WinRM') -join ' '
        if (-not $fix) { $fix = 'Start EVTXER as administrator and make sure the WinRM service runs on this PC.' }
        throw "This PC cannot use plain WinRM yet - nothing was sent to the targets. $fix (Windows said: $($_.Exception.Message))"
    }
    $saved  = [pscustomobject]@{ Value = $original }
    $merged = Merge-TrustedHosts $original $Targets
    if ($merged -ne $original) {
        try   { Set-Item -Path $path -Value $merged -Force -ErrorAction Stop }
        catch { throw "This PC could not add the targets to its WinRM TrustedHosts list - start EVTXER as administrator (EVTXER.cmd asks for it). Nothing was sent to the targets. (Windows said: $($_.Exception.Message))" }
    }
    return $saved
}

function Restore-CollectTrustedHosts($Saved) {
    # Returns what happened, because the caller used to announce "TrustedHosts
    # reverted." unconditionally - including the run where the revert had just
    # failed, right under the red error text.
    #
    # Two things this has to get right:
    #   * WRITING NEEDS ADMIN. The WSMan provider throws a TERMINATING
    #     InvalidOperationException, which -ErrorAction SilentlyContinue does
    #     not swallow, so an unelevated run printed a stack trace mid-report.
    #   * NOTHING TO DO IS THE COMMON CASE. If the target was already in
    #     TrustedHosts, Add- changed nothing, so restoring means writing the
    #     value that is already there - a pointless write that is also the
    #     only thing that fails without admin. Compare first, write only on a
    #     real difference.
    $path = 'WSMan:\localhost\Client\TrustedHosts'
    $want = [string]$Saved.Value
    try   { $current = [string](Get-Item -Path $path -ErrorAction Stop).Value }
    catch { return [pscustomobject]@{ Ok = $false; Changed = $false; Reason = "could not read TrustedHosts: $($_.Exception.Message)" } }

    if ($current -eq $want) { return [pscustomobject]@{ Ok = $true; Changed = $false; Reason = '' } }

    try {
        if ($want) { Set-Item -Path $path -Value $want -Force -ErrorAction Stop }
        else       { Clear-Item -Path $path -Force -ErrorAction Stop }
        return [pscustomobject]@{ Ok = $true; Changed = $true; Reason = '' }
    } catch {
        return [pscustomobject]@{ Ok = $false; Changed = $false; Reason = $_.Exception.Message }
    }
}

function Assert-CollectPortOpen([string]$HostName, [string]$Method) {
    # Runs before New-PSDrive / New-PSSession. Neither has a timeout, and both
    # run on the UI thread, so a firewall silently dropping the port used to
    # freeze the window while Windows waited it out.
    $port = Get-CollectPort $Method
    $r = Test-TcpPort $HostName $port
    if ($r.Status -eq 'Open') { return }
    # The wrong WinRM flavour is the one failure where the generic "enable
    # it" advice is wrong, so the other port gets one probe before blaming the
    # target.
    # Not after 'Error' (a name that does not resolve, a network that is
    # unreachable): no other port answers then either, and the probe would only
    # add another timeout on the UI thread.
    # $alt, not $switch: that is an automatic variable.
    $alt = Get-WinRmSwitch $Method
    if ($alt -and $r.Status -ne 'Error' -and (Test-TcpPort $HostName (Get-CollectPort $alt.Method)).Status -eq 'Open') {
        throw "$Method port $port is closed, $($alt.Text)"
    }
    throw "$Method port $port $(Get-PortCheckText $port $r.Status)"
}

function Test-CollectPorts([string[]]$Targets, [scriptblock]$LogWriter) {
    # Credential-free reachability for every method, so the operator can pick
    # the one that will work before typing a password.
    if (-not $LogWriter) { $LogWriter = { param($m) Write-Host $m -NoNewline } }
    $hosts = @($Targets | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($hosts.Count -eq 0) { return @() }

    # Every port of every host goes out in one batch - see Test-TcpPortSet. The
    # log is written afterwards rather than host-by-host, which costs the
    # running commentary and buys back a minute and a half on 20 hosts.
    $methods = 'SMB', 'WinRM', 'WinRM-HTTPS'
    $probes = foreach ($hostname in $hosts) {
        foreach ($m in $methods) {
            @{ Key = "$hostname|$m"; HostName = $hostname; Port = (Get-CollectPort $m) }
        }
    }
    & $LogWriter ("Probing {0} host(s) on tcp/445, tcp/5985 and tcp/5986...`n" -f $hosts.Count)
    $byKey = @{}
    foreach ($r in (Test-TcpPortSet -Probes $probes)) { $byKey[$r.Key] = $r }

    $results = foreach ($hostname in $hosts) {
        & $LogWriter "`n$hostname`n"
        $row = [ordered]@{ Target = $hostname }
        foreach ($m in $methods) {
            $r = $byKey["$hostname|$m"]
            $mark = if ($r.Status -eq 'Open') { 'OK' } else { '--' }
            & $LogWriter ("  [{0}] {1} (tcp/{2}): {3}`n" -f $mark, $m, $r.Port, (Get-PortCheckText $r.Port $r.Status))
            $row[$m] = ($r.Status -eq 'Open')
        }
        [pscustomobject]$row
    }
    return @($results)
}

function Set-CollectProgress($Progress, [hashtable]$Values) {
    # $Progress is the synchronized table the GUI reads from the UI thread
    # while this runs in a background runspace. Absent when called directly.
    if (-not $Progress) { return }
    # A new step (or the next log of the same step) restarts the step clock
    # the status line counts from, and forgets the last step's remote size.
    if (($Values.ContainsKey('Step') -and $Values.Step -ne $Progress.Step) -or
        ($Values.ContainsKey('LogName') -and $Values.LogName -ne $Progress.LogName)) {
        $Progress.StepStarted = [datetime]::UtcNow
        $Progress.RemoteBytes = -1
    }
    foreach ($k in $Values.Keys) { $Progress[$k] = $Values[$k] }
}

function Assert-CollectNotCancelled($Progress) {
    # Checked between steps. Inside a long step Invoke-CollectStep does the
    # checking. Either way the throw lands in the host's catch, so its finally
    # still removes the staging folder and closes the session, and the outer
    # finally still restores TrustedHosts. Killing the runspace would skip both.
    if ($Progress -and $Progress.Cancel) { throw 'Cancelled by the operator.' }
}

function Invoke-CollectStep {
    # A step that can run for minutes - one log's export, the archive, one
    # file's transfer - in a PowerShell of its own, so Cancel can stop it in
    # the middle. Cancel used to be checked only between steps, and one
    # Copy-Item of a big archive kept going for five minutes after the click.
    # The script travels as text and gets its inputs as arguments (a PSSession
    # among them): a scriptblock belongs to the runspace that made it. $OnPoll
    # runs about every 2 s while the step works - see Update-RemoteSize.
    # Returns the script's output; its terminating error is rethrown as itself,
    # so callers and Get-CollectErrorHint see the same message as before.
    param(
        [scriptblock]$Script,
        [object[]]$ArgumentList = @(),
        [hashtable]$Progress,
        [scriptblock]$OnPoll
    )
    $ps = [powershell]::Create()
    $stopped = $true
    try {
        $null = $ps.AddScript($Script.ToString())
        foreach ($a in $ArgumentList) { $null = $ps.AddArgument($a) }
        $handle = $ps.BeginInvoke()
        $poll = [Diagnostics.Stopwatch]::StartNew()
        while (-not $handle.AsyncWaitHandle.WaitOne(250)) {
            if ($Progress -and $Progress.Cancel) {
                # Stop() waits for the step to notice. A Copy-Item notices at
                # its next chunk; a stuck one gets 15 s and is then abandoned
                # rather than disposed, which would wait for it all over again.
                $stopping = $ps.BeginStop($null, $null)
                $stopped = $stopping.AsyncWaitHandle.WaitOne(15000)
                throw 'Cancelled by the operator.'
            }
            if ($OnPoll -and $poll.ElapsedMilliseconds -ge 2000) {
                $poll.Restart()
                try { & $OnPoll } catch { }
            }
        }
        try { return $ps.EndInvoke($handle) }
        catch {
            $e = $_.Exception
            while ($e -is [Management.Automation.MethodInvocationException] -and $e.InnerException) { $e = $e.InnerException }
            throw $e
        }
    }
    finally { if ($stopped) { $ps.Dispose() } }
}

function Update-RemoteSize {
    # Invoke-CollectStep's poll for the WinRM steps: how big the file the step
    # is writing on the target is right now, over a SECOND session (the first
    # is busy running the step). Opened the first time a step runs long enough
    # to poll and tried once per host; a target that refuses it still collects,
    # with the step clock alone on the status line. Short timeouts: the poll
    # runs inside the step's wait loop, so a stalled target must not hold up
    # Cancel - New-PSSession's own default waits about three minutes.
    param($Probe, $Progress, [string]$Path, [string]$HostName, $Credential, [hashtable]$SessionArgs)
    if (-not $Probe.Tried) {
        $Probe.Tried = $true
        # A copy: the caller's session settings (Get-CollectSessionArgs) keep
        # their own timeouts for the main session.
        $probeArgs = @{} + $SessionArgs
        $opt = if ($probeArgs.SessionOption) { $probeArgs.SessionOption } else { New-PSSessionOption }
        $opt.OpenTimeout = [timespan]::FromSeconds(5)
        $opt.OperationTimeout = [timespan]::FromSeconds(10)
        $probeArgs.SessionOption = $opt
        try { $Probe.Session = New-PSSession -ComputerName $HostName -Credential $Credential @probeArgs -ErrorAction Stop } catch { }
    }
    if (-not $Probe.Session) { return }
    try {
        $n = Invoke-Command -Session $Probe.Session -ErrorAction Stop -ScriptBlock {
            param($p) $i = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue; if ($i) { $i.Length } else { 0 }
        } -ArgumentList $Path
        Set-CollectProgress $Progress @{ RemoteBytes = [long](@($n) | Select-Object -Last 1) }
    } catch { }
}

# Ported faithfully from the original collector script (~lines 283-458):
#   - TrustedHosts save/restore (~283-297, ~443-449)
#   - SMB collection (~347-372)
#   - WinRM collection (~377-431)
#   - finally-block credential purge (~452-453)
function Invoke-EvtxCollection {
    param(
        [string[]]$Targets,
        [ValidateSet('SMB','WinRM','WinRM-HTTPS')]
        [string]$Method,
        [ValidateSet('DFIR','All','Custom')]
        [string]$Category,
        [string[]]$CustomLogs,
        [pscredential]$Credential,
        # WinRM-HTTPS only. See Get-CollectSessionArgs.
        [switch]$SkipCertificateCheck,
        # Empty = off-domain: each target logs in as TARGET\user. See
        # Resolve-CollectUsername.
        [string]$Domain,
        [string]$OutRoot,
        # NOT $Log: PowerShell resolves variables through the caller chain and
        # is case-insensitive, so a parameter named $Log shadows the $log
        # RichTextBox that Write-Log writes to, and every callback died.
        [scriptblock]$LogWriter,
        # Optional synchronized hashtable: what is happening now (for the
        # status line and bar) and .Cancel (set by the GUI's Cancel button).
        [hashtable]$Progress
    )

    $attempted  = 0
    $succeeded  = 0
    $partial    = 0
    $failed     = 0
    $skipped    = 0
    $files      = @()
    $outFolders = @()
    $problems   = @()
    # Hostnames only, and only those that did not fully succeed. This is the
    # input for the next collection, so anything but a bare hostname in here
    # would be re-collected as a target by that name.
    $retry      = @()
    # One row per target, whatever happened to it - the per-host answer the
    # counts above cannot give. See Format-CollectResults.
    $hostResults = @()

    $missionTimestamp = Get-Date -Format 'yyyyMMdd_HHmm'
    $logsToPull = Resolve-LogPreset -Category $Category -Custom $CustomLogs

    # DFIR and Custom name specific logs, so all of them have to arrive. ALL
    # enumerates every channel on the box and most are empty or disabled, so
    # demanding all of those would mark every ALL collection partial. See
    # Get-HostOutcome.
    $outcomeMode = if ($Category -eq 'All') { 'BestEffort' } else { 'Exact' }

    $savedTrustedHosts = $null
    $operatorAddresses = @(Get-OperatorAddresses)

    try {
        # Inside the try (not before it) so that if this step itself throws,
        # the finally block below still runs and purges the credential.
        # Behind the Collect tab's own check: a name that is not a host or an
        # address never reaches TrustedHosts, the evidence folder's path or a
        # session ('..\x' would climb out of evtx\).
        foreach ($bad in @($Targets | Where-Object { "$_".Trim() -and -not (Test-TargetName "$_".Trim()) })) {
            & $LogWriter "  [SKIPPED] '$bad' - not a host name or address"
            $skipped++
            $hostResults += New-CollectHostResult "$bad" '' 'Skipped' 0 0 '' 'not a host name or address'
        }
        $Targets = @($Targets | ForEach-Object { "$_".Trim() } | Where-Object { Test-TargetName $_ })
        if (Test-NeedsTrustedHosts $Method) { $savedTrustedHosts = Add-CollectTrustedHosts $Targets }

        $hostList  = @($Targets | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $hostIndex = 0
        Set-CollectProgress $Progress @{ HostCount = $hostList.Count }
        foreach ($hostname in $hostList) {
            if ($Progress -and $Progress.Cancel) {
                # Everything not yet visited goes back on the retry list, so a
                # cancelled run can be finished later with one click.
                $rest = @($hostList | Select-Object -Skip $hostIndex)
                & $LogWriter "  [--] Cancelled - not attempted: $($rest -join ', ')"
                $retry += $rest
                break
            }
            $hostIndex++
            $attempted++
            Set-CollectProgress $Progress @{
                HostIndex = $hostIndex; Host = $hostname; Step = 'connecting'
                LogIndex = 0; LogCount = 0; LogName = ''
                DownloadPath = ''; DownloadDone = 0; DownloadTotal = 0
            }

            & $LogWriter "==== Target: $hostname ===="
            $hostCred = Get-TargetCredential $Credential $Domain $hostname
            & $LogWriter "  Account: $($hostCred.UserName)"

            # --- Connectivity check: ADVISORY, never a gate ---
            # This used to [SKIPPED] any host that did not answer a ping, which
            # dropped hosts that collect perfectly (inbound echo is off by
            # default on the firewall's Public profile) and contradicted
            # Test-CollectAccess, which never pings at all. Get-ConnectivityPlan
            # holds that policy and is unit-tested so the gate cannot come back.
            $pingOk = $false
            try   { $pingOk = [bool](Test-Connection -ComputerName $hostname -Count 1 -Quiet -ErrorAction Stop) }
            catch { $pingOk = $false }
            $plan = Get-ConnectivityPlan -PingSucceeded $pingOk -Method $Method
            if ($plan.Note) { & $LogWriter "  [..] $($plan.Note)" }

            # --- Timestamped output folder (original ~339-341) ---
            # In its own try/catch: an inaccessible/invalid $OutRoot must not
            # abort the batch.
            #
            # The timestamp only has minute resolution, and -Force on an
            # existing directory SUCCEEDS. Two collections of the same target
            # inside one minute therefore used to share a folder silently, and
            # an evidence folder holding two acquisitions cannot be untangled
            # afterwards - the name says one collection and the contents are
            # two. Get-NextFreeFolder already solved this for Takajo's output.
            try {
                if (-not (Test-Path -LiteralPath $OutRoot)) {
                    New-Item -ItemType Directory -Path $OutRoot -Force -ErrorAction Stop | Out-Null
                }
                # -Force stays off the per-host folder deliberately: after
                # Get-NextFreeFolder the name is free, so anything that makes
                # New-Item find it occupied is a real collision and has to
                # raise rather than silently hand back somebody else's folder.
                $outFolder = Get-NextFreeFolder (Join-Path $OutRoot "${hostname}_${missionTimestamp}")
                New-Item -ItemType Directory -Path $outFolder -ErrorAction Stop | Out-Null
            }
            catch {
                & $LogWriter "  [SKIPPED] $hostname - could not create output folder: $_"
                $skipped++
                $retry += $hostname
                $hostResults += New-CollectHostResult $hostname $hostCred.UserName 'Skipped' 0 0 '' "could not create output folder: $_"
                continue
            }
            $outFolders += $outFolder

            # Per-host state. $requested/$collected drive the outcome;
            # $expectedFiles/$expectedBytes drive reconciliation, which asks a
            # different question: not "did we get what we asked for" but "did
            # everything we started sending actually arrive intact".
            $session       = $null
            # The second WinRM session Update-RemoteSize opens on demand.
            $probe         = @{ Session = $null; Tried = $false }
            $stagingPath   = $null
            $zipAttempted  = $false
            $drv           = $null
            $errored       = $false
            $requested     = 0
            $collected     = 0
            $expectedFiles = 0
            $expectedBytes = [long](-1)
            $actualBytes   = [long]0
            # Which logs did not arrive, and why. The summary used to say only
            # "5 of 6", so finding the missing one meant scrolling the log.
            $missing       = @()
            # Requested logs this host simply does not have. Reported, but not
            # held against it - see Get-ExportVerdict.
            $absent        = @()
            $hostError     = $null
            # One entry per acquired file: its SHA-256, and the source's where
            # the source could be hashed at rest. See New-ManifestEntry.
            $manifest      = @()
            $remoteHashes  = @{}
            # The visit itself, for tagging our own activity later.
            $hostStartUtc  = (Get-Date).ToUniversalTime()
            $clockSkew     = $null
            # A hash mismatch or a short transfer. Makes the host Partial, so it
            # is offered for RETRY instead of reading Success.
            $integrityBad  = $false
            $integrityText = ''
            $leftOnTarget  = ''

            try {
                Assert-CollectPortOpen $hostname $Method

                # ------------------------------------------------------------
                # SMB METHOD (original ~347-372)
                # ------------------------------------------------------------
                if ($Method -eq 'SMB') {
                    # Not a hard-coded T: - that force-removed whatever the
                    # examiner had mapped there and never put it back.
                    $drv = Get-FreeDriveLetter
                    if (-not $drv) { throw 'no free drive letter available to mount the C$ share' }

                    New-PSDrive -Name $drv -PSProvider FileSystem -Root "\\${hostname}\C$" -Credential $hostCred -ErrorAction Stop | Out-Null
                    & $LogWriter "  [SMB] C`$ share mounted on ${drv}:\"

                    $logDir = "${drv}:\Windows\System32\winevt\Logs"

                    # Both categories run the SAME per-file loop now. ALL used
                    # to be one wildcard Copy-Item -ErrorAction Stop, so the
                    # first locked log aborted the entire host - and a locked
                    # Security.evtx is the normal case, not the exception.
                    if ($logsToPull -eq 'ALL') {
                        & $LogWriter "  [SMB] Enumerating the remote log store..."
                        $wanted = @(Get-ChildItem -LiteralPath $logDir -Filter '*.evtx' -File -ErrorAction Stop |
                                    ForEach-Object { [pscustomobject]@{ Name = $_.Name; Source = $_.FullName } })
                    } else {
                        $wanted = @(foreach ($log in $logsToPull) {
                            $evtxName = ConvertTo-EvtxFileName $log
                            [pscustomobject]@{ Name = $evtxName; Source = (Join-Path $logDir $evtxName) }
                        })
                    }
                    $requested = $wanted.Count

                    # What the log folder actually holds, read once. A named log
                    # with no file there is not on this host (not installed, or a
                    # channel that has never been enabled) - unlike a file that
                    # is listed but cannot be reached. $null when the listing
                    # itself fails, and then every miss counts as before.
                    $present = $null
                    if ($logsToPull -ne 'ALL') {
                        try {
                            $present = @{}
                            Get-ChildItem -LiteralPath $logDir -Filter '*.evtx' -File -ErrorAction Stop |
                                ForEach-Object { $present[$_.Name.ToLowerInvariant()] = $true }
                        } catch { $present = $null }
                    }

                    $logIndex = 0
                    foreach ($w in $wanted) {
                        Assert-CollectNotCancelled $Progress
                        $logIndex++
                        if ($present -and -not $present.ContainsKey($w.Name.ToLowerInvariant()) -and (Test-LogCanBeAbsent $w.Name)) {
                            & $LogWriter "  [..] Not on this host: $($w.Name)"
                            $absent += $w.Name
                            continue
                        }
                        if (-not (Test-Path -LiteralPath $w.Source)) {
                            & $LogWriter "  [--] Not Found / Access Denied: $($w.Name)"
                            $missing += "$($w.Name) (not found / access denied)"
                            continue
                        }
                        $expectedFiles++
                        $dest = Join-Path $outFolder $w.Name
                        $srcBytes = [long]0
                        try { $srcBytes = (Get-Item -LiteralPath $w.Source -ErrorAction Stop).Length } catch { }
                        Set-CollectProgress $Progress @{
                            Step = 'copying'; LogIndex = $logIndex; LogCount = $wanted.Count; LogName = $w.Name
                            DownloadPath = "$dest.partial"; DownloadDone = 0; DownloadTotal = $srcBytes
                        }
                        try {
                            # -ErrorAction Stop: without it Copy-Item's error is
                            # non-terminating, execution falls through, and the
                            # next lines record the file and log [OK] for a copy
                            # that never happened.
                            $v = Invoke-StagedCopy -Destination $dest -Copy {
                                param($to) Copy-Item -LiteralPath $w.Source -Destination $to -Force -ErrorAction Stop
                            }
                        }
                        catch {
                            & $LogWriter "  [FAILED] $($w.Name) - $($_.Exception.Message)"
                            $missing += "$($w.Name) ($($_.Exception.Message))"
                            continue
                        }
                        if ($v.Ok) {
                            $files += $dest
                            $collected++
                            $actualBytes += $v.Bytes
                            # No source hash: SMB reads the log while Windows is
                            # still writing to it, so hashing the far side would
                            # differ from the copy for innocent reasons.
                            $manifest += New-ManifestEntry -Path $dest -LogName $w.Name
                            & $LogWriter "  [OK] Acquired: $($w.Name)"
                        } else {
                            & $LogWriter "  [FAILED] $($w.Name) - $($v.Reason)"
                            $missing += "$($w.Name) ($($v.Reason))"
                        }
                    }
                    # $expectedBytes stays -1 ("not measured"). The SMB source is
                    # a LIVE log that grows between the stat and the copy, so a
                    # byte total would report a mismatch on a good collection.
                    # Get-TransferReconciliation takes -1 for exactly this case.
                }

                # ------------------------------------------------------------
                # WINRM METHOD (original ~377-431)
                # ------------------------------------------------------------
                else {
                    & $LogWriter "  [WinRM] Establishing PSSession$(if ($Method -eq 'WinRM-HTTPS') { ' over HTTPS' })..."
                    $sessionArgs = Get-CollectSessionArgs $Method -SkipCertificateCheck:$SkipCertificateCheck
                    $session = New-PSSession -ComputerName $hostname -Credential $hostCred @sessionArgs -ErrorAction Stop

                    # A fresh folder per run - see New-EvtxStagingPath. The old
                    # fixed path was reused by every collection and cleaned only
                    # on the success path, so a previous run's leftovers could be
                    # copied back and analysed as current evidence.
                    $stagingPath = New-EvtxStagingPath
                    $asked = (Get-Date).ToUniversalTime()
                    $theirs = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                        # No -Force: the name is new, so finding it already
                        # there means someone else made it - stop, never reuse.
                        New-Item -ItemType Directory -Path $using:stagingPath -ErrorAction Stop | Out-Null
                        # SYSTEM and Administrators only. C:\Windows\Temp lets
                        # every user create entries and passes that right down,
                        # so a user could otherwise plant a file or a link in
                        # the folder the exports are written to.
                        $null = icacls $using:stagingPath /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1
                        (Get-Date).ToUniversalTime()
                    }
                    # The target's clock against ours, so the tagging window
                    # can be in the target's time. Midpoint of the round trip.
                    try {
                        $mid = $asked.AddTicks(((Get-Date).ToUniversalTime() - $asked).Ticks / 2)
                        $clockSkew = [Math]::Round((([datetime](@($theirs) | Select-Object -Last 1)) - $mid).TotalSeconds)
                    } catch { $clockSkew = $null }
                    if ($null -ne $clockSkew -and [Math]::Abs($clockSkew) -gt $script:MaxTrustedSkewSeconds) {
                        & $LogWriter "  [--] Target clock is $clockSkew s off this machine's - recorded, but not used to tag this visit's detections."
                    }

                    if ($logsToPull -eq 'ALL') {
                        & $LogWriter "  [WinRM] Enumerating remote log store..."
                        $logNames = @(Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock { wevtutil el })
                    } else {
                        $logNames = @($logsToPull)
                    }
                    $requested = $logNames.Count

                    # The target's disk before anything is copied onto it - see
                    # Test-TargetStagingSpace. Read in one round trip; a target
                    # that cannot answer is collected with a note, not refused.
                    $space = $null
                    try {
                        $disk = @(Invoke-Command -Session $session -ErrorAction Stop -ArgumentList (, [string[]]$logNames) -ScriptBlock {
                            param($names)
                            $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -OperationTimeoutSec 30
                            $want = @{}; foreach ($n in $names) { $want[$n] = $true }
                            $sum = (Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
                                    Where-Object { $want.ContainsKey($_.LogName) } | Measure-Object FileSize -Sum).Sum
                            [pscustomobject]@{ Free = [long]$d.FreeSpace; Size = [long]$d.Size; Logs = [long]$sum }
                        }) | Select-Object -Last 1
                        $space = Test-TargetStagingSpace -FreeBytes $disk.Free -DiskBytes $disk.Size -LogBytes $disk.Logs
                    } catch {
                        $space = Test-TargetStagingSpace -FreeBytes -1 -DiskBytes 0 -LogBytes 0
                    }
                    if (-not $space.Ok) { throw $space.Message }
                    & $LogWriter "  [$(if ($space.Known) { 'OK' } else { '--' })] Disk: $($space.Message)"

                    # Export every requested log on the target first. wevtutil
                    # reads logs that are open and locked, which is the reason
                    # WinRM can collect files SMB cannot.
                    $exported = @()
                    $logIndex = 0
                    foreach ($log in $logNames) {
                        Assert-CollectNotCancelled $Progress
                        $logIndex++
                        Set-CollectProgress $Progress @{
                            Step = 'exporting'; LogIndex = $logIndex; LogCount = $logNames.Count; LogName = $log
                        }
                        $exportName = ConvertTo-ExportFileName $log
                        $exportPath = "$stagingPath\$exportName"
                        & $LogWriter "  -> Exporting $log..."

                        # One round trip: the export, its exit code, and whether
                        # the file is there. -ErrorAction Stop so a session that
                        # died mid-run stops the host with the real reason; it
                        # used to come back empty and blame every remaining log
                        # on "permissions or log name".
                        $r = Invoke-CollectStep -Progress $Progress -ArgumentList $session, $log, $exportPath -OnPoll {
                            Update-RemoteSize $probe $Progress $exportPath $hostname $hostCred $sessionArgs
                        } -Script {
                            param($s, $l, $p)
                            Invoke-Command -Session $s -ErrorAction Stop -ArgumentList $l, $p -ScriptBlock {
                                param($l, $p)
                                wevtutil epl $l $p /overwrite:true 2>$null
                                [pscustomobject]@{ Code = $LASTEXITCODE; Exists = (Test-Path -LiteralPath $p) }
                            }
                        }
                        $r = @($r) | Select-Object -Last 1
                        $verdict = Get-ExportVerdict ([int]$r.Code) ([bool]$r.Exists) $log

                        if ($verdict -eq 'Exported') {
                            $exported += [pscustomobject]@{ Log = $log; Path = $exportPath; Name = $exportName }
                        } elseif ($verdict -eq 'Absent' -and $logsToPull -ne 'ALL') {
                            & $LogWriter "  [..] Not on this host: $log"
                            $absent += $log
                        } elseif ($logsToPull -eq 'ALL') {
                            # Enumerating every channel always turns up some that
                            # are empty or disabled; that is normal, not an error.
                            & $LogWriter "  [SKIPPED] Export failed or log empty: $log"
                        } else {
                            & $LogWriter "  [FAILED] Check permissions or log name: $log"
                            $missing += "$log (export failed - check permissions or log name)"
                        }
                    }

                    if ($exported.Count -eq 0) {
                        & $LogWriter "  [WinRM] Nothing was exported on $hostname."
                    } else {
                        # Copy-Item -FromSession sends each file base64-encoded
                        # over WS-Man (~+33% on the wire) in its own round-trip.
                        # EVTX compresses hard, so one archive is much cheaper -
                        # where the target can build one.
                        $remoteInfo = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                            $sum = (Get-ChildItem -Path $using:stagingPath -Filter '*.evtx' -File -ErrorAction SilentlyContinue |
                                    Measure-Object -Property Length -Sum).Sum
                            [pscustomobject]@{
                                PsMajor = $PSVersionTable.PSVersion.Major
                                Bytes   = [long]$(if ($sum) { $sum } else { 0 })
                            }
                        }
                        $psMajor = 0
                        $bytes   = [long]0
                        if ($remoteInfo) {
                            $psMajor = [int]$remoteInfo.PsMajor
                            $bytes   = [long]$remoteInfo.Bytes
                        }
                        # Unlike SMB these are STATIC copies sitting in staging,
                        # not live logs, so the byte total is meaningful and a
                        # mismatch means a real short transfer.
                        $expectedFiles = $exported.Count
                        $expectedBytes = $bytes

                        # Hashed on the target before anything is transferred:
                        # these are static exports in staging, not live logs, so
                        # comparing them with the local copy is a true
                        # end-to-end check rather than a size heuristic.
                        try {
                            $remoteHashList = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                                Get-ChildItem -LiteralPath $using:stagingPath -Filter '*.evtx' -File -ErrorAction SilentlyContinue |
                                    ForEach-Object {
                                        [pscustomobject]@{ Name = $_.Name; Hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
                                    }
                            }
                            foreach ($rh in @($remoteHashList)) { $remoteHashes[$rh.Name] = $rh.Hash }
                        }
                        catch {
                            # An old target without Get-FileHash, or a locked
                            # staging file: the collection still stands, the
                            # manifest just records NotCompared for it.
                            & $LogWriter "  [--] Could not hash the exports on the target: $($_.Exception.Message)"
                        }

                        $mode = Select-WinRmTransferMode -ExportedBytes $bytes -RemotePsMajor $psMajor
                        & $LogWriter ("  [WinRM] {0} file(s), {1:N1} MB exported. Transfer mode: {2} (remote PowerShell {3})" -f `
                                $exported.Count, ($bytes / 1MB), $mode, $psMajor)

                        Assert-CollectNotCancelled $Progress
                        $pulled = $false
                        if ($mode -eq 'Zip') {
                            $remoteZip = "$stagingPath.zip"
                            $zipAttempted = $true
                            $localZip  = Join-Path $outFolder 'collected.zip'
                            try {
                                Set-CollectProgress $Progress @{ Step = 'compressing' }
                                # .NET's zip writer, the one Compress-Archive
                                # wraps, called directly. MEASURED on 837 MB of
                                # real EVTX: same size, same contents, about the
                                # same time - but it writes the archive as it
                                # goes, so Update-RemoteSize can show it growing,
                                # where Compress-Archive's file showed nothing
                                # until it was finished. Compress-Archive is still
                                # the fallback. Nothing is installed on the target.
                                $zipBytes = Invoke-CollectStep -Progress $Progress -ArgumentList $session, $stagingPath, $remoteZip -OnPoll {
                                    Update-RemoteSize $probe $Progress $remoteZip $hostname $hostCred $sessionArgs
                                } -Script {
                                    param($s, $staging, $zip)
                                    Invoke-Command -Session $s -ErrorAction Stop -ArgumentList $staging, $zip -ScriptBlock {
                                        param($staging, $zip)
                                        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
                                        try {
                                            Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem -ErrorAction Stop
                                            $archive = [IO.Compression.ZipFile]::Open($zip, [IO.Compression.ZipArchiveMode]::Create)
                                            try {
                                                foreach ($f in @(Get-ChildItem -LiteralPath $staging -Filter '*.evtx' -File)) {
                                                    [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                                                        $archive, $f.FullName, $f.Name, [IO.Compression.CompressionLevel]::Optimal)
                                                }
                                            } finally { $archive.Dispose() }
                                        }
                                        catch [Management.Automation.PipelineStoppedException] { throw }
                                        catch {
                                            Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
                                            Compress-Archive -Path (Join-Path $staging '*.evtx') -DestinationPath $zip -CompressionLevel Optimal
                                        }
                                        (Get-Item -LiteralPath $zip).Length
                                    }
                                }
                                Set-CollectProgress $Progress @{
                                    Step = 'downloading'; DownloadPath = "$localZip.partial"; DownloadDone = 0
                                    DownloadTotal = [long](@($zipBytes) | Select-Object -Last 1)
                                }

                                $zv = Invoke-StagedCopy -Destination $localZip -Copy {
                                    param($to)
                                    $null = Invoke-CollectStep -Progress $Progress -ArgumentList $session, $remoteZip, $to -Script {
                                        param($s, $from, $to) Copy-Item -FromSession $s -Path $from -Destination $to -Force -ErrorAction Stop
                                    }
                                }
                                if (-not $zv.Ok) { throw "the archive $($zv.Reason)" }
                                # Unpacked beside the evidence, then moved in.
                                # Expand-Archive writes each file under its real
                                # name as it goes, so a failure part way used to
                                # leave half-written .evtx files in the folder.
                                $unpack = Join-Path $outFolder $script:UnzipStagingName
                                Expand-Archive -LiteralPath $localZip -DestinationPath $unpack -Force -ErrorAction Stop
                                # Only the files this run exported: the target
                                # built the archive, and a compromised target
                                # could add files of its own choosing to it.
                                $expected = @($exported | ForEach-Object { $_.Name })
                                Get-ChildItem -LiteralPath $unpack -File | ForEach-Object {
                                    if ($expected -contains $_.Name) {
                                        Move-Item -LiteralPath $_.FullName -Destination (Join-Path $outFolder $_.Name) -Force -ErrorAction Stop
                                    } else {
                                        & $LogWriter "  [--] Not exported by this run, left out of the evidence: $($_.Name)"
                                    }
                                }
                                Remove-Item -LiteralPath $unpack -Recurse -Force -ErrorAction SilentlyContinue
                                Remove-Item -LiteralPath $localZip -Force -ErrorAction SilentlyContinue

                                # Set BEFORE the per-file accounting below, so a
                                # problem while counting can never send us into
                                # the fallback and count the same file twice.
                                $pulled = $true
                                & $LogWriter ("  [WinRM] Pulled 1 archive instead of {0} separate files." -f $exported.Count)
                            }
                            catch {
                                # A zip problem - remote disk full, the archive
                                # over the size limit, a locked file - must not
                                # cost the whole host. Falling back to per-file
                                # copy is slower but has always worked.
                                & $LogWriter "  [WinRM] Zip transfer failed ($_). Falling back to per-file copy."
                                Remove-Item -LiteralPath $localZip -Force -ErrorAction SilentlyContinue
                                Remove-Item -LiteralPath (Join-Path $outFolder $script:UnzipStagingName) -Recurse -Force -ErrorAction SilentlyContinue
                            }
                            Invoke-Command -Session $session -ScriptBlock {
                                Remove-Item -LiteralPath $using:remoteZip -Force -ErrorAction SilentlyContinue
                            } | Out-Null
                        }

                        if ($pulled) {
                            foreach ($e in $exported) {
                                $localFile = Join-Path $outFolder $e.Name
                                $v = Test-CopiedFile $localFile
                                if ($v.Ok) {
                                    $files += $localFile
                                    $collected++
                                    $actualBytes += $v.Bytes
                                    $manifest += New-ManifestEntry -Path $localFile -LogName $e.Log `
                                                     -SourceSha256 ([string]$remoteHashes[$e.Name])
                                    & $LogWriter "  [OK] $($e.Log)"
                                } else {
                                    & $LogWriter "  [--] Missing from archive: $($e.Log) - $($v.Reason)"
                                    $missing += "$($e.Log) (missing from archive: $($v.Reason))"
                                }
                            }
                        } else {
                            $pulledBytes = [long]0
                            foreach ($e in $exported) {
                                $dest = Join-Path $outFolder $e.Name
                                Set-CollectProgress $Progress @{
                                    Step = 'downloading'; DownloadPath = "$dest.partial"; DownloadDone = $pulledBytes; DownloadTotal = $bytes
                                }
                                try {
                                    # Same non-terminating trap as the SMB copy:
                                    # without -ErrorAction Stop this logged [OK]
                                    # for a file that never came across.
                                    $v = Invoke-StagedCopy -Destination $dest -Copy {
                                        param($to)
                                        $null = Invoke-CollectStep -Progress $Progress -ArgumentList $session, $e.Path, $to -Script {
                                            param($s, $from, $to) Copy-Item -FromSession $s -Path $from -Destination $to -Force -ErrorAction Stop
                                        }
                                    }
                                }
                                catch {
                                    & $LogWriter "  [FAILED] $($e.Log) - $($_.Exception.Message)"
                                    $missing += "$($e.Log) ($($_.Exception.Message))"
                                    continue
                                }
                                if ($v.Ok) {
                                    $pulledBytes += $v.Bytes
                                    $files += $dest
                                    $collected++
                                    $actualBytes += $v.Bytes
                                    $manifest += New-ManifestEntry -Path $dest -LogName $e.Log `
                                                     -SourceSha256 ([string]$remoteHashes[$e.Name])
                                    & $LogWriter "  [OK] $($e.Log)"
                                } else {
                                    & $LogWriter "  [FAILED] $($e.Log) - $($v.Reason)"
                                    $missing += "$($e.Log) ($($v.Reason))"
                                }
                            }
                        }
                    }
                }
            }
            catch {
                $errored = $true
                $hostError = "$_"
                & $LogWriter "  [ERROR] ${hostname} - $_"
                $hint = Get-CollectErrorHint "$_"
                if ($hint) { & $LogWriter "  [->] $hint" }
            }
            finally {
                # Runs whatever happened. Both of these used to sit at the
                # bottom of the try, so a host that threw kept its staging
                # folder on the target AND leaked an open WinRM session for the
                # life of the process.
                Set-CollectProgress $Progress @{ Step = 'cleaning up'; DownloadPath = '' }
                if ($drv -and (Get-PSDrive -Name $drv -ErrorAction SilentlyContinue)) {
                    Remove-PSDrive -Name $drv -Force -ErrorAction SilentlyContinue
                    & $LogWriter "  [SMB] Share unmounted."
                }
                if ($probe.Session) { Remove-PSSession -Session $probe.Session -ErrorAction SilentlyContinue }
                if ($session) {
                    $clean = Remove-EvtxStaging -Session $session -CurrentPath $stagingPath -LogWriter $LogWriter -ZipAttempted:$zipAttempted
                    Remove-PSSession -Session $session -ErrorAction SilentlyContinue
                    # Said only when it is true. "Remote temp cleaned" used to
                    # print even when the session had died and the exports were
                    # still sitting on the target.
                    if ($clean.Clean) {
                        & $LogWriter "  [WinRM] Session closed. Remote temp cleaned."
                    } else {
                        $leftOnTarget = @($clean.Left) -join ', '
                        & $LogWriter "  [!!] Left on the target: $leftOnTarget - $($clean.Reason). Delete it by hand; otherwise the next WinRM collection from this host removes it once it is 24 hours old."
                        $problems += "${hostname}: exports left on the target - $leftOnTarget"
                    }
                }
                # A hard kill mid-copy can leave a .partial or a half-unpacked
                # archive; neither may look like evidence.
                foreach ($p in @(Remove-PartialTransfers $outFolder)) { & $LogWriter "  [..] Removed incomplete transfer: $p" }
            }

            # --- Manifest: is what arrived what was on the target? ---
            # Reconciliation below asks whether everything we started sending
            # got here; this asks whether it is the same bytes. Only the second
            # one survives a challenge to the evidence.
            if ($manifest.Count -gt 0) {
                $ms = Get-ManifestSummary $manifest
                $integrityText =
                    if ($ms.Mismatched -or $ms.Missing) { "SHA-256: $($ms.Mismatched) MISMATCH, $($ms.Missing) missing of $($manifest.Count)" }
                    elseif ($ms.Verified)               { "SHA-256 verified against the target: $($ms.Verified) of $($manifest.Count)" }
                    else                                { "SHA-256 recorded for $($manifest.Count) file(s); live logs cannot be compared at the source" }
                & $LogWriter ("  [{0}] {1}" -f $(if ($ms.Ok) { '..' } else { '!!' }), $ms.Text)
                if (-not $ms.Ok) { $problems += "${hostname}: $($ms.Text)"; $integrityBad = $true }
                try {
                    $footprint = New-CollectionFootprint -Account $hostCred.UserName -StartUtc $hostStartUtc `
                                     -EndUtc (Get-Date).ToUniversalTime() -TargetClockSkewSeconds $clockSkew `
                                     -StagingFolder $(if ($stagingPath) { Split-Path -Leaf $stagingPath } else { '' }) `
                                     -OperatorAddresses $operatorAddresses
                    $manifestPath = Write-EvtxManifest -Entries $manifest -Folder $outFolder -HostName $hostname -Method $Method `
                                        -CertificateCheckSkipped:($SkipCertificateCheck -and $Method -eq 'WinRM-HTTPS') `
                                        -Footprint $footprint
                    & $LogWriter "  [..] Manifest written: $manifestPath"
                }
                catch { & $LogWriter "  [--] Could not write the manifest: $($_.Exception.Message)" }
            }

            # --- Reconciliation: did everything we started sending arrive? ---
            # Get-TransferReconciliation was written and tested but never
            # called, so a short or missing file reached the operator with
            # nothing flagging it.
            if ($expectedFiles -gt 0) {
                $rec = Get-TransferReconciliation -ExpectedFiles $expectedFiles -ActualFiles $collected `
                                                  -ExpectedBytes $expectedBytes -ActualBytes $actualBytes
                & $LogWriter ("  [{0}] {1}" -f $(if ($rec.Ok) { '..' } else { '!!' }), $rec.Summary)
                if (-not $rec.Ok) {
                    $problems += "${hostname}: $($rec.Summary)"
                    $integrityText = (@($integrityText, $rec.Summary) | Where-Object { $_ }) -join '; '
                    # Only a measured transfer (WinRM's static exports) counts
                    # against the host here. Over SMB an ALL collection always
                    # meets a few locked live logs; Exact mode already counts
                    # those as missing, and BestEffort deliberately forgives them.
                    if ($expectedBytes -ge 0) { $integrityBad = $true }
                }
            }

            # A host that delivered nothing leaves no folder. An empty
            # HOST_yyyyMMdd_HHmm beside the real ones looks like evidence,
            # fifty unreachable targets left fifty of them, and the activity
            # log pointed at one as the Output (lab run, 2026-10-16).
            if (-not @(Get-ChildItem -LiteralPath $outFolder -Force -ErrorAction SilentlyContinue).Count) {
                Remove-Item -LiteralPath $outFolder -Force -ErrorAction SilentlyContinue
                if (-not (Test-Path -LiteralPath $outFolder)) {
                    $outFolders = @($outFolders | Where-Object { $_ -ne $outFolder })
                    $outFolder = ''
                }
            }

            # --- Outcome: did we get what was asked for? ---
            $outcome = Get-HostOutcome -Requested ($requested - $absent.Count) -Collected $collected -Errored $errored -Mode $outcomeMode -IntegrityFailed $integrityBad
            $detail  = if ($hostError) { $hostError } elseif ($missing) { "missing: $($missing -join ', ')" } else { '' }
            if ($absent) {
                & $LogWriter "  [..] Not on this host (not counted against it): $($absent -join ', ')"
                $detail = (@($detail, "not on host: $($absent -join ', ')") | Where-Object { $_ }) -join '; '
            }
            # The integrity failure is the reason itself when every log arrived;
            # without this the results line read "6/6" with no reason at all.
            if ($integrityBad) { $detail = (@($integrityText, $detail) | Where-Object { $_ }) -join '; ' }
            $hostResults += New-CollectHostResult $hostname $hostCred.UserName $outcome $collected $requested $outFolder $detail `
                                -Bytes $actualBytes -Seconds ((Get-Date).ToUniversalTime() - $hostStartUtc).TotalSeconds `
                                -Integrity $integrityText -LeftOnTarget $leftOnTarget
            # The job queue takes each host as soon as it is in, not at the end
            # of the run. A failed host has nothing to process, and a set that
            # did not verify is not scanned, uploaded and archived unattended
            # (code review): the operator checks it first.
            if ($outcome -ne 'Failed' -and $Progress -and $null -ne $Progress.HostDone -and (Test-Path -LiteralPath $outFolder)) {
                if ($integrityBad) { & $LogWriter "  [!!] $hostname is not queued: its logs did not verify. Check them, then queue the folder with Add folders..." }
                else { $Progress.HostDone.Enqueue($outFolder) }
            }
            switch ($outcome) {
                'Success' {
                    $succeeded++
                    & $LogWriter "  [DONE] $hostname - $collected of $requested log(s) collected."
                }
                'Partial' {
                    $partial++
                    $retry += $hostname
                    $why = if ($integrityBad -and -not $missing) { "all $collected log(s) arrived but the set did not verify - $integrityText" }
                           else { "only $collected of $requested requested log(s) collected" }
                    & $LogWriter "  [PARTIAL] $hostname - $why"
                    $problems += "${hostname}: $why"
                    foreach ($m in $missing) { $problems += "${hostname}:   missing $m" }
                    if ($hostError) { $problems += "${hostname}:   error $hostError" }
                }
                'Failed' {
                    $failed++
                    $retry += $hostname
                    & $LogWriter "  [FAILED] $hostname - $collected of $requested log(s) collected."
                    $problems += "${hostname}: collection failed - $collected of $requested log(s) collected"
                    foreach ($m in $missing) { $problems += "${hostname}:   missing $m" }
                    if ($hostError) { $problems += "${hostname}:   error $hostError" }
                }
            }
        }
    }
    finally {
        # --- OPSEC cleanup (original ~438-458): restore TrustedHosts, purge credential ---
        if ($savedTrustedHosts) {
            $rev = Restore-CollectTrustedHosts $savedTrustedHosts
            if     (-not $rev.Ok)  { & $LogWriter "  [!!] TrustedHosts NOT reverted - $($rev.Reason). The targets are still trusted; remove them by hand in an elevated PowerShell." }
            elseif ($rev.Changed)  { & $LogWriter "  -> TrustedHosts reverted." }
            else                   { & $LogWriter "  -> TrustedHosts unchanged (the targets were already trusted)." }
        }

        $Credential = $null; $hostCred = $null
        & $LogWriter "  -> Credentials purged from memory."
    }

    [pscustomobject]@{
        Attempted  = $attempted
        Succeeded  = $succeeded
        Partial    = $partial
        Failed     = $failed
        Skipped    = $skipped
        Files      = $files
        OutFolders = $outFolders
        Problems   = $problems
        Retry      = $retry
        Hosts      = $hostResults
    }
}

function Test-CollectAccess {
    # Answers "will a collection actually work?" in seconds instead of finding
    # out twenty minutes into a transfer. Proves the whole chain the real run
    # depends on - credentials, reachability on the chosen method, the log
    # directory being listable, and Security.evtx being genuinely readable -
    # then puts everything back.
    #
    # Deliberately does NOT ping: collection does not gate on ICMP either (see
    # Get-ConnectivityPlan), so the two agree about which hosts are viable.
    #
    # Read-only by construction: it mounts and unmounts, opens and closes, and
    # writes nothing to the target that it does not remove again.
    param(
        [string[]]$Targets,
        [ValidateSet('SMB','WinRM','WinRM-HTTPS')]
        [string]$Method,
        [pscredential]$Credential,
        [string]$Domain,
        [switch]$SkipCertificateCheck,
        [scriptblock]$LogWriter
    )
    $results = @()

    # Same reason the collector takes -LogWriter and not -Log: PowerShell
    # resolves variables up the caller chain case-insensitively, so a parameter
    # named $Log shadows the GUI's $log RichTextBox and every write fails.
    if (-not $LogWriter) { $LogWriter = { param($m) Write-Host $m -NoNewline } }

    $note = Get-TargetAuthNote $Targets
    if ($note) { & $LogWriter "$note`n" }

    # Verify Access has to see WinRM exactly as Collect will, so it adds the
    # targets to TrustedHosts the same way and puts the list back afterwards.
    $savedTrustedHosts = if (Test-NeedsTrustedHosts $Method) { Add-CollectTrustedHosts $Targets }
    try {
        foreach ($t in $Targets) {
            $hostname = "$t".Trim()
            if (-not $hostname) { continue }
            $checks = @()
            & $LogWriter "`n$hostname`n"
            $hostCred = Get-TargetCredential $Credential $Domain $hostname
            & $LogWriter "  account $($hostCred.UserName)`n"

            try {
                Assert-CollectPortOpen $hostname $Method
                $checks += @{ Ok = $true; Text = "$Method port $(Get-CollectPort $Method) open" }

                if ($Method -eq 'SMB') {
                    # Not a hard-coded V: - this runs on the examiner's own
                    # workstation and used to force-remove whatever was mapped
                    # there without ever restoring it.
                    $drv = Get-FreeDriveLetter
                    if (-not $drv) { throw 'no free drive letter available to mount the C$ share' }
                    New-PSDrive -Name $drv -PSProvider FileSystem -Root "\\${hostname}\C$" -Credential $hostCred -ErrorAction Stop | Out-Null
                    $checks += @{ Ok = $true; Text = 'credentials accepted, C$ share mounted' }
                    try {
                        $logDir = "${drv}:\Windows\System32\winevt\Logs"
                        $found  = @(Get-ChildItem -LiteralPath $logDir -Filter '*.evtx' -File -ErrorAction Stop)
                        $checks += @{ Ok = $true; Text = "winevt\Logs listable - $($found.Count) .evtx present" }

                        # FileShare::ReadWrite, not Read - see Test-EvtxReadable.
                        # Asking for Read reports a copyable Security.evtx as locked.
                        #
                        # UNC, not the "${drv}:" path the listing above uses: a
                        # PSDrive exists only inside PowerShell, and
                        # Test-EvtxReadable opens the file through .NET, which
                        # has never heard of it. Handing it "T:\..." failed
                        # every SMB check with "Could not find a part of the
                        # path" while Test-Path -LiteralPath on the SAME path
                        # said the file was there - the two disagree because
                        # one is provider-aware and the other is not. The mount
                        # above authenticated the SMB session, so the UNC path
                        # needs no credentials of its own.
                        $sec = Join-Path $logDir 'Security.evtx'
                        if (Test-Path -LiteralPath $sec) {
                            $r = Test-EvtxReadable "\\${hostname}\C`$\Windows\System32\winevt\Logs\Security.evtx"
                            $checks += @{ Ok = $r.Readable; Text = if ($r.Readable) { "Security.evtx readable ($('{0:N0}' -f $r.Bytes) bytes)" } else { "Security.evtx NOT readable - $($r.Reason)" } }
                        } else {
                            $checks += @{ Ok = $false; Text = 'Security.evtx not present or not visible to this account' }
                        }
                    } finally {
                        Remove-PSDrive -Name $drv -Force -ErrorAction SilentlyContinue
                    }
                }
                else {
                    $sessionArgs = Get-CollectSessionArgs $Method -SkipCertificateCheck:$SkipCertificateCheck
                    $session = New-PSSession -ComputerName $hostname -Credential $hostCred @sessionArgs -ErrorAction Stop
                    $checks += @{ Ok = $true; Text = "credentials accepted, $Method session opened" }
                    try {
                        # wevtutil gli is the same interface the real export uses,
                        # so a pass here means the export will work - not merely
                        # that the file exists on disk.
                        $probe = Invoke-Command -Session $session -ScriptBlock {
                            $out = & wevtutil gli Security 2>&1
                            [pscustomobject]@{ Code = $LASTEXITCODE; Text = ($out | Out-String) }
                        }
                        if ($probe.Code -eq 0) {
                            $checks += @{ Ok = $true; Text = 'wevtutil can read the Security log - export will work' }
                        } else {
                            $checks += @{ Ok = $false; Text = "wevtutil refused the Security log: $($probe.Text.Trim())" }
                        }

                        # Collection stages its exports on the target and then pulls
                        # them back over WS-Man. wevtutil gli proves the log can be
                        # read and proves nothing at all about the channel: WSMan
                        # envelope/transfer limits and a full local disk both fail
                        # at the transfer step, which is exactly the twenty-minutes-
                        # in surprise Verify Access exists to prevent. So this
                        # stages a small file and pulls it back for real, the same
                        # way collection does, and verifies it the same way too.
                        $stagingParent = Split-Path -Parent (Get-EvtxStagingPaths)[0]
                        $probeDir      = New-EvtxStagingPath
                        $probeFile     = "$probeDir\transfer-probe.bin"
                        $localProbe    = Join-Path ([IO.Path]::GetTempPath()) ("transfer-probe-{0}.bin" -f [guid]::NewGuid().ToString('N').Substring(0,8))
                        $staging = Invoke-Command -Session $session -ScriptBlock {
                            try {
                                # Made and locked like a collection's staging folder.
                                New-Item -ItemType Directory -Path $using:probeDir -ErrorAction Stop | Out-Null
                                $null = icacls $using:probeDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1
                                # Small, but never empty: Test-CopiedFile counts a
                                # 0-byte arrival as a failed transfer, and it should
                                # do so here for the same reason it does there.
                                Set-Content -LiteralPath $using:probeFile -Value ('hayabusa transfer probe ' * 8) `
                                            -Encoding Ascii -ErrorAction Stop
                                return ''
                            } catch { return $_.Exception.Message }
                        }
                        if ([string]::IsNullOrWhiteSpace($staging)) {
                            $checks += @{ Ok = $true; Text = "staging folder can be created in $stagingParent" }
                            try {
                                Copy-Item -FromSession $session -Path $probeFile -Destination $localProbe -Force -ErrorAction Stop
                                $probe = Test-CopiedFile $localProbe
                                if ($probe.Ok) {
                                    $checks += @{ Ok = $true; Text = "sample file pulled back over WS-Man ($($probe.Bytes) bytes) - the transfer path works" }
                                } else {
                                    $checks += @{ Ok = $false; Text = "sample file did not survive the transfer - $($probe.Reason)" }
                                }
                            }
                            catch {
                                $checks += @{ Ok = $false; Text = "sample transfer back over WS-Man failed: $($_.Exception.Message)" }
                            }
                            finally {
                                Remove-Item -LiteralPath $localProbe -Force -ErrorAction SilentlyContinue
                            }
                        } else {
                            $checks += @{ Ok = $false; Text = "cannot create a staging folder in ${stagingParent}: $staging" }
                        }
                        # Whatever happened above, the target goes back as it was.
                        Invoke-Command -Session $session -ErrorAction SilentlyContinue -ScriptBlock {
                            # The one file, then the folder - never -Recurse (see Remove-StagingPlan).
                            Remove-Item -LiteralPath $using:probeFile -Force -ErrorAction SilentlyContinue
                            Remove-Item -LiteralPath $using:probeDir -Force -ErrorAction SilentlyContinue
                        } | Out-Null
                    } finally {
                        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
                    }
                }
            }
            catch {
                $checks += @{ Ok = $false; Text = $_.Exception.Message }
                $hint = Get-CollectErrorHint $_.Exception.Message
                if ($hint) { $checks += @{ Ok = $false; Text = $hint } }
            }

            foreach ($c in $checks) {
                # [!!], not [--]: a failed check blocks collection, so it
                # reads red. [--] is the amber "absent / closed" marker.
                & $LogWriter ("  [{0}] {1}`n" -f $(if ($c.Ok) { 'OK' } else { '!!' }), $c.Text)
            }
            $results += [pscustomobject]@{
                Target  = $hostname
                Ok      = (@($checks | Where-Object { -not $_.Ok }).Count -eq 0)
                Checks  = @($checks | ForEach-Object { $_.Text })
                # For the activity ledger.
                Account = $hostCred.UserName
            }
        }
    }
    finally {
        # Captured, never left bare: an uncaptured result is function output,
        # and it came back as an extra "ready" target in $results.
        if ($savedTrustedHosts) {
            $rev = Restore-CollectTrustedHosts $savedTrustedHosts
            if     (-not $rev.Ok) { & $LogWriter "`n  [!!] TrustedHosts NOT reverted - $($rev.Reason). The targets are still trusted; remove them by hand in an elevated PowerShell.`n" }
            elseif ($rev.Changed) { & $LogWriter "`n  -> TrustedHosts reverted.`n" }
        }
    }

    $Credential = $null; $hostCred = $null
    return $results
}

# ------------------------------------------------- background collection ---
# The GUI runs the collection here rather than on its own thread: a WinRM
# Copy-Item of a gigabyte archive blocks for minutes, and on the UI thread
# nothing redraws the window while it does. Log lines and progress cross back
# through thread-safe containers that the UI thread polls:
# Start-LibJob 'Invoke-EvtxCollection' -Script $script:EvtxCollectorPath.
$script:EvtxCollectorPath = $PSCommandPath
