# tests/UsabilityWalk.Tests.ps1
#
# Fixes from the usability walk of 2026-10-21 (an expert walk-through of every
# tab as a first-time analyst) and the answers the same day.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
$root = Split-Path -Parent $PSScriptRoot
$src = @{}
foreach ($f in 'HayabusaMissionTool.ps1', 'wpf-collect.ps1', 'wpf-upload.ps1', 'wpf-kibana.ps1', 'wpf-settings.ps1', 'wpf-takajo.ps1', 'wpf-convert.ps1') {
    $src[$f] = Get-Content (Join-Path $root "code\$f") -Raw
}

# ---- U-2: a wrapped job error reaches the operator as its cause ----
$inner = New-Object System.Exception 'This PC cannot use plain WinRM yet - nothing was sent to the targets.'
$wrapped = New-Object System.Management.Automation.MethodInvocationException ('Exception calling "EndInvoke" with "1" argument(s): "' + $inner.Message + '"'), $inner
Assert-Equal (Get-CollectFailureText $wrapped) $inner.Message "the EndInvoke wrapper is taken off"
Assert-Equal (Get-CollectFailureText (New-Object System.Exception 'Exception calling "X" with "2" argument(s): "the cause"')) 'the cause' "and a wrapper written into the message text too"
Assert-Equal (Get-CollectFailureText (New-Object System.Exception 'plain')) 'plain' "a plain message is left alone"

# ---- EVTXER runs as administrator; WinRM's needs said up front ----
Assert-Equal @(Get-LocalWinRmProblems 'WinRM' -Elevated $true -ServiceStatus 'Running').Count 0 "elevated with WinRM running: nothing to say"
$p = @(Get-LocalWinRmProblems 'WinRM' -Elevated $false -ServiceStatus 'Stopped')
Assert-Equal $p.Count 2 "not elevated and the service stopped: both said"
Assert-True ($p[0] -match 'EVTXER\.cmd' -and $p[1] -match 'Start-Service WinRM') "each with its fix"
Assert-Equal @(Get-LocalWinRmProblems 'WinRM-HTTPS' -Elevated $false -ServiceStatus 'Stopped').Count 0 "HTTPS needs neither"
Assert-Equal @(Get-LocalWinRmProblems 'SMB' -Elevated $false -ServiceStatus 'Stopped').Count 0 "nor does SMB"
$cmd = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes((Join-Path $root 'EVTXER.cmd')))
Assert-True ($cmd -match '(?m)^"%SystemRoot%\\System32\\fltmc\.exe" >nul' -and $cmd -match '-Verb RunAs') "the .cmd asks Windows for administrator rights (fltmc: no service needed to tell)"
Assert-True ($cmd -notmatch '(?m)^net session') "not net session, which fails with the Server service off and looped the relaunch"
Assert-True ($cmd -match "-ArgumentList 'evtxer-elevated'" -and $cmd -match '(?m)^if /i "%~1"=="evtxer-elevated" goto run') "the relaunched copy never relaunches again"
Assert-True ($cmd -match '\$env:EVTXER_SELF' -and $cmd -notmatch "'%~f0'") "the path travels in the environment, not a quoted string"
Assert-True ($cmd -match 'DisplayRoot') "a mapped drive is turned into its share path"
Assert-True ($cmd -match ':run' -and $cmd -match 'not given - starting without them') "and starts without them when refused"
Assert-True ($src['HayabusaMissionTool.ps1'] -match 'if \(-not \(Test-IsElevated\)\)') "the window says so at startup when not elevated"
Assert-True ($src['wpf-collect.ps1'] -match 'x:Name="lblWinRmLocal"' -and $src['wpf-collect.ps1'] -match 'Get-LocalWinRmProblems') "and under WinRM when it is picked"

# ---- U-6: nothing answering gets the firewall hint ----
$h = Get-ConnectionHint 'Exception calling "EndConnect" with "1" argument(s): "No connection could be made because the target machine actively refused it 127.0.0.1:9200"' '127.0.0.1' 9200
Assert-True ($h -match '^Nothing answered at 127\.0\.0\.1:9200' -and $h -match 'LETTING EVTXER IN') "a refused connection points at the firewall section"
Assert-True ($h -notmatch 'EndConnect') "without the .NET wrapper"
Assert-True ((Get-ConnectionHint 'Unable to connect to the remote server' 'so1' 9200) -match '^Nothing answered at so1:9200') "and so does 'Unable to connect'"
Assert-Equal (Get-ConnectionHint 'HTTP 403 forbidden' 'so1' 9200) 'HTTP 403 forbidden' "any other error is passed on"
# Owner, 2026-10-26: when nothing answers, print what the Security Onion
# administrator needs to let this PC in - its address and the exact command.
$h = Get-ConnectionHint 'Unable to connect to the remote server' 'so1' 9200 -LocalIp '192.0.2.10'
Assert-True ($h -match "this PC's address is 192\.0\.2\.10") "it names this PC's address"
Assert-True ($h.Contains('sudo so-firewall --apply includehost elasticsearch_rest 192.0.2.10')) "and the exact command for 9200, address filled in"
# Review, 2026-10-26: the plain-Elastic team uses 9200 too, where so-firewall does not exist.
Assert-True ($h -match 'If they are right and this is Security Onion' -and $h -match 'plain Elastic stack') "the Security Onion command is offered as such, with what to check on a plain Elastic stack"
Assert-True ($h -notmatch "
 [^ ]") "no stray space after the command's line break (the command itself is indented by four)"
$h = Get-ConnectionHint 'Unable to connect to the remote server' 'so1' 443 -LocalIp '192.0.2.10'
Assert-True ($h.Contains('sudo so-firewall --apply includehost analyst 192.0.2.10')) "443 (the Kibana tab) gets the analyst group"
$h = Get-ConnectionHint 'Unable to connect to the remote server' 'so1' 9200 -LocalIp ''
Assert-True ($h.Contains('includehost elasticsearch_rest <this PC') -and $h -match 'ipconfig') "an address that cannot be found is a placeholder, with where to look"
$h = Get-ConnectionHint 'The remote name could not be resolved: so1' 'so1' 9200 -LocalIp '192.0.2.10'
Assert-True ($h -notmatch 'so-firewall' -and $h -match 'name') "a name that does not resolve is not a firewall problem - no command"
Assert-Equal (Get-LocalAddressFor '127.0.0.1' 9200) '127.0.0.1' "this PC's address on the way to a host - nothing is sent"
Assert-True ((Get-ConnectionHint 'Unable to connect to the remote server' '127.0.0.1' 9200).Contains('includehost elasticsearch_rest 127.0.0.1')) "called as the tabs call it - no address given - it looks the address up itself"
foreach ($f in 'wpf-upload.ps1', 'wpf-kibana.ps1') {
    Assert-True ($src[$f] -match 'Get-ConnectionHint' -and $src[$f] -match "New-LedgerRow -Action 'Certificate fetch'") "$f explains fetch failures and records every fetch (U-12)"
}

# ---- U-12: one spelling of a failure in the activity log ----
Assert-Equal (New-LedgerRow -Action 'x' -Target 't' -Result 'FAILED').Result 'Failed' "FAILED is written as Failed"
Assert-Equal (New-LedgerRow -Action 'x' -Target 't' -Result 'Success').Result 'Success' "other results are left alone"
Assert-True ($src['wpf-collect.ps1'] -match "(?s)Verify failed: \`$why.*?New-LedgerRow -Action 'Verify access'") "a verify that fails on this PC still writes its row"

# ---- U-1: a selected radio is a filled dot ----
$tpl = [regex]::Match($src['HayabusaMissionTool.ps1'], '(?s)<Style TargetType="RadioButton">.*?</Style>').Value
Assert-True ($tpl -match 'x:Name="dot"' -and $tpl -match '(?s)Property="IsChecked" Value="True">\s*<Setter TargetName="dot" Property="Visibility" Value="Visible"') "the radio template shows its dot only when chosen"

# ---- U-3 / U-19: honest status line, version in the title ----
Assert-True ($src['HayabusaMissionTool.ps1'] -match 'Finished with errors after') "a job with errors does not end on a plain Finished"
Assert-True ($src['HayabusaMissionTool.ps1'] -match '"Failed: \$w0 - see the log"') "nor does a short action that failed"
Assert-True ($src['HayabusaMissionTool.ps1'] -notmatch "\`$win\.Title = 'EVTXER'") "the title never loses the version"

# ---- U-11, U-18: one count, one IP note ----
Assert-True ($src['wpf-collect.ps1'] -match '\$res = @\(Test-CollectAccess') "a single target is still counted"
Assert-True ($src['wpf-collect.ps1'] -match 'if \(\$state\.SkipCertCheck\) \{ Write-CollectAuthNote @\(\) \$true \}') "the IP note is said once, by the check itself"

# ---- U-7, U-8: the index name ----
Assert-True ($src['wpf-upload.ps1'] -match 'not checked against Elasticsearch yet') "an unchecked name is not called free"
Assert-True ($src['wpf-upload.ps1'] -match '(?s)function Invoke-GenerateIndexName \{.*?Get-MissionIndexName') "with a mission named, its index is the name"
Assert-True ($src['wpf-upload.ps1'] -match 'Not the mission index') "and another name is warned about"

# ---- wording ----
Assert-True ($src['wpf-settings.ps1'] -match 'nothing deletes it for you') "the mission index is not said to delete itself"
Assert-True ($src['wpf-takajo.ps1'] -match 'Takajo summarises Hayabusa') "the Takajo tab says what Takajo is"
Assert-True ($src['wpf-convert.ps1'] -match 'scanned and converted by the QUEUE') "the Convert tab says the queue does collected hosts"
Assert-True ((Get-PathGuide) -join "`n" -match 'jobs\\') "and where the queue's results go"
Assert-True ($src['wpf-kibana.ps1'] -match 'Kibana 9 / Security Onion - this tab') "the Kibana tab names its file"
$readme = Get-Content (Join-Path $root 'README.txt') -Raw
Assert-True ($readme -notmatch "review server listens on ALL interfaces") "README no longer describes the removed Takajo server"
Assert-True ($readme -match 'runs as ADMINISTRATOR') "README says EVTXER runs as administrator"

# ---- the target disk guard: WinRM stages ON the target ----
$ok = Test-TargetStagingSpace -FreeBytes 50GB -DiskBytes 100GB -LogBytes 1GB
Assert-True ($ok.Ok -and $ok.Known) "plenty of room: collected"
Assert-Equal $ok.NeedBytes (2GB) "logs small enough to zip count twice (the zip sits beside them)"
$no = Test-TargetStagingSpace -FreeBytes 11GB -DiskBytes 100GB -LogBytes 1GB
Assert-True (-not $no.Ok) "11 GB free on a 100 GB disk, 2 GB to stage: refused - it would leave under 10%"
Assert-True ($no.Message -match '^NOT COLLECTED to protect the target' -and $no.Message -match 'SMB') "and says why, and what to do instead"
Assert-True ((Test-TargetStagingSpace -FreeBytes 7GB -DiskBytes 30GB -LogBytes 1GB).Ok) "a small disk keeps at least 5 GB, not 10%"
Assert-True (-not (Test-TargetStagingSpace -FreeBytes 6GB -DiskBytes 30GB -LogBytes 1GB).Ok) "and refuses below that"
$big = (Get-WinRmZipCeilingBytes) + 1
Assert-Equal (Test-TargetStagingSpace -FreeBytes 1TB -DiskBytes 2TB -LogBytes $big).NeedBytes $big "logs too big to zip count once"
$unk = Test-TargetStagingSpace -FreeBytes -1 -DiskBytes 0 -LogBytes 0
Assert-True ($unk.Ok -and -not $unk.Known) "a target that cannot say is collected, with a note"
$coll = Get-Content (Join-Path $root 'code\EvtxCollector.ps1') -Raw
Assert-True ($coll.IndexOf('Test-TargetStagingSpace -FreeBytes $disk.Free') -gt 0 -and
             $coll.IndexOf('Test-TargetStagingSpace -FreeBytes $disk.Free') -lt $coll.IndexOf('# Export every requested log on the target first.')) "the collector checks before it exports anything"
Assert-True ($coll -match 'if \(-not \$space\.Ok\) \{ throw \$space\.Message \}') "and stops that host when there is no room"

# The review of 2026-10-21: a Kibana import that failed ended on 'Finished'.
$kbs = Get-Content (Join-Path $root 'code\wpf-kibana.ps1') -Raw
Assert-True ($kbs -notmatch "lblStatus\.Text = 'Finished'") "the Kibana tab hands its status to Set-AppBusy, which says Failed"
Assert-Equal (ConvertFrom-WrappedErrorText 'Exception calling "A" with "1" argument(s): "Exception calling "B" with "0" argument(s): "deep""') 'deep' "a doubly wrapped error is unwrapped to its cause"
