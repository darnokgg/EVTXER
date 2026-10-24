# tests/StatusPills.Tests.ps1
#
# Ease of use:
#   1. a row of pills in the title bar - Mission, ELK, SO beside PCAP - green
#      when that part is ready, grey when not, a click opens where to fix it;
#   2. the queue is the main path: its automation switches live on the queue
#      pane, not on the Settings tab;
#   3. Settings is split into "This mission" and "Setup";
#   4. after an upload or a raw import the tool says where to look.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
$code = Join-Path $PSScriptRoot '..\code'

# ---- 1. the readiness pills ----
$p = @(Get-ReadinessPills -MissionName '' -MissionIndex '' -ElkOk $false -ElkHost '' -SoReady $false -SoHost '')
Assert-Equal (($p | ForEach-Object Key) -join ',') 'Mission,Elk,So' "three pills, in the order the work needs them"
Assert-True (-not ($p | Where-Object On)) "nothing set up: all three are off"
Assert-Equal $p[0].Text 'No mission' "an unnamed mission says so"
Assert-True ($p[0].Tip -match 'Settings tab') "and the tip says where to name it"
Assert-Equal $p[1].Text 'ELK not verified' "an unverified Elasticsearch says so"
Assert-True ($p[1].Tip -match 'VERIFY CONNECTIVITY') "and names the button"
Assert-Equal $p[2].Text 'SO not set' "an empty Raw Events tab says so"
Assert-True ($p[2].Tip -match 'only needed for raw imports') "and that it is optional - a plain Elastic stack has no SO"

$p = @(Get-ReadinessPills -MissionName 'op-falcon' -MissionIndex 'hayabusa-mission-op-falcon' -ElkOk $true -ElkHost '10.0.0.5' -SoReady $true -SoHost '10.0.0.9')
Assert-True (@($p | Where-Object On).Count -eq 3) "all set up: all three are on"
Assert-Equal $p[0].Text 'Mission: op-falcon' "the mission by the name the operator typed"
Assert-True ($p[0].Tip -match 'hayabusa-mission-op-falcon') "and the index its uploads go into"
Assert-Equal $p[1].Text 'ELK connected' "a verified connection"
Assert-True ($p[1].Tip -match '10\.0\.0\.5') "to which host"
Assert-Equal $p[2].Text 'SO ready' "a filled-in Raw Events tab"
Assert-True ($p[2].Tip -match '10\.0\.0\.9' -and $p[2].Tip -match 'checked when an import runs') "which is not a checked login, and the tip says so"

$shell = Get-Content (Join-Path $code 'HayabusaMissionTool.ps1') -Raw
foreach ($n in 'Mission', 'Elk', 'So') {
    Assert-True ($shell -match "x:Name=`"pnlPill$n`"") "the $n pill is in the title row"
}
$fn = [regex]::Match($shell, '(?s)function Update-ReadyPills.*?\r?\n\}').Value
Assert-True ($fn -match 'Get-ReadinessPills') "the window shows the tested state"
Assert-True ($fn -match 'Test-SoReady') "SO ready means what the queue's raw step needs"
Assert-True ($fn -match 'Get-UploadConnKey') "ELK connected means the connection VERIFY checked, as the queue's upload step does"
Assert-True ($fn -notmatch 'Invoke-UiPump') "it runs from the timer and never pumps"
Assert-True ($fn -notmatch 'Write-Log(?! -Background)') "and logs only with -Background"
Assert-True ($shell -match '(?s)\$script:PcapTimer\.Add_Tick\(\{[^}]*Update-ReadyPills') "the PCAP pill's timer keeps them current"
Assert-True ($shell -match '\.Parent') "a click selects the TabItem, not the ScrollViewer inside it"
$xamlTitle = [regex]::Match($shell, '(?s)<!-- title row -->.*?<!-- Tabs on the left').Value
Assert-True ($xamlTitle.IndexOf('pnlPillMission') -lt $xamlTitle.IndexOf('pnlPcap') -and
             $xamlTitle.IndexOf('pnlPcap') -lt $xamlTitle.IndexOf('pnlBusy')) "Mission, ELK, SO, PCAP, then the busy pill last - so it appearing moves nothing"
$soi = Get-Content (Join-Path $code 'wpf-soimport.ps1') -Raw
Assert-True ($soi -match 'function Test-SoReady') "the Raw Events tab says when it is filled in enough"
$q = Get-Content (Join-Path $code 'wpf-queue.ps1') -Raw
Assert-True ([regex]::Match($q, '(?s)function Get-QueueBlockers.*?\n\}').Value -match 'Test-SoReady') "and the queue uses the same test"

# ---- 2. the queue is the main path ----
$set = Get-Content (Join-Path $code 'wpf-settings.ps1') -Raw
foreach ($c in 'chkAutoConvert', 'chkAutoUpload', 'chkAutoRaw', 'chkAutoArchive') {
    Assert-True ($q -match "x:Name=`"$c`"") "$c is on the queue pane"
    Assert-True ($set -notmatch $c) "and no longer on the Settings tab"
}
Assert-True ($q -notmatch 'Settings tab first' -and $q -notmatch "automatic processing is off \(Settings tab\)") "the queue no longer sends the operator to Settings for its switches"

# ---- 3. Settings: this mission, then setup ----
$at = { param($s) $set.IndexOf($s) }
$order = @('Text="THIS MISSION"', 'Text="Mission"', 'Text="Accountability PCAP"', 'Text="Archive"',
           'Text="SETUP"', 'Text="EVTX drop folder"', 'Text="Hayabusa rules"')
for ($i = 1; $i -lt $order.Count; $i++) {
    Assert-True ((& $at $order[$i - 1]) -ge 0 -and (& $at $order[$i - 1]) -lt (& $at $order[$i])) "Settings: $($order[$i - 1]) comes before $($order[$i])"
}

# ---- 4. where to look ----
$d = Get-WhereToLook 'detections'
Assert-True ($d -match 'Kibana' -and $d -match 'Hayabusa dashboards') "detections: Kibana and its Hayabusa dashboards"
Assert-True ($d -match "not in Security Onion's Hunt") "and not Security Onion's own pages"
$r = Get-WhereToLook 'raw'
Assert-True ($r -match "Security Onion's Hunt" -and $r -match 'Raw Events dashboards') "raw events: Security Onion and the Raw Events dashboards"
$up = Get-Content (Join-Path $code 'wpf-upload.ps1') -Raw
Assert-True ($up -match "Get-WhereToLook 'detections'") "the Upload tab says it after a successful upload"
Assert-True ($soi -match "Get-WhereToLook 'raw'") "the Raw Events tab after an import"
Assert-True ($q -match "Get-WhereToLook" -and $q -match 'QueueToldWhere') "and the queue, once a session per kind rather than per host"

# ---- review fixes (2026-10-18) ----
# The busy pill coming and going must not move the window: shown inside a
# WrapPanel it wrapped onto a second line in a narrow window and pushed the
# tabs down ~31 px at the start and end of every action. It keeps its slot.
Assert-True ($shell -match 'x:Name="pnlBusy"[^>]*Visibility="Hidden"') "the busy pill starts hidden, not collapsed - its space is kept"
$busyFn = [regex]::Match($shell, '(?s)function Set-AppBusy.*?\r?\n\}').Value
Assert-True ($busyFn -match "\`$pnlBusy\.Visibility = 'Hidden'" -and $busyFn -notmatch "pnlBusy\.Visibility = 'Collapsed'") "and Set-AppBusy hides it the same way"
Assert-True ($shell -match '(?s)<Grid Width="\d+"[^>]*>\s*<Border x:Name="pnlBusy"') "in a slot of fixed width, so a longer job name cannot rewrap the row"
Assert-True ($shell -match 'x:Name="lblBusy"[^>]*TextTrimming="CharacterEllipsis"') "a long job name is trimmed, not wrapped"
# The window's own TextBlock style wraps - measured: a long job name broke
# onto two lines and moved the tabs down 16 px even in a wide window.
Assert-True ($shell -match 'x:Name="lblBusy"[^>]*TextWrapping="NoWrap"') "the busy text never wraps"
Assert-True ($shell -match '(?s)<Style x:Key="PillText".*?TextWrapping" Value="NoWrap"') "nor does a pill's"
# A tab that failed to load greys only its own pill - the others still
# agree with the queue.
Assert-True ($fn -match '(?s)try \{ \$elkOk' -and $fn -match '(?s)try \{ \$soReady') "each tab's fact is read on its own"
# The switches live on the queue but save through the Settings tab.
$sw = [regex]::Match($q, '(?s)\$autoSwitch = \{.*?\r?\n\}').Value
Assert-True ($sw.IndexOf('Show-Queue') -ge 0 -and $sw.IndexOf('Show-Queue') -lt $sw.IndexOf('Save-SettingsTab')) "a switch updates the queue before saving"
Assert-True ($sw -match 'Get-Command Save-SettingsTab') "and still works when the Settings tab failed to load"
