# tests/Pcap.Tests.ps1
#
# Accountability PCAP:
# before EVTXER touches the network the operator should be capturing their
# own traffic. dumpcap captures; EVTXER starts it, sees one already running,
# and reminds. Every file is kept (never a ring buffer); the capture outlives
# EVTXER.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# ---- dumpcap's interface list ----
$ifs = @(ConvertFrom-DumpcapInterfaces @(
    '1. \Device\NPF_{00000000-0000-0000-0000-000000000001} (Local Area Connection* 10)',
    '5. \Device\NPF_{00000000-0000-0000-0000-000000000005} (Wi-Fi)',
    '13. \Device\NPF_Loopback (Adapter for loopback traffic capture)',
    '14. etwdump (Event Tracing for Windows (ETW) reader)',
    'some warning line'))
Assert-Equal $ifs.Count 4 "every numbered interface is read, anything else ignored"
Assert-Equal $ifs[1].Device '\Device\NPF_{00000000-0000-0000-0000-000000000005}' "the device is what -i takes"
Assert-Equal $ifs[1].Name 'Wi-Fi' "the name is what a person recognises"
Assert-Equal $ifs[3].Name 'Event Tracing for Windows (ETW) reader' "a name with brackets inside it is read whole"

# ---- the capture keeps every file ----
$a = Get-DumpcapArgs -Interface '\Device\NPF_{X}' -OutFolder 'D:\pcap' -Now ([datetime]'2026-10-16 14:03:09') -FileSizeMB 512
Assert-Equal ($a[0..1] -join ' ') '-i \Device\NPF_{X}' "on the chosen interface"
Assert-True ($a -contains 'filesize:524288') "rolling over to a new file every 512 MB"
Assert-True (-not ($a -match '^files:')) "with no files: limit - nothing is ever overwritten"
Assert-True ((Get-DumpcapArgs -Interface x -OutFolder D:\pcap) -contains 'filesize:3145728') "and by default a new file every 3 GB"
Assert-Equal $a[$a.IndexOf('-w') + 1] "D:\pcap\evtxer_$($env:COMPUTERNAME)_20261016_140309.pcapng" "into a file named for this machine and the start time"

# ---- what a running dumpcap is capturing ----
$c = ConvertFrom-DumpcapCommandLine '"C:\Program Files\Wireshark\dumpcap.exe" -i \Device\NPF_{A} -i "Wi-Fi 2" -b filesize:1048576 -w "D:\my pcaps\x.pcapng" -q'
Assert-Equal ($c.Interfaces -join '|') '\Device\NPF_{A}|Wi-Fi 2' "every -i is read, quoted or not"
Assert-Equal $c.File 'D:\my pcaps\x.pcapng' "and the file it writes"
Assert-Equal @((ConvertFrom-DumpcapCommandLine '').Interfaces).Count 0 "an elevated dumpcap shows no command line, and that is not an error"

# ---- when the reminder asks ----
$on  = [pscustomobject]@{ PcapReminder = 'on';  PcapSnoozeUntil = '' }
$off = [pscustomobject]@{ PcapReminder = 'off'; PcapSnoozeUntil = '' }
$now = [datetime]'2026-10-16 09:00'
Assert-True  (Test-PcapReminderDue $on 0 $now) "it asks when the reminder is on and nothing is capturing"
Assert-True  (-not (Test-PcapReminderDue $on 1 $now)) "not while a capture is already running"
Assert-True  (-not (Test-PcapReminderDue $off 0 $now)) "not when the reminder is switched off"
$snoozed = [pscustomobject]@{ PcapReminder = 'on'; PcapSnoozeUntil = (Get-PcapSnoozeDate $now) }
Assert-Equal $snoozed.PcapSnoozeUntil '2026-10-17' "'until tomorrow' means the next calendar day"
Assert-True  (-not (Test-PcapReminderDue $snoozed 0 ([datetime]'2026-10-16 23:59'))) "silent for the rest of today"
Assert-True  (Test-PcapReminderDue $snoozed 0 ([datetime]'2026-10-17 00:01')) "and asking again tomorrow"
Assert-True  (Test-PcapReminderDue ([pscustomobject]@{ PcapReminder = 'on'; PcapSnoozeUntil = 'garbage' }) 0 $now) "a broken snooze date is no snooze"

# ---- the settings carry it, on by default ----
$conf = Join-Path ([IO.Path]::GetTempPath()) ("pcapconf-{0}.json" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
try {
    $s = Read-ToolSettings $conf
    Assert-Equal $s.PcapReminder 'on' "the reminder is on until switched off"
    $s.PcapReminder = 'off'; $s.PcapInterface = '\Device\NPF_{X}'; Save-ToolSettings $s $conf
    $s2 = Read-ToolSettings $conf
    Assert-Equal "$($s2.PcapReminder)|$($s2.PcapInterface)" 'off|\Device\NPF_{X}' "switched off and the interface, both remembered"
} finally { Remove-Item -LiteralPath $conf -ErrorAction SilentlyContinue }

Assert-True (Test-NpcapRefused "The capture session could not be initiated on interface (Access is denied)") "Npcap's admin-only refusal is recognised"
Assert-True (-not (Test-NpcapRefused "Capturing on 'Wi-Fi'")) "a capture that started is not"

# ---- a real capture outlives the process that started it ----
$dumpcap = Find-Dumpcap ''
if (-not $dumpcap) {
    Write-Host "  [SKIP] Wireshark's dumpcap is not installed - live capture not exercised" -ForegroundColor Yellow
} else {
    $wifi = @(ConvertFrom-DumpcapInterfaces @(& $dumpcap -D 2>$null)) | Where-Object { $_.Name -match '^(Wi-Fi|Ethernet)' } | Select-Object -First 1
    $out = Join-Path ([IO.Path]::GetTempPath()) ("pcaptest-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $out -Force | Out-Null
    $before = @(Get-RunningCaptures | ForEach-Object ProcessId)
    try {
        $dcArgs = Get-DumpcapArgs -Interface $wifi.Device -OutFolder $out -FileSizeMB 16
        # Started from a powershell.exe that exits at once - the way the
        # capture must outlive EVTXER.
        $argLine = ($dcArgs | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }) -join ','
        powershell -NoProfile -Command "Start-Process -FilePath '$dumpcap' -ArgumentList @($argLine) -WindowStyle Hidden" | Out-Null
        $mine = $null
        foreach ($i in 1..20) {
            $mine = @(Get-RunningCaptures | Where-Object { $before -notcontains $_.ProcessId -and $_.File -like "$out*" })[0]
            if ($mine) { break }; Start-Sleep -Milliseconds 250
        }
        Assert-True ($null -ne $mine) "the capture is still running after the process that started it exited"
        Assert-True ($mine.Interfaces -contains $wifi.Device) "and EVTXER can tell which interface it captures"
        Start-Sleep -Seconds 4
        $files = @(Get-ChildItem -LiteralPath $out -Filter *.pcapng)
        # The directory's size for a file still open lags behind (NTFS), so
        # the file itself is asked. Rolling files get _00001_<time> added.
        $len = 0
        if ($files.Count) { $fs = [IO.File]::Open($files[0].FullName, 'Open', 'Read', 'ReadWrite'); try { $len = $fs.Length } finally { $fs.Dispose() } }
        Assert-True ($files.Count -ge 1 -and $len -gt 0) "the capture file is being written ($($files[0].Name), $len bytes)"
    } finally {
        Get-RunningCaptures | Where-Object { $before -notcontains $_.ProcessId -and $_.File -like "$out*" } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 500
        Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---- every network action asks first; local work does not ----
# Driven in the real window 2026-10-16: closing the question cancels, START
# CAPTURE starts dumpcap and goes on, OK goes on, "until tomorrow" is saved
# and silences it, and a running capture means no question at all.
$root = Split-Path -Parent $PSScriptRoot
$code = Join-Path $root 'code'
$gated = @{
    'wpf-collect.ps1'  = @('verifying access', 'testing ports', 'collecting EVTX')
    'wpf-upload.ps1'   = @('checking the Elasticsearch connection', 'uploading to ELK', 'uploading raw events to ELK')
    'wpf-kibana.ps1'   = @('importing dashboards', 'removing dashboards')
}
foreach ($f in $gated.Keys) {
    $src = Get-Content (Join-Path $code $f) -Raw
    foreach ($busy in $gated[$f]) {
        Assert-True ($src -match "Confirm-PcapBeforeNetwork (?:'[^']+'|`"[^`"]+`")\)\) \{ return \}\s+Set-AppBusy \`$true '$([regex]::Escape($busy))'") "$f asks about the capture before '$busy'"
    }
}
$up = Get-Content (Join-Path $code 'wpf-upload.ps1') -Raw
$kb = Get-Content (Join-Path $code 'wpf-kibana.ps1') -Raw
Assert-True ($up -match "(?s)Confirm-PcapBeforeNetwork 'fetch the Elasticsearch certificate'.{0,800}Get-ServerCertThumbprint") "and before fetching a certificate"
Assert-True ($kb -match "(?s)Confirm-PcapBeforeNetwork 'fetch the Kibana certificate'.{0,200}Get-ServerCertThumbprint") "on both tabs"
# Code review: once connected, Check and Generate list the indices on
# Elasticsearch - network work too.
foreach ($b in 'btnGen', 'btnCheck') {
    Assert-True ($up -match "\`$$b\.Add_Click\(\{ if \(-not \`$script:ConnOk -or \(Confirm-PcapBeforeNetwork") "the Upload tab's $b asks too, when it would reach Elasticsearch"
}
$set = Get-Content (Join-Path $code 'wpf-settings.ps1') -Raw
Assert-True ($set -match "\`$dest -like '\\\\\*' -and -not \(Confirm-PcapBeforeNetwork") "archiving asks only when the archive is a network share"
foreach ($f in 'wpf-convert.ps1', 'wpf-takajo.ps1') {
    Assert-True ((Get-Content (Join-Path $code $f) -Raw) -notmatch 'Confirm-PcapBeforeNetwork') "$f is local work and does not ask"
}
$shell = Get-Content (Join-Path $code 'HayabusaMissionTool.ps1') -Raw
Assert-True ($shell -match "Start-Process -FilePath \`$dumpcap[^\r\n]*-WindowStyle Hidden") "dumpcap runs as a process of its own, so it outlives EVTXER"
Assert-True ($shell -match "-Verb RunAs") "and is started elevated only when Npcap refuses this user"
Assert-True ($shell -match "New-LedgerRow -Action 'PCAP start'") "starting a capture is in the activity log"
Assert-True ($set -match "New-LedgerRow -Action 'PCAP stop'") "and so is stopping one"

# ---- the Wireshark live viewer ("visual confirmation") ----
$v = Get-WiresharkViewerArgs '\Device\NPF_{X}'
Assert-Equal ($v[0..2] -join ' ') '-i \Device\NPF_{X} -k' "the viewer opens on the capture interface and starts at once"
Assert-True ($v -contains 'files:2' -and $v -contains 'filesize:5120') "and keeps only a small ring, so a long mission cannot fill memory or disk"
Assert-True (Test-ViewerCapture $v[$v.IndexOf('-w') + 1]) "its own capture is recognised as the viewer"
Assert-True (-not (Test-ViewerCapture 'D:\pcap\evtxer_HOST_20261016_081340.pcapng')) "and THE recording is not"
$shell = Get-Content (Join-Path $PSScriptRoot '..\code\HayabusaMissionTool.ps1') -Raw
Assert-True ($shell -match "Where-Object \{ -not \`$_\.IsViewer \}\)\.Count") "a viewer alone does not silence the question - it records nothing to keep"
# Once per session: answered "continue without capture",
# it is not asked again until EVTXER restarts.
Assert-True (-not (Test-PcapReminderDue $on 0 $now -AnsweredThisSession)) "not again once answered this session"
Assert-True ($shell -match '-AnsweredThisSession:\(\[bool\]\$script:PcapAnswered\)' -and $shell -match '\$script:PcapAnswered = \$true') "the window remembers the answer for the session"
Assert-True ($shell -match 'Content="Continue without capture"') "and the button says what it does"
Assert-True ($shell -match "if \(\`$script:Settings\.PcapViewer -ne 'off'\) \{ Open-CaptureViewer \}") "starting a capture opens the viewer unless switched off"
Assert-Equal (Read-ToolSettings (Join-Path $env:TEMP 'no-such-settings.conf')).PcapViewer 'on' "the viewer is on by default"

# ---- the PCAP pill in the title row ----
# Beside "Things are cookin'": is the accountability PCAP recording? Read from
# the machine, so a capture that died - or one Wireshark started - shows as it is.
$cap  = [pscustomobject]@{ ProcessId = 4242; File = 'D:\pcap\evtxer_HOST_20261018_090000.pcapng'; IsViewer = $false }
$view = [pscustomobject]@{ ProcessId = 777;  File = 'C:\Temp\EVTXER-viewer\evtxer-live-view_00001.pcapng'; IsViewer = $true }
$elev = [pscustomobject]@{ ProcessId = 5150; File = ''; IsViewer = $false }
$p = Get-PcapPill @()
Assert-True (-not $p.On) "no dumpcap: the pill is off"
Assert-Equal $p.Text 'No PCAP' "and says so, dimmed rather than gone"
$p = Get-PcapPill $null
Assert-True (-not $p.On) "nothing at all is the same as none"
$p = Get-PcapPill @($view)
Assert-True (-not $p.On) "EVTXER's own Wireshark viewer is not the recording"
$p = Get-PcapPill @($view, $cap)
Assert-True $p.On "a real capture turns it on"
Assert-Equal $p.Text 'PCAP rolling' "with words in the busy pill's style"
Assert-True ($p.Tip -match '4242' -and $p.Tip -match 'evtxer_HOST_20261018_090000') "hovering says which dumpcap and which file"
Assert-True ($p.Tip -notmatch 'live-view') "and leaves the viewer out"
$p = Get-PcapPill @($elev)
Assert-True ($p.On -and $p.Tip -match '5150' -and $p.Tip -match 'elevated') "an elevated capture whose file cannot be read still counts"

$shell = Get-Content (Join-Path $PSScriptRoot '..\code\HayabusaMissionTool.ps1') -Raw
Assert-True ($shell -match 'x:Name="pnlPcap"') "the pill is in the window"
$fn = [regex]::Match($shell, '(?s)function Update-PcapPill.*?\r?\n\}').Value
Assert-True ($fn.Length -gt 0) "one function keeps it current"
Assert-True ($fn -match 'Get-PcapPill') "from the tested state"
# It runs from a timer: a pump inside it would let a click start a job
# nested in the tick (the queue's trap), and a plain Write-Log pumps.
Assert-True ($fn -notmatch 'Invoke-UiPump') "it never pumps"
Assert-True ($fn -notmatch 'Write-Log(?! -Background)') "and logs only with -Background"
Assert-True ($fn -match 'Get-Process -Name dumpcap') "it reads command lines only when the dumpcap processes changed"
Assert-True ($shell -match '(?s)\$script:PcapTimer\.Add_Tick\(.*?Update-PcapPill') "a timer keeps it current"
Assert-True ($set -match '(?s)function Update-PcapStatus.*?Update-PcapPill') "and the Settings card's start/stop updates it at once"

# ---- review fixes (2026-10-18) ----
# Wireshark runs dumpcap helpers that record nothing: -D/-L to list
# interfaces, -S for its welcome page's sparklines (as long as that page is
# open). Counted as captures they turned the pill red and silenced the
# reminder with nothing being recorded.
$ws = '"C:\Program Files\Wireshark\dumpcap.exe"'
foreach ($helper in "$ws -S -Z none", "$ws -D -Z none", "$ws -L -i \Device\NPF_{X} -Z none", "$ws --list-interfaces") {
    Assert-True (ConvertFrom-DumpcapCommandLine $helper).Helper "a Wireshark helper is not a capture: $helper"
}
Assert-True (-not (ConvertFrom-DumpcapCommandLine "$ws -i \Device\NPF_{X} -b filesize:3145728 -w D:\pcap\x.pcapng -q").Helper) "EVTXER's own capture is one"
Assert-True (-not (ConvertFrom-DumpcapCommandLine "$ws -n -i \Device\NPF_{X} -Z 1234").Helper) "so is a Wireshark capture to its temp file"
Assert-True (-not (ConvertFrom-DumpcapCommandLine '').Helper) "and an elevated one whose command line cannot be read"
$lib = Get-Content (Join-Path $PSScriptRoot '..\code\HayabusaLib.ps1') -Raw
Assert-True ([regex]::Match($lib, '(?s)function Get-RunningCaptures.*?\n\}').Value -match '\.Helper') "Get-RunningCaptures leaves helpers out, for the pill, the reminder and Stop alike"
$wsTemp = [pscustomobject]@{ ProcessId = 6060; File = ''; IsViewer = $false; CommandLine = "$ws -n -i \Device\NPF_{X} -Z 1234" }
$p = Get-PcapPill @($wsTemp)
Assert-True ($p.On -and $p.Tip -match 'temporary' -and $p.Tip -notmatch 'elevated') "a readable capture with no file is Wireshark's temp file, not 'elevated'"
# The click: $tabSettings is the ScrollViewer INSIDE the TabItem; WPF
# ignores a SelectedItem that is not one of its items.
Assert-True ($shell -match '\$pnlPcap\.Add_MouseLeftButtonUp\(\{ \$tabs\.SelectedItem = \$tabSettings\.Parent \}\)') "clicking the pill selects the Settings TabItem"
# A failed read is retried when the dumpcap processes change, not every tick.
$fn = [regex]::Match($shell, '(?s)function Update-PcapPill.*?\r?\n\}').Value
Assert-True ($fn -match '(?s)\$script:PcapPillPids = \$pids.*?Get-PcapPill') "the PIDs are remembered before the read, so a failing read is not redone every 3 s"
