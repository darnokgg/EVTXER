# tests/ActivityLedger.Tests.ps1
#
# The accountability record (operator request, 2026-10-14): one CSV that keeps
# growing across every session, a row per thing the tool did to a target -
# when, who, from where, to which IP and port, over what, with which account,
# and whether it worked. The mission log is per launch, untimestamped and
# prose; this is the table you hand to whoever asks "what touched that box".
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ledger-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $path = Join-Path $tmp 'activity_log.csv'
    $when = [datetime]'2026-10-14 09:05:07'

    # ---- a row carries every column, in a fixed order ----
    $r = New-LedgerRow -Action 'Collect' -Target '10.0.0.5' -Port 5985 -Protocol 'WinRM' -Account 'CORP\admin' `
            -Result 'Success' -Files '6/6' -Bytes 1610612736 -Seconds 95 -Integrity 'SHA-256 verified 6/6' `
            -Output 'C:\x\evtx\10.0.0.5_20261014_0905' -Details "line one`r`nline two" -When $when
    $cols = @($r.PSObject.Properties.Name)
    foreach ($c in 'Date','Time','UTC','Operator','Workstation','WorkstationIP','Action','Target','Port','Protocol',
                   'Account','Result','Files','Size','Duration','Integrity','LeftOnTarget','Output','Details','ToolVersion') {
        Assert-True ($cols -contains $c) "the ledger has a $c column"
    }
    Assert-Equal $r.Date '2026-10-14' "the date is ISO, so it sorts"
    Assert-Equal $r.Time '09:05:07' "the local time is to the second"
    Assert-Equal $r.UTC ($when.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) "UTC rides alongside for cross-site comparison"
    Assert-Equal $r.Size '1.50 GB' "bytes are shown in human units"
    Assert-Equal $r.Duration '01:35' "the duration reads as a clock"
    Assert-Equal $r.Details 'line one line two' "a multi-line detail is flattened so the row stays one row"
    Assert-True ($r.Operator -match [regex]::Escape($env:USERNAME)) "the operator is the Windows account running the tool"
    Assert-Equal $r.Workstation $env:COMPUTERNAME "the workstation is this machine"
    Assert-Equal (New-LedgerRow -Action 'Port test' -Target 'x' -Bytes -1).Size '' "unmeasured bytes leave Size empty, not 0"

    # ---- nothing from a target can become an Excel formula ----
    # Hostnames, account names and error messages come from the far end; a
    # cell starting = + - @ is run as a formula when Excel opens the CSV.
    $evil = New-LedgerRow -Action 'Collect' -Target '=HYPERLINK("http://x","y")' -Account '+cmd' `
                -Details '-2+3' -Output '@SUM(1)' -LeftOnTarget "`t=1"
    Assert-Equal $evil.Target "'=HYPERLINK(`"http://x`",`"y`")" "a leading = is neutralised"
    Assert-Equal $evil.Account "'+cmd" "a leading + is neutralised"
    Assert-Equal $evil.Details "'-2+3" "a leading - is neutralised"
    Assert-Equal $evil.Output "'@SUM(1)" "a leading @ is neutralised"
    Assert-True ($evil.LeftOnTarget.StartsWith("'")) "a leading tab is neutralised"
    Assert-Equal (New-LedgerRow -Action 'x' -Target ' =cmd').Target "'=cmd" "leading spaces cannot hide a formula character"
    Assert-Equal (New-LedgerRow -Action 'Collect' -Target '10.0.0.5').Target '10.0.0.5' "ordinary values are untouched"

    # ---- appended across sessions, one header ----
    $w1 = Add-LedgerRows @($r) $path
    $w2 = Add-LedgerRows @((New-LedgerRow -Action 'Port test' -Target '10.0.0.6' -Port 445 -Protocol 'SMB' -Result 'Closed')) $path
    Assert-Equal $w1.Pending $false "a free file is written directly"
    $back = @(Import-Csv -LiteralPath $path)
    Assert-Equal $back.Count 2 "rows accumulate in one file"
    Assert-Equal $back[0].Target '10.0.0.5' "the first row reads back"
    Assert-Equal $back[1].Result 'Closed' "the second row reads back"
    Assert-Equal @(Get-Content -LiteralPath $path | Where-Object { $_ -match '^"Date"' }).Count 1 "the header is written once"
    $bytes = [IO.File]::ReadAllBytes($path)
    Assert-True ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) "UTF-8 with a BOM, so Excel shows names like BüRO-PC correctly"

    # ---- open in Excel: nothing is lost ----
    # Excel holds an open CSV with a lock that refuses writers. The row goes to
    # a pending file instead and is folded in by the next write that can.
    $lock = [IO.File]::Open($path, 'Open', 'Read', 'None')
    try {
        $w3 = Add-LedgerRows @((New-LedgerRow -Action 'Verify access' -Target '10.0.0.7' -Result 'OK')) $path
    } finally { $lock.Dispose() }
    Assert-Equal $w3.Pending $true "a locked ledger is reported, not silently skipped"
    Assert-True (Test-Path -LiteralPath $w3.Path) "the row went to the pending file"
    $w4 = Add-LedgerRows @((New-LedgerRow -Action 'Upload' -Target 'so' -Result 'Success')) $path
    $back = @(Import-Csv -LiteralPath $path)
    Assert-Equal $back.Count 4 "the next free write folds the pending row back in"
    Assert-Equal $back[2].Target '10.0.0.7' "in the order it happened"
    Assert-True (-not (Test-Path -LiteralPath $w3.Path)) "and the pending file is gone"
}
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }

# ---- the collector hands the ledger what it needs per host ----
$h = New-CollectHostResult '10.0.0.5' 'CORP\admin' 'Success' 6 6 'C:\x' '' -Bytes 2048 -Seconds 12 -Integrity 'ok' -LeftOnTarget 'C:\Windows\Temp\EVTX_Export_1'
Assert-Equal $h.Bytes ([long]2048) "a host result carries the bytes collected"
Assert-Equal $h.LeftOnTarget 'C:\Windows\Temp\EVTX_Export_1' "and anything left behind on the target"
$plain = New-CollectHostResult '10.0.0.5' 'CORP\admin' 'Failed' 0 6 '' 'x'
Assert-Equal $plain.Bytes ([long]-1) "an unmeasured host says so rather than claiming 0 bytes"

# ---- every action that touches a target writes a row ----
$src = Get-ToolSource
foreach ($a in "'Port test'", "'Verify access'", "'Collect'", "'Convert'", "'Upload'") {
    Assert-True ($src -match "Write-Ledger[^\r\n]*-Action $a|-Action $a") "$a is recorded in the activity log"
}

# ---- it survives a restart, and it can be handed over ----
# The activity log "has to be persistent even after the app
# is closed and reopened and there should be an export option".
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ledger-x-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $path = Join-Path $tmp 'activity_log.csv'
    # Two "sessions": the second process knows nothing the first one held.
    $s1 = "& { . '$PSScriptRoot\..\code\HayabusaLib.ps1'; Add-LedgerRows @(New-LedgerRow -Action 'Collect' -Target 'HOSTA' -Port 445 -Protocol SMB -Account 'HOSTA\op' -Result 'Success' -Files '6/6' -Bytes 2048 -Seconds 61 -Output 'D:\evtx\HOSTA_x' -Details '=cmd|x') '$path' | Out-Null }"
    $s2 = "& { . '$PSScriptRoot\..\code\HayabusaLib.ps1'; Add-LedgerRows @(New-LedgerRow -Action 'Port test' -Target 'HOSTB' -Port 5985 -Protocol WinRM -Result 'Not open') '$path' | Out-Null }"
    foreach ($c in $s1, $s2) { powershell -NoProfile -Command $c }
    $rows = @(Get-LedgerRows $path)
    Assert-Equal (($rows | ForEach-Object Action) -join ',') 'Collect,Port test' "rows from two separate runs of the tool are both kept, in order"

    # A row written while Excel held the file waits in the pending file; an
    # export must not leave it out.
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'None')
    try { Add-LedgerRows @(New-LedgerRow -Action 'Upload' -Target 'es:9200' -Result 'Success') $path | Out-Null } finally { $fs.Dispose() }
    Assert-True (Test-Path -LiteralPath (Get-LedgerPendingPath $path)) "a locked log sends the row to the pending file"
    Assert-Equal @(Get-LedgerRows $path).Count 3 "and it is still counted"

    $csv = Join-Path $tmp 'out\export.csv'
    New-Item -ItemType Directory -Path (Split-Path $csv) -Force | Out-Null
    Assert-Equal (Export-ActivityLog $path $csv) 3 "the export writes every action"
    $back = @(Import-Csv -LiteralPath $csv -Encoding UTF8)
    Assert-Equal (($back | ForEach-Object Action) -join ',') 'Collect,Port test,Upload' "the .csv holds them all, pending one included"
    Assert-Equal (@($back[0].PSObject.Properties.Name) -join ',') ($script:LedgerColumns -join ',') "with every column, in the ledger's order"
    Assert-Equal $back[0].Details "'=cmd|x" "a formula-looking cell stays text in the copy too"
    Assert-True ([IO.File]::ReadAllBytes($csv)[0] -eq 0xEF) "the .csv starts with a BOM, so Excel reads accents"

    $txt = Join-Path $tmp 'out\export.txt'
    Export-ActivityLog $path $txt | Out-Null
    $t = Get-Content -LiteralPath $txt -Encoding UTF8
    Assert-True ($t[1] -match '3 action\(s\)') "the .txt says how many actions it holds"
    Assert-True (@($t -match '^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \(.+Z\)  Collect  HOSTA, port 445, SMB  -  Success$').Count -eq 1) "each action opens with when, what, where and the result"
    Assert-True (@($t -match '^    Files:\s+6/6$').Count -eq 1) "then what was pulled"
    Assert-True (@($t -match '^    Account:\s+HOSTA\\op$').Count -eq 1) "and with which account"
    Assert-True (-not (@($t -match '^    LeftOnTarget:').Count)) "empty fields are left out"
    Assert-True (Test-Path -LiteralPath $path) "the live log stays where it is"

    # Code review, 2026-10-16: the Save dialog would let the export land on
    # the live log itself - rewriting the append-only record, or replacing it
    # with the .txt report.
    $live = [IO.File]::ReadAllBytes($path)
    foreach ($onto in $path, (Get-LedgerPendingPath $path), ($path -replace '\.csv$', '.CSV')) {
        $threw = $false
        try { Export-ActivityLog $path $onto | Out-Null } catch { $threw = $true }
        Assert-True $threw "exporting onto $(Split-Path -Leaf $onto) is refused"
    }
    Assert-True ([Linq.Enumerable]::SequenceEqual([byte[]]$live, [byte[]][IO.File]::ReadAllBytes($path))) "and the live log is byte-for-byte unchanged"

    $none = Join-Path $tmp 'empty\activity_log.csv'
    $noneOut = Join-Path $tmp 'out\none.csv'
    Assert-Equal (Export-ActivityLog $none $noneOut) 0 "an empty log exports nothing"
    Assert-Equal (@(Get-Content -LiteralPath $noneOut -Encoding UTF8)[0]) ('"' + ($script:LedgerColumns -join '","') + '"') "but the .csv still has its header"
}
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
Assert-True ($src -match "Export-ActivityLog \`$script:LedgerPath") "the window has an Export button for it"

# ---- the network log: the activity log re-shaped, network actions only ----
# columns: date/time, target IP, command run, success,
# what was pulled/sent, duration, notes. Network actions only - scanning,
# converting and a local archive never touched a target.
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("networklog-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $path = Join-Path $tmp 'activity_log.csv'
    $when = [datetime]'2026-10-17 14:02:09'
    Add-LedgerRows @(
        New-LedgerRow -When $when -Action 'Port test' -Target '10.0.0.5' -Port 5985 -Protocol 'WinRM' -Result 'Not open'
        New-LedgerRow -When $when -Action 'Collect' -Target '10.0.0.5' -Port 445 -Protocol 'SMB' -Account 'CORP\admin' `
            -Result 'Success' -Files '6/6 logs' -Bytes 1610612736 -Seconds 95 -Integrity 'SHA-256 verified 6/6' -LeftOnTarget 'none'
        New-LedgerRow -When $when -Action 'Collect' -Target '10.0.0.6' -Port 5985 -Protocol 'WinRM' -Account 'CORP\admin' `
            -Result 'FAILED' -Details 'Access is denied'
        New-LedgerRow -When $when -Action 'Convert' -Target '10.0.0.5_20261017' -Protocol 'Hayabusa scan + ECS' -Result 'Success'
        New-LedgerRow -When $when -Action 'EVTX archive' -Target '10.0.0.5_20261017' -Protocol 'local disk' -Result 'Success' -Output 'D:\archive\a.zip'
        New-LedgerRow -When $when -Action 'EVTX archive' -Target '10.0.0.5_20261017' -Protocol 'SMB' -Result 'Success' `
            -Files '6 EVTX' -Output '\\filer01\evidence\10.0.0.5_20261017.zip'
        # A failed archive has no zip; the share it tried is still a network action.
        New-LedgerRow -When $when -Action 'EVTX archive' -Target '10.0.0.6_20261017' -Protocol 'SMB' -Result 'FAILED' `
            -Output '\\filer01\evidence' -Details 'Access is denied'
        New-LedgerRow -When $when -Action 'Upload' -Target '192.0.2.30' -Port 9200 -Protocol 'HTTPS (Elasticsearch)' `
            -Result 'Success' -Files '17,008 documents' -Output 'hayabusa-mission-x'
        New-LedgerRow -When $when -Action 'Rules update' -Target 'github.com (Yamato-Security/hayabusa-rules)' -Protocol 'HTTPS (git)' -Result 'Success'
        New-LedgerRow -When $when -Action 'Rules update' -Target 'rules.zip' -Protocol 'file' -Result 'Success'
        New-LedgerRow -When $when -Action 'PCAP start' -Target 'Ethernet' -Protocol 'dumpcap' -Result 'Success'
    ) $path | Out-Null

    $out = Join-Path $tmp 'network.csv'
    Assert-Equal (Export-NetworkLog $path $out) 7 "the network log keeps only the actions that went over the network"
    $c = @(Import-Csv -LiteralPath $out -Encoding UTF8)
    Assert-Equal (@($c[0].PSObject.Properties.Name) -join ',') 'Date / time,Target IP,Command run,Success,Pulled / sent,Duration,Notes' "in the network log's columns, left to right"
    Assert-Equal (($c | ForEach-Object 'Target IP') -join ',') '10.0.0.5,10.0.0.5,10.0.0.6,filer01,filer01,192.0.2.30,github.com' "the target is the machine the action reached"
    Assert-Equal $c[0].'Date / time' '2026-10-17 14:02:09' "date and time in one sortable cell"
    Assert-Equal (($c | ForEach-Object Success) -join ',') 'No,Yes,No,Yes,No,Yes,Yes' "success is a plain yes or no"
    Assert-True ($c[3].'Command run' -match [regex]::Escape('onto \\filer01\evidence as .partial')) "an archive to a share names the share"
    Assert-True ($c[4].'Command run' -match [regex]::Escape('onto \\filer01\evidence as .partial')) "and so does one that failed before any zip existed"
    Assert-Equal $c[4].Notes 'Failed - Access is denied' "with its error (one spelling: Failed)"
    Assert-Equal $c[0].Notes 'Not open' "a no says why"
    Assert-True ($c[1].'Command run' -match [regex]::Escape('\\10.0.0.5\C$\Windows\System32\winevt\Logs') -and $c[1].'Command run' -match 'CORP\\admin') "an SMB collection names the share it copied from and the account"
    Assert-True ($c[2].'Command run' -match 'wevtutil epl' -and $c[2].'Command run' -match '5985') "a WinRM collection names the export and the port"
    Assert-Equal $c[1].'Pulled / sent' '6/6 logs, 1.50 GB' "what was pulled, and how much"
    Assert-Equal $c[1].Duration '0:01:35' "how long it took, as h:mm:ss - Excel reads 01:35 as 1 h 35 min"
    Assert-Equal $c[1].Notes 'SHA-256 verified 6/6 - left on target: none' "a clean collection notes its integrity check and what it left behind"
    Assert-Equal $c[2].Notes 'Failed - Access is denied' "a failure carries its error"
    Assert-True ($c[5].'Command run' -match '_index_template/hayabusa-evtx' -and $c[5].'Command run' -match '_bulk' -and $c[5].'Command run' -match 'hayabusa-mission-x') "an upload names the template, the bulk API and the index"
    Assert-Equal (ConvertTo-NetworkLogRow ([pscustomobject]@{ Action = 'EVTX archive'; Protocol = 'SMB'; Output = '\\=evil\s\x.zip'; Result = 'Success' })).'Target IP' "'=evil" "a share name cannot become an Excel formula"
    Assert-True ([IO.File]::ReadAllBytes($out)[0] -eq 0xEF) "the .csv starts with a BOM, so Excel reads accents"

    $threw = $false
    try { Export-NetworkLog $path $path | Out-Null } catch { $threw = $true }
    Assert-True $threw "the network log is never written over the live activity log"
    $none = Join-Path $tmp 'none.csv'
    Assert-Equal (Export-NetworkLog (Join-Path $tmp 'empty\activity_log.csv') $none) 0 "an empty log gives an empty network log"
    Assert-Equal (@(Get-Content -LiteralPath $none -Encoding UTF8)[0]) '"Date / time","Target IP","Command run","Success","Pulled / sent","Duration","Notes"' "with its header"
}
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
Assert-True ($src -match "Export-NetworkLog \`$script:LedgerPath") "the window has a Network log button"
Assert-True ($src -match "btnLogsFolder\.Add_Click\(\{\s+New-Item -ItemType Directory -Path \`$script:Folders\.Logs") "a Logs folder button opens logs\ (the owner chose it over a Logs tab)"
