# tests/RawEvents.Tests.ps1
#
# Raw events (v81): every event of a log, not only the ones a rule matched,
# exported by Hayabusa's search command and sent to their own index,
# hayabusa-raw-<mission>. They keep a curated set of fields - the ones a hunt
# or an endpoint investigation uses - promoted to the same ECS names the
# detections use, so one query works on both indices.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$tmp = Join-Path $env:TEMP ("rawevents-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

# Records shaped as `hayabusa search -L -O -b` writes them: one record over
# three lines - "{", the members on one line, "}".
Add-Type -AssemblyName System.Web.Extensions
$js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
function New-RawRecord([string]$Channel, $EventId, [long]$RecordId, [hashtable]$Fields, [string]$Computer = 'WS01.corp.local') {
    $r = [ordered]@{
        Timestamp = '2026-10-14T10:00:00.123456Z'; Hostname = $Computer; Channel = $Channel
        'Event ID' = $EventId; 'Record ID' = $RecordId; EventTitle = '-'
        AllFieldInfo = $Fields; EvtxFile = "C:\evtx\WS01\$($Channel -replace '/', '_').evtx"
    }
    $j = $script:js.Serialize($r)
    return "{`n$($j.Substring(1, $j.Length - 2))`n}"
}
function Get-Doc([string]$Record) {
    $body = ($Record -split "`n")[1]
    return ConvertTo-RawEcsDocument (ConvertFrom-RawRecordLine $body) 'imp1'
}

$psClassic = 'NewEngineState=Available PreviousEngineState=None SequenceNumber=13 HostName=ConsoleHost ' +
             'HostVersion=5.1.19041.1 HostId=b94a5d91 HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -enc SQBFAFgA ' +
             'EngineVersion=5.1.19041.1 RunspaceId=f211cc3a PipelineId= CommandName= CommandType= ScriptName= CommandPath= CommandLine='
$records = @(
    (New-RawRecord 'Security' 4624 1001 @{ TargetUserName = 'jsmith'; TargetDomainName = 'CORP'; LogonType = '3'
        IpAddress = '::ffff:10.1.2.3'; IpPort = '50123'; WorkstationName = 'WS07'; HandleId = '0x4d8'; Binary = 'AABB' })
    (New-RawRecord 'Microsoft-Windows-Sysmon/Operational' 1 1002 @{ Image = 'C:\Windows\System32\cmd.exe'
        CommandLine = 'cmd /c whoami'; ParentImage = 'C:\Office\WINWORD.EXE'; ParentCommandLine = '"WINWORD.EXE" /n doc.docm'
        ProcessId = '4242'; Hashes = 'SHA256=AABB,MD5=CCDD'; User = 'CORP\jsmith'; UtcTime = '2026-10-14 10:00:00.123' })
    (New-RawRecord 'Windows PowerShell' 400 1003 @{ 'Data[1]' = 'Available'; 'Data[2]' = 'None'; 'Data[3]' = $psClassic })
    (New-RawRecord 'Application' 1531 1004 @{ '' = '' })
    (New-RawRecord 'Application' 1000 1005 @{ 'Data[1]' = 'app.exe'; 'Data[2]' = '1.0.0.0'; 'Data[3]' = 'ntdll.dll' })
    (New-RawRecord 'Microsoft-Windows-PowerShell/Operational' '-' 1006 @{ Payload = 'CommandInvocation(Out-Default)'; UserData = '' })
    (New-RawRecord 'Security' 4769 1007 @{ TargetUserName = 'jsmith@CORP.LOCAL'; ServiceName = 'MSSQLSvc'
        TicketEncryptionType = '0x17'; TicketOptions = '0x40810000'; IpAddress = '::ffff:10.0.0.5'; Status = '0x0' } 'DC01.corp.local')
    (New-RawRecord 'Microsoft-Windows-Sysmon/Operational' 13 1008 @{ TargetObject = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\upd'
        Details = 'C:\Users\Public\upd.exe'; EventType = 'SetValue'; Image = 'C:\x\a.exe' })
)

try {
    # ---- reading Hayabusa's record layout ----
    Assert-True ($null -eq (ConvertFrom-RawRecordLine '{')) "the opening brace line of a record is not a record"
    Assert-True ($null -eq (ConvertFrom-RawRecordLine '}')) "nor is the closing one"
    Assert-True ($null -eq (ConvertFrom-RawRecordLine '   ')) "nor a blank line"
    # 626 of the sample corpus' 47,699 records end on the next one's opening
    # brace: "}{" on a line of its own between two records.
    Assert-True ($null -eq (ConvertFrom-RawRecordLine '}{')) "nor the '}{' line Hayabusa sometimes writes between two records"
    $rec = ConvertFrom-RawRecordLine (($records[0] -split "`n")[1])
    Assert-Equal $rec['Channel'] 'Security' "the members line reads as the record"

    # ---- the document ----
    $d = Get-Doc $records[0]
    Assert-Equal $d['@timestamp'] '2026-10-14T10:00:00.123456Z' "@timestamp is the event's own time"
    Assert-Equal $d.event.kind 'event' "a raw event is event.kind event (detections are alert)"
    Assert-Equal $d.event.dataset 'evtx.raw' "event.dataset evtx.raw"
    Assert-Equal $d.event.code '4624' "event.code is the event id"
    Assert-Equal $d.host.name 'WS01.corp.local' "host.name is the machine that logged it"
    Assert-Equal $d.winlog.channel 'Security' "winlog.channel"
    Assert-Equal $d.winlog.event_id '4624' "winlog.event_id"
    Assert-Equal ([long]$d.winlog.record_id) 1001 "winlog.record_id"
    Assert-Equal $d.import.id 'imp1' "import.id is the upload batch"
    Assert-Equal $d.log.file.path 'C:\evtx\WS01\Security.evtx' "log.file.path names the collected file"
    Assert-Equal $d.agent.name 'EVTXER' "agent.name"
    Assert-True ($d.event.id -match '^[0-9a-f]{40}$') "event.id is a 40-character SHA-1"
    Assert-Equal @($d.event.Keys)[0] 'id' "event.id is the first key of event, so the upload reads it without parsing"
    $line = ConvertTo-RawEcsLine $d
    Assert-Equal (Get-EcsLineId $line) $d.event.id "the upload's id reader finds it in the written line"
    Assert-True ($script:EcsImportIdPattern.Match($line).Success) "and the import.id the count check asks about"
    Assert-True (-not $line.Contains("`n")) "one document is one line"

    # ---- the curated fields ----
    Assert-Equal $d.winlog.event_data.TargetUserName 'jsmith' "an allow-listed field is kept under its Windows name"
    Assert-True (-not $d.winlog.event_data.ContainsKey('HandleId')) "a field off the allow-list is dropped"
    Assert-True (-not $d.winlog.event_data.ContainsKey('Binary')) "binary blobs are dropped"
    Assert-Equal $d.user.name 'jsmith' "user.name is promoted as for detections"
    Assert-Equal $d.winlog.logon.type 'Network' "the logon type gets Winlogbeat's name"
    Assert-Equal $d.source.ip '10.1.2.3' "an IPv4-mapped address (::ffff:) is promoted as plain IPv4"
    Assert-Equal ([long]$d.source.port) 50123 "with its port"
    Assert-Equal $d.winlog.event_data.IpAddress '::ffff:10.1.2.3' "the Windows field keeps what Windows wrote"

    $p = Get-Doc $records[1]
    Assert-Equal $p.process.executable 'C:\Windows\System32\cmd.exe' "Sysmon 1: process.executable"
    Assert-Equal $p.process.name 'cmd.exe' "process.name"
    Assert-Equal $p.process.command_line 'cmd /c whoami' "process.command_line"
    Assert-Equal $p.process.parent.name 'WINWORD.EXE' "process.parent.name"
    Assert-Equal $p.process.parent.command_line '"WINWORD.EXE" /n doc.docm' "process.parent.command_line"
    Assert-Equal ([long]$p.process.pid) 4242 "process.pid"
    Assert-Equal $p.file.hash.sha256 'AABB' "the Sysmon hashes become file.hash.*"
    Assert-True (-not $p.winlog.event_data.ContainsKey('UtcTime')) "Sysmon's UtcTime is dropped - @timestamp is the same time"

    $ps = Get-Doc $records[2]
    Assert-Equal $ps.winlog.event_data.HostApplication 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -enc SQBFAFgA' `
        "classic PowerShell 400: HostApplication is pulled out of the text, arguments and all"
    Assert-Equal $ps.winlog.event_data.EngineVersion '5.1.19041.1' "and EngineVersion"
    Assert-True (-not $ps.winlog.event_data.ContainsKey('CommandLine')) "an empty Key= is not a field"
    Assert-True (-not $ps.winlog.event_data.ContainsKey('Data[3]')) "the text it came from is not kept as well"

    $e = Get-Doc $records[3]
    Assert-Equal $e.winlog.channel 'Application' "a record with an empty field name still converts"
    Assert-True (-not $e.winlog.ContainsKey('event_data')) "and the empty name is not a field"

    $u = Get-Doc $records[4]
    Assert-Equal $u.winlog.event_data['Data[1]'] 'app.exe' "an event with no named field keeps its positional Data[n]"
    Assert-Equal $u.winlog.event_data['Data[3]'] 'ntdll.dll' "all of them"

    $x = Get-Doc $records[5]
    Assert-True (-not $x.event.ContainsKey('code')) "an event id Hayabusa writes as '-' gives no event.code"
    Assert-Equal $x.winlog.event_data.Payload 'CommandInvocation(Out-Default)' "PowerShell 4103's Payload is kept"
    Assert-True (-not $x.winlog.event_data.ContainsKey('UserData')) "Hayabusa's empty UserData leftover is dropped"

    $k = Get-Doc $records[6]
    Assert-Equal $k.winlog.event_data.TicketEncryptionType '0x17' "Kerberos 4769: the ticket encryption type (RC4 = kerberoasting)"
    Assert-Equal $k.winlog.event_data.ServiceName 'MSSQLSvc' "the service asked for"
    Assert-Equal $k.source.ip '10.0.0.5' "and who asked, as plain IPv4"
    Assert-Equal $k.host.name 'DC01.corp.local' "logged on the domain controller"

    $g = Get-Doc $records[7]
    Assert-Equal $g.registry.path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\upd' "Sysmon 13: registry.path"
    Assert-Equal $g.winlog.event_data.Details 'C:\Users\Public\upd.exe' "and the value written"

    # ---- the compiled promotion is the detections' promotion ----
    # The raw converter is C# for speed; Add-EcsPromotedFields is what the
    # detections use. The same fields through both must give the same ECS
    # fields - here the raw fixtures, and the hunt-field fixtures written the
    # way Hayabusa's Details names them (short aliases and all).
    $canon = {
        param($o)
        if ($o -is [System.Collections.IDictionary]) {
            '{' + ((@($o.Keys) | Sort-Object | ForEach-Object { "$_=" + (& $canon $o[$_]) }) -join ',') + '}'
        } elseif ($o -is [System.Collections.IEnumerable] -and $o -isnot [string]) {
            '[' + ((@($o) | ForEach-Object { & $canon $_ }) -join ',') + ']'
        } else { "$o" }
    }
    $cases = @(foreach ($r in $records) {
        $rec = ConvertFrom-RawRecordLine (($r -split "`n")[1])
        [pscustomobject]@{ Fields = $rec['AllFieldInfo']; Eid = "$($rec['Event ID'])" -replace '^-$', ''; Channel = $rec['Channel']; Computer = $rec['Hostname'] }
    })
    $cases += @(
        @{ e = '4624'; c = 'Security'; f = @{ TargetUserName = 'jsmith'; LogonType = '10 - REMOTE_INTERACTIVE'; IpAddress = '10.0.0.9' } }
        @{ e = '4625'; c = 'Security'; f = @{ Type = '3 - NETWORK'; TgtUser = 'admin'; AuthPkg = 'NTLM'; SrcIP = '::ffff:10.2.2.2'; SrcPort = '0x1F90' } }
        @{ e = '7045'; c = 'System'; f = @{ Svc = 'agent'; ImagePath = '"C:\Program Files\Agent\svc.exe" -k netsvcs' } }
        @{ e = '4697'; c = 'Security'; f = @{ ServiceName = 'lsvc'; ServiceFileName = '%SystemRoot%\system32\svchost.exe -k LocalService' } }
        @{ e = '10'; c = 'Microsoft-Windows-Sysmon/Operational'; f = @{ SrcProc = 'C:\x\a.exe'; SrcUser = 'CORP\eve'; TgtUser = 'NT AUTHORITY\SYSTEM' } }
        @{ e = '14'; c = 'Microsoft-Windows-Sysmon/Operational'; f = @{ OldName = 'HKLM\SOFTWARE\Old'; NewName = 'HKLM\SOFTWARE\New' } }
        @{ e = '22'; c = 'Microsoft-Windows-Sysmon/Operational'; f = @{ Query = 'bad.example.com'; Proc = 'C:\x\a.exe' } }
        @{ e = '19'; c = 'Microsoft-Windows-Sysmon/Operational'; f = @{ Query = 'SELECT * FROM __InstanceModificationEvent'; Name = 'evil' } }
        @{ e = '1'; c = 'Microsoft-Windows-Sysmon/Operational'; f = @{ Proc = 'C:\Windows\System32\cmd.exe'; Cmdline = 'cmd /c whoami'; ParentCmdline = 'x'; ParentProc = 'C:\Office\WINWORD.EXE'; PID = '0x10'; Hashes = 'SHA256=AABB,MD5=CCDD' } }
        @{ e = '4624'; c = 'Security'; f = @{ TargetUserName = @('n/a', 'Bob', 'bob'); WorkstationName = 'WS9'; LogonType = 0 } }
    ) | ForEach-Object { [pscustomobject]@{ Fields = (ConvertFrom-RawRecordLine ($js.Serialize($_.f))); Eid = $_.e; Channel = $_.c; Computer = 'H1' } }
    foreach ($c in $cases) {
        if ($c.Fields.ContainsKey('')) { continue }     # ConvertFrom-Json cannot hold an empty name
        $ps = [ordered]@{}
        $asObject = $js.Serialize($c.Fields) | ConvertFrom-Json     # what a detection's Details is
        Add-EcsPromotedFields $ps $asObject ([pscustomobject]@{}) $c.Eid $c.Channel $c.Computer
        $cs = [EvtxerRawConverter]::PromoteOnly($c.Fields, $null, $c.Eid, $c.Channel, $c.Computer)
        Assert-Equal (& $canon $cs) (& $canon $ps) "compiled promotion = Add-EcsPromotedFields for event $($c.Eid) ($($c.Channel))"
    }

    $noRec = ConvertTo-RawEcsDocument (ConvertFrom-RawRecordLine '"Timestamp":"2026-10-14T10:00:00Z","Hostname":"WS01","Channel":"System","Event ID":7036,"Record ID":"-","AllFieldInfo":{}') 'imp1'
    Assert-True (-not $noRec.winlog.ContainsKey('record_id')) "a record number written as '-' gives no record_id (a long - Elasticsearch refused the document)"

    # ---- the id ----
    $again = Get-Doc $records[0]
    Assert-Equal $again.event.id $d.event.id "the same event always gets the same id - a re-send adds nothing"
    $other = Get-Doc (New-RawRecord 'Security' 4624 9999 @{ TargetUserName = 'jsmith' })
    Assert-True ($other.event.id -ne $d.event.id) "another record of the same log gets another id"
    $moved = (Get-Doc ($records[0] -replace 'C:\\\\evtx\\\\WS01', 'D:\\other')).event.id
    Assert-Equal $moved $d.event.id "where the file was copied to does not change the id"

    # ---- detections get the same IP fix ----
    $det = '{"Timestamp":"2026-10-14T10:00:00Z","RuleTitle":"Logon","Level":"low","Computer":"DC01","Channel":"Security","EventID":4624,"Details":{"TgtUser":"x","SrcIP":"::ffff:10.9.8.7"}}' | ConvertFrom-Json
    Assert-Equal (ConvertTo-EcsDocument $det 't').source.ip '10.9.8.7' "a detection's IPv4-mapped source address is plain IPv4 too"

    # ---- names and arguments ----
    Assert-Equal (Get-RawIndexName 'Op Falcon 1') 'hayabusa-raw-op-falcon-1' "the raw index is hayabusa-raw-<mission>"
    Assert-True (Test-HayabusaIndexName (Get-RawIndexName 'Op Falcon 1')) "and passes the hayabusa-* write guard"
    Assert-Equal (Get-RawIndexName '  ') '' "no mission, no index"
    $a = Get-HayabusaRawExportArgs -EvtxDir 'C:\e' -OutFile 'C:\o\raw.jsonl'
    Assert-Equal $a[0] 'search' "the export is Hayabusa's search command"
    foreach ($flag in '-L', '-O', '-b', '-q', '-K', '-C', '-Q') { Assert-True ($a -contains $flag) "the export passes $flag" }
    Assert-Equal $a[[array]::IndexOf($a, '-r') + 1] '.*' "every event: the regex matches anything"
    Assert-Equal $a[[array]::IndexOf($a, '-d') + 1] 'C:\e' "the folder"
    Assert-Equal $a[[array]::IndexOf($a, '-o') + 1] 'C:\o\raw.jsonl' "the output file"

    # ---- the whole file, one worker and several ----
    $src = Join-Path $tmp 'raw.jsonl'
    $text = (($records + $records + $records) -join "`n") + "`n"
    $text = $text.Replace("`n}`n{`n", "`n}{`n")    # every boundary written the glued way
    Assert-True ($text.Contains("}{")) "(the fixture really has glued records)"
    [IO.File]::WriteAllText($src, $text, (New-Object Text.UTF8Encoding($false)))
    $one = Convert-HayabusaJsonlToEcs -Raw -Source $src -Destination (Join-Path $tmp 'one.jsonl') -ImportId 'imp1' -Workers 1
    Assert-Equal ([long]$one.Converted) ([long]($records.Count * 3)) "every record converts, none counted twice"
    Assert-Equal ([long]$one.Bad) 0L "no record is unreadable"
    $three = Convert-HayabusaJsonlToEcs -Raw -Source $src -Destination (Join-Path $tmp 'three.jsonl') -ImportId 'imp1' -Workers 3
    Assert-Equal ([long]$three.Converted) ([long]$one.Converted) "three workers convert as many"
    # "ingested" is the wall-clock time of the conversion, the one field two
    # runs may differ in (as in ParallelConvert.Tests).
    $strip = { param($f) [IO.File]::ReadAllText((Join-Path $tmp $f)) -replace '"ingested":"[^"]*"', '' }
    Assert-Equal (& $strip 'three.jsonl') (& $strip 'one.jsonl') "and write the same file, line for line"
    $kind = Get-JsonlKind (Join-Path $tmp 'one.jsonl')
    Assert-Equal $kind.Kind 'Raw' "the Upload tab tells a raw events file from a detections file"
    Assert-Equal (Get-JsonlKind $src).Kind 'RawExport' "and from Hayabusa's unconverted export"
    # ---- review fixes (v81) ----
    # An earlier run's raw-ecs.jsonl never passes for this run's: it goes
    # before anything else, so a failed export leaves nothing to send.
    $stale = Join-Path $tmp 'stale'; New-Item -ItemType Directory -Path $stale -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $stale 'raw-ecs.jsonl') -Value '{"old":1}'
    $x = Invoke-RawEventExport -EvtxDir $stale -WorkDir $stale -HayabusaExe 'nothing.exe' -ImportId 'imp2' -Run { param($p) 3 }
    Assert-True (-not $x.Ok -and -not (Test-Path -LiteralPath (Join-Path $stale 'raw-ecs.jsonl'))) "a failed export leaves no earlier raw-ecs.jsonl behind to be sent"
    Assert-Equal (Get-RawExportProblem $x) "Hayabusa's raw export exited with code 3" "and says why"
    Assert-Equal (Get-RawExportProblem ([pscustomobject]@{ Ok = $true; Cancelled = $false; Converted = 0L; Bad = 5L })) 'none of the 5 exported record(s) could be read' "every record unreadable is a failure, not '0 events'"
    Assert-Equal (Get-RawExportProblem ([pscustomobject]@{ Ok = $true; Cancelled = $false; Converted = 9L; Bad = 2L })) '2 record(s) of the export could not be read' "some unreadable is said"
    Assert-Equal (Get-RawExportProblem ([pscustomobject]@{ Ok = $true; Cancelled = $false; Converted = 9L; Bad = 0L })) '' "a clean export has nothing to say"
    $lib = Get-Content "$PSScriptRoot\..\code\HayabusaLib.ps1" -Raw
    Assert-True ([regex]::Match($lib, "(?s)'raw' \{.*?Publish-EcsFile").Value -match 'if \(\$x\.Bad -and -not \$x\.Converted\) \{ throw') "the queue's raw step fails when no record could be read"
    # Detections never into the raw events' pattern.
    Assert-True ((New-IndexName 'raw' @()) -notlike 'hayabusa-raw-*' -and (New-IndexName 'Raw WS01' @()) -notlike 'hayabusa-raw-*') "a generated detections index name is never in hayabusa-raw-*"
    $why = ''
    try { Publish-EcsFile -Base 'https://192.0.2.1:9200' -Headers @{} -Index 'hayabusa-raw-x' -Path 'nothing' -Template '{}' | Out-Null } catch { $why = $_.Exception.Message }
    Assert-True ($why -match "refusing to write detections to 'hayabusa-raw-x'") "the upload itself refuses detections into hayabusa-raw-*"
    # The data views: the detections' own view never covers the raw events,
    # "Mission - everything" does - what Set-KibanaLink and the stale-view
    # warning tell apart.
    Assert-True (-not (Test-IndexCoveredByPattern 'hayabusa-raw-x' 'hayabusa-*,-hayabusa-raw-*') -and (Test-IndexCoveredByPattern 'hayabusa-raw-x' 'hayabusa-*')) "the exclusion in the detections view is honoured"
    $up = Get-Content "$PSScriptRoot\..\code\wpf-upload.ps1" -Raw
    Assert-True ($up -match "\`$_\.Id -eq 'hayabusa-evtx-dataview'" -and $up -match "-not \(Test-IndexCoveredByPattern 'hayabusa-raw-x'") "the Kibana link prefers the detections' own data view, never 'Mission - everything'"
    Assert-True ($up -match '\(Get-JsonlImportId \$beside\) -eq \$fileImportId') "the raw events beside a detections file are offered only from the same conversion"
    Assert-True ($up -match 'Get-StaleDetectionsViewWarning' -and $lib -match "(?s)'raw' \{.*?Get-StaleDetectionsViewWarning") "both raw routes warn about pre-v81 dashboards"
    $cv = Get-Content "$PSScriptRoot\..\code\wpf-convert.ps1" -Raw
    Assert-True ($cv -match 'ScanNoDetections -and \$chkRaw\.IsChecked') "a scan with no detections still exports the raw events"

    # ---- end to end with the real Hayabusa, on a sample folder ----
    # evtx-samples is not shipped (gitignored), so this runs in the repo only.
    $hy = Get-ChildItem "$PSScriptRoot\..\code\hayabusa-x64" -Filter 'hayabusa-*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    $sample = Join-Path $PSScriptRoot '..\evtx-samples\hayabusa-sample-evtx-main\DeepBlueCLI'
    if ($hy -and (Test-Path -LiteralPath $sample)) {
        # Under output\ (Defender-excluded on the development machine): the
        # samples are attack logs, and Defender quarantines their export in %TEMP%.
        $work = Join-Path $PSScriptRoot ('..\output\test-raw-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $x = Invoke-RawEventExport -EvtxDir $sample -WorkDir $work -HayabusaExe $hy.FullName -ImportId 'imp1' `
                 -Run { param($p) & $p.Exe @($p.Arguments) | Out-Null; $LASTEXITCODE }
        $want = 0
        foreach ($f in Get-ChildItem -LiteralPath $sample -Recurse -File -Filter *.evtx) {
            $rd = New-Object System.Diagnostics.Eventing.Reader.EventLogReader((New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($f.FullName, 'FilePath')))
            while ($null -ne ($ev = $rd.ReadEvent())) { $want++; $ev.Dispose() }
        }
        Assert-True $x.Ok "the raw export of a sample folder succeeds ($($x.Detail))"
        Assert-Equal $x.Converted ([long]$want) "it holds every event Windows' own reader counts in those files"
        Assert-Equal $x.Bad 0L "none unreadable"
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $work 'raw.jsonl'))) "Hayabusa's export is deleted once converted"
        Assert-Equal (Get-JsonlKind $x.Path).Kind 'Raw' "what is left is the raw events file, ready to upload"
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    } else { Write-Host "  [SKIP] no Hayabusa or no evtx-samples - raw export end to end skipped" -ForegroundColor Yellow }

    # v82: every field the converter keeps is mapped before any event carries
    # it. A Lens panel on a field the index has never seen draws an error,
    # not "No results" - and most networks have no Sysmon or AD CS events.
    # The list's case twins (Consumer / CONSUMER, Param1 / param1, Name /
    # name) get ONE mapping: Publish-EcsFile reads the template with
    # ConvertFrom-Json, which refuses a file holding both spellings - every
    # raw upload would fail.
    $tpl = Get-Content -LiteralPath "$PSScriptRoot\..\code\raw-index-template.json" -Raw | ConvertFrom-Json
    $mapped = @($tpl.template.mappings.properties.winlog.properties.event_data.properties.PSObject.Properties.Name)
    $unmapped = @($script:RawEventFields | Where-Object { $mapped -notcontains $_ })
    Assert-Equal ($unmapped -join ', ') '' "raw-index-template.json maps every field in RawEventFields (one spelling of a case twin)"
    # ... so a raw panel must use the mapped spelling, EXACTLY (case-sensitive):
    # the BITS panel once ranked "name" while the template maps "Name".
    $objects = Get-Content -LiteralPath "$PSScriptRoot\..\kibana\hayabusa-kibana-objects.ndjson" -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json } |
               Where-Object { $_.type -eq 'lens' -and @($_.references | Where-Object { $_.id -eq 'hayabusa-raw-dataview' }).Count }
    $wrong = foreach ($o in $objects) {
        foreach ($layer in $o.attributes.state.datasourceStates.formBased.layers.PSObject.Properties.Value) {
            foreach ($c in $layer.columns.PSObject.Properties.Value) {
                if ("$($c.sourceField)" -like 'winlog.event_data.*' -and $mapped -cnotcontains $c.sourceField.Substring(18)) { "$($o.id): $($c.sourceField)" }
            }
        }
    }
    Assert-Equal (@($wrong) -join '; ') '' "every raw panel's winlog.event_data field is mapped by the template, in the same case"
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
