# tests/HostLinks.Tests.ps1
#
# After an upload or a raw import EVTXER shows each host's
# two links - Hayabusa detections in Kibana, raw events in Security Onion -
# covering everything ever collected from it ("as far back as possible").
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# ---- one machine, one row, whichever name form it reported ----
Assert-Equal (Get-HostKey 'WIN2022-SRV-X64.corp.local') 'WIN2022-SRV-X64' "the FQDN groups under its short name"
Assert-Equal (Get-HostKey 'IE10Win7') 'IE10WIN7' "case does not split a machine in two"
Assert-Equal (Get-HostKey '192.0.2.12') '192.0.2.12' "an IP is kept whole, not cut at its first dot"
Assert-Equal (Get-HostKey '') '' "nothing in, nothing out"

$set = @(Get-HostLinkSet @('WIN2022-SRV-X64.corp.local', 'WIN2022-SRV-X64', 'IE10Win7', ' ', 'WIN2022-SRV-X64'))
Assert-Equal (($set | ForEach-Object Key) -join ',') 'WIN2022-SRV-X64,IE10WIN7' "two machines, in the order first seen"
Assert-Equal ($set[0].Names -join ',') 'WIN2022-SRV-X64.corp.local,WIN2022-SRV-X64' "each keeps every form it was seen under, once"

# ---- the query asks for each name exactly as written ----
# host.name is a keyword, matched case and all: the sample machine calls
# itself IE10Win7, and a query for IE10WIN7 / ie10win7 alone found nothing.
$q = Get-HostLinkQuery @('IE10Win7')
Assert-True ($q -match '"IE10Win7"') "the mixed-case name is asked for as written"
Assert-True ($q -match 'IE10Win7\.\*') "and any FQDN of it"
Assert-True ($q -match '"IE10WIN7"' -and $q -match '"ie10win7"') "and its upper- and lower-case forms, which another source may have stored"
$q2 = Get-HostLinkQuery @('WIN2022-SRV-X64.corp.local')
Assert-True ($q2 -match '"WIN2022-SRV-X64\.corp\.local"' -and $q2 -match '"WIN2022-SRV-X64"' -and $q2 -match 'WIN2022-SRV-X64\.\*') "an FQDN brings its short form with it"
Assert-Equal (Get-HostLinkQuery @('192.0.2.12')) 'host.name:("192.0.2.12")' "an IP is asked for exactly, with no wildcard"
# Code review, 2026-10-16: Security Onion's query language only knows OR in
# capitals - a lower-case "or" there is a word to search for.
Assert-True ($q -cmatch ' OR ' -and $q -cnotmatch ' or ') "the terms are joined by OR, which KQL and Security Onion both read"
# [IPAddress]::TryParse takes "1234" as 0.0.4.210; a host may well be named so.
Assert-Equal (Get-HostKey 'srv1234'.Substring(3)) '1234' "a numeric host name is still a name"
Assert-True ((Get-HostLinkQuery @('1234')) -match '1234\.\*') "and gets its FQDN wildcard like any other"

# ---- Kibana: the detections data view, this host, all time ----
$k = New-HostDetectionsUrl -KibanaHost 'so.lab' -DataViewId 'hayabusa-dv' -Names @('WIN10')
Assert-True ($k.StartsWith('https://so.lab/kibana/app/discover#/?_g=')) "it opens Discover in Security Onion's Kibana"
Assert-True ($k -match "from:'1970-01-01T00:00:00\.000Z',to:now%2B1d") "from the beginning of time to tomorrow (+ escaped, or it reads as a space)"
Assert-True ($k -match "index:'hayabusa-dv'") "on the detections data view"
Assert-True ($k -match 'host\.name:\(%22WIN10%22') "for this host"
Assert-True ($k -notmatch ' ' -and $k -notmatch '"') "with nothing left in it that breaks a URL"
Assert-True ((New-HostDetectionsUrl -KibanaHost 'kibana' -DataViewId 'x' -Names @('A') -Port 5601).StartsWith('https://kibana:5601/')) "a non-default port is kept"
Assert-True ((New-HostDetectionsUrl -KibanaHost 'so' -DataViewId 'x' -Names @("O'BRIEN-PC")) -match "O!'BRIEN-PC") "a quote in a name is escaped the Rison way"
$odd = New-HostDetectionsUrl -KibanaHost 'so' -DataViewId 'x' -Names @('R&D#1!')
Assert-True ($odd -match 'R%26D%231!!' -and $odd -notmatch '[&#](?!.*_a=)' -and ($odd -split '&_a=').Count -eq 2) "& # ! in a name cannot end the parameter, start a fragment or break Rison"

# ---- Security Onion: its own dashboards, this host, all time ----
$r = New-HostRawUrl -SoHost 'so.lab' -Names @('WIN10') -NowUtc ([datetime]'2026-10-16T05:00:00Z')
Assert-True ($r.StartsWith('https://so.lab/#/dashboards?q=winlog.computer_name')) "it opens Security Onion's dashboards, like so-import-evtx's own link"
# A real SO 2.4.211 import (2026-10-16): host.name there is the Security Onion
# box itself ("manager"); the Windows machine is in winlog.computer_name.
Assert-True ($r -notmatch 'q=host\.name') "on the Windows machine's name, not the Security Onion box that ingested the events"
Assert-True ($r -match '%7C%20groupby%20event\.dataset') "grouped by dataset, as the importer's link is"
Assert-True ($r.EndsWith('&t=1970%2F01%2F01%2000%3A00%3A00%20AM%20-%202026%2F10%2F17%2000%3A00%3A00%20AM&z=UTC')) "from 1970 to tomorrow, in the importer's own time format"
Assert-Equal ([uri]::UnescapeDataString(($r -split 'q=|&t=')[1])) ((Get-HostLinkQuery @('WIN10') 'winlog.computer_name') + ' | groupby event.dataset') "the query reads back exactly"
Assert-True ((Get-HostLinkQuery @('WIN10')).StartsWith('host.name:(')) "the detections link still asks host.name - our documents carry the event's Computer there"

# ---- the Raw Events tab reads the machine names from the EVTX themselves ----
$sample = Join-Path $PSScriptRoot '..\evtx-samples'
if (Test-Path -LiteralPath $sample) {
    $dir = Get-ChildItem -LiteralPath $sample -Recurse -Filter *.evtx -File | Select-Object -First 1 | ForEach-Object DirectoryName
    $names = @(Get-EvtxHostNames $dir)
    $want = (Get-WinEvent -Path (Get-ChildItem -LiteralPath $dir -Filter *.evtx -File | Sort-Object Length -Descending | Select-Object -First 1).FullName -MaxEvents 1).MachineName
    Assert-True ($names -ccontains $want) "the machine name comes from the events, as written ($want)"
} else {
    Write-Host "  [SKIP] evtx-samples absent - machine names from real EVTX not checked" -ForegroundColor Yellow
}
Assert-Equal @(Get-EvtxHostNames (Join-Path $env:TEMP 'no-such-folder-9e1f')).Count 0 "a missing folder names no machines"

# ---- the links are drawn in EVTXER, after the work ----
$root = Split-Path -Parent $PSScriptRoot
$shell = Get-Content (Join-Path $root 'code\HayabusaMissionTool.ps1') -Raw
$up    = Get-Content (Join-Path $root 'code\wpf-upload.ps1') -Raw
$so    = Get-Content (Join-Path $root 'code\wpf-soimport.ps1') -Raw
Assert-True ($shell -match 'function Show-HostLinks') "the shell draws the host links, for every tab"
Assert-True ($shell -match "Hayabusa detections" -and $shell -match "'Raw events'") "each host gets both links"
Assert-True ($shell -match 'set the Security Onion manager on the Raw Events tab') "a side that is not set up says so instead of offering a dead link"
Assert-True ($up -match '(?s)Set-KibanaLink -Base \$base -Headers \$h -Index \$idx\s+Show-UploadHostLinks') "an upload shows its hosts' links right after its own Kibana link"
Assert-True ($up -match '"terms":\{"field":"host\.name"') "the Upload tab takes the hosts, every name form, from the index"
Assert-True ($up -match 'dataview_id = \[string\]\$script:DetectionsDataViewId' -and $up -match '\$c\.dataview_id') "the detections data view is remembered across restarts"
Assert-True ($so -match 'Show-HostLinks \$pnlSoHostLinks @\(Get-EvtxHostNames') "a raw import shows the links for the machines named in its EVTX"
