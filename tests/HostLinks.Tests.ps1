# tests/HostLinks.Tests.ps1
#
# After an upload EVTXER shows each host's two links - its Hayabusa
# detections and its raw events, both in Kibana's Discover - covering
# everything ever collected from it ("as far back as possible").
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

# ---- raw events: the same Discover link, on the raw data view ----
$r = New-HostRawUrl -KibanaHost 'so.lab' -Names @('WIN10')
Assert-True ($r.StartsWith('https://so.lab/kibana/app/discover#/?_g=')) "the raw events link opens Discover too"
Assert-True ($r -match "index:'hayabusa-raw-dataview'") "on the raw events' data view (its id is fixed by the dashboards file)"
Assert-True ($r -match 'host\.name:\(%22WIN10%22') "for this host - host.name is the Windows machine in EVTXER's raw events"
Assert-True ($r -match "from:'1970-01-01T00:00:00\.000Z'") "all time, as the detections link"
Assert-True ((New-HostRawUrl -KibanaHost 'k' -Names @('A') -Port 5601).StartsWith('https://k:5601/')) "a non-default port is kept"

# ---- the links are drawn in EVTXER, after the work ----
$root = Split-Path -Parent $PSScriptRoot
$shell = Get-Content (Join-Path $root 'code\HayabusaMissionTool.ps1') -Raw
$up    = Get-Content (Join-Path $root 'code\wpf-upload.ps1') -Raw
Assert-True ($shell -match 'function Show-HostLinks') "the shell draws the host links, for every tab"
Assert-True ($shell -match "Hayabusa detections" -and $shell -match "'Raw events'") "each host gets both links"
Assert-True ($shell -match 'no Elasticsearch host yet - fill in the Upload tab') "a side that is not set up says so instead of offering a dead link"
Assert-True ($up -match '(?s)Set-KibanaLink -Base \$base -Headers \$h -Index \$idx\s+Show-UploadHostLinks') "an upload shows its hosts' links right after its own Kibana link"
Assert-True ($up -match '"terms":\{"field":"host\.name"') "the Upload tab takes the hosts, every name form, from the index"
Assert-True ($up -match 'dataview_id = \[string\]\$script:DetectionsDataViewId' -and $up -match '\$c\.dataview_id') "the detections data view is remembered across restarts"

