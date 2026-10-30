# tests/KibanaFind.Tests.ps1
#
# After an upload the Upload tab lists what to paste where - data views, KQL,
# Dev Tools - every value filled in (owner, 2026-10-29: "these syntaxes at the
# bottom for copy and paste, ready to go").
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$lines = @(Get-KibanaFindLines -MissionIndex 'hayabusa-mission-op1' -RawIndex 'hayabusa-raw-op1' -ImportId '20261029abc' `
              -Hosts @('WS01', 'WS01.corp.local', 'DC01'))
$text = ($lines | ForEach-Object { "$($_.Label)`n$($_.Text)" }) -join "`n"

Assert-True ($lines.Count -ge 5) "a handful of lines, each a label and a text to paste"
Assert-True (@($lines | Where-Object { -not $_.Label -or -not $_.Text }).Count -eq 0) "no line is missing its label or its text"
Assert-True ($text.Contains('import.id:"20261029abc"')) "the upload's own import.id, ready as KQL"
$ws = @($lines | Where-Object { $_.Label -like 'KQL - WS01*' })[0].Text
Assert-True ($ws.StartsWith('host.name:(') -and $ws.Contains('"WS01"') -and $ws.Contains('"WS01.corp.local"')) "one host's KQL covers every name form it was seen under"
Assert-True ($text.Contains('DC01')) "every host of the upload gets a line"
Assert-Equal @($lines | Where-Object { $_.Label -like 'KQL - WS01*' }).Count 1 "WS01 and WS01.corp.local are one machine, one line"
Assert-True ($text.Contains("GET hayabusa-mission-op1/_count") -and $text.Contains("GET hayabusa-raw-op1/_count")) "Dev Tools counts for both indices"
Assert-True ($text.Contains('hayabusa-raw-*') -and $text.Contains('-hayabusa-raw-*')) "the data views are named with their patterns"
Assert-True ($text.Contains('event.kind:"event"')) "how to tell raw events from detections in the combined view"
Assert-True ($text -notmatch 'so-import|Hunt') "nothing points at the removed Security Onion importer"

$many = @(Get-KibanaFindLines -MissionIndex 'hayabusa-mission-x' -RawIndex '' -ImportId '' -Hosts @(1..9 | ForEach-Object { "HOST$_" }))
Assert-Equal @($many | Where-Object { $_.Label -like 'KQL - HOST*' }).Count 5 "at most five host lines"
Assert-True (@($many | Where-Object { $_.Label -eq 'More hosts' -and $_.Text -like '4 more*' }).Count -eq 1) "and a line saying how many more"
Assert-True (-not (($many | ForEach-Object { $_.Text }) -join ' ').Contains('hayabusa-raw-x/_count')) "no raw index, no raw count"
