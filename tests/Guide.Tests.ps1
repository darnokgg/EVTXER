# tests/Guide.Tests.ps1
#
# The Guide tab (owner, 2026-10-26): a cheat sheet for the crew - a short
# answer to each thing that is not obvious, with "More..." opening the
# README chapter - and one search box over the cheat sheet AND the whole
# README.txt, which stays the full manual.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
$root = Split-Path -Parent $PSScriptRoot
$code = Join-Path $root 'code'

# ---- README chapters ----
$sample = @('TOOL', '====', '', 'Intro text.', '', 'FIRST PART', '----------', 'alpha beta', 'beta', '',
            'SECOND (ONE TAB)', '----------------', 'gamma Beta', '') -join "`n"
$ch = @(Get-ReadmeChapters $sample)
Assert-Equal (($ch | ForEach-Object Title) -join '|') 'FIRST PART|SECOND (ONE TAB)' "a chapter is a heading underlined with dashes; the ==== title is not one"
Assert-True ($ch[0].Body -match '^FIRST PART' -and $ch[0].Body -match 'alpha beta' -and $ch[0].Body -notmatch 'gamma') "a chapter runs from its heading to the next"
Assert-True ($ch[1].Body -match 'gamma Beta$') "the last runs to the end, trailing blank lines dropped"

$f = @(Find-ReadmeChapters $ch 'beta')
Assert-Equal (($f | ForEach-Object { "$($_.Title)=$($_.Count)" }) -join '|') 'FIRST PART=2|SECOND (ONE TAB)=1' "case-insensitive, the most matches first"
Assert-True ($f[0].Label -match 'FIRST PART' -and $f[0].Label -match '2 matches') "each hit says how many matches"
Assert-Equal @(Find-ReadmeChapters $ch 'beta gamma').Count 1 "several words: chapters holding all of them"
Assert-Equal @(Find-ReadmeChapters $ch '   ').Count 0 "an empty search lists no chapters"
Assert-Equal @(Find-ReadmeChapters $ch 'zeta').Count 0 "and a word nowhere finds nothing"

# ---- the README reading window (owner, 2026-10-29: "the search sucks") ----
# Each hit shows the lines that hold the words, each opening the README there.
$snip = @(Get-ReadmeSnippets ([pscustomobject]@{ Title = 'TIMES'; Body = "TIMES`n-----`n`nThe event time is @timestamp.`nNothing here.`nevent.created is gone; @timestamp stays." }) 'timestamp event')
Assert-Equal $snip.Count 2 "the matching lines of a chapter, not the others"
Assert-Equal $snip[0].Title 'TIMES' "each knows its chapter"
Assert-True ($snip[0].Score -ge $snip[-1].Score) "the lines with the most words first"
Assert-True (@($snip | Where-Object { $_.Line -eq 'TIMES' -or $_.Line -match '^-+$' }).Count -eq 0) "never the heading or its underline"
Assert-True (@(Find-ReadmeChapters $ch 'beta')[0].Snippets.Count -ge 1) "a search hit carries its lines"
# Every mention of another chapter in the text is a link to it.
$keys = Get-ReadmeLinkKeys @([pscustomobject]@{ Title = 'MISSION (SETTINGS TAB)' }, [pscustomobject]@{ Title = 'THE QUEUE (AUTOMATIC PROCESSING)' },
                            [pscustomobject]@{ Title = 'FINDING YOUR DATA: INDEX NAMES AND WHERE TO LOOK' }, [pscustomobject]@{ Title = 'PCAP' })
Assert-Equal $keys['MISSION'] 'MISSION (SETTINGS TAB)' "a chapter is named short in the text - the part before ' ('"
Assert-Equal $keys['FINDING YOUR DATA'] 'FINDING YOUR DATA: INDEX NAMES AND WHERE TO LOOK' "or before ':'"
Assert-True (-not $keys.ContainsKey('PCAP')) "too short a title is no link (PCAP, ELK are everywhere)"
$parts = @(Split-ReadmeLine 'Name it (see MISSION), then THE QUEUE (AUTOMATIC PROCESSING) runs. A mission is fine.' $keys)
Assert-Equal (@($parts | Where-Object Link | ForEach-Object Link) -join '|') 'MISSION (SETTINGS TAB)|THE QUEUE (AUTOMATIC PROCESSING)' "the mentions become links, the longest title whole"
Assert-Equal (($parts | ForEach-Object Text) -join '') 'Name it (see MISSION), then THE QUEUE (AUTOMATIC PROCESSING) runs. A mission is fine.' "and the line reads exactly as before"
Assert-Equal @(Split-ReadmeLine 'see MISSION' $keys 'MISSION (SETTINGS TAB)' | Where-Object Link).Count 0 "a chapter does not link to itself"
Assert-Equal @(Split-ReadmeLine 'MISSIONS and SUBMISSION' $keys | Where-Object Link).Count 0 "only whole words"

$readme = [IO.File]::ReadAllText((Join-Path $root 'README.txt'))
$real = @(Get-ReadmeChapters $readme)
Assert-True ($real.Count -ge 20) "the real README splits into its chapters ($($real.Count))"
$titles = @($real | ForEach-Object Title)
Assert-True ($titles -contains 'FINDING THINGS: TIME, PIVOTS, WHERE DATA LANDS') "the README has the chapter on times, pivots and where data lands"
Assert-True ($titles -contains 'THE SEVEN TABS' -and ($real | Where-Object Title -eq 'THE SEVEN TABS').Body -match '7\. Guide') "and lists the Guide tab"
Assert-True ($titles -contains 'EVERY RAW EVENT, NOT JUST DETECTIONS') "and the chapter on raw events"

# ---- the cheat sheet ----
$g = @(Get-GuideEntries)
Assert-True ($g.Count -ge 15) "a cheat sheet of short entries ($($g.Count))"
foreach ($e in $g) {
    Assert-True ($e.Group -and $e.Title -and $e.Answer -and $e.Chapter) "complete: $($e.Title)"
    Assert-True ($titles -contains $e.Chapter) "its More... opens a chapter that exists: $($e.Chapter)"
    Assert-True ("$($e.Title)$($e.Answer)" -notmatch '[^\x20-\x7E]') "plain ASCII (the library is read by PowerShell 5.1 without a BOM): $($e.Title)"
}
$all = ($g | ForEach-Object { "$($_.Title) $($_.Answer)" }) -join ' '
# v81: raw events are EVTXER's own (hayabusa-raw-*), timed by when they happened.
Assert-True ($all -match '@timestamp - when it happened' -and $all -notmatch 'event\.created') "the raw-event time: @timestamp, as for detections - no more import-day trap"
Assert-True ($all -match 'winlog\.record_id' -and $all -match 'host\.name' -and $all -match 'winlog\.channel') "the pivot from a detection to the raw event, field by field"
Assert-True ($all -match 'View surrounding documents') "and the one-click way, in Mission - everything"
Assert-True ($all -match 'only what a rule matched|only the events a rule matched') "detections are not the whole log"
Assert-True ($all -match 'deletes') "what Archive deletes"
# Review, 2026-10-26: a cheat sheet must be exact.
# The pivot is KQL in Kibana now (no Hunt): lower-case and is KQL's own.
$pivot = [regex]::Match($all + ' ' + $readme, 'host\.name:"WS01" and winlog\.channel:"Security" and winlog\.record_id:12345')
Assert-True $pivot.Success "the pivot query is the KQL Discover takes"
Assert-True ("$all $readme" -notmatch 'winlog\.computer_name:"WS01"') "and no longer Security Onion's winlog.computer_name form"
Assert-True ("$all $readme" -notmatch 'hayabusa-raw-dataview') "data views by the name Kibana's picker shows, never their id"
$export = Get-Content (Join-Path $root 'kibana\hayabusa-kibana-objects.ndjson') -Raw
Assert-True ($export.Contains('"name":"Raw Windows events (EVTXER)"')) "the raw data view is called that in the shipped export"
Assert-True ($all.Contains('"Raw Windows events (EVTXER)"')) "and the cheat sheet calls it that"
Assert-True ($export.Contains('"name":"Mission - everything"') -and $all.Contains('"Mission - everything"')) "and the combined one, both places"
$shellSrc = Get-Content (Join-Path $code 'HayabusaMissionTool.ps1') -Raw
Assert-True ($shellSrc -match 'Content="Continue without capture"' -and $all -match 'Continue without capture' -and $all -notmatch '\bOK to go on') "the PCAP entry names the buttons the question really has"
Assert-True ($all -match 'Remember') "passwords last only with Remember"

Assert-True (Test-GuideMatch $g[0] '') "an empty search shows every entry"
Assert-True (Test-GuideMatch ([pscustomobject]@{ Group = 'Times'; Title = 'When'; Answer = 'Use event.created' }) 'EVENT.created times') "an entry matches every word, any case, in its group, title or answer"
Assert-True (-not (Test-GuideMatch ([pscustomobject]@{ Group = 'Times'; Title = 'When'; Answer = 'x' }) 'times zeta')) "and not when one word is missing"

# ---- the tab ----
$shell = Get-Content (Join-Path $code 'HayabusaMissionTool.ps1') -Raw
Assert-True ($shell -match '<TabItem Header="Guide"[^>]*><ScrollViewer x:Name="tabGuide"') "the Guide tab, after Settings"
Assert-True ($shell -match "'wpf-settings\.ps1', 'wpf-guide\.ps1'") "loaded with the other tabs"
$busy = [regex]::Match($shell, '(?s)function Set-AppBusy.*?\r?\n\}').Value
Assert-True ($busy -notmatch 'tabGuide') "a running job does not lock it - reading while waiting is the point"
$tab = Get-Content (Join-Path $code 'wpf-guide.ps1') -Raw
Assert-True ($tab -match 'Get-GuideEntries' -and $tab -match 'Find-ReadmeChapters' -and $tab -match 'Get-ReadmeChapters') "the tab shows the tested entries and searches"
Assert-True ($tab -match "Join-Path \`$script:Root 'README\.txt'") "the README beside EVTXER.cmd - the copy that shipped with this tool"
