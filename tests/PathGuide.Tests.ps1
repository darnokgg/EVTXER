# tests/PathGuide.Tests.ps1
#
# The Convert tab writes two files whose names differ by a few characters and
# which go to opposite places: results.jsonl feeds Takajo, ecs.jsonl feeds the
# Security Onion upload. Sending the wrong one indexes Timestamp instead of
# @timestamp with no hayabusa.details object and disagrees with the index
# template - which is why both tabs already validate their input.
#
# This guide is the explanation of that, so getting the two the wrong way round
# would be worse than saying nothing. The wording is asserted, the same way the
# SMB caution and the Takajo server caution are.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$g = Get-PathGuide
$text = $g -join "`n"

Assert-True ($g.Count -gt 0)                    "the guide has lines"

# ---- the two outputs, and which way round they go ----
Assert-True ($text -match 'results\.jsonl')     "it names results.jsonl"
Assert-True ($text -match 'ecs\.jsonl')         "it names ecs.jsonl"

# Selected by what the line says it is, not by filename: the ECS file is
# called results.ecs.jsonl, so matching on 'ecs.jsonl' alone would also catch
# the raw line and a lookbehind for 'results.' now excludes the very line it
# is meant to find.
$resultsLine = @($g | Where-Object { $_ -match 'raw Hayabusa timeline' })[0]
$ecsLine     = @($g | Where-Object { $_ -match 'ECS transform' })[0]
Assert-True ($null -ne $resultsLine) "the guide has a line for the raw timeline"
Assert-True ($null -ne $ecsLine)     "the guide has a line for the ECS transform"
Assert-True ($resultsLine -match 'results\.jsonl')      "the raw line names results.jsonl"
Assert-True ($ecsLine -match 'results\.ecs\.jsonl')     "the ECS line names results.ecs.jsonl"

Assert-True ($resultsLine -match '(?i)takajo')  "results.jsonl is pointed at Takajo"
Assert-True ($resultsLine -notmatch '(?i)onion') "results.jsonl is NOT pointed at Security Onion"
Assert-True ($ecsLine -match '(?i)onion|upload') "ecs.jsonl is pointed at the upload"
Assert-True ($ecsLine -notmatch '(?i)takajo')   "ecs.jsonl is NOT pointed at Takajo"

# ---- the folders that matter ----
Assert-True ($text -match 'evtx')               "it names the evtx folder"
Assert-True ($text -match 'output')             "it names the output folder"
Assert-True ($text -match 'takajo')             "it names the takajo output folder"

# ---- CSV is a local artifact, never uploaded ----
$csvLine = @($g | Where-Object { $_ -match '\.csv' })[0]
Assert-True ($null -ne $csvLine)                "it mentions the CSV copy"
Assert-True ($csvLine -match '(?i)local|never') "the CSV is described as local only"

# ---- PS 5.1 + WinForms render non-ASCII unreliably ----
foreach ($line in $g) {
    Assert-True ($line -notmatch '[^\x20-\x7E]') "guide line is ASCII only: $line"
}

# ---- it has to fit the panel it is drawn in ----
foreach ($line in $g) {
    Assert-True ($line.Length -le 92) "guide line fits the panel width ($($line.Length) chars): $line"
}

# ---- partner-staged evidence ----
# A client's admin exporting logs to a share they own is a real engagement
# pattern, and it needs no collection method at all - once the files exist
# somewhere readable, collection is over and this is just a folder. The guide
# has to say so, because nothing else in the UI does.
Assert-True ($text -match '(?i)UNC') "the guide says a UNC share works as an EVTX folder"
