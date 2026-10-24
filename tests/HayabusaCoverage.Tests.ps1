# tests/HayabusaCoverage.Tests.ps1
#
# Hayabusa outputs only the events that matched a rule. The Convert tab states
# that share after every scan, read from Hayabusa's own summary line.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$line = "Events with hits / Total events: 3,140 / 7,053 (Data reduction: 3,913 events (55.48%))"
$c = Get-HayabusaCoverage "junk`r`n$line`r`nmore"
Assert-Equal $c.Hits ([long]3140) "hits are read, thousands separators and all"
Assert-Equal $c.Total ([long]7053) "and the total"
Assert-Equal $c.Percent 44.5 "the share is rounded to one decimal"
Assert-Equal $c.Text '3,140 of 7,053 event records matched a rule (44.5%)' "and stated in plain words"
Assert-Equal (Get-HayabusaCoverage 'no summary here') $null "no summary line, no claim"

$cv = Get-Content "$PSScriptRoot\..\code\wpf-convert.ps1" -Raw
Assert-True ($cv -match 'Get-HayabusaCoverage') "the Convert tab reports coverage after a scan"
