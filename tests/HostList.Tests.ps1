# tests/HostList.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
$a = ConvertTo-HostList "10.0.0.5, 10.0.0.6 ,10.0.0.5" $null
Assert-Equal ($a -join ',') '10.0.0.5,10.0.0.6' "splits, trims, dedups (comma)"
$b = ConvertTo-HostList "host1`nhost2`n`n host1 " $null
Assert-Equal ($b -join ',') 'host1,host2' "splits on newlines, drops blanks/dupes"
$tmp = "$env:TEMP\targets_$PID.txt"; "fileA`nfileB" | Set-Content $tmp
$c = ConvertTo-HostList "" $tmp
Assert-Equal ($c -join ',') 'fileA,fileB' "reads from target file"
Remove-Item $tmp

# ---- the Targets window's Tidy ----
$tidy = Format-TargetList "10.0.0.10, dc01`r`n10.0.0.2`n`nDC01, 10.0.0.2 ,192.0.2.83`nfs03.corp.local`n300.1.1.1"
Assert-Equal $tidy "10.0.0.2`r`n10.0.0.10`r`n192.0.2.83`r`n300.1.1.1`r`ndc01`r`nfs03.corp.local" "Tidy: one per line, each once, IPs in number order, then names A-Z (300.1.1.1 is no IP)"
Assert-Equal (Format-TargetList '') '' "an empty list stays empty"
Assert-Equal @(ConvertTo-HostList $tidy).Count 6 "and the collection reads it the same way"
$col = Get-Content "$PSScriptRoot\..\code\wpf-collect.ps1" -Raw
Assert-True ($col -match 'x:Name="btnExpandTargets"') "the Collect tab has an Expand list button"
Assert-True ($col -match '(?s)x:Name="txtBigTargets"[^>]*AcceptsReturn="True"[^>]*VerticalScrollBarVisibility="Auto"') "its window is editable and scrolls"
Assert-True ($col -match 'ConvertTo-HostList \$txtTargets\.Text \$script:CollectTargetFile\) -join') "it opens with the box AND a loaded file - what the collection will visit"
