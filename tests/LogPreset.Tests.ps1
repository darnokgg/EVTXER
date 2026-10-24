# tests/LogPreset.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
$dfir = Resolve-LogPreset 'DFIR' @()
Assert-True ($dfir -contains 'Security') "DFIR includes Security"
Assert-True ($dfir -contains 'Microsoft-Windows-Sysmon/Operational') "DFIR includes Sysmon"
Assert-True ($dfir -contains 'Microsoft-Windows-TaskScheduler/Operational') "DFIR includes TaskScheduler (task creation without audit policy)"
Assert-Equal $dfir[-1] 'Microsoft-Windows-Sysmon/Operational' "Sysmon is exported last, after the noise of the other exports"
Assert-Equal $dfir.Count 16 "DFIR has 16 logs"
foreach ($c in 'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-WMI-Activity/Operational',
               'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', 'Microsoft-Windows-AppLocker/EXE and DLL',
               'Microsoft-Windows-AppLocker/MSI and Script', 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall') {
    Assert-True ($dfir -contains $c) "DFIR includes $c"
}
# Every preset log can also be picked on its own under Custom.
$catalog = @(Get-LogCatalog | ForEach-Object { $_.LogName })
Assert-Equal (@($dfir | Where-Object { $catalog -notcontains $_ }) -join ',') '' "every DFIR log is in the Custom catalog"

# ---- a log the host does not have is not a failed collection ----
Assert-Equal (Get-ExportVerdict 0 $true)      'Exported' "a file that arrived is exported"
Assert-Equal (Get-ExportVerdict 15007 $false 'Microsoft-Windows-Sysmon/Operational') 'Absent' "channel-not-found means the host does not have it"
# The answer comes from the target. A compromised host claiming to have no
# Security log must read PARTIAL, not clean.
foreach ($core in 'Security', 'System', 'Application', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational') {
    Assert-Equal (Get-ExportVerdict 15007 $false $core) 'Failed' "$core can never be 'not on this host'"
}
Assert-True (-not (Test-LogCanBeAbsent 'Microsoft-Windows-PowerShell%4Operational.evtx')) "core logs are recognised by file name too (SMB)"
Assert-True (Test-LogCanBeAbsent 'Microsoft-Windows-Sysmon%4Operational.evtx') "an optional log's file may be absent"
Assert-Equal (Get-ExportVerdict 5 $false)     'Failed'   "access denied is still a failure"
Assert-Equal (Get-ExportVerdict 0 $false)     'Failed'   "a clean exit with no file is still a failure"
Assert-Equal (Resolve-LogPreset 'All' @()) 'ALL' "All returns sentinel"
$cust = Resolve-LogPreset 'Custom' @('Security','System')
Assert-Equal ($cust -join ',') 'Security,System' "Custom passes names through"
Assert-True ((Get-LogCatalog).Count -ge 15) "catalog has >=15 entries"
