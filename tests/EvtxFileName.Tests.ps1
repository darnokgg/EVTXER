# tests/EvtxFileName.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
Assert-Equal (ConvertTo-EvtxFileName 'Security') 'Security.evtx' "plain log"
Assert-Equal (ConvertTo-EvtxFileName 'Microsoft-Windows-Sysmon/Operational') `
    'Microsoft-Windows-Sysmon%4Operational.evtx' "slash becomes %4"
