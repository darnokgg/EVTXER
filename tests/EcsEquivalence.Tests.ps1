# tests/EcsEquivalence.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
$doc = @{
    Computer='WS01'; Timestamp='2019-04-27T21:04:25.733401Z'; Level='high'
    RuleTitle='Net Conn'; EventID=5156; Channel='Security'
    Details=@{ ProcessID=820; DestinationIp='10.0.0.9' }   # capital-D on purpose
} | ConvertTo-Json -Depth 6 | ConvertFrom-Json
$ecs = ConvertTo-EcsDocument $doc 'testid'
Assert-Equal $ecs.host.name 'WS01' "host.name from Computer"
Assert-Equal $ecs.process.pid 820 "process.pid found via case-insensitive ProcessID"
