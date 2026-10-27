# tests/CollectionFootprint.Tests.ps1
#
# A collection is a remote admin logon, and the logs it pulls are snapshots
# taken during it, so some detections are the collection itself. Each host's
# manifest records a footprint of the visit and the ECS conversion tags what
# matches it 'evtxer-collection' - tagged, never dropped.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$scratch = Join-Path ([IO.Path]::GetTempPath()) "footprint_$PID"
$hostDir = Join-Path $scratch 'evtx\WS01_20261012_1000'
$other   = Join-Path $scratch 'evtx\WS02_20261012_1000'
New-Item -ItemType Directory -Path $hostDir, $other -Force | Out-Null

# ---- the footprint ----
$fp = New-CollectionFootprint -Account 'CORP\analyst' -StartUtc ([datetime]'2026-10-12T10:00:00Z').ToUniversalTime() `
         -EndUtc ([datetime]'2026-10-12T10:05:00Z').ToUniversalTime() -StagingFolder 'EVTX_Export_1a2b3c4d' `
         -TargetClockSkewSeconds 0 -OperatorAddresses @('10.9.9.9')
Assert-Equal $fp.AccountName 'analyst' "DOMAIN\user is matched on the user part"
Assert-Equal (New-CollectionFootprint -Account 'analyst@corp.local' -StartUtc (Get-Date) -EndUtc (Get-Date)).AccountName 'analyst' "user@upn too"
Assert-Equal $fp.StartUtc '2026-10-12T10:00:00Z' "times are written as UTC"

# ---- it travels in the manifest, and comes back out ----
$m = Write-EvtxManifest -Entries @() -Folder $hostDir -HostName 'WS01' -Method 'WinRM' -Footprint $fp
Assert-True ((Get-Content $m -Raw | ConvertFrom-Json).Footprint.Account -eq 'CORP\analyst') "the manifest carries the footprint"
$fps = @(Get-CollectionFootprints (Join-Path $scratch 'evtx'))
Assert-Equal $fps.Count 1 "footprints are found under the scanned folder"
$pat = $fps[0].Needles -join ' '
Assert-True ($pat -match 'analyst' -and $pat -match '10\\.9' -and $pat -match 'wsmprovhost') `
    "it looks for our account, our address and the WinRM host process"

# ---- which detections are ours ----
function New-Det($file, $time, $details) {
    [pscustomobject]@{ EvtxFile = $file; Timestamp = $time; Details = $details; Computer = 'WS01'; RuleTitle = 'x'; Level = 'info' }
}
$inFile  = Join-Path $hostDir 'Security.evtx'
$outFile = Join-Path $other 'Security.evtx'
Assert-True  (Test-CollectionNoise (New-Det $inFile '2026-10-12T10:02:00Z' @{ TgtUser = 'analyst'; SrcIP = '10.9.9.9' }) $fps) "our logon, in our window, on our host, is ours"
Assert-True  (Test-CollectionNoise (New-Det $inFile '2026-10-12T10:02:00Z' @{ Data = 'HostApplication=C:\Windows\system32\wsmprovhost.exe' }) $fps) "the WinRM host process is ours"
Assert-True (-not (Test-CollectionNoise (New-Det $inFile '2026-10-12T10:02:00Z' @{ TgtUser = 'bob' }) $fps)) "someone else in the same minutes is not"
Assert-True (-not (Test-CollectionNoise (New-Det $inFile '2026-10-12T09:00:00Z' @{ TgtUser = 'analyst' }) $fps)) "our account an hour earlier is not this visit"
Assert-True (-not (Test-CollectionNoise (New-Det $outFile '2026-10-12T10:02:00Z' @{ TgtUser = 'analyst' }) $fps)) "another host's logs are not matched by this host's visit"
Assert-True (Test-CollectionNoise (New-Det $inFile '2026-10-12T10:05:50Z' @{ TgtUser = 'analyst' }) $fps) "a minute's slack covers the clocks"
Assert-True (-not (Test-CollectionNoise (New-Det $inFile '2026-10-12T10:02:00Z' @{ SrcIP = '10.9.9.90' }) $fps)) "10.9.9.9 does not match 10.9.9.90"
Assert-True (-not (Test-CollectionNoise (New-Det $inFile '2026-10-12T10:02:00Z' @{ SrcIP = '110.9.9.9' }) $fps)) "nor 110.9.9.9"
Assert-True (-not (Test-CollectionNoise (New-Det $inFile '2026-10-12T10:02:00Z' @{ TgtUser = 'analyst2' }) $fps)) "analyst does not match analyst2"
Assert-True (Test-CollectionNoise (New-Det $inFile '2026-10-12T10:02:00Z' @{ TgtUser = 'CORP\analyst' }) $fps) "but does match CORP\analyst"

# Over SMB nothing of ours ran on the target, so wsmprovhost is someone else's.
$smbDir = Join-Path $scratch 'evtx\WS03_20261012_1000'
New-Item -ItemType Directory -Path $smbDir -Force | Out-Null
$smbFp = New-CollectionFootprint -Account 'CORP\analyst' -StartUtc ([datetime]'2026-10-12T10:00:00Z').ToUniversalTime() `
            -EndUtc ([datetime]'2026-10-12T10:05:00Z').ToUniversalTime() -StagingFolder '' -OperatorAddresses @('10.9.9.9')
[void](Write-EvtxManifest -Entries @() -Folder $smbDir -HostName 'WS03' -Method 'SMB' -Footprint $smbFp)
$all = @(Get-CollectionFootprints (Join-Path $scratch 'evtx'))
Assert-True (-not (Test-CollectionNoise (New-Det (Join-Path $smbDir 'PS.evtx') '2026-10-12T10:02:00Z' @{ Data = 'wsmprovhost.exe' }) $all)) `
    "an SMB visit does not claim a WinRM session in its window"
Assert-Equal @(Get-CollectionFootprints (Join-Path $scratch 'nothing-here')).Count 0 "no footprints means an empty list, not one null"
# Several scanned folders (the Convert tab's +, 2026-10-27): every one's
# manifests count; a missing one is ignored.
$several = @(Get-CollectionFootprints @($smbDir, (Join-Path $scratch 'nothing-here')))
Assert-Equal $several.Count 1 "with several folders, each one's manifests are read and a missing folder is skipped"
Assert-Equal @(Get-CollectionFootprints @((Join-Path $scratch 'evtx'), $smbDir)).Count $all.Count "a folder listed twice (itself and a parent) is not counted twice"

# The clock skew is the target's word. A huge one is not believed: it would
# slide the window onto other activity and tag it as ours.
$liarDir = Join-Path $scratch 'liar\evtx\WS09_20261012_1000'
New-Item -ItemType Directory -Path $liarDir -Force | Out-Null
$liar = New-CollectionFootprint -Account 'CORP\analyst' -StartUtc ([datetime]'2026-10-12T10:00:00Z').ToUniversalTime() `
           -EndUtc ([datetime]'2026-10-12T10:05:00Z').ToUniversalTime() -StagingFolder 'EVTX_Export_aaaaaaaa' `
           -TargetClockSkewSeconds 7200 -OperatorAddresses @('10.9.9.9')
[void](Write-EvtxManifest -Entries @() -Folder $liarDir -HostName 'WS09' -Method 'WinRM' -Footprint $liar)
$lfp = @(Get-CollectionFootprints (Join-Path $scratch 'liar\evtx'))
$attacker = New-Det (Join-Path $liarDir 'PS.evtx') '2026-10-12T12:02:00Z' @{ Data = 'wsmprovhost.exe' }
Assert-True (-not (Test-CollectionNoise $attacker $lfp)) "a two-hour 'skew' does not move the window onto someone else's WinRM session"
Assert-True (Test-CollectionNoise (New-Det (Join-Path $liarDir 'Security.evtx') '2026-10-12T10:02:00Z' @{ TgtUser = 'analyst' }) $lfp) `
    "the window stays on our own clock instead"

# ---- the conversion tags them and drops nothing ----
$jsonl = Join-Path $scratch 'results.jsonl'
$docs = @(
    (New-Det $inFile '2026-10-12T10:02:00Z' @{ TgtUser = 'analyst' })
    (New-Det $inFile '2026-10-12T10:02:00Z' @{ TgtUser = 'bob' })
    (New-Det $outFile '2026-10-12T10:02:00Z' @{ TgtUser = 'analyst' })
)
[IO.File]::WriteAllLines($jsonl, @($docs | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 }))
$ecsOut = Join-Path $scratch 'results.ecs.jsonl'
$r = Convert-HayabusaJsonlToEcs -Source $jsonl -Destination $ecsOut -EvtxDir (Join-Path $scratch 'evtx')
Assert-Equal $r.Converted 3 "nothing is dropped"
Assert-Equal $r.Tagged 1 "only our own activity is tagged"
$out = @(Get-Content $ecsOut | ConvertFrom-Json)
Assert-True (@($out[0].tags) -contains 'evtxer-collection') "the tag is on our logon"
Assert-True (-not (@($out[1].tags) -contains 'evtxer-collection')) "and not on anyone else's"
$r = Convert-HayabusaJsonlToEcs -Source $jsonl -Destination $ecsOut
Assert-Equal $r.Tagged 0 "with no EVTX folder there is nothing to match, and nothing is tagged"

# ---- the collector writes it ----
$collector = Get-Content "$PSScriptRoot\..\code\EvtxCollector.ps1" -Raw
Assert-True ($collector -match 'New-CollectionFootprint') "the collector builds a footprint per host"
Assert-True ($collector -match '-Footprint \$footprint') "and writes it into the manifest"

Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
