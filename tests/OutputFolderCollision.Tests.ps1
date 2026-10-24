# tests/OutputFolderCollision.Tests.ps1
. "$PSScriptRoot\..\code\EvtxCollector.ps1"

# The local output folder was "<host>_<yyyyMMdd_HHmm>" created with
# New-Item -Force. Minute resolution plus -Force means two collections of the
# same target inside the same minute do not collide loudly - they SHARE a
# folder, silently.
#
# That is worse than any transfer bug this collector had. A DFIR run followed
# by a Custom run leaves one folder holding files from two separate
# acquisitions, with matching names overwritten and non-matching names simply
# accumulating. Nothing downstream can tell them apart: the folder name says
# one collection and the contents are two. An evidence folder that quietly
# mixes provenance is not recoverable by re-reading it later.
#
# Get-NextFreeFolder already solved exactly this for Takajo's --output and is
# unit-tested in ProcessArgs.Tests.ps1; the collector uses it, without -Force.
#
# Runs offline: the .invalid target (RFC 2606 guarantees it never resolves)
# fails at the mount. Since v42 a host that delivered nothing removes its own
# empty folder, so this no longer counts empty folders: it plants the folders
# an earlier collection in the same minute would have left - one holding
# evidence, one empty - and proves the run neither wrote into them nor
# deleted them, and that only its own folder went.

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("outfolder-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$quiet = { param($m) }
$target = 'no-such-host-9e1f.invalid'

try {
    # This minute and the next, so a run that crosses the minute still meets them.
    $planted = @()
    foreach ($t in (Get-Date), (Get-Date).AddMinutes(1)) {
        $base = Join-Path $tmp ("{0}_{1}" -f $target, $t.ToString('yyyyMMdd_HHmm'))
        New-Item -ItemType Directory -Path $base -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $base 'Security.evtx'), 'earlier collection')
        New-Item -ItemType Directory -Path "$base-2" -Force | Out-Null   # empty, but not this run's
        $planted += $base, "$base-2"
    }

    $r = Invoke-EvtxCollection -Targets @($target) -Method SMB -Category DFIR -CustomLogs @() `
            -Credential $null -OutRoot $tmp -LogWriter $quiet
    Assert-Equal $r.Failed 1 "the unreachable target fails"

    foreach ($p in $planted) {
        Assert-True (Test-Path -LiteralPath $p) "an existing folder of the same name is left in place ($(Split-Path -Leaf $p))"
    }
    foreach ($p in $planted | Where-Object { $_ -notlike '*-2' }) {
        Assert-Equal ((Get-ChildItem -LiteralPath $p | ForEach-Object Name) -join ',') 'Security.evtx' "and the earlier collection in it is untouched"
    }
    Assert-Equal @(Get-ChildItem -LiteralPath $tmp -Directory).Count $planted.Count "the run's own empty folder was the only one removed"
    Assert-Equal @($r.OutFolders).Count 0 "and it reports no output folder"

    # The rule itself, at its source: a free name, and no -Force that would
    # hand back somebody else's folder.
    $src = Get-Content "$PSScriptRoot\..\code\EvtxCollector.ps1" -Raw
    Assert-True ($src -match '\$outFolder = Get-NextFreeFolder') "the host folder name comes from Get-NextFreeFolder"
    Assert-True ($src -match 'New-Item -ItemType Directory -Path \$outFolder -ErrorAction Stop \| Out-Null') "and is created without -Force"
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
