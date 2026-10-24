# tests/StagedCopy.Tests.ps1
#
# A copy that dies half way (the network drops, the session breaks) used to
# leave a truncated .evtx under its real name in the evidence folder. Nothing
# counted it, but Hayabusa scans the folder recursively and analysed it anyway.
# Every transfer now lands as <name>.partial and is renamed only once it is
# complete, so a broken one can never look like evidence.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("staged-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $src  = Join-Path $tmp 'source.bin'
    [IO.File]::WriteAllBytes($src, [byte[]](1..200))

    # ---- a good copy arrives under its real name, with no .partial left ----
    $dest = Join-Path $tmp 'Security.evtx'
    $v = Invoke-StagedCopy -Destination $dest -Copy { param($to) Copy-Item -LiteralPath $src -Destination $to -Force -ErrorAction Stop }
    Assert-True $v.Ok "a complete copy is reported ok"
    Assert-Equal $v.Bytes ([long]200) "with its size"
    Assert-True (Test-Path -LiteralPath $dest) "and lands under its final name"
    Assert-True (-not (Test-Path -LiteralPath "$dest.partial")) "leaving no .partial behind"

    # ---- a copy that throws half way leaves nothing ----
    $dest2 = Join-Path $tmp 'System.evtx'
    $threw = $false
    try {
        Invoke-StagedCopy -Destination $dest2 -Copy {
            param($to)
            [IO.File]::WriteAllBytes($to, [byte[]](1..50))   # half a file landed...
            throw 'The network connection was lost.'          # ...then the link dropped
        } | Out-Null
    } catch { $threw = $true }
    Assert-True $threw "the copy's own error still reaches the caller"
    Assert-True (-not (Test-Path -LiteralPath $dest2)) "no truncated file appears under the real name"
    Assert-True (-not (Test-Path -LiteralPath "$dest2.partial")) "and the partial is cleaned up"

    # ---- a copy that 'succeeds' with an empty file is refused ----
    $dest3 = Join-Path $tmp 'Application.evtx'
    $v3 = Invoke-StagedCopy -Destination $dest3 -Copy { param($to) [IO.File]::WriteAllBytes($to, [byte[]]@()) }
    Assert-True (-not $v3.Ok) "an empty arrival is not ok"
    Assert-True (-not (Test-Path -LiteralPath $dest3)) "and never gets the real name"
    Assert-True (-not (Test-Path -LiteralPath "$dest3.partial")) "nor stays as a partial"

    # ---- leftovers from a killed run are swept, real files are not ----
    $host1 = Join-Path $tmp 'host1'
    New-Item -ItemType Directory -Path $host1 -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $host1 'Security.evtx.partial'), [byte[]](1..5))
    [IO.File]::WriteAllBytes((Join-Path $host1 'System.evtx'), [byte[]](1..5))
    New-Item -ItemType Directory -Path (Join-Path $host1 $script:UnzipStagingName) -Force | Out-Null
    $swept = @(Remove-PartialTransfers $host1)
    Assert-Equal $swept.Count 2 "a stray .partial and an unfinished unzip folder are swept"
    Assert-True (Test-Path -LiteralPath (Join-Path $host1 'System.evtx')) "a finished file is left alone"
}
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }

# ---- the collector uses it on every path ----
$col = Get-Content "$PSScriptRoot\..\code\EvtxCollector.ps1" -Raw
Assert-Equal ([regex]::Matches($col, 'Invoke-StagedCopy').Count) 3 "SMB, WinRM per-file and the zip download all go through Invoke-StagedCopy"
Assert-True ($col -notmatch "Expand-Archive[^\r\n]*-DestinationPath \`$outFolder") "the archive is never unpacked straight into the evidence folder"
Assert-True ($col -match '(?s)if \(\$clean\.Clean\) \{\s*& \$LogWriter "  \[WinRM\] Session closed\. Remote temp cleaned\."') "'Remote temp cleaned' is said only when the cleanup was confirmed"
