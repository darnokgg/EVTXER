# tests/Archive.Tests.ps1
#
# Phase 2: the operator only collects; the
# raw EVTX then go into an archive - one zip per host folder, on a local disk
# or an SMB share - and leave the drop folder. Evidence is deleted here, so
# the rules are strict: a .partial until verified, every entry re-hashed, the
# source removed only after that, and nothing touched on failure or Cancel.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
Add-Type -AssemblyName System.IO.Compression

# ---- the folder layout follows the Settings tab ----
$r = 'C:\EVTXER'
$l = Get-FolderLayout $r
Assert-Equal $l.Evtx    'C:\EVTXER\evtx'    "the drop folder defaults to evtx\ beside code\"
Assert-Equal $l.Archive 'C:\EVTXER\archive' "the archive defaults to archive\"
$l = Get-FolderLayout $r 'D:\drop' '\\nas\evidence'
Assert-Equal $l.Evtx    'D:\drop'          "a chosen drop folder replaces it"
Assert-Equal $l.Archive '\\nas\evidence'   "a chosen archive folder (a share) replaces it"
Assert-Equal $l.Hayabusa 'C:\EVTXER\output\hayabusa' "the results stay where they were"

# ---- what the Settings tab accepts as a folder ----
# Code review, 2026-10-16: "D:\" was trimmed to "D:", which Windows reads as
# the CURRENT folder on D: - the drop folder would quietly have been code\.
Assert-Equal (ConvertTo-FolderSetting 'D:\')               'D:\'             "a drive root stays the root"
Assert-Equal (ConvertTo-FolderSetting ' D:\evtx\ ')        'D:\evtx'         "a trailing slash and spaces are trimmed"
Assert-Equal (ConvertTo-FolderSetting 'D:\a\..\evtx')      'D:\evtx'         "dots are resolved, so the path compares equal later"
Assert-Equal (ConvertTo-FolderSetting '\\nas\share\')      '\\nas\share'     "a share root is accepted"
Assert-Equal (ConvertTo-FolderSetting '\\nas\share\case1') '\\nas\share\case1' "and a folder on it"
foreach ($bad in 'D:', 'D:evtx', '\evtx', 'evtx', '\\nas', '\\nas\', '', 'D:\a|b') {
    Assert-Equal (ConvertTo-FolderSetting $bad) '' "'$bad' is refused - it would resolve against the current folder, or is not a path"
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("archive-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

function New-HostFolder([string]$Root, [string]$Name, [int]$Files = 2, [int]$Size = 1500000) {
    $d = Join-Path $Root $Name
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    $rng = New-Object Random 7
    foreach ($i in 1..$Files) {
        # Over the 1 MB copy buffer, so a file takes more than one read.
        $b = New-Object byte[] $Size; $rng.NextBytes($b)
        [IO.File]::WriteAllBytes((Join-Path $d "Log$i.evtx"), $b)
    }
    '{"Host":"x"}' | Set-Content -LiteralPath (Join-Path $d 'manifest.json')
    return $d
}
function Get-ZipNames([string]$Zip) {
    $za = [IO.Compression.ZipFile]::OpenRead($Zip)
    try { @($za.Entries | ForEach-Object FullName | Sort-Object) } finally { $za.Dispose() }
}
Add-Type -AssemblyName System.IO.Compression.FileSystem

try {
    # ---- settings survive a restart, and a broken file is just the defaults ----
    $conf = Join-Path $tmp 'settings.conf'
    $s = Read-ToolSettings $conf
    Assert-Equal "$($s.EvtxFolder)|$($s.ArchiveFolder)" '|' "no settings file means the defaults"
    $s.EvtxFolder = 'D:\drop'; $s.ArchiveFolder = '\\nas\evidence'
    Save-ToolSettings $s $conf
    $s2 = Read-ToolSettings $conf
    Assert-Equal "$($s2.EvtxFolder)|$($s2.ArchiveFolder)" 'D:\drop|\\nas\evidence' "they are read back after a restart"
    'not json{' | Set-Content -LiteralPath $conf
    Assert-Equal (Read-ToolSettings $conf).EvtxFolder '' "a corrupt settings file does not stop the tool"

    # ---- which folders are offered ----
    $drop = Join-Path $tmp 'evtx'
    $h1 = New-HostFolder $drop 'HOSTA_20261016_100000'
    $h2 = New-HostFolder $drop 'HOSTB_20261016_100000' 1
    New-Item -ItemType Directory -Path (Join-Path $drop 'empty') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $drop '_unpacking') -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $drop '_unpacking\x.evtx'), [byte[]](1..10))
    [IO.File]::WriteAllBytes((Join-Path $drop 'loose.evtx'), [byte[]](1..10))
    $c = @(Get-ArchiveCandidates $drop)
    Assert-Equal (($c | ForEach-Object Name) -join ',') 'HOSTA_20261016_100000,HOSTB_20261016_100000' "only host folders holding .evtx are offered"
    Assert-Equal $c[0].Files 2 "with their file count"
    Assert-Equal $c[0].Bytes ([long]3000000) "and their size"
    Assert-Equal @(Get-ArchiveCandidates (Join-Path $tmp 'nope')).Count 0 "a missing drop folder offers nothing"

    # ---- a host folder becomes one verified zip, and leaves the drop folder ----
    $arch = Join-Path $tmp 'archive'
    $res = Compress-EvtxFolder -Folder $h1 -ArchiveRoot $arch
    Assert-Equal $res.Zip (Join-Path $arch 'HOSTA_20261016_100000.zip') "the zip is named after the host folder"
    Assert-Equal ((Get-ZipNames $res.Zip) -join ',') 'Log1.evtx,Log2.evtx,manifest.json' "it holds the raw .evtx and their manifest"
    Assert-Equal $res.Files 2 "two .evtx archived"
    Assert-True ($res.ZipBytes -gt 0) "the zip size is reported"
    Assert-Equal @(Get-ChildItem $arch -Filter *.partial).Count 0 "no .partial is left once it is done"
    Assert-True (-not (Test-Path -LiteralPath $h1)) "the verified source folder is removed"
    $za = [IO.Compression.ZipFile]::OpenRead($res.Zip)
    try {
        $ms = New-Object IO.MemoryStream; $s = $za.GetEntry('Log1.evtx').Open(); $s.CopyTo($ms); $s.Dispose()
        $b = New-Object byte[] 1500000; (New-Object Random 7).NextBytes($b)
        Assert-True ([Linq.Enumerable]::SequenceEqual([byte[]]$ms.ToArray(), $b)) "the archived bytes are the original bytes"
    } finally { $za.Dispose() }

    # ---- an archive is never overwritten ----
    $again = New-HostFolder $drop 'HOSTA_20261016_100000' 1
    $res2 = Compress-EvtxFolder -Folder $again -ArchiveRoot $arch
    Assert-Equal (Split-Path -Leaf $res2.Zip) 'HOSTA_20261016_100000-2.zip' "the same host archived again gets a new name"

    # ---- only what was archived is deleted ----
    $h3 = New-HostFolder $drop 'HOSTC_20261016_100000' 1
    'notes' | Set-Content -LiteralPath (Join-Path $h3 'analyst-notes.txt')
    [IO.File]::WriteAllBytes((Join-Path $h3 'Half.evtx.partial'), [byte[]](1..10))
    $res3 = Compress-EvtxFolder -Folder $h3 -ArchiveRoot $arch
    Assert-Equal ((Get-ZipNames $res3.Zip) -join ',') 'Log1.evtx,manifest.json' "a half-copied .evtx.partial and other files are not archived"
    Assert-Equal ((Get-ChildItem -LiteralPath $h3 | ForEach-Object Name | Sort-Object) -join ',') 'analyst-notes.txt,Half.evtx.partial' "and are left where they were, with their folder"

    # ---- a file rewritten after it was hashed is kept ----
    # Code review, 2026-10-16: the zip holds the OLD copy, so deleting the new
    # one would lose it. The "[OK] <zip>" line is logged after the zip is
    # verified and renamed and before anything is deleted - exactly the window.
    $h6 = New-HostFolder $drop 'HOSTF_20261016_100000' 1
    New-Item -ItemType Directory -Path (Join-Path $h6 'sub') -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $h6 'sub\Nested.evtx'), [byte[]](1..64))
    $man6 = Join-Path $h6 'manifest.json'
    $rewrite = { param($m) if ($m -match '\[OK\] .*\.zip') { [IO.File]::AppendAllText($man6, 'rewritten') } }.GetNewClosure()
    $res6 = Compress-EvtxFolder -Folder $h6 -ArchiveRoot $arch -LogWriter $rewrite
    Assert-True (@($res6.Left) -match 'manifest\.json \(changed') "a file changed since it was hashed is reported, not deleted"
    Assert-Equal ((Get-ChildItem -LiteralPath $h6 -Recurse -File | ForEach-Object Name) -join ',') 'manifest.json' "and only it is left"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $h6 'sub'))) "an emptied subfolder is removed"
    Assert-Equal ((Get-ZipNames $res6.Zip) -join ',') 'Log1.evtx,manifest.json,sub/Nested.evtx' "subfolders keep their place in the zip"

    # ---- Cancel deletes the .partial and keeps the source ----
    $h4 = New-HostFolder $drop 'HOSTD_20261016_100000'
    $threw = $null
    try { Compress-EvtxFolder -Folder $h4 -ArchiveRoot $arch -Progress @{ Cancel = $true } | Out-Null } catch { $threw = $_.Exception.Message }
    Assert-True ($threw -match 'Cancelled') "Cancel stops it"
    Assert-Equal @(Get-ChildItem $arch -Filter 'HOSTD*').Count 0 "leaving no zip and no .partial"
    Assert-Equal @(Get-ArchiveFiles $h4).Count 3 "and every source file in place"

    # ---- the archive folder may not sit inside the folder being deleted ----
    $threw = $null
    try { Compress-EvtxFolder -Folder $h4 -ArchiveRoot (Join-Path $h4 'zips') | Out-Null } catch { $threw = $_.Exception.Message }
    Assert-True ($threw -match 'inside') "an archive folder inside the host folder is refused"
    Assert-Equal @(Get-ArchiveFiles $h4).Count 3 "before anything is touched"

    # ---- verification catches a zip that does not match ----
    $ok = @{ 'Log1.evtx' = 'x'; 'manifest.json' = 'y' }
    Assert-True ((Test-EvtxArchive $res3.Zip $ok) -match 'Log1\.evtx does not match') "a wrong hash fails verification"
    $hashes = @{}
    foreach ($n in Get-ZipNames $res3.Zip) {
        $za = [IO.Compression.ZipFile]::OpenRead($res3.Zip)
        try { $s = $za.GetEntry($n).Open(); $hashes[$n] = Get-StreamSha256 $s (New-Object byte[] 4096) $null; $s.Dispose() } finally { $za.Dispose() }
    }
    Assert-Equal (Test-EvtxArchive $res3.Zip $hashes) '' "the right hashes pass"
    $hashes['Extra.evtx'] = 'z'
    Assert-True ((Test-EvtxArchive $res3.Zip $hashes) -match 'Extra\.evtx is missing') "a file missing from the zip fails"
    $bytes = [IO.File]::ReadAllBytes($res3.Zip)
    for ($i = 200; $i -lt 400; $i++) { $bytes[$i] = 0 }
    $broken = Join-Path $tmp 'broken.zip'; [IO.File]::WriteAllBytes($broken, $bytes)
    Assert-True ((Test-EvtxArchive $broken $hashes) -ne '') "a corrupted zip fails"

    # ---- it runs in the background, and its log lines come back ----
    $job = Start-LibJob 'Compress-EvtxFolder' @{ Folder = $h4; ArchiveRoot = $arch }
    $res4 = Complete-LibJob $job
    $lines = @($job.Lines.ToArray())
    Assert-Equal (Split-Path -Leaf $res4.Zip) 'HOSTD_20261016_100000.zip' "a background job archives the folder"
    Assert-True ($lines -match 'Source removed') "and reports what it did"
    Assert-Equal $job.Progress.Done $job.Progress.Total "progress reaches its total (written and read back)"

    # ---- a real SMB path ----
    # The administrative share is SMB through the redirector, as a file
    # server would be. Needs an admin token; skipped without one.
    $unc = '\\localhost\' + $tmp.Substring(0, 1) + '$' + $tmp.Substring(2)
    if (Test-Path -LiteralPath $unc) {
        $h5 = New-HostFolder $drop 'HOSTE_20261016_100000'
        $res5 = Compress-EvtxFolder -Folder $h5 -ArchiveRoot (Join-Path $unc 'share-archive')
        Assert-True ($res5.Zip -like '\\localhost\*') "an archive folder on an SMB share works"
        Assert-True (Test-Path -LiteralPath (Join-Path $tmp 'share-archive\HOSTE_20261016_100000.zip')) "the zip lands on the share"
    } else {
        Write-Host "  [SKIP] $unc is not reachable (needs admin) - SMB archive not exercised" -ForegroundColor Yellow
    }

    # ---- the rename of the verified zip waits out a scanner ----
    # An antivirus or sync client holding the new .partial for a moment made
    # the rename fail, and the catch deleted the verified zip.
    $held = Join-Path $tmp 'held.zip.partial'; $flag = Join-Path $tmp 'held.flag'
    Set-Content -LiteralPath $held -Value 'zip'
    $ps = [powershell]::Create()
    [void]$ps.AddScript({ param($p, $f)
        $fs = [IO.File]::Open($p, 'Open', 'Read', 'Read')
        [IO.File]::WriteAllText($f, 'x'); Start-Sleep -Milliseconds 500; $fs.Dispose() }).AddArgument($held).AddArgument($flag)
    $h = $ps.BeginInvoke()
    while (-not (Test-Path -LiteralPath $flag)) { Start-Sleep -Milliseconds 20 }
    Move-FileWithRetry $held (Join-Path $tmp 'held.zip')
    [void]$ps.EndInvoke($h); $ps.Dispose()
    Assert-True (Test-Path -LiteralPath (Join-Path $tmp 'held.zip')) "a file held for half a second is still renamed"

    $fs = [IO.File]::Open((Join-Path $tmp 'held.zip'), 'Open', 'Read', 'Read')
    try {
        $threw = $false
        try { Move-FileWithRetry (Join-Path $tmp 'held.zip') (Join-Path $tmp 'gone.zip') -Tries 2 -DelayMs 10 } catch { $threw = $true }
        Assert-True $threw "a file that stays held still fails, after the retries"
    } finally { $fs.Dispose() }
    $lib = Get-Content -LiteralPath "$PSScriptRoot\..\code\HayabusaLib.ps1" -Raw
    Assert-True ($lib -match 'Test-EvtxArchive \$part[^\n]*\n[^\n]*\n\s*Move-FileWithRetry \$part \$zip') "the archive renames its verified zip that way"
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
