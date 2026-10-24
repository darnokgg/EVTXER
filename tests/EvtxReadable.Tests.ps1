# tests/EvtxReadable.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# MEASURED, not assumed. On Windows 11 (2026-09-09, elevated) the Event Log
# service holds winevt\Logs\*.evtx with a share mode that:
#
#     FileShare::Read       REFUSED  "used by another process"
#     FileShare::ReadWrite  OPENED   20,975,616 bytes readable
#     FileShare::None       REFUSED  "used by another process"
#
# So a probe that asks for FileShare::Read - the intuitive choice when you only
# intend to read - reports a perfectly copyable Security.evtx as locked. That
# false negative is the whole reason this test exists: it pins the share mode
# so nobody "simplifies" it back to Read.
#
# Tested against a file this test locks itself, so it needs no elevation and no
# real event log.

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("evtx-readable-{0}.tmp" -f [guid]::NewGuid().ToString('N').Substring(0,8))
Set-Content -LiteralPath $tmp -Value 'not really an evtx' -Encoding Ascii

try {
    # ---- nothing holding it: readable ----
    $free = Test-EvtxReadable $tmp
    Assert-True $free.Readable          "an unlocked file is readable"
    Assert-True ($free.Bytes -gt 0)     "the readable result carries the size"

    # ---- held exactly the way the Event Log service holds a log ----
    # Writer keeps the handle open and permits ReadWrite sharing.
    $holder = [System.IO.File]::Open($tmp, [System.IO.FileMode]::Open,
                                     [System.IO.FileAccess]::ReadWrite,
                                     [System.IO.FileShare]::ReadWrite)
    try {
        $held = Test-EvtxReadable $tmp
        Assert-True $held.Readable  "a file held with FileShare::ReadWrite is still readable - this is the Security.evtx case"
    } finally {
        $holder.Close()
    }

    # ---- held exclusively: genuinely unreadable, and says why ----
    $excl = [System.IO.File]::Open($tmp, [System.IO.FileMode]::Open,
                                   [System.IO.FileAccess]::ReadWrite,
                                   [System.IO.FileShare]::None)
    try {
        $blocked = Test-EvtxReadable $tmp
        Assert-True (-not $blocked.Readable)      "an exclusively held file is not readable"
        Assert-True ($blocked.Reason.Length -gt 0) "an unreadable result explains itself"
    } finally {
        $excl.Close()
    }

    # ---- a PSDrive path is NOT a path .NET understands ----
    # The trap that broke Verify Access on every SMB target: the check mounted
    # C$ as a PSDrive, listed the folder with Get-ChildItem (provider-aware,
    # fine) and then handed "T:\...\Security.evtx" to Test-EvtxReadable, which
    # opens through .NET. .NET has no idea what T: is, so a present, copyable
    # log was reported as "Could not find a part of the path" - while Test-Path
    # on the very same string said it was there. Callers must resolve a PSDrive
    # to a real path (UNC) before calling this.
    $psDriveDir = Join-Path ([IO.Path]::GetTempPath()) ("evtx-psdrive-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $psDriveDir -Force | Out-Null
    $inDrive = Join-Path $psDriveDir 'Security.evtx'
    Set-Content -LiteralPath $inDrive -Value 'not really an evtx' -Encoding Ascii
    $drv = Get-FreeDriveLetter
    Assert-True ($null -ne $drv) "a free drive letter is available for the PSDrive case"
    New-PSDrive -Name $drv -PSProvider FileSystem -Root $psDriveDir -Scope Global -ErrorAction Stop | Out-Null
    try {
        $viaDrive = "${drv}:\Security.evtx"
        Assert-True (Test-Path -LiteralPath $viaDrive) "PowerShell itself sees the file through the PSDrive"
        Assert-True (-not (Test-EvtxReadable $viaDrive).Readable) "a PSDrive path is NOT readable through .NET - resolve it to UNC first"
        Assert-True (Test-EvtxReadable $inDrive).Readable "the same file IS readable by its real path"
    } finally {
        Remove-PSDrive -Name $drv -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $psDriveDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # ---- a missing file fails cleanly rather than throwing ----
    $gone = Test-EvtxReadable (Join-Path ([IO.Path]::GetTempPath()) 'definitely-not-here-9e1f.evtx')
    Assert-True (-not $gone.Readable)       "a missing file is reported unreadable"
    Assert-True ($gone.Reason.Length -gt 0) "a missing file explains itself"
}
finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}
