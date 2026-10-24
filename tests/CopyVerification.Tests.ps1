# tests/CopyVerification.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# Copy-Item's errors are NON-TERMINATING by default, and nothing in this
# codebase sets $ErrorActionPreference = 'Stop' outside the test runner. So
#
#     Copy-Item -Path $src -Destination $dst -Force
#     $files += $dst
#     Write-Log "[OK] Acquired: $name"
#
# logs [OK] and records a file that is not there. The failure it hides is the
# one this tool documents as EXPECTED: a Security.evtx locked by the Event Log
# service, which is the entire reason the WinRM path exists. The most likely
# real-world failure was the one that reported success.
#
# -ErrorAction Stop alone is not enough - it turns a refusal into a catchable
# error, but says nothing about a copy that "succeeded" and produced a 0-byte
# file. The destination gets checked, every time, before anything is counted.

$dir = Join-Path ([IO.Path]::GetTempPath()) ("copyverify-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $dir -Force | Out-Null

try {
    # ---- a real file with content ----
    $good = Join-Path $dir 'good.evtx'
    Set-Content -LiteralPath $good -Value 'pretend evtx bytes' -Encoding Ascii
    $r = Test-CopiedFile $good
    Assert-True  $r.Ok               "a file that arrived with content verifies"
    Assert-True  ($r.Bytes -gt 0)    "the verified result carries the size"

    # ---- the file never arrived ----
    $missing = Join-Path $dir 'never-arrived.evtx'
    $m = Test-CopiedFile $missing
    Assert-True  (-not $m.Ok)             "a file that never arrived does not verify"
    Assert-True  ($m.Reason.Length -gt 0) "a missing file explains itself"
    Assert-Equal $m.Bytes ([long]0)       "a missing file reports zero bytes"

    # ---- the copy 'succeeded' but produced nothing ----
    # An interrupted transfer leaves a 0-byte destination. Test-Path alone says
    # yes; a real .evtx is never empty, so zero bytes is a failed copy.
    $empty = Join-Path $dir 'empty.evtx'
    New-Item -ItemType File -Path $empty -Force | Out-Null
    $e = Test-CopiedFile $empty
    Assert-True  (-not $e.Ok)             "a 0-byte destination does not count as copied"
    Assert-True  ($e.Reason.Length -gt 0) "an empty file explains itself"

    # ---- a directory is not a copied file ----
    $sub = Join-Path $dir 'subdir'
    New-Item -ItemType Directory -Path $sub -Force | Out-Null
    Assert-True (-not (Test-CopiedFile $sub).Ok) "a directory is not a copied file"

    # ---- junk input fails cleanly instead of throwing ----
    Assert-True (-not (Test-CopiedFile '').Ok)    "an empty path does not verify"
    Assert-True (-not (Test-CopiedFile $null).Ok) "a null path does not verify"
}
finally {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}
