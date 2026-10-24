# tests/Manifest.Tests.ps1
#
# Until now the tool proved a file ARRIVED (Test-CopiedFile: exists, non-empty,
# right size class). It never proved the file that arrived is the file that was
# on the target. For evidence that may be challenged, those are different
# claims, and only the second one is worth anything.
#
# The manifest records a SHA-256 of every acquired file. Where the source can be
# hashed too - WinRM exports a STATIC copy into staging, so it can - the two are
# compared and the verdict recorded per file. SMB reads a LIVE log that Windows
# is still writing to, so a source hash there would differ from the copy for
# entirely innocent reasons; the manifest says "not compared" rather than
# inventing a mismatch.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("manifest-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

try {
    $a = Join-Path $tmp 'Security.evtx'
    $b = Join-Path $tmp 'System.evtx'
    Set-Content -LiteralPath $a -Value 'alpha' -NoNewline
    Set-Content -LiteralPath $b -Value 'beta'  -NoNewline
    $hashA = (Get-FileHash -LiteralPath $a -Algorithm SHA256).Hash
    $hashB = (Get-FileHash -LiteralPath $b -Algorithm SHA256).Hash

    # ---- an entry records what was acquired ----
    $e = New-ManifestEntry -Path $a -LogName 'Security'
    Assert-Equal $e.Sha256 $hashA        "the entry carries the file's SHA-256"
    Assert-Equal $e.File 'Security.evtx' "the entry names the file"
    Assert-Equal $e.LogName 'Security'   "and the channel it came from"
    Assert-Equal $e.Bytes 5              "and its size"
    Assert-Equal $e.SourceSha256 ''      "with no source hash until one is supplied"
    Assert-Equal $e.Verdict 'NotCompared' "so the verdict is NotCompared, not Match"

    # ---- with a source hash, the two are compared ----
    $match = New-ManifestEntry -Path $a -LogName 'Security' -SourceSha256 $hashA
    Assert-Equal $match.Verdict 'Match'      "identical hashes verify the transfer"
    $bad = New-ManifestEntry -Path $a -LogName 'Security' -SourceSha256 $hashB
    Assert-Equal $bad.Verdict 'MISMATCH'     "different hashes are a mismatch"
    # Case must not decide it: Get-FileHash returns upper case, wevtutil-side
    # helpers and .NET formatters do not always agree.
    $lower = New-ManifestEntry -Path $a -LogName 'Security' -SourceSha256 $hashA.ToLower()
    Assert-Equal $lower.Verdict 'Match'      "hash comparison ignores case"

    # ---- a file that is not there is not evidence ----
    $gone = New-ManifestEntry -Path (Join-Path $tmp 'nope.evtx') -LogName 'Nope'
    Assert-Equal $gone.Verdict 'Missing'     "a missing file is Missing"
    Assert-Equal $gone.Sha256 ''             "and has no hash"

    # ---- the summary is what the operator is told ----
    $entries = @(
        (New-ManifestEntry -Path $a -LogName 'Security' -SourceSha256 $hashA),
        (New-ManifestEntry -Path $b -LogName 'System'   -SourceSha256 $hashB)
    )
    $sum = Get-ManifestSummary $entries
    Assert-True  $sum.Ok                 "all verified means Ok"
    Assert-Equal $sum.Verified 2         "both files verified"
    Assert-Equal $sum.Mismatched 0       "none mismatched"
    Assert-True  ($sum.Text -match '(?i)verified') "the summary says so in words"

    $mixed = @($entries[0], (New-ManifestEntry -Path $a -LogName 'System' -SourceSha256 $hashB))
    $sumBad = Get-ManifestSummary $mixed
    Assert-True  (-not $sumBad.Ok)       "one mismatch fails the whole set"
    Assert-Equal $sumBad.Mismatched 1    "and is counted"
    Assert-True  ($sumBad.Text -match '(?i)mismatch') "and named in the summary"

    # A set where nothing could be compared is NOT a pass. It is the SMB case,
    # and calling it verified would be a lie told in an evidence log.
    $nc = @((New-ManifestEntry -Path $a -LogName 'Security'))
    $sumNc = Get-ManifestSummary $nc
    Assert-Equal $sumNc.Verified 0       "nothing is verified when nothing was compared"
    Assert-True  $sumNc.Ok               "but it is not a failure either"
    Assert-True  ($sumNc.Text -match '(?i)not compared|hashed') "the summary says what it did do"

    # ---- written to disk beside the evidence, as text a human can read ----
    $file = Write-EvtxManifest -Entries $entries -Folder $tmp -HostName 'WKS01' -Method 'WinRM'
    Assert-True (Test-Path -LiteralPath $file) "the manifest is written into the evidence folder"
    $json = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
    Assert-Equal $json.Host 'WKS01'            "it records which host"
    Assert-Equal $json.Method 'WinRM'          "and how it was collected"
    Assert-Equal @($json.Files).Count 2        "and every file"
    Assert-True  ($json.CollectedUtc -match '^\d{4}-\d{2}-\d{2}T') "with an ISO-8601 UTC timestamp"
    Assert-True  ($json.Files[0].Sha256.Length -eq 64) "the hashes are full SHA-256"
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- and the collector actually uses it, on every path that acquires a file ----
# Three code paths acquire files: SMB copy, WinRM zip-expand, WinRM per-file.
# A manifest that covers two of the three is worse than none, because the gap is
# invisible in the output.
$collector = Get-Content (Join-Path $PSScriptRoot '..\code\EvtxCollector.ps1') -Raw
# Call sites, not mentions: a comment naming the function is not a code path.
$entries = ([regex]::Matches($collector, '\$manifest \+= New-ManifestEntry')).Count
Assert-Equal $entries 3 "all three acquisition paths record a manifest entry (found $entries)"
Assert-True ($collector -match 'Write-EvtxManifest')  "the collector writes the manifest out"
Assert-True ($collector -match 'Get-ManifestSummary') "and reports the verdict"

# The WinRM source hash must come from the STAGING copy, which is static.
# Hashing the live log instead would produce mismatches on good collections.
Assert-True ($collector -match "Get-FileHash -LiteralPath \`$_\.FullName -Algorithm SHA256") `
    "the target-side hash is taken over the staging folder"
Assert-True ($collector -match '(?s)stagingPath.*Get-FileHash') `
    "and it is the staging path that is hashed, not the live log directory"
