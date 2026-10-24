# tests/CollectionAccounting.Tests.ps1
. "$PSScriptRoot\..\code\EvtxCollector.ps1"

# The summary the GUI colours its status label from. It used to carry only
# Attempted/Succeeded/Skipped, and the per-host catch incremented NONE of them,
# so a host that threw mid-collection simply vanished from the arithmetic:
# Attempted never equalled Succeeded + Skipped and nothing said why. The label
# went green either way.
#
# Runs offline. The unreachable target below is a .invalid name, which RFC 2606
# guarantees will never resolve, so the mount fails locally rather than by
# waiting on a real network.

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("collect-acct-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$quiet = { param($m) }

try {
    # ---- the summary exposes every outcome, not just the happy one ----
    $none = Invoke-EvtxCollection -Targets @() -Method 'SMB' -Category 'DFIR' `
                                  -CustomLogs @() -Credential $null -OutRoot $tmp -LogWriter $quiet
    foreach ($p in 'Attempted','Succeeded','Partial','Failed','Skipped','Files','OutFolders','Problems') {
        Assert-True ($null -ne $none.PSObject.Properties[$p]) "the summary carries $p"
    }
    Assert-Equal $none.Attempted 0 "no targets means nothing attempted"

    # ---- a host that throws is counted, and counted as Failed ----
    # This is the regression. The mount raises a terminating error, the per-host
    # catch swallows it, and the host has to land in Failed rather than nowhere.
    $dead = Invoke-EvtxCollection -Targets @('no-such-host-9e1f.invalid') -Method 'SMB' -Category 'DFIR' `
                                  -CustomLogs @() -Credential $null -OutRoot $tmp -LogWriter $quiet
    Assert-Equal $dead.Attempted 1 "an unreachable host is still attempted"
    Assert-Equal $dead.Failed    1 "a host that threw is counted as Failed"
    Assert-Equal $dead.Succeeded 0 "a host that threw is not counted as succeeded"
    Assert-Equal $dead.Files.Count 0 "a host that threw contributes no files"
    # The summary names the cause, not just the count, so the operator does not
    # have to dig through the log pane to learn why a host failed.
    Assert-True (@($dead.Problems | Where-Object { $_ -like '*error*' }).Count -ge 1) "a failed host's error text is in Problems"

    # The invariant the old counters could not hold. Every attempted host ends
    # in exactly one bucket, so an operator reading the summary can tell that
    # hosts went missing.
    Assert-Equal ($dead.Succeeded + $dead.Partial + $dead.Failed + $dead.Skipped) $dead.Attempted `
        "Attempted equals Succeeded + Partial + Failed + Skipped"

    # A failure the operator can read, not just a number that does not add up.
    Assert-True ($dead.Problems.Count -ge 1) "a failed host explains itself in Problems"

    # ---- a ping that fails must not skip the host ----
    # .invalid never answers ICMP, so if the old gate were still there this
    # host would have been Skipped and never attempted at all.
    Assert-Equal $dead.Skipped 0 "an unpingable host is attempted, not skipped"

    # ---- files recorded are files that exist ----
    # $files used to be appended before the copy was verified, so it could name
    # paths that were never written. Whatever comes back must be real.
    foreach ($f in $none.Files) { Assert-True (Test-Path -LiteralPath $f) "every reported file exists: $f" }
    foreach ($f in $dead.Files) { Assert-True (Test-Path -LiteralPath $f) "every reported file exists: $f" }
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
