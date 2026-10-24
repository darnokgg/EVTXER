# tests/RetryTargets.Tests.ps1
#
# A batch that comes back "5 of 6" leaves the operator to work out which one
# failed from the log and retype it. The summary already knows, so it says so in
# a form the Collect tab can act on rather than only in prose a human must parse.
#
# Runs offline: .invalid never resolves (RFC 2606), so the mount fails locally
# rather than by waiting on a network.
. "$PSScriptRoot\..\code\EvtxCollector.ps1"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("retry-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$quiet = { param($m) }

try {
    $res = Invoke-EvtxCollection -Targets @('no-such-host-a1.invalid','no-such-host-b2.invalid') `
               -Method 'SMB' -Category 'DFIR' -CustomLogs @() -Credential $null `
               -OutRoot $tmp -LogWriter $quiet

    Assert-True ($null -ne $res.PSObject.Properties['Retry']) "the summary carries a Retry list"
    Assert-Equal @($res.Retry).Count 2 "both failed hosts are offered for retry"
    Assert-True (@($res.Retry) -contains 'no-such-host-a1.invalid') "the first failed host is named"
    Assert-True (@($res.Retry) -contains 'no-such-host-b2.invalid') "the second failed host is named"

    # The point of the list: it is the exact input for another collection, so it
    # holds hostnames and nothing else. A message like "host: only 5 of 6" in
    # here would be re-collected as a target called "host: only 5 of 6".
    foreach ($t in @($res.Retry)) {
        Assert-True ($t -notmatch '[:,]') "a retry entry is a bare hostname, not a sentence ('$t')"
    }

    # Nothing to retry after a clean run, so the button has an honest off state.
    $none = Invoke-EvtxCollection -Targets @() -Method 'SMB' -Category 'DFIR' -CustomLogs @() `
                -Credential $null -OutRoot $tmp -LogWriter $quiet
    Assert-Equal @($none.Retry).Count 0 "an empty run offers nothing to retry"

    # Every host that did not fully succeed is retryable - partial included.
    # A partial host is the one most worth retrying: some logs came back, and
    # the missing ones are usually a permissions or lock problem that a second
    # attempt with different credentials fixes.
    Assert-Equal @($res.Retry).Count ($res.Failed + $res.Partial + $res.Skipped) `
        "the retry list is exactly the hosts that did not fully succeed"
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
