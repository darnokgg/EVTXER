# tests/ConnectivityPlan.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# Collection used to gate every host on Test-Connection and [SKIPPED] anything
# that did not answer a ping. Two things were wrong with that:
#
#   1. ICMP is not a precondition for SMB or WinRM. Inbound echo is blocked by
#      default on the Windows Firewall's Public profile and is routinely
#      dropped in hardened environments, so hosts that collect perfectly were
#      skipped without ever being tried.
#   2. Test-CollectAccess never pings. A host could pass Verify Access clean
#      and then be silently skipped by the collection it just verified - the
#      single worst thing a pre-flight check can do.
#
# So a ping is now advisory: it flavours the log line, it never decides. The
# authoritative answer is the protocol attempt itself, which fails with a real
# error message instead of an unexplained skip. These assertions exist to stop
# the hard skip being re-added.

foreach ($m in @('SMB','WinRM','WinRM-HTTPS')) {
    $ok = Get-ConnectivityPlan -PingSucceeded $true -Method $m
    Assert-True $ok.Proceed          "$m proceeds when the host answers a ping"
    Assert-Equal $ok.Note ''         "$m says nothing extra when the ping succeeds"

    $noPing = Get-ConnectivityPlan -PingSucceeded $false -Method $m
    Assert-True $noPing.Proceed              "$m proceeds even when the ping fails - ICMP is advisory, never a gate"
    Assert-True ($noPing.Note.Length -gt 0)  "$m explains that it is continuing past a failed ping"
    Assert-True ($noPing.Note -match $m)     "$m names the protocol it is about to try anyway"
}

# The note is a note, not a verdict: nothing in it may read as a skip, or the
# operator will believe the host was dropped when it was actually attempted.
$n = (Get-ConnectivityPlan -PingSucceeded $false -Method 'SMB').Note
Assert-True ($n -notmatch 'SKIP') "the failed-ping note never claims the host was skipped"

# An unknown method is refused rather than quietly treated as SMB - the same
# rule Test-CollectReadiness enforces.
Assert-Throws { Get-ConnectivityPlan -PingSucceeded $true -Method 'Telepathy' } "an unknown method is rejected"
