# tests/HostOutcome.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# $succeeded++ used to run at the bottom of the per-host try block, so it fired
# whenever no exception escaped. A host where every requested log came back
# "Not Found / Access Denied", and a host where WinRM exported nothing at all,
# both counted as successes. Worse, the catch incremented NOTHING, so
# Attempted never equalled Succeeded + Skipped and the shortfall was invisible.
# The GUI then painted the line green regardless.
#
# Three outcomes, because two cannot tell the truth here: a run that got some
# of what was asked for is neither a success nor a failure, and an examiner
# has to know which one they are looking at before they start analysing.

# ---- Exact: DFIR and Custom name specific logs, so all of them must arrive ----
Assert-Equal (Get-HostOutcome -Requested 5 -Collected 5 -Errored $false -Mode 'Exact') 'Success' "every requested log arrived"
Assert-Equal (Get-HostOutcome -Requested 5 -Collected 3 -Errored $false -Mode 'Exact') 'Partial' "three of five requested logs is partial, not success"
Assert-Equal (Get-HostOutcome -Requested 5 -Collected 0 -Errored $false -Mode 'Exact') 'Failed'  "nothing collected is a failure even with no exception"

# ---- BestEffort: ALL enumerates every channel on the box ----
# Most of those channels are empty or disabled and never export. Demanding all
# of them would mark every ALL collection partial, which trains the operator
# to ignore the word.
Assert-Equal (Get-HostOutcome -Requested 400 -Collected 220 -Errored $false -Mode 'BestEffort') 'Success' "ALL is content with the channels that actually had data"
Assert-Equal (Get-HostOutcome -Requested 400 -Collected 0   -Errored $false -Mode 'BestEffort') 'Failed'  "ALL that produced no file at all is still a failure"
Assert-Equal (Get-HostOutcome -Requested 0   -Collected 0   -Errored $false -Mode 'BestEffort') 'Failed'  "a host that enumerated no channels is a failure, not a vacuous success"

# ---- an exception beats any file count ----
# A host that threw mid-transfer has an unknown amount of an unknown thing on
# disk. Files already collected do not redeem it.
Assert-Equal (Get-HostOutcome -Requested 5 -Collected 5 -Errored $true -Mode 'Exact')      'Failed' "an exception makes the host failed however many files landed"
Assert-Equal (Get-HostOutcome -Requested 5 -Collected 2 -Errored $true -Mode 'BestEffort') 'Failed' "an exception outranks BestEffort too"

# ---- collecting more than was asked for is not an error ----
# The ALL branch counts requested channels but a channel can export more than
# one file; over-delivery must not read as a shortfall.
Assert-Equal (Get-HostOutcome -Requested 3 -Collected 4 -Errored $false -Mode 'Exact') 'Success' "more files than requested is still success"

Assert-Throws { Get-HostOutcome -Requested 1 -Collected 1 -Errored $false -Mode 'Vibes' } "an unknown mode is rejected"

# ---- a set that arrived but does not verify is not a success (2026-10-14) ----
# A SHA-256 MISMATCH, or fewer files/bytes than the target sent, used to be
# logged and then ignored: the host still read Success, went nowhere near the
# retry list, and its files went on to be analysed as evidence.
Assert-Equal (Get-HostOutcome -Requested 5 -Collected 5 -Errored $false -Mode 'Exact' -IntegrityFailed $true) 'Partial' "a hash mismatch turns a full set into partial"
Assert-Equal (Get-HostOutcome -Requested 400 -Collected 220 -Errored $false -Mode 'BestEffort' -IntegrityFailed $true) 'Partial' "and ALL, which forgives missing channels, does not forgive a bad transfer"
Assert-Equal (Get-HostOutcome -Requested 5 -Collected 0 -Errored $false -Mode 'Exact' -IntegrityFailed $true) 'Failed' "nothing collected stays failed"
