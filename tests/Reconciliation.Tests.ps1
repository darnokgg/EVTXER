# tests/Reconciliation.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# The WinRM zip path already gets integrity for free: zip entries carry a
# CRC32, so Expand-Archive fails on a damaged archive. The per-file fallback
# (PowerShell 4 targets, exports over the ~1.5 GB zip ceiling, or any zip
# failure) has nothing checking what arrived, and neither does SMB.
#
# Hashing would not help on the main path anyway: a live .evtx is being written
# to while it is read, so a source hash never matches by design. Counting files
# and bytes catches the failure that actually happens - a log that did not make
# it, or one that arrived short.

# ---- clean transfer ----
$ok = Get-TransferReconciliation -ExpectedFiles 5 -ActualFiles 5 -ExpectedBytes 178364416 -ActualBytes 178364416
Assert-True  $ok.Ok                       "matching counts and bytes reconcile"
Assert-True  ($ok.Summary -match '5')     "the summary names the file count"
Assert-True  ($ok.Summary -notmatch '(?i)missing|short') "a clean transfer is not described as a problem"

# ---- a log that never arrived ----
$missing = Get-TransferReconciliation -ExpectedFiles 5 -ActualFiles 4 -ExpectedBytes 178364416 -ActualBytes 178364416
Assert-True  (-not $missing.Ok)             "a missing file does not reconcile"
Assert-True  ($missing.Summary -match '(?i)missing|4 of 5') "the summary says a file is missing"

# ---- a truncated file: right count, wrong bytes ----
$short = Get-TransferReconciliation -ExpectedFiles 5 -ActualFiles 5 -ExpectedBytes 178364416 -ActualBytes 120000000
Assert-True  (-not $short.Ok)               "a byte shortfall does not reconcile"
Assert-True  ($short.Summary -match '(?i)short|byte') "the summary names the byte shortfall"

# ---- more bytes than expected is ALSO a mismatch, not a pass ----
# A live log grows between the size probe and the copy, so this is expected on
# the SMB path - but it must be reported, not silently swallowed as "fine".
$over = Get-TransferReconciliation -ExpectedFiles 5 -ActualFiles 5 -ExpectedBytes 100 -ActualBytes 200
Assert-True  (-not $over.Ok) "receiving more bytes than expected is still a mismatch"

# ---- unknown expected size: report, do not fail ----
# The SMB path cannot measure the remote total without a round trip, so it may
# have nothing to compare against. That is not a failed transfer.
$unknown = Get-TransferReconciliation -ExpectedFiles 5 -ActualFiles 5 -ExpectedBytes -1 -ActualBytes 178364416
Assert-True  $unknown.Ok                        "an unmeasurable expected size still reconciles on count"
Assert-True  ($unknown.Summary -match '(?i)not measured|unknown') "the summary admits the byte total was not measured"

# ---- nothing collected at all ----
$nothing = Get-TransferReconciliation -ExpectedFiles 5 -ActualFiles 0 -ExpectedBytes 178364416 -ActualBytes 0
Assert-True  (-not $nothing.Ok) "collecting nothing does not reconcile"

# ---- ASCII only, for WinForms ----
foreach ($r in @($ok, $missing, $short, $unknown, $nothing)) {
    Assert-True ($r.Summary -notmatch '[^\x20-\x7E]') "reconciliation summary is ASCII only"
}
