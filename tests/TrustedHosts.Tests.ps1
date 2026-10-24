# tests/TrustedHosts.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# A workgroup target has no Kerberos, so WinRM refuses it until the target is in
# the client's TrustedHosts. Collect added it; Verify Access did not, so Verify
# failed on exactly the hosts that needed checking most.

# ---- merging ----
Assert-Equal (Merge-TrustedHosts '' @('192.0.2.234')) '192.0.2.234' "an empty list gains the target"
Assert-Equal (Merge-TrustedHosts $null @('wks01')) 'wks01' "a null list gains the target"
Assert-Equal (Merge-TrustedHosts 'dc01' @('wks01', 'wks02')) 'dc01,wks01,wks02' "existing entries are kept, in order"
Assert-Equal (Merge-TrustedHosts 'dc01,WKS01' @('wks01')) 'dc01,WKS01' "an entry already present (any case) is not added twice"
Assert-Equal (Merge-TrustedHosts 'a' @('', '  ', 'b ')) 'a,b' "blank targets are ignored and names are trimmed"
Assert-Equal (Merge-TrustedHosts '*' @('wks01')) '*' "a wildcard list already trusts everything and is left alone"

# The old check was `-notmatch [regex]::Escape($t)`, a SUBSTRING test: an
# existing 192.0.2.234 made 192.0.2.23 look trusted, so it was never added
# and WinRM refused it with the TrustedHosts error.
Assert-Equal (Merge-TrustedHosts '192.0.2.234' @('192.0.2.23')) '192.0.2.234,192.0.2.23' `
    "a target that is only a substring of an existing entry is still added"

# ---- both buttons go through the same helpers ----
$src = Get-Content "$PSScriptRoot\..\code\EvtxCollector.ps1" -Raw
$collect = [regex]::Match($src, '(?s)function Invoke-EvtxCollection.*?(?=\nfunction )').Value
$verify  = [regex]::Match($src, '(?s)function Test-CollectAccess.*').Value
foreach ($pair in @(@('Collect', $collect), @('Verify Access', $verify))) {
    Assert-True ($pair[1] -match 'Add-CollectTrustedHosts')     "$($pair[0]) adds the targets to TrustedHosts"
    Assert-True ($pair[1] -match 'Restore-CollectTrustedHosts') "$($pair[0]) restores TrustedHosts afterwards"
}
foreach ($pair in @(@('Collect', $collect), @('Verify Access', $verify))) {
    Assert-True ($pair[1] -notmatch 'WSMan:') "$($pair[0]) never edits TrustedHosts directly, only via the helpers"
}

# ---- the revert has to be REPORTED, not assumed ----
# Writing TrustedHosts needs admin, and the WSMan provider throws a TERMINATING
# error that -ErrorAction SilentlyContinue does not swallow. An unelevated
# collection therefore printed a red stack trace and then cheerfully announced
# "TrustedHosts reverted." on the next line. The restore now reports Ok /
# Changed / Reason and the caller branches on it.
$restore = [regex]::Match($src, '(?s)function Restore-CollectTrustedHosts.*?(?=\nfunction )').Value
Assert-True ($restore -match 'Ok\s*=')      "the restore reports whether it succeeded"
Assert-True ($restore -match 'Changed\s*=') "the restore reports whether it had to change anything"
Assert-True ($restore -match 'Reason\s*=')  "the restore explains a failure"
Assert-True ($restore -match '\$current -eq \$want') "the restore skips the write when the value is already correct"
# Comments stripped: the function's own comment EXPLAINS the SilentlyContinue
# trap, and a naive match on the whole body finds that explanation.
$restoreCode = ($restore -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
Assert-True ($restoreCode -notmatch 'SilentlyContinue') "the restore does not rely on SilentlyContinue, which the WSMan provider ignores"
Assert-True ($collect -match '(?s)\$rev\s*=\s*Restore-CollectTrustedHosts.*?-not \$rev\.Ok') `
    "Collect only claims the revert happened when it actually did"
