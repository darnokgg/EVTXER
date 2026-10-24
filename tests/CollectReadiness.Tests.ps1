# tests/CollectReadiness.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# The Collect tab used to accept a click with no method chosen, because
# `if ($rbWinRM.Checked) { 'WinRM' } else { 'SMB' }` treats "nothing selected"
# as SMB. Neither radio is checked at startup now, so the readiness check is
# the only thing standing between an unchosen method and a silent SMB run.

# ---- everything present ----
$ok = Test-CollectReadiness -Targets @('dc01') -Method 'SMB' -Username 'CORP\a' -Category 'DFIR' -CustomLogs @()
Assert-True  $ok.Ready               "a fully filled form is ready"
Assert-Equal $ok.Missing.Count 0     "nothing is reported missing"

# ---- each field missing on its own ----
$noTarget = Test-CollectReadiness -Targets @() -Method 'SMB' -Username 'CORP\a' -Category 'DFIR' -CustomLogs @()
Assert-True  (-not $noTarget.Ready)              "no targets is not ready"
Assert-True  ($noTarget.Missing -contains 'Targets') "missing targets is named"

$noMethod = Test-CollectReadiness -Targets @('dc01') -Method '' -Username 'CORP\a' -Category 'DFIR' -CustomLogs @()
Assert-True  (-not $noMethod.Ready)              "no collection method is not ready"
Assert-True  ($noMethod.Missing -contains 'Method') "missing method is named"

$noUser = Test-CollectReadiness -Targets @('dc01') -Method 'SMB' -Username '' -Category 'DFIR' -CustomLogs @()
Assert-True  ($noUser.Missing -contains 'Username') "missing username is named"

# ---- a blank password is NOT a gap ----
# A standalone workstation account with no password set is a real target. The
# form used to refuse it, so the only account that could log in was unusable.
# Every call in this file now omits the password, so $ok above already proves
# a passwordless form is ready; this pins the name.
Assert-True  ($ok.Missing -notcontains 'Password') "Password is never reported missing"

# ---- Custom category needs at least one log ticked ----
$noLogs = Test-CollectReadiness -Targets @('dc01') -Method 'SMB' -Username 'CORP\a' -Category 'Custom' -CustomLogs @()
Assert-True  ($noLogs.Missing -contains 'CustomLogs') "Custom with nothing ticked names CustomLogs"

$withLogs = Test-CollectReadiness -Targets @('dc01') -Method 'SMB' -Username 'CORP\a' -Category 'Custom' -CustomLogs @('Security')
Assert-True  $withLogs.Ready         "Custom with a log ticked is ready"

# DFIR and All must NOT demand the custom list.
$dfirNoLogs = Test-CollectReadiness -Targets @('dc01') -Method 'SMB' -Username 'CORP\a' -Category 'DFIR' -CustomLogs @()
Assert-True  ($dfirNoLogs.Missing -notcontains 'CustomLogs') "DFIR does not demand the custom list"

# ---- everything missing at once ----
# The whole point of the change: report every gap in one pass so the operator
# fixes them together, instead of being told about them one click at a time.
$empty = Test-CollectReadiness -Targets @() -Method '' -Username '' -Category 'Custom' -CustomLogs @()
Assert-True  (-not $empty.Ready)     "an empty form is not ready"
Assert-Equal $empty.Missing.Count 4  "an empty form reports all four gaps at once"

# ---- whitespace is not a value ----
$blank = Test-CollectReadiness -Targets @('dc01') -Method 'SMB' -Username '   ' -Category 'DFIR' -CustomLogs @()
Assert-True  ($blank.Missing -contains 'Username') "a whitespace-only username counts as missing"

# ---- an unknown method is refused, not silently treated as SMB ----
Assert-Throws { Test-CollectReadiness -Targets @('dc01') -Method 'Telepathy' -Username 'a' -Category 'DFIR' -CustomLogs @() } `
    "an unknown collection method is rejected"

# ---- and both buttons must actually go through it, via one shared helper ----
# Verify Access and Collect each opened with their own copy of the same
# read-check-paint-bail block. Two copies is how one button ends up enforcing
# something the other one does not, so the block lives in exactly one place.
# Comment lines are excluded on purpose: the tool explains the check in prose
# in two places, and prose is not a second code path.
$toolLines = Get-ToolSourceLines | Where-Object { $_ -notmatch '^\s*#' }
$direct = @($toolLines | Where-Object { $_ -match 'Test-CollectReadiness' }).Count
Assert-Equal $direct 1 "the tool calls Test-CollectReadiness once, inside the shared helper (found $direct)"
$uses = @($toolLines | Where-Object { $_ -match 'Get-ReadyCollectFormState' }).Count
Assert-Equal $uses 3 "the helper is defined once and called by both click handlers (found $uses)"

# ---- the credential must accept a blank password ----
# `'' | ConvertTo-SecureString -AsPlainText -Force` throws "Cannot bind
# argument ... because it is an empty string", so letting a blank password past
# the readiness check alone only moved the failure to the click.
$blankCred = New-CollectCredential 'WKS01\analyst' ''
Assert-Equal $blankCred.UserName 'WKS01\analyst'                  "blank password: username kept"
Assert-Equal $blankCred.GetNetworkCredential().Password ''       "blank password: credential has an empty password"
$realCred = New-CollectCredential 'CORP\a' 'hunter2'
Assert-Equal $realCred.GetNetworkCredential().Password 'hunter2' "a real password round-trips"

# Both buttons build the credential through the helper, never inline, so the
# empty-string trap cannot come back in one of them.
$inline = @($toolLines | Where-Object { $_ -match 'ConvertTo-SecureString' }).Count
Assert-Equal $inline 0 "the tool never calls ConvertTo-SecureString directly (found $inline)"
$credUses = @($toolLines | Where-Object { $_ -match 'New-CollectCredential' }).Count
Assert-Equal $credUses 2 "both click handlers build the credential via New-CollectCredential (found $credUses)"
