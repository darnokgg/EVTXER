# tests/ErrorHint.Tests.ps1
. "$PSScriptRoot\..\code\EvtxCollector.ps1"

# Windows names the symptom and never the fix. "The network name cannot be
# found" sounds like a hostname problem and is not one - the share is missing.
# Every message below was seen on a real off-domain target.

# ---- the C$ share is not there (the IP and the login are both fine) ----
$h = Get-CollectErrorHint 'The network name cannot be found.'
Assert-True ($h -match 'C\$')              "a missing share is named as the C`$ admin share"
Assert-True ($h -match '(?i)home')         "Windows Home having no admin shares is called out"
# It may mention the password only to rule it out, never to send the operator
# off checking credentials that are already correct.
Assert-True ($h -match '(?i)not a name or password problem') "it says outright that the credentials are not the cause"
Assert-True ($h -notmatch '(?i)check the account')           "it does not send the operator to the credentials"

# ---- blank password refused for a network logon ----
$r = Get-CollectErrorHint 'Logon failure: user account restriction. Possible reasons are blank passwords not allowed.'
Assert-True ($r -match '(?i)blank password') "an account restriction points at the blank-password policy"

# ---- credentials / remote UAC ----
$d = Get-CollectErrorHint 'Access is denied.'
Assert-True ($d -match 'LocalAccountTokenFilterPolicy') "access denied points at remote UAC filtering"
Assert-True ($d.Contains('HOST\user'))                 "access denied shows the local-account username form"
Assert-True ($d.Contains('user@corp.local'))           "and the UPN form that always works for a domain account"
$p = Get-CollectErrorHint 'The user name or password is incorrect.'
Assert-True ($p -match '(?i)local account')             "a bad password points at the username form too"

# ---- anything unrecognised adds nothing rather than guessing ----
Assert-Equal (Get-CollectErrorHint 'Some entirely novel failure') '' "an unknown message gets no invented hint"
Assert-Equal (Get-CollectErrorHint '') '' "an empty message gets no hint"

# ---- both paths run their failure through it ----
$src = Get-Content "$PSScriptRoot\..\code\EvtxCollector.ps1" -Raw
$collect = [regex]::Match($src, '(?s)function Invoke-EvtxCollection.*?(?=\nfunction )').Value
$verify  = [regex]::Match($src, '(?s)function Test-CollectAccess.*?(?=\nfunction |\z)').Value
Assert-True ($collect -match 'Get-CollectErrorHint') "Collect explains its failures"
Assert-True ($verify  -match 'Get-CollectErrorHint') "Verify Access explains its failures"

# ---- a dropped link says so, and points at RETRY (2026-10-14) ----
$drop = Get-CollectErrorHint "Processing data for a remote command failed with the following error message: The WinRM client cannot process the request. The session state is Broken."
Assert-True ($drop -match 'dropped')  "a broken WinRM session reads as a dropped connection"
Assert-True ($drop -match 'RETRY')    "and points at RETRY"
$smbDrop = Get-CollectErrorHint "The specified network name is no longer available."
Assert-True ($smbDrop -match 'dropped') "an SMB copy whose link went away reads the same"
Assert-True ($smbDrop -notmatch 'C\$ admin share') "and is not mistaken for a missing admin share"
