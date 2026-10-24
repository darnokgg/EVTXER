# tests/TargetAuthNote.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# Kerberos needs an SPN (cifs/HOST.domain.local), and an SPN needs a NAME.
# Connect by IP and Windows falls back to NTLM: the password still never
# crosses the wire in cleartext, but the target's identity is never verified.
# That is what this note has to say - and what it must NOT say is that the
# password is exposed, which would be false. Same bar as MethodCaption.Tests.

# ---- hostnames: nothing to warn about ----
$names = Get-TargetAuthNote @('dc01', 'fs02.corp.local')
Assert-Equal $names '' "all-hostname targets produce no note"

$none = Get-TargetAuthNote @()
Assert-Equal $none '' "an empty target list produces no note"

# ---- IPv4 literals: warn ----
$ip = Get-TargetAuthNote @('192.0.2.48')
Assert-True ($ip.Length -gt 0)          "an IPv4 target produces a note"
Assert-True ($ip -match '(?i)ntlm')     "the note names NTLM as the fallback"
Assert-True ($ip -match '(?i)kerberos') "the note names Kerberos as what is lost"

# ---- the note must not teach the wrong threat model ----
# Both methods authenticate by challenge-response. Claiming the password is
# exposed because of an IP address would be wrong.
Assert-True ($ip -notmatch '(?i)password') "the note does NOT claim the password is exposed"
Assert-True ($ip -notmatch '(?i)cleartext|clear text|plaintext') "the note does NOT claim cleartext credentials"

# ---- it counts, so the operator knows how much of the list is affected ----
$mixed = Get-TargetAuthNote @('dc01', '10.0.0.5', '10.0.0.6')
Assert-True ($mixed -match '2')  "a mixed list reports how many targets are IPs"

# ---- IPv6 counts too ----
$v6 = Get-TargetAuthNote @('fe80::1')
Assert-True ($v6.Length -gt 0)   "an IPv6 literal also produces a note"

# ---- a hostname that merely contains digits is not an IP ----
$digity = Get-TargetAuthNote @('srv2019', '10-0-0-5.corp.local')
Assert-Equal $digity '' "hostnames containing digits are not mistaken for IPs"

# ---- PS 5.1 renders non-ASCII unreliably in WinForms ----
Assert-True ($ip -notmatch '[^\x20-\x7E]') "the note is ASCII only"
