# tests/MethodCaption.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$smb   = Get-MethodCaption 'SMB'
$winrm = Get-MethodCaption 'WinRM'

# ---- SMB carries a caution; WinRM does not ----
Assert-True ($smb.Caution.Length -gt 0)   "SMB has a caution"
Assert-True ($winrm.Caution.Length -eq 0) "WinRM has no caution"

# ---- the caution must be about the DATA, not the password ----
# SMB and WinRM both authenticate by challenge-response; neither puts the
# password on the wire in cleartext. Saying otherwise would be wrong and would
# teach the operator the wrong threat model.
Assert-True ($smb.Caution -match 'does not encrypt')      "SMB caution says it does not encrypt"
Assert-True ($smb.Caution -match 'data')                  "SMB caution names the log data as what is exposed"
Assert-True ($smb.Caution -notmatch '(?i)password')       "SMB caution does NOT claim the password is exposed"
Assert-True ($smb.Caution -match '(?i)caution')           "SMB caution is labelled as a caution"

# ---- the counterpart claim belongs on WinRM ----
Assert-True ($winrm.Caption -match '(?i)encrypts')        "WinRM caption states that it encrypts in transit"

# ---- PS 5.1 renders non-ASCII unreliably in WinForms ----
foreach ($m in 'SMB', 'WinRM', 'WinRM-HTTPS') {
    $c = Get-MethodCaption $m
    Assert-True ($c.Caption.Length -gt 0) "$m has a caption"
    Assert-True ($c.Caption -notmatch '[^\x20-\x7E]') "$m caption is ASCII only"
    Assert-True ($c.Caution -notmatch '[^\x20-\x7E]') "$m caution is ASCII only"
}

Assert-Throws { Get-MethodCaption 'Telepathy' } "an unknown collection method is rejected"
