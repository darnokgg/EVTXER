# tests/PasswordToggle.Tests.ps1
# A masked password box with no way to look at it means a typo is only found
# when the logon fails, so every password field gets a "Show" toggle.
#
# WPF changed the mechanics: a PasswordBox cannot unmask itself the way a
# WinForms TextBox could (there is no UseSystemPasswordChar to clear, and the
# value is deliberately not a bindable property). The toggle therefore swaps in
# a parallel plain TextBox, which introduces a NEW way to get this wrong - two
# controls holding the same secret, and callers reading the wrong one. These
# assertions pin the shape that avoids it.
$src = Get-ToolSource

# ---- every password field is a PasswordBox, not a TextBox ----
$pwBoxes = ([regex]::Matches($src, '<PasswordBox x:Name="(\w+)"')).Count
Assert-True ($pwBoxes -ge 2) "both password fields are PasswordBox controls (found $pwBoxes)"

# ---- each one has a Show toggle and a plain twin ----
$plains  = ([regex]::Matches($src, 'x:Name="\w*PassPlain"')).Count
$toggles = ([regex]::Matches($src, 'x:Name="chkShow\w*"')).Count
Assert-Equal $plains  $pwBoxes "every PasswordBox has a plain twin to reveal into ($plains of $pwBoxes)"
Assert-Equal $toggles $pwBoxes "every PasswordBox has a Show toggle ($toggles of $pwBoxes)"

# ---- the twin starts hidden ----
Assert-True ($src -match 'x:Name="\w*PassPlain"[^>]*Visibility="Collapsed"') `
    "the revealed copy starts hidden, so the password is masked until asked for"

# ---- nobody reads the boxes directly ----
# Whichever control is visible holds the truth; a caller that reads one of them
# by hand gets an empty string in exactly the state the other is showing.
foreach ($getter in 'Get-CollectPassword', 'Get-UploadPassword', 'Get-SoPassword') {
    Assert-True ($src -match [regex]::Escape($getter)) "$getter exists to hide which box is live"
}
# Two READS per field are legitimate and no more: the getter itself, and the
# reveal swap. A third means a handler went around the getter and will read an
# empty string in whichever state it is not in. Writes are not counted: since
# v45 a remembered password is filled into both boxes, and cleared from both.
$direct = ([regex]::Matches($src, '\$txt(Cred)?Pass\.Password(?!\s*=[^=])')).Count
Assert-True ($direct -le 4) "reads go through the getters, not the controls (direct reads: $direct)"

# ---- and the plaintext still never reaches the log or the settings file ----
Assert-True ($src -notmatch 'Write-Log.*\$pass\b')   "the password is never written to the log"
Assert-True ($src -notmatch "password.*=.*\`$txtPass\.Password.*ConvertTo-Json") "the password never goes into a settings file (the only store is the opt-in DPAPI one, v45)"
