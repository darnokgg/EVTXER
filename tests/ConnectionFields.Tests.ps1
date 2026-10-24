# tests/ConnectionFields.Tests.ps1
#
# A password of spaces passed `-not $secret`, went out as Basic auth, and came
# back 401 - which the tool reports as "username or password is wrong" about a
# password the operator never typed. Whitespace-only is missing. A real
# password is never trimmed: leading and trailing spaces can be part of it.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

Assert-Equal ((Get-MissingConnectionFields 'so' 'analyst' 'pw') -join ',')   ''          "all present: nothing missing"
Assert-Equal ((Get-MissingConnectionFields 'so' 'analyst' '   ') -join ',')  'password'  "a whitespace-only password is missing"
Assert-Equal ((Get-MissingConnectionFields 'so' 'analyst' '') -join ',')     'password'  "an empty password is missing"
Assert-Equal ((Get-MissingConnectionFields 'so' 'analyst' $null) -join ',')  'password'  "a null password is missing"
Assert-Equal ((Get-MissingConnectionFields 'so' 'analyst' ' pw ') -join ',') ''          "a password with spaces around it is kept"
Assert-Equal ((Get-MissingConnectionFields 'so' '  ' 'pw') -join ',')        'username'  "a whitespace-only username is missing"
Assert-Equal ((Get-MissingConnectionFields '' '' '') -join ',')              'host / IP,username,password' "every missing field is named, in form order"

# Both places that send these credentials ask it, rather than each keeping
# its own weaker test.
$kibana = Get-Content "$PSScriptRoot\..\code\wpf-kibana.ps1" -Raw
$upload = Get-Content "$PSScriptRoot\..\code\wpf-upload.ps1" -Raw
Assert-True ($kibana -match 'Get-MissingConnectionFields') "the Kibana tab uses it"
Assert-True ($kibana -notmatch 'if \(-not \$secret\)')     "the Kibana tab dropped its own -not test"
Assert-True ($upload -match 'Get-MissingConnectionFields') "the Upload tab uses it"

# The Kibana note reads the same missing list instead of a second copy of the
# rule.
Assert-True ($kibana -match "'password' -notin \`$c\.Missing") "the Kibana note uses the computed missing list"
Assert-True ($kibana -notmatch 'IsNullOrWhiteSpace\(\$c\.Secret\)') "the Kibana note has no second copy of the rule"

# ---- what was verified is what gets uploaded ----
# UPLOAD trusted a Verify from any earlier state of the form: verify with the
# right password, blank it, press UPLOAD, and the blank went out. A fingerprint
# of what was verified is compared at upload time. It is a hash, so the
# password is not kept in a second plaintext copy.
$fp = Get-ConnectionFingerprint 'https://so:9200' 'analyst' 'pw'
Assert-Equal (Get-ConnectionFingerprint 'https://so:9200' 'analyst' 'pw') $fp "same connection, same fingerprint"
Assert-True ($fp -ne (Get-ConnectionFingerprint 'https://so:9200' 'analyst' 'pw2'))  "a changed password changes it"
Assert-True ($fp -ne (Get-ConnectionFingerprint 'https://so:9200' 'root' 'pw'))      "a changed user changes it"
Assert-True ($fp -ne (Get-ConnectionFingerprint 'https://so2:9200' 'analyst' 'pw'))  "a changed host changes it"
Assert-True ($fp -ne (Get-ConnectionFingerprint 'https://so:9200' 'analyst' ''))     "a blanked password changes it"
Assert-True ((Get-ConnectionFingerprint 'b' 'u' 'hunter2hunter2') -notmatch 'hunter2') "the password is not in it"
Assert-True ($upload -match '\$script:ConnKey\s*=\s*Get-UploadConnKey')              "VERIFY records what it verified"
Assert-True ($upload -match '\$script:ConnKey\s*-ne\s*\(Get-UploadConnKey\)')        "UPLOAD refuses a connection that changed since"
# Security review (v48): Skip or another pin after VERIFY is a different
# connection too, or the unattended queue would upload under the old trust.
Assert-True ($upload -match '(?s)function Get-UploadConnKey \{.*?rbTlsSkip.*?txtPin') "and so is a change of certificate trust"
$queue = Get-Content "$PSScriptRoot\..\code\wpf-queue.ps1" -Raw
Assert-True ($queue -match "(?s)if \(\`$step -eq 'upload'\) \{.*?Set-TlsTrustFromUi") "a queued upload puts back the Upload tab's trust before it starts"
