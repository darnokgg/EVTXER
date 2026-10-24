# tests/CollectUsername.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# The Domain field on the Collect tab. `.\user` and a bare `user` both fail
# remotely - they name the examiner's machine - so the prefix is chosen for the
# operator: the domain when one is given, the target itself when not.

# ---- domain given: DOMAIN\user on every target ----
Assert-Equal (Resolve-CollectUsername 'admin' 'CORP' 'dc01') 'CORP\admin' "domain prefixes a bare user"
Assert-Equal (Resolve-CollectUsername 'admin' 'CORP' '10.0.0.5') 'CORP\admin' "domain wins over an IP target"
Assert-Equal (Resolve-CollectUsername ' admin ' ' CORP\ ' 'dc01') 'CORP\admin' "whitespace and a trailing backslash are trimmed"

# ---- a DNS domain name becomes a UPN (2026-10-14) ----
# "corp.local\admin" is refused by many targets while "admin@corp.local" - the
# form the operator found by hand - always works for a real AD domain: every
# account has the implicit UPN sAMAccountName@dns-domain. So a dotted Domain
# builds that form, and only a NetBIOS name builds DOMAIN\user.
Assert-Equal (Resolve-CollectUsername 'admin' 'corp.local' 'dc01') 'admin@corp.local' "a dotted domain builds user@domain"
Assert-Equal (Resolve-CollectUsername 'admin' '@corp.local' 'dc01') 'admin@corp.local' "a leading @ in the Domain field is dropped"
Assert-Equal (Resolve-CollectUsername '.\admin' 'corp.local' 'ws01') 'admin@corp.local' ".\user with a dotted domain is a UPN too"
Assert-Equal (Resolve-CollectUsername 'admin' '@CORP' 'dc01') 'CORP\admin' "a NetBIOS name keeps DOMAIN\user even with a stray @"
Assert-Equal (Resolve-CollectUsername 'admin' '10.0.0.5' '10.0.0.5') '10.0.0.5\admin' "an IP in Domain still means that host's local account, not a UPN"

# ---- no domain: the target is the prefix (local account) ----
Assert-Equal (Resolve-CollectUsername 'admin' '' '192.0.2.48') '192.0.2.48\admin' "off-domain IP target prefixes itself"
Assert-Equal (Resolve-CollectUsername 'admin' '' 'ws01') 'ws01\admin' "off-domain hostname target prefixes itself"
Assert-Equal (Resolve-CollectUsername '.\admin' '' 'ws01') 'ws01\admin' ".\user is rewritten - it names the examiner's box"
Assert-Equal (Resolve-CollectUsername '.\admin' 'CORP' 'ws01') 'CORP\admin' ".\user takes the domain when one is given"

# ---- an explicit account is the operator's call ----
Assert-Equal (Resolve-CollectUsername 'OTHER\admin' 'CORP' 'dc01') 'OTHER\admin' "explicit DOMAIN\user is verbatim"
Assert-Equal (Resolve-CollectUsername 'admin@corp.local' '' 'dc01') 'admin@corp.local' "a UPN is verbatim"
Assert-Equal (Resolve-CollectUsername '' 'CORP' 'dc01') '' "no username stays empty"

# ---- the credential keeps its password, only the name changes ----
$cred = New-CollectCredential 'admin' 'S3cret!'
$c1 = Get-TargetCredential $cred '' '10.0.0.5'
$c2 = Get-TargetCredential $cred '' '10.0.0.6'
Assert-Equal $c1.UserName '10.0.0.5\admin' "per-target name for the first target"
Assert-Equal $c2.UserName '10.0.0.6\admin' "per-target name for the second target"
Assert-Equal $c1.GetNetworkCredential().Password 'S3cret!' "the password is carried over unchanged"
Assert-Equal $cred.UserName 'admin' "the source credential is not modified"

# Loading a target file changes the first target, so the account hint has to
# be recomputed then - not on the operator's next keystroke.
$loadHandler = [regex]::Match((Get-Content "$PSScriptRoot\..\code\wpf-collect.ps1" -Raw), '(?s)\$btnLoadTargets\.Add_Click\(\{.*?\n\}\)').Value
Assert-True ($loadHandler -match 'Update-CollectCredHint') "loading a target file refreshes the account hint"

# The hint runs on every keystroke in three boxes. Reading the target file
# there re-read the whole file per character on the UI thread; its first host
# is cached when the file is loaded instead.
$hintFn = [regex]::Match((Get-Content "$PSScriptRoot\..\code\wpf-collect.ps1" -Raw), '(?s)function Update-CollectCredHint \{.*?\n\}').Value
Assert-True ($hintFn.Length -gt 0)                        "Update-CollectCredHint found"
Assert-True ($hintFn -notmatch 'CollectTargetFile\b')     "the hint does not read the target file"
Assert-True ($hintFn -match 'CollectTargetFirst')         "the hint uses the first host cached at load"
Assert-True ($loadHandler -match 'CollectTargetFirst\s*=') "loading a file caches its first host"
