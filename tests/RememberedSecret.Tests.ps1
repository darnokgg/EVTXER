# tests/RememberedSecret.Tests.ps1
#
# Passwords are not saved "unless you can create a safe
# storage for it". Opt-in, per connection, DPAPI for the current Windows user,
# kept in the user's profile - never in the tool folder.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$dir = Join-Path ([IO.Path]::GetTempPath()) ("secrets-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
try {
    $pw = 'S3cret-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + "!'`"ü"
    Assert-Equal (Get-RememberedSecret 'es' 'so.lab' 'analyst' $dir) $null "nothing is remembered until asked"

    Save-RememberedSecret 'es' 'so.lab' 'analyst' $pw $dir
    Assert-Equal (Get-RememberedSecret 'es' 'so.lab' 'analyst' $dir) $pw "a remembered password comes back exactly, odd characters and all"
    Assert-Equal (Get-RememberedSecret 'es' 'SO.LAB ' 'analyst' $dir) $pw "the host is matched however it is typed"

    Assert-Equal (Get-RememberedSecret 'es' 'so.lab' 'someone-else' $dir) $null "another user on the same server gets nothing"
    Assert-Equal (Get-RememberedSecret 'es' 'other.lab' 'analyst' $dir) $null "the same user on another server gets nothing"
    Assert-Equal (Get-RememberedSecret 'ssh' 'so.lab' 'analyst' $dir) $null "the SSH password and the Elasticsearch one are kept apart"

    $files = @(Get-ChildItem -LiteralPath $dir -File)
    Assert-Equal $files.Count 1 "one file per connection"
    $raw = [IO.File]::ReadAllText($files[0].FullName)
    Assert-True ($raw -notmatch [regex]::Escape($pw) -and $raw -notmatch 'so\.lab|analyst') "the file holds neither the password nor which server or account it is for"
    $bytes = [Convert]::FromBase64String($raw)
    Assert-True ([Text.Encoding]::UTF8.GetString($bytes) -notmatch 'S3cret') "and decoding it gives no plaintext either - it is DPAPI ciphertext"

    # Damaged or not ours (another account's, another machine's): DPAPI
    # refuses, and that must read as "not remembered", never an error.
    [IO.File]::WriteAllText($files[0].FullName, [Convert]::ToBase64String([byte[]](1..64)))
    Assert-Equal (Get-RememberedSecret 'es' 'so.lab' 'analyst' $dir) $null "a file DPAPI cannot open is treated as nothing remembered"

    Save-RememberedSecret 'es' 'so.lab' 'analyst' $pw $dir
    Remove-RememberedSecret 'es' 'so.lab' 'analyst' $dir
    Assert-Equal (Get-RememberedSecret 'es' 'so.lab' 'analyst' $dir) $null "Forget removes it"
} finally {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- where it lives ----
Assert-True ($script:SecretFolder -like "$env:LOCALAPPDATA*") "the store is in the user's own profile"
$root = Split-Path -Parent $PSScriptRoot
Assert-True (-not $script:SecretFolder.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) "never in the tool folder - copies and handoff packages cannot carry it"

# ---- the tabs: the review's two findings, and the cut-off Remember box ----
$up = Get-Content (Join-Path $PSScriptRoot '..\code\wpf-upload.ps1') -Raw
$set = Get-Content (Join-Path $PSScriptRoot '..\code\wpf-settings.ps1') -Raw
# A password filled in for one host/user is cleared when either changes, so it
# is never sent to another server (code review, 2026-10-16).
Assert-True ($up -match '\$script:UpFilledFor -and \$script:UpFilledFor -ne \$key\) \{\s+\$txtPass\.Password = ''''') "Upload: a filled-in password does not follow a changed host or user"
Assert-True ($set -match '-not \$script:ConnOk -or \$script:ConnKey -ne \(Get-UploadConnKey\)') "the mission delete needs the connection still to be the one verified"
# Found in use: "the REMEMBER button for passwords is cut off" - beside the password
# it ran off the tab. Measured in the real window after the move: inside.
foreach ($pair in @(, @($up, 'chkRememberPass', 'chkShowPass'))) {
    $src = $pair[0]
    Assert-True ($src.IndexOf("x:Name=`"$($pair[1])`"") -gt $src.IndexOf("x:Name=`"$($pair[2])`"") -and
                 $src.Substring($src.IndexOf("x:Name=`"$($pair[2])`""), $src.IndexOf("x:Name=`"$($pair[1])`"") - $src.IndexOf("x:Name=`"$($pair[2])`"")) -match 'A line of its own') "$($pair[1]) has a line of its own, under the password"
}

# ---- v81: what the removed Raw Events tab left behind goes ----
# Its settings file, and the SSH password it remembered - a stored password
# for a feature that no longer exists is only a liability.
$app = Join-Path $env:TEMP ("evtxer-retired-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
$sec = Join-Path $app 'secrets'
New-Item -ItemType Directory -Path $app -Force | Out-Null
try {
    Assert-Equal @(Remove-RetiredRawImportState $app $sec).Count 0 "nothing left behind, nothing to say"
    @{ host = 'so.lab'; port = '22'; user = 'analyst'; hostkey = 'SHA256:x' } | ConvertTo-Json | Set-Content (Join-Path $app 'soimport.conf')
    Save-RememberedSecret 'ssh' 'so.lab' 'analyst' 'S3cr3t-ssh' $sec
    # One for an earlier manager the .conf no longer names (review, v81).
    Save-RememberedSecret 'ssh' 'old-so.lab' 'admin' 'S3cr3t-old' $sec
    Save-RememberedSecret 'elastic' 'so.lab' 'analyst' 'keep-me' $sec
    $gone = @(Remove-RetiredRawImportState $app $sec)
    Assert-True (-not (Test-Path (Join-Path $app 'soimport.conf'))) "the Raw Events tab's settings file is deleted"
    Assert-True ($null -eq (Get-RememberedSecret 'ssh' 'so.lab' 'analyst' $sec)) "and the SSH password it remembered"
    Assert-True ($null -eq (Get-RememberedSecret 'ssh' 'old-so.lab' 'admin' $sec)) "and one for a manager the .conf no longer named"
    Assert-Equal (Get-RememberedSecret 'elastic' 'so.lab' 'analyst' $sec) 'keep-me' "but no other remembered password"
    $said = $gone -join ' '
    Assert-True ($said -match '2 remembered SSH password' -and $said -match 'analyst@so\.lab' -and $said -match 'soimport\.conf') "and the log says what went"
    Assert-True ($said -notmatch 'S3cr3t') "never the password itself"
    # Another Windows user of the same install starts later: the .conf is
    # already gone, their own SSH password still goes.
    Save-RememberedSecret 'ssh' 'so.lab' 'other' 'S3cr3t-2' $sec
    $gone = @(Remove-RetiredRawImportState $app $sec)
    Assert-True ($null -eq (Get-RememberedSecret 'ssh' 'so.lab' 'other' $sec) -and ($gone -join ' ') -match '1 remembered SSH password') "with no .conf left, a remembered SSH password still goes"
    Assert-Equal (Get-RememberedSecret 'elastic' 'so.lab' 'analyst' $sec) 'keep-me' "and still nothing else"
} finally { Remove-Item -LiteralPath $app -Recurse -Force -ErrorAction SilentlyContinue }
