# tests/SoImport.Tests.ps1
#
# The Raw Events tab: collected EVTX copied to a Security Onion manager with
# PuTTY's pscp and imported there with so-import-evtx, every raw event
# searchable beside the Hayabusa detections. The command strings and the
# reading of the importer's report are library functions, tested here; the
# live round trip is tests/SoImport.Integration.Tests.ps1.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
$root = Split-Path -Parent $PSScriptRoot

# ---- PuTTY ships with the tool, signed ----
# The binaries are not in git: a fresh clone has no code\putty until they are
# added (README.md, Quick start), and then all three must be there.
if (-not (Test-Path (Join-Path $root 'code\putty'))) {
    Write-Host "  [SKIP] code\putty absent (a fresh clone) - PuTTY checks skipped" -ForegroundColor Yellow
} else {
    foreach ($t in 'plink', 'pscp') {
        $p = Find-PuttyTool $t
        Assert-True ($p -and (Test-Path -LiteralPath $p)) "$t.exe ships in code\putty"
        if ($p) { Assert-Equal "$((Get-AuthenticodeSignature $p).Status)" 'Valid' "$t.exe carries a valid Authenticode signature (Simon Tatham, PuTTY's author)" }
    }
    Assert-True (Test-Path (Join-Path $root 'code\putty\LICENCE')) "PuTTY's MIT licence ships beside it"
}

# ---- the host key, read from plink's refusal ----
$refusal = @'
The host key is not cached for this server:
  192.0.2.22 (port 22)
You have no guarantee that the server is the computer
you think it is.
The server's ssh-ed25519 key fingerprint is:
  ssh-ed25519 255 SHA256:ExampleHostKeyForTestsOnlyNotARealServer000
Connection abandoned.
'@
Assert-Equal (Get-SshHostKeyFingerprint $refusal) 'SHA256:ExampleHostKeyForTestsOnlyNotARealServer000' "the SHA-256 fingerprint is read from plink's refusal"
Assert-Equal (Get-SshHostKeyFingerprint 'Network error: Connection timed out') '' "no fingerprint, no guess"

# ---- the password is never on a command line ----
$a = Get-PlinkArgs -HostName 'so1' -Port 2222 -User 'analyst' -HostKey 'SHA256:x' -PasswordFile 'C:\t\pw.txt' -Command 'echo hi'
Assert-Equal ($a -join ' ') '-ssh -batch -P 2222 -l analyst -hostkey SHA256:x -pwfile C:\t\pw.txt so1 echo hi' "plink: batch, pinned host key, password from a file"
$a = Get-PscpArgs -HostName 'so1' -User 'analyst' -HostKey 'SHA256:x' -PasswordFile 'C:\t\pw.txt' -LocalFile 'C:\e\Security.evtx' -RemotePath '/tmp/d/001_x.evtx'
Assert-Equal ($a -join ' ') '-batch -scp -P 22 -l analyst -hostkey SHA256:x -pwfile C:\t\pw.txt C:\e\Security.evtx so1:/tmp/d/001_x.evtx' "pscp: one file to one remote path, the same protections"
$tab = Get-Content (Join-Path $root 'code\wpf-soimport.ps1') -Raw
Assert-True ($tab -notmatch "'-pw'") "the tab never passes -pw (a password on the command line)"
Assert-True ($tab -match 'New-PasswordFile' -and $tab -match '(?s)finally \{.*?Remove-Item -LiteralPath \$pw') "the password file is removed in a finally"

# A file left by a killed run is swept up by the next one - but never one
# still in use: a raw import can run for an hour, and sweeping by age deleted
# a running import's file at copy 570 of 598 (v50).
$tmpDir = [IO.Path]::GetTempPath()
$deadPid = 999999; while (Get-Process -Id $deadPid -ErrorAction SilentlyContinue) { $deadPid-- }
$stale = Join-Path $tmpDir "evtxer-pw-$deadPid-stale000000000000000000000000.txt"
$inUse = Join-Path $tmpDir "evtxer-pw-$PID-inuse000000000000000000000000.txt"
$legacy = Join-Path $tmpDir 'evtxer-pw-stale0000000000000000000000000000.txt'
foreach ($f in $stale, $inUse, $legacy) {
    Set-Content -LiteralPath $f -Value 'old' -NoNewline
    (Get-Item -LiteralPath $f).LastWriteTime = (Get-Date).AddHours(-2)
}
$pwf = New-PasswordFile 'S3cret!'
Assert-True (-not (Test-Path -LiteralPath $stale)) "a password file left by a killed run is removed by the next one"
Assert-True (Test-Path -LiteralPath $inUse) "one whose EVTXER is still running is in use, however old, and stays"
Assert-True (-not (Test-Path -LiteralPath $legacy)) "an old one named before owners were recorded is removed after an hour"
Assert-True ([IO.Path]::GetFileName($pwf) -match "^evtxer-pw-$PID-[0-9a-f]{32}\.txt$") "a new one carries its owner's process id"
Remove-Item -LiteralPath $inUse -Force -ErrorAction SilentlyContinue
try {
    Assert-Equal ([IO.File]::ReadAllText($pwf)) 'S3cret!' "the password file holds exactly the password (no BOM, no newline)"
    $acl = Get-Acl -LiteralPath $pwf
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $who = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    Assert-True ($acl.AreAccessRulesProtected) "it inherits nothing from the temp folder"
    Assert-Equal ($who -join ',') $me "only this Windows account can read it"
} finally { Remove-Item -LiteralPath $pwf -Force -ErrorAction SilentlyContinue }

# ---- on the manager ----
$dir = New-SoImportStagingDir ([datetime]'2026-10-15T12:00:00')
Assert-True ($dir -match '^/tmp/evtxer-import-20261015120000-[0-9a-f]{8}$') "the staging folder is private to one import and safe unquoted ($dir)"
Assert-Equal (Get-SoImportRemoteName 3 'C:\evtx\WS01_20261015_1200\Microsoft-Windows-PowerShell%4Operational.evtx') `
    '003_WS01_20261015_1200__Microsoft-Windows-PowerShell_4Operational.evtx' "a remote name keeps host folder and file, shell-safe"
Assert-True ((Get-SoImportRemoteName 1 'C:\e\HOST A\Windows PowerShell.evtx') -notmatch '\s') "spaces never reach the remote shell"
$names = @(1..2 | ForEach-Object { Get-SoImportRemoteName $_ "C:\e\H$_\Security.evtx" })
Assert-Equal @($names | Sort-Object -Unique).Count 2 "two hosts' Security.evtx do not overwrite each other"

$import = Get-SoRemoteCommand Import $dir
Assert-Equal $import "sudo -S -p '' so-import-evtx $dir/*.evtx" "the import is sudo -S (password on stdin, no prompt) over the staged files"
Assert-True ((Get-SoRemoteCommand Clean $dir) -match "^rm -rf $([regex]::Escape($dir)) ") "cleanup removes exactly the staging folder"
Assert-True ((Get-SoRemoteCommand Stage $dir) -match 'chmod 700') "the staging folder is private to the user while files land"

$v = Get-SoTestVerdict @('EVTXER-SSH-OK', 'EVTXER-SUDO-OK')
Assert-True ($v.Ssh -and $v.Sudo -and -not $v.Importer) "the test reports SSH, sudo and the importer separately"

# ---- reading so-import-evtx's report (its 2.4 wording) ----
$report = @(
    'Processing Import: /tmp/evtxer-import-x/001_WS01__Security.evtx'
    '- assigning unique identifier to import: 8f14e45fceea167a5a36dedd4bea2543'
    '- importing logs to Elasticsearch...'
    'Processing Import: /tmp/evtxer-import-x/002_WS01__System.evtx'
    '- assigning unique identifier to import: c9f0f895fb98ab9159f51fd0297e236d'
    '- this EVTX has already been imported; skipping'
    'Import complete!'
    'Use the following hyperlink to view the imported data.'
    'Triple-click to quickly highlight the entire hyperlink and then copy it into a browser:'
    'https://so-import/#/dashboards?q=import.id:8f14e45fceea167a5a36dedd4bea2543%20OR%20import.id:c9f0f895fb98ab9159f51fd0297e236d%20%7C%20groupby%20-sankey%20event.dataset&t=2026%2F10%2F01%2000%3A00%3A00%20AM%20-%202026%2F10%2F16%2000%3A00%3A00%20AM&z=UTC'
    'or, manually set the Time Range to be (in UTC):'
    'From: 2026-10-01    To: 2026-10-16'
    'Note: It can take 30 seconds or more for events to appear in Security Onion Console.'
)
$r = Get-SoImportResult $report
Assert-True $r.Complete "Import complete! is recognised"
Assert-Equal "$($r.Imported)/$($r.Skipped)/$($r.Warnings)" '1/1/0' "imported, already-imported and warned files are counted"
Assert-True ($r.Url -like 'https://so-import/#/dashboards?q=import.id:*') "the link to the imported events is kept"
Assert-Equal $r.TimeRange 'From: 2026-10-01    To: 2026-10-16' "and the time range, for setting it by hand"
# Security Onion 2.4.211 files imported events under the IMPORT time (event.created
# keeps their own), so its link - oldest to newest EVENT - opens on nothing.
# The tab's link runs from the oldest event to tomorrow and finds them either way.
$wide = Get-SoWideLink $r.Url ([datetime]'2026-10-20T15:00:00Z')
Assert-True ($wide -match '&t=2026%2F10%2F01%2000%3A00%3A00%20AM%20-%202026%2F10%2F21%2000%3A00%3A00%20AM&z=UTC$') "the link runs from the oldest event to tomorrow ($wide)"
Assert-True ($wide.StartsWith('https://so-import/#/dashboards?q=import.id:8f14e45f')) "and keeps Security Onion's own query"
Assert-Equal $r.WideUrl (Get-SoWideLink $r.Url) "Get-SoImportResult offers the widened link"
Assert-Equal (Get-SoWideLink 'https://x/#/dashboards?q=a') 'https://x/#/dashboards?q=a' "a link without a time range is left alone"
Assert-True ($tab -match '\$script:SoUrl = \$r\.WideUrl') "the tab opens the widened link"

$r = Get-SoImportResult @('Processing Import: /tmp/x', '- WARNING: This evtx file may not have fully imported successfully')
Assert-True (-not $r.Complete -and $r.Warnings -eq 1 -and -not $r.Url) "an unfinished import is not mistaken for one"

# ---- the tab is a tab like the others ----
$launcher = Get-Content (Join-Path $root 'code\HayabusaMissionTool.ps1') -Raw
Assert-True ($launcher -match "'wpf-soimport\.ps1'") "the shell loads the tab"
Assert-True ($launcher -match '(?s)function Set-AppBusy.*?\$tabSoImport') "Set-AppBusy locks it with the others"
Assert-True ($tab -match "Set-AppBusy \`$true 'importing raw events to Security Onion'") "the import shows the busy indicator"
Assert-True ($tab -match 'Write-Ledger @\(New-LedgerRow -Action ''SO import''') "the import writes an activity-log row"
# The import itself is Invoke-SoImport, shared with the job queue.
$so = ${function:Invoke-SoImport}.ToString()
Assert-True ($tab -match 'Invoke-SoImport -Files') "the tab imports through Invoke-SoImport"
Assert-True ($so -match '(?s)finally \{.*?Get-SoRemoteCommand Clean') "the staging folder is cleaned up in a finally - after a failure or Cancel too"
Assert-True ($tab -match 'Mask = @\(Get-SoPassword\)') "the password is masked if anything ever echoes it"

# ---- review 2026-10-15 ----
Assert-True ($so -match 'Get-SoRemoteCommand Import \$soRemote\) -Sudo -NoCancel') "Cancel waits for so-import-evtx instead of killing plink while the importer runs on"
Assert-True ($so -match "\(& \`$IsCancelled\) -or \`$r\.Error -match 'Cancelled'") "a cancelled copy is recorded as Cancelled, not FAILED"
Assert-True ($tab -match "New-LedgerRow -Action 'SO host key read'") "Fetch writes an activity-log row - it connects to the stack"
$tool = Get-Content (Join-Path $root 'code\HayabusaMissionTool.ps1') -Raw
Assert-True ($tool -match '-and -not \$StandardInput -and \$null -eq \$Capture\)') "a captured or stdin-fed run never goes to the console window (console mode broke the tab)"
Assert-True ($tool -match 'if \(\$NoCancel\)') "Invoke-ExternalTool honours -NoCancel"
