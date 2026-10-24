# tests/RulesUpdate.Tests.ps1
#
# The Hayabusa rule updater. Online it runs Hayabusa's
# own update-rules (measured by hand: refuses a rules folder that is not a git
# clone, exits 0 on failure, breaks past 259 characters). These pin what
# EVTXER does around it, offline, with a fake rules folder: the rules in use
# are backed up, a bad update puts them back, and an undo can be undone.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
Add-Type -AssemblyName System.IO.Compression.FileSystem

$scratch = Join-Path ([IO.Path]::GetTempPath()) "rulesupd_$PID"
$hdir = Join-Path $scratch 'hayabusa-x64'
$exe = Join-Path $hdir 'hayabusa-test.exe'
function New-Rules([string]$Path, [int]$Count, [switch]$NoConfig, [string]$Tag = 'old') {
    New-Item -ItemType Directory -Path (Join-Path $Path 'hayabusa\builtin') -Force | Out-Null
    if (-not $NoConfig) {
        New-Item -ItemType Directory -Path (Join-Path $Path 'config') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $Path 'config\default_details.txt') -Value 'x'
    }
    foreach ($i in 1..$Count) { Set-Content -LiteralPath (Join-Path $Path "hayabusa\builtin\$Tag-$i.yml") -Value "title: $Tag $i" }
}
function New-RulesZip([string]$Zip, [int]$Count, [switch]$NoConfig) {
    $src = Join-Path $scratch ('zipsrc_' + [guid]::NewGuid().ToString('N').Substring(0, 6))
    New-Rules (Join-Path $src 'hayabusa-rules-main') $Count -NoConfig:$NoConfig -Tag 'new'
    [IO.Compression.ZipFile]::CreateFromDirectory($src, $Zip)
}
try {
    New-Item -ItemType Directory -Path $hdir -Force | Out-Null
    Set-Content -LiteralPath $exe -Value ''
    $rules = Join-Path $hdir 'rules'
    New-Rules $rules 3

    $i = Get-RulesInfo $rules
    Assert-Equal "$($i.Count)|$($i.From)|$($i.HasPrevious)" '3||False' "the shipped rules: counted, no update yet, nothing to go back to"
    Assert-Equal (Get-LongestRulePath $rules) ('\hayabusa\builtin\old-1.yml'.Length) "the deepest rule path is measured below rules\"

    # ---- a good zip ----
    $good = Join-Path $scratch 'hayabusa-rules-main.zip'; New-RulesZip $good 5
    $r = Update-HayabusaRules -HayabusaExe $exe -ZipFile $good -MinRules 4
    Assert-Equal "$($r.Before)->$($r.After)" '3->5' "an update from a zip replaces the rules"
    Assert-True (Test-Path -LiteralPath (Join-Path $rules 'hayabusa\builtin\new-5.yml')) "GitHub's hayabusa-rules-main\ wrapper is unwrapped"
    $i = Get-RulesInfo $rules
    Assert-True ($i.From -match '^updated \d{4}-\d\d-\d\d \d\d:\d\d from file hayabusa-rules-main\.zip$') "it says when and where the rules came from ($($i.From))"
    Assert-True $i.HasPrevious "the rules in use before are kept as the backup"
    Assert-True (Test-Path -LiteralPath (Join-Path $hdir 'rules.previous\hayabusa\builtin\old-1.yml')) "the backup is the old rules"

    # ---- a bad zip: the rules in use come back ----
    $bad = Join-Path $scratch 'broken.zip'; New-RulesZip $bad 5 -NoConfig
    Assert-Throws { Update-HayabusaRules -HayabusaExe $exe -ZipFile $bad -MinRules 4 } "a zip without config\ is refused"
    Assert-True (Test-Path -LiteralPath (Join-Path $rules 'hayabusa\builtin\new-5.yml')) "and the rules in use are put back, not left half replaced"
    Assert-True (Test-Path -LiteralPath (Join-Path $rules 'config\default_details.txt')) "complete, config and all"
    $few = Join-Path $scratch 'few.zip'; New-RulesZip $few 2
    Assert-Throws { Update-HayabusaRules -HayabusaExe $exe -ZipFile $few -MinRules 4 } "so is one with too few rules"
    Assert-Equal (Get-RulesInfo $rules).Count 5 "the rules in use survive that too"

    # ---- undo, and undo the undo ----
    New-Rules (Join-Path $hdir 'rules.previous') 3
    $i = Restore-HayabusaRules $hdir
    Assert-Equal $i.Count 3 "Restore previous rules brings the earlier ones back"
    Assert-True $i.HasPrevious "and keeps the replaced ones as the backup"
    Assert-Equal (Restore-HayabusaRules $hdir).Count 5 "so an undo can be undone"
    Remove-Item -LiteralPath (Join-Path $hdir 'rules.previous') -Recurse -Force
    Assert-Throws { Restore-HayabusaRules $hdir } "with no backup there is nothing to restore, and it says so"

    # ---- code review: a folder Windows will not move ----
    # Something holding a file open in rules\ (Explorer, antivirus, a scan)
    # stops the rename. That must stop the update - not nest the new rules
    # inside the old ones and report success.
    $lock = [IO.File]::Open((Join-Path $rules 'config\default_details.txt'), 'Open', 'Read', 'None')
    try {
        Assert-Throws { Update-HayabusaRules -HayabusaExe $exe -ZipFile $good -MinRules 4 } "a rules folder that cannot be moved stops the update"
    } finally { $lock.Dispose() }
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $rules 'hayabusa-rules-main'))) "nothing was moved inside the rules in use"
    Assert-Equal (Get-RulesInfo $rules).Count 5 "they are untouched"
    Assert-True (Test-Path -LiteralPath (Join-Path $hdir 'rules.previous')) "and the backup is still there"

    # ---- after a crash in the middle: put back on the next start ----
    Move-Item -LiteralPath $rules -Destination (Join-Path $hdir 'rules.previous.x')
    Remove-Item -LiteralPath (Join-Path $hdir 'rules.previous') -Recurse -Force
    Move-Item -LiteralPath (Join-Path $hdir 'rules.previous.x') -Destination (Join-Path $hdir 'rules.previous')
    Assert-True (-not (Test-Path -LiteralPath $rules)) "(an update stopped while the rules were set aside)"
    Assert-True ((Repair-HayabusaRules $hdir) -match 'rules\.previous') "the rules set aside are put back"
    Assert-Equal (Get-RulesInfo $rules).Count 5 "complete"
    Assert-Equal (Repair-HayabusaRules $hdir) '' "and nothing is done when nothing is wrong"
    New-Rules (Join-Path $hdir 'rules.previous') 3
    Move-Item -LiteralPath $rules -Destination (Join-Path $hdir 'rules.swap')
    [void](Repair-HayabusaRules $hdir)
    Assert-Equal (Get-RulesInfo $rules).Count 5 "a restore stopped after its first move: the rules in use come back from rules.swap"
    Assert-Equal (Get-RulesInfo (Join-Path $hdir 'rules.previous')).Count 3 "and the backup stays the backup"
    Move-Item -LiteralPath (Join-Path $hdir 'rules.previous') -Destination (Join-Path $hdir 'rules.swap')
    [void](Repair-HayabusaRules $hdir)
    Assert-Equal (Get-RulesInfo (Join-Path $hdir 'rules.previous')).Count 3 "one stopped before its last move: the backup goes back to rules.previous"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $hdir 'rules.swap'))) "with nothing left over"

    # ---- too deep a folder is refused before anything moves ----
    Assert-True (Test-RulesPathFits 'C:\EVTXER\code\hayabusa-x64\rules' 166) "C:\EVTXER fits"
    Assert-True (-not (Test-RulesPathFits 'C:\Users\analyst\Documents\Investigations\Example xxxxxxxxxxxxxxx\EVTXER\code\hayabusa-x64\rules' 166)) "a deep install folder is too deep (96 + 166 > 259)"
    $deep = Join-Path $scratch ('d' * 120)
    New-Item -ItemType Directory -Path $deep -Force | Out-Null
    $dexe = Join-Path $deep 'hayabusa.exe'; Set-Content -LiteralPath $dexe -Value ''
    New-Rules (Join-Path $deep 'rules') 3
    Assert-Throws { Update-HayabusaRules -HayabusaExe $dexe -ZipFile $good -MinRules 1 } "an update in too deep a folder is refused up front"
    Assert-Equal (Get-RulesInfo (Join-Path $deep 'rules')).Count 3 "and nothing was moved"
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
