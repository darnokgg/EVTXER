# tests/Hardening.Tests.ps1
#
# A DFIR tool works against machines that may be compromised, from target
# lists someone else may have written. Each block here is one way such input
# could have turned the tool against its operator or its targets.
. "$PSScriptRoot\..\code\EvtxCollector.ps1"
$root = Split-Path -Parent $PSScriptRoot

# ---- targets are host names or addresses, nothing else ----
foreach ($ok in 'dc01', 'dc01.corp.local', 'WIN-01', '192.0.2.10', 'fe80::1', '10.0.0.5') {
    Assert-True (Test-TargetName $ok) "'$ok' is a valid target"
}
foreach ($bad in '*', '..\x', '-proxycmd', 'a b', 'x\y', '', 'host;calc', 'C:\x', '.hidden', 'a/b') {
    Assert-True (-not (Test-TargetName $bad)) "'$bad' is refused as a target"
}
$r = Test-CollectReadiness -Targets @('dc01', '*', '..\x') -Method 'SMB' -Username 'u' -Category 'DFIR'
Assert-True (-not $r.Ready) "a list with a bad target is not ready to collect"
Assert-True (@($r.Missing) -contains 'Targets') "the Targets label turns red"
Assert-Equal (@($r.Invalid) -join ',') '*,..\x' "and the bad ones are named"
$r = Test-CollectReadiness -Targets @('dc01', '192.0.2.10') -Method 'SMB' -Username 'u' -Category 'DFIR'
Assert-True $r.Ready "a list of real names and addresses is ready"

$threw = $false; try { Get-PlinkArgs -HostName '-proxycmd' -User 'u' | Out-Null } catch { $threw = $true }
Assert-True $threw "plink is never given a host that would read as an option"
$threw = $false; try { Get-PscpArgs -HostName '-x' -User 'u' -HostKey 'k' -PasswordFile 'p' -LocalFile 'l' -RemotePath '/tmp' | Out-Null } catch { $threw = $true }
Assert-True $threw "nor is pscp"
Assert-Equal ((Get-PlinkArgs -HostName 'so.example.local' -User 'u')[-1]) 'so.example.local' "a real host still works"

$col = Get-Content (Join-Path $root 'code\EvtxCollector.ps1') -Raw
Assert-True ($col -match 'function Add-CollectTrustedHosts[\s\S]{0,400}Test-TargetName') "TrustedHosts only ever gets real names"
Assert-True ($col -match "\[SKIPPED\] '\`$bad' - not a host name or address") "the collector skips a bad target even past the form"

# ---- argument lines parse back to exactly the arguments given ----
Add-Type -Namespace EvtxerTest -Name Argv -MemberDefinition @'
[DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern IntPtr CommandLineToArgvW(string cmd, out int n);
[DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
public static string[] Split(string cmd) {
    int n; IntPtr p = CommandLineToArgvW(cmd, out n);
    var r = new string[n];
    for (int i = 0; i < n; i++) r[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, i * IntPtr.Size));
    LocalFree(p); return r;
}
'@ -ErrorAction SilentlyContinue
$cases = @('plain', 'C:\Case Files\x.jsonl', 'C:\a b\', 'a"b', 'he said "hi"', 'x\\"y', '', 'trail\\', 'tab	in')
$back = [EvtxerTest.Argv]::Split('prog.exe ' + (ConvertTo-ProcessArgumentLine $cases))
Assert-Equal ($back.Count - 1) $cases.Count "every argument survives, the empty one included"
for ($i = 0; $i -lt $cases.Count; $i++) {
    Assert-Equal $back[$i + 1] $cases[$i] "argument [$($cases[$i])] comes back unchanged"
}

# ---- the collection results CSV never starts a formula ----
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("hard-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $h = New-CollectHostResult 'dc01' 'CORP\u' 'Failed' 0 16 '' '=HYPERLINK("http://x","click")'
    $csv = Export-CollectResults @($h) (Join-Path $tmp 'results.csv')
    $row = Import-Csv -LiteralPath $csv
    Assert-Equal $row.Detail "'=HYPERLINK(`"http://x`",`"click`")" "error text from the target is kept as text, not run as a formula"
    Assert-Equal $row.Requested '16' "numbers stay numbers"
    Assert-Equal $row.Target 'dc01' "ordinary text is unchanged"
}
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }

# ---- who may own what the sweep deletes: SIDs, not translated names ----
$me = 'S-1-5-21-1-2-3-1001'
foreach ($o in 'BA', 'SY', 'S-1-5-32-544', 'S-1-5-18', $me) {
    Assert-True (Test-StagingOwner $o $me) "an item owned by $o may be deleted"
}
Assert-True (-not (Test-StagingOwner 'S-1-5-21-1-2-3-1002' $me)) "one another user owns may not"
Assert-True (-not (Test-StagingOwner '' $me)) "nor one whose owner could not be read"
Assert-True (-not (Test-StagingOwner 'VORDEFINIERT\Administratoren' $me)) "(a translated NAME is never what is compared)"
Assert-True (Test-StagingOwner 'LA' 'S-1-5-21-1-2-3-500') "the built-in Administrator, which SDDL writes as LA, is an administrator"
Assert-True (Test-StagingOwner 'LA' $me) "(whoever runs the collection: LA is in Administrators for good)"

# ---- the plan: top-level files an administrator made, nothing else ----
$now = Get-Date '2026-10-24 12:00'
$old = $now.AddDays(-2)
$cur = 'C:\Windows\Temp\EVTX_Export_aaaaaaaa'
function Row($Path, $Top = '', [switch]$Dir, [switch]$Link, $Owner = 'BA', $When = $old) {
    [pscustomobject]@{ Path = $Path; Name = (Split-Path -Leaf $Path); Top = $Top; Me = $me
                       IsDir = [bool]$Dir; IsLink = [bool]$Link; Owner = $Owner; LastWrite = $When }
}
$rows = @(
    (Row $cur -Dir -Owner $me -When $now)
    (Row "$cur\Security.evtx" $cur -Owner $me)
    (Row "$cur\planted.dll" $cur -Owner 'S-1-5-21-1-2-3-1002')
    (Row "$cur\sub" $cur -Dir)
    (Row "$cur\link" $cur -Dir -Link)
    (Row 'C:\Windows\Temp\EVTX_Export_bbbbbbbb' -Dir)
    (Row 'C:\Windows\Temp\EVTX_Export_bbbbbbbb\System.evtx' 'C:\Windows\Temp\EVTX_Export_bbbbbbbb')
    (Row 'C:\Windows\Temp\EVTX_Export_bbbbbbbb.zip')
    (Row 'C:\Windows\Temp\EVTX_Export_cccccccc' -Dir -Link)
    (Row 'C:\Windows\Temp\EVTX_Export_dddddddd' -Dir -Owner 'S-1-5-21-1-2-3-1002')
    (Row 'C:\Windows\Temp\EVTX_Export_eeeeeeee' -Dir -When $now.AddMinutes(-5))
)
$plan = Get-StagingDeletePlan -Listing $rows -Current @($cur, "$cur.zip") -Now $now
Assert-Equal (@($plan.Files) -join '|') "$cur\Security.evtx|$cur\planted.dll|C:\Windows\Temp\EVTX_Export_bbbbbbbb\System.evtx|C:\Windows\Temp\EVTX_Export_bbbbbbbb.zip" `
    "the files in this run's folder and in an abandoned administrator's run go - only files, whoever made them"
Assert-Equal (@($plan.Dirs) -join '|') "$cur|C:\Windows\Temp\EVTX_Export_bbbbbbbb" "their folders go once empty"
foreach ($l in "$cur\sub", "$cur\link", 'C:\Windows\Temp\EVTX_Export_cccccccc', 'C:\Windows\Temp\EVTX_Export_dddddddd') {
    Assert-True (@($plan.Left) -contains $l) "left alone and reported: $(Split-Path -Leaf $l)"
}
Assert-True (-not (@($plan.Files + $plan.Dirs + $plan.Left) -match 'eeeeeeee')) "a running collection's folder is not even looked at"
$la = @((Row 'C:\Windows\Temp\EVTX_Export_ffffffff' -Dir -Owner 'LA'),
        (Row 'C:\Windows\Temp\EVTX_Export_ffffffff\Security.evtx' 'C:\Windows\Temp\EVTX_Export_ffffffff' -Owner 'LA'))
$planLA = Get-StagingDeletePlan -Listing $la -Current @() -Now $now
Assert-True (@($planLA.Dirs) -contains 'C:\Windows\Temp\EVTX_Export_ffffffff') "a run the built-in Administrator abandoned is swept"
$own = @((Row $cur -Dir -Owner 'S-1-5-21-9-9-9-1001' -When $now), (Row "$cur\Security.evtx" $cur -Owner 'S-1-5-21-9-9-9-1001'))
$planOwn = Get-StagingDeletePlan -Listing $own -Current @($cur) -Now $now
Assert-Equal (@($planOwn.Files) -join '|') "$cur\Security.evtx" "this run's own folder goes whoever Windows made its owner"

# ---- the same on a real remote session, and in ConstrainedLanguage ----
# A second local powershell.exe over a named pipe (PipeSession.ps1), so the
# listing and the delete really run in another process. A temp folder stands
# in for C:\Windows\Temp, which only an administrator can list. The second
# pass switches that session to ConstrainedLanguage, as AppLocker or WDAC
# would: the cleanup must still remove this run's folder.
. "$PSScriptRoot\PipeSession.ps1"
$token  = [guid]::NewGuid().ToString('N').Substring(0, 8)
$parent = Join-Path ([IO.Path]::GetTempPath()) "wtemp-$token"
$vict   = Join-Path ([IO.Path]::GetTempPath()) "victim-$token"
function New-RunToken { [guid]::NewGuid().ToString('N').Substring(0, 8) }
$pipe = $null
try {
    $stale = "$parent\EVTX_Export_$(New-RunToken)"          # abandoned, holds a junction
    $clean = "$parent\EVTX_Export_$(New-RunToken)"          # abandoned, just exports
    $run   = "$parent\EVTX_Export_$(New-RunToken)"          # this run's, checked in CLM
    New-Item -ItemType Directory -Path $stale, $clean, $run, $vict -Force | Out-Null
    Set-Content "$vict\precious.txt" 'keep me'
    foreach ($d in $stale, $clean, $run) { Set-Content "$d\Security.evtx" 'x' }
    cmd /c mklink /J "$stale\link" $vict | Out-Null
    foreach ($d in $stale, $clean) { (Get-Item -LiteralPath $d).LastWriteTime = (Get-Date).AddDays(-2) }
    $pipe = New-PipeSession
    $log = New-Object System.Collections.ArrayList
    $r = Remove-EvtxStaging -Session $pipe.Session -KnownPaths @("$parent\EVTX_Export") -LogWriter { param($m) [void]$log.Add($m) }
    Assert-True (-not (Test-Path -LiteralPath $clean)) "an abandoned staging folder is swept on the target"
    Assert-True (-not (Test-Path -LiteralPath "$stale\Security.evtx")) "the export in the one with a junction goes too"
    Assert-True ([bool](Get-Item -LiteralPath "$stale\link" -Force -ErrorAction SilentlyContinue)) "but the junction is left alone"
    Assert-True (Test-Path -LiteralPath "$vict\precious.txt") "and what it points at is untouched"
    Assert-True (@($log | Where-Object { $_ -match [regex]::Escape("$stale\link") }).Count -eq 1) "the log names what was left"
    Assert-True (Test-Path -LiteralPath $run) "a young folder that is not this run's is left for its own run"

    Invoke-Command -Session $pipe.Session -ScriptBlock { $ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage' }
    Assert-Equal (Invoke-Command -Session $pipe.Session -ScriptBlock { "$($ExecutionContext.SessionState.LanguageMode)" }) 'ConstrainedLanguage' "(the target now runs in ConstrainedLanguage)"
    $r = Remove-EvtxStaging -Session $pipe.Session -CurrentPath $run -KnownPaths @("$parent\EVTX_Export")
    Assert-True $r.Clean "in ConstrainedLanguage this run's staging is still cleaned"
    Assert-True (-not (Test-Path -LiteralPath $run)) "and the folder is really gone"
}
finally {
    if ($pipe) { try { Remove-PSSession $pipe.Session } catch { }; Stop-Process -Id $pipe.Process.Id -Force -ErrorAction SilentlyContinue }
    if ($stale -and (Get-Item -LiteralPath "$stale\link" -Force -ErrorAction SilentlyContinue)) { [IO.Directory]::Delete("$stale\link") }
    foreach ($d in $parent, $vict) { if ($d -and (Test-Path -LiteralPath $d)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue } }
}
$col = Get-Content (Join-Path $root 'code\EvtxCollector.ps1') -Raw
Assert-True ($col -match "New-Item -ItemType Directory -Path \`$using:stagingPath -ErrorAction Stop") "the staging folder is never reused (no -Force)"

# ---- the icacls line closes the folder to everyone but SYSTEM and Administrators ----
$acl = Join-Path ([IO.Path]::GetTempPath()) "acl-$token"
New-Item -ItemType Directory -Path $acl | Out-Null
try {
    $null = icacls $acl /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1
    $a = Get-Acl -LiteralPath $acl
    $sids = @($a.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    Assert-Equal ($sids -join ',') 'S-1-5-18,S-1-5-32-544' "only SYSTEM and Administrators keep access"
    Assert-True $a.AreAccessRulesProtected "and nothing is inherited from C:\Windows\Temp"
}
finally {
    $null = icacls $acl /reset 2>&1
    Remove-Item -LiteralPath $acl -Recurse -Force -ErrorAction SilentlyContinue
}
foreach ($m in "icacls \`$using:stagingPath /inheritance:r", "icacls \`$using:probeDir /inheritance:r") {
    Assert-True ($col -match $m) "the same lock is applied: $($m.Split(' ')[1])"
}

# ---- export names and the archive ----
Assert-Equal (ConvertTo-ExportFileName 'Microsoft-Windows-PowerShell/Operational') 'Microsoft-Windows-PowerShell_Operational.evtx' "a log path becomes one file name"
Assert-Equal (ConvertTo-ExportFileName 'evil:stream') 'evil_stream.evtx' "a ':' cannot make an alternate data stream"
Assert-Equal (ConvertTo-ExportFileName '..\..\x') '.._.._x.evtx' "a name cannot climb out of the staging folder"
Assert-True ($col -match '\$expected -contains \$_\.Name') "only files this run exported are taken out of the target's archive"

# ---- the launcher runs Windows' own programs ----
$cmd = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes((Join-Path $root 'EVTXER.cmd')))
Assert-True ($cmd -match '(?m)^"%SystemRoot%\\System32\\fltmc\.exe"') "fltmc is called by its full path"
Assert-True ($cmd -notmatch '(?m)^powershell\.exe') "powershell is never looked up beside the .cmd"
Assert-Equal ([regex]::Matches($cmd, '(?m)^"%SystemRoot%\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe"').Count) 2 "both PowerShell calls use the full path"

# ---- the dashboard helper checks certificates ----
$ks = Get-Content (Join-Path $root 'scripts\kibana_setup.py') -Raw
Assert-True ($ks -notmatch 'verify = False') "kibana_setup.py no longer turns TLS checks off for every run"
Assert-True ($ks -match 'SO_ES_INSECURE') "only SO_ES_INSECURE=1 does"
