# tests/AnomalyRuntime.Integration.Tests.ps1
#
# The Anomaly Hunt dashboards (2026-10-17) lean on runtime fields for what
# Lens cannot express: the best-available process path (Sysmon, else 4688),
# "system program in the wrong folder", "run from a user-writable folder",
# the UTC hour and day, and lengths. They are defined once, in
# scripts\anomaly_runtime_fields.py; this runs them on a real Elasticsearch
# against hand-made events, edge cases included (mixed-case paths, a doc
# with none of the fields, 00:xx and 23:xx, Sunday and Monday).
# Needs TEST_ES_BASE / TEST_ES_USER / TEST_ES_PASSWORD (the Docker lab).
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$base = $env:TEST_ES_BASE
if (-not $base) { Write-Host "  [SKIP] TEST_ES_BASE not set - live anomaly runtime-field test skipped" -ForegroundColor Yellow; return }
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Write-Host "  [SKIP] python not found - anomaly runtime-field test skipped" -ForegroundColor Yellow; return }
Set-TlsTrust -Mode 'Skip'
$h = Get-AuthHeader $(if ($env:TEST_ES_USER) { $env:TEST_ES_USER } else { 'admin' }) $env:TEST_ES_PASSWORD
$gen = Join-Path $PSScriptRoot '..\scripts\anomaly_runtime_fields.py'

function Get-RuntimeMap([string]$View) {
    $json = & { $ErrorActionPreference = 'Continue'; & $py.Source -I $gen --view $View 2>$null }
    return (($json -join "`n") | ConvertFrom-Json)
}

function Invoke-Runtime([string]$Index, $Map, [string]$Id) {
    # The runtime fields' values for one document, as Elasticsearch computes them.
    $body = @{ query = @{ ids = @{ values = @($Id) } }; runtime_mappings = $Map; fields = @('op.*'); _source = $false } |
            ConvertTo-Json -Depth 20 -Compress
    $r = Invoke-EsJson -Uri "$base/$Index/_search" -Method Post -Headers $h -ContentType 'application/json' -Body $body -TimeoutSec 30
    return $r.hits.hits[0].fields
}

$idx = "hayabusa-anomaly-rt-$(Get-Date -Format 'yyyyMMddHHmmss')"
try {
    $mapping = '{"mappings":{"dynamic_templates":[{"s":{"match_mapping_type":"string","mapping":{"type":"keyword","ignore_above":256}}}],' +
               '"properties":{"event":{"properties":{"created":{"type":"date"}}},"@timestamp":{"type":"date"}}}}'
    Invoke-EsJson -Uri "$base/$idx" -Method Put -Headers $h -ContentType 'application/json' -Body $mapping -TimeoutSec 30 | Out-Null
    $docs = @{
        # v81: raw events are EVTXER's own, timed by @timestamp (Security Onion's
        # importer kept the event's time in event.created).
        s1 = @{ '@timestamp' = '2026-10-18T03:07:00Z'; winlog = @{ channel = 'Microsoft-Windows-Sysmon/Operational'; event_id = '1'
                event_data = @{ Image = 'C:\Users\eve\AppData\Local\Temp\svchost.exe'; ParentImage = 'C:\Windows\explorer.exe' } } }
        p1 = @{ '@timestamp' = '2026-10-19T23:59:00Z'; winlog = @{ channel = 'Security'; event_id = '4688'
                event_data = @{ NewProcessName = 'C:\WINDOWS\System32\SVCHOST.EXE' } } }
        c1 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4688'
                event_data = @{ NewProcessName = 'C:\Windows\System32\cmd.exe'; CommandLine = 'powershell -enc AAAA' } } }
        # Longer than the keyword's ignore_above: no doc value, the length must still come out.
        l1 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4688'
                event_data = @{ NewProcessName = 'C:\Windows\System32\cmd.exe'; CommandLine = ('x' * 300) } } }
        v1 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'System'; event_id = '7045'
                event_data = @{ ServiceName = 'x'; ImagePath = 'C:\Users\Public\x.exe' } } }
        e1 = @{ '@timestamp' = '2026-10-18T00:00:00Z'; winlog = @{ channel = 'Application'; event_id = '1000' } }
        # Built-in accounts are left out of the account hunts - by their EXACT
        # shape only, with the SID of the SAME account, and never without one,
        # so an attacker cannot hide as "DWM-backdoor" or a fake SYSTEM
        # (security reviews, 2026-10-17).
        b1 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4624'; event_data = @{ TargetUserName = 'DWM-3'; TargetUserSid = 'S-1-5-90-0-3' } } }
        b2 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4624'; event_data = @{ TargetUserName = 'DWM-backdoor'; TargetUserSid = 'S-1-5-90-0-3' } } }
        b3 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4624'; event_data = @{ TargetUserName = 'sshd_1464'; TargetUserSid = 'S-1-5-111-1-2' } } }
        b4 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4624'; event_data = @{ TargetUserName = 'DWM-3' } } }
        b5 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4624'; event_data = @{ TargetUserName = 'SYSTEM'; TargetUserSid = 'S-1-5-18' } } }
        b6 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4624'; event_data = @{ TargetUserName = 'SYSTEM'; TargetUserSid = 'S-1-5-21-1-2-3-1001' } } }
        b7 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4624'; event_data = @{ TargetUserName = 'alice'; TargetUserSid = 'S-1-5-21-1-2-3-1002' } } }
        b8 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4624'; event_data = @{ TargetUserName = 'SYSTEM' } } }
        b9 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4624'; event_data = @{ TargetUserName = ('DWM-' + [char]0x0663); TargetUserSid = 'S-1-5-90-0-3' } } }
        d4 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; user = @{ name = 'UMFD-0' }; winlog = @{ event_data = @{ TargetUserName = 'UMFD-0'; TargetUserSid = 'S-1-5-96-0-0' } } }
        d5 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; user = @{ name = 'UMFD-x' }; winlog = @{ event_data = @{ TargetUserName = 'UMFD-x'; TargetUserSid = 'S-1-5-96-0-0' } } }
        # user.name came from SubjectUserName: its SID is SubjectUserSid.
        d6 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; user = @{ name = 'SYSTEM' }; winlog = @{ event_data = @{ SubjectUserName = 'SYSTEM'; SubjectUserSid = 'S-1-5-18' } } }
        # A fake "SYSTEM" target must not borrow the real SYSTEM subject's SID.
        d7 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; user = @{ name = 'SYSTEM'; id = 'S-1-5-18' }
                winlog = @{ event_data = @{ TargetUserName = 'SYSTEM'; TargetUserSid = 'S-1-5-21-9-9-9-1001'; SubjectUserName = 'admin'; SubjectUserSid = 'S-1-5-18' } } }
        b11 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4624'; event_data = @{ TargetUserName = 'sshd_4242'; TargetUserSid = 'S-1-5-21-1-2-3-1003' } } }
        # Final review, 2026-10-17: a null-session logon is attacker activity, not noise.
        b10 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4624'; event_data = @{ TargetUserName = 'ANONYMOUS LOGON'; TargetUserSid = 'S-1-5-7' } } }
        # Final review: a detection's file.path is the service path cut at the
        # first .exe; the whole line is winlog.event_data.ImagePath.
        d8 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; service = @{ name = 'svc' }; file = @{ path = 'C:\Windows\System32\cmd.exe' }
                winlog = @{ event_data = @{ ImagePath = 'C:\Windows\System32\cmd.exe /c powershell -nop -enc AAAA' } } }
        # Final review: a detection command line past the keyword's ignore_above
        # has no doc value - the panel's row must come from op.CmdLine.
        d9 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; process = @{ command_line = ('y' * 300) } }
        # 64-bit Windows ships a 32-bit explorer.exe in SysWOW64 (lab run, 2026-10-17).
        x1 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; winlog = @{ channel = 'Security'; event_id = '4688'
                event_data = @{ NewProcessName = 'C:\Windows\SysWOW64\explorer.exe' } } }
        d1 = @{ '@timestamp' = '2026-10-18T03:07:00Z'; process = @{ executable = 'C:\Users\eve\AppData\Local\Temp\svchost.exe'
                command_line = 'svchost.exe -k x'; parent = @{ executable = 'C:\Windows\explorer.exe' } } }
        d2 = @{ '@timestamp' = '2026-10-19T23:59:00Z'; process = @{ executable = 'C:\WINDOWS\System32\SVCHOST.EXE' } }
        d3 = @{ '@timestamp' = '2026-10-19T12:00:00Z'; service = @{ name = 'evil' }; file = @{ path = 'C:\Windows\Temp\evil.exe' } }
    }
    foreach ($k in $docs.Keys) {
        Invoke-EsJson -Uri "$base/$idx/_doc/$k" -Method Put -Headers $h -ContentType 'application/json' -Body ($docs[$k] | ConvertTo-Json -Depth 10 -Compress) -TimeoutSec 30 | Out-Null
    }
    Invoke-EsJson -Uri "$base/$idx/_refresh" -Method Post -Headers $h -TimeoutSec 30 | Out-Null

    $raw = Get-RuntimeMap 'raw'
    $det = Get-RuntimeMap 'detections'
    foreach ($n in 'op.HourUTC','op.DayUTC','op.ProcPath','op.ParentPath','op.CmdLine','op.CmdLen','op.ProcWrongPlace','op.ProcUserWritable',
                   'op.ServiceBinary','op.ServiceBinaryLen','op.ServiceUserWritable','op.HostApplicationLen') {
        Assert-True ($raw.PSObject.Properties.Name -contains $n) "the raw view defines $n"
    }
    foreach ($n in 'op.HourUTC','op.DayUTC','op.ProcPath','op.ParentPath','op.CmdLen','op.ProcWrongPlace','op.ProcUserWritable',
                   'op.ServiceBinary','op.ServiceBinaryLen','op.ServiceUserWritable') {
        Assert-True ($det.PSObject.Properties.Name -contains $n) "the detections view defines $n"
    }

    $f = Invoke-Runtime $idx $raw 's1'
    Assert-Equal "$($f.'op.ProcPath')" 'c:\users\eve\appdata\local\temp\svchost.exe' "Sysmon's Image is the process path, lowercased"
    Assert-Equal "$($f.'op.ParentPath')" 'c:\windows\explorer.exe' "and ParentImage the parent"
    Assert-Equal "$($f.'op.ProcWrongPlace')" 'True' "svchost.exe outside System32 is in the wrong place"
    Assert-Equal "$($f.'op.ProcUserWritable')" 'True' "and AppData\Local\Temp is user-writable"
    Assert-Equal "$($f.'op.HourUTC')" '03' "the hour is zero-padded UTC"
    Assert-Equal "$($f.'op.DayUTC')" '7 Sun' "the day sorts Monday first and names itself"

    $f = Invoke-Runtime $idx $raw 'p1'
    Assert-Equal "$($f.'op.ProcPath')" 'c:\windows\system32\svchost.exe' "4688's NewProcessName is the fallback, lowercased"
    Assert-Equal "$($f.'op.ProcWrongPlace')" 'False' "a mixed-case System32 path is the right place"
    Assert-Equal "$($f.'op.ProcUserWritable')" 'False' "and not user-writable"
    Assert-Equal "$($f.'op.HourUTC')" '23' "23:59 is hour 23"
    Assert-Equal "$($f.'op.DayUTC')" '1 Mon' "Monday is 1"

    $f = Invoke-Runtime $idx $raw 'c1'
    Assert-Equal "$($f.'op.CmdLine')" 'powershell -enc AAAA' "4688's CommandLine is the command line"
    Assert-Equal "$($f.'op.CmdLen')" '20' "and its length"
    $f = Invoke-Runtime $idx $raw 'l1'
    Assert-Equal "$($f.'op.CmdLen')" '300' "a command line too long for a doc value still has its length"

    $f = Invoke-Runtime $idx $raw 'v1'
    Assert-Equal "$($f.'op.ServiceBinary')" 'c:\users\public\x.exe' "7045's ImagePath is the service binary, lowercased"
    Assert-Equal "$($f.'op.ServiceUserWritable')" 'True' "Users\Public is user-writable"
    Assert-Equal "$($f.'op.ServiceBinaryLen')" '21' "and its length"

    foreach ($case in @(@('b1', 'True', 'DWM-<digits> with its S-1-5-90 SID is a built-in session account'),
                        @('b2', 'False', 'DWM-backdoor is NOT - only the exact shape counts'),
                        @('b3', 'True', "sshd_<digits> with OpenSSH's S-1-5-111 virtual-account SID is built-in (test workstation, 2026-10-17)"),
                        @('b11', 'False', 'an ordinary account named sshd_<digits> (S-1-5-21 SID) is not'),
                        @('b4', 'False', 'DWM-3 with NO SID is not trusted (fail closed)'),
                        @('b5', 'True', 'SYSTEM with its well-known SID S-1-5-18 is built-in'),
                        @('b6', 'False', 'an account NAMED SYSTEM with another SID is not'),
                        @('b7', 'False', 'an ordinary account is not'),
                        @('b8', 'False', 'SYSTEM with NO SID is not trusted (fail closed)'),
                        @('b9', 'False', 'non-ASCII digits are not digits'),
                        @('b10', 'False', 'ANONYMOUS LOGON stays visible - a null session is attacker activity'))) {
        $f = Invoke-Runtime $idx $raw $case[0]
        Assert-Equal "$($f.'op.BuiltinAccount')" $case[1] $case[2]
    }
    Assert-Equal "$((Invoke-Runtime $idx $det 'd4').'op.BuiltinAccount')" 'True' "detections: UMFD-0 with its target SID is built-in"
    Assert-Equal "$((Invoke-Runtime $idx $det 'd5').'op.BuiltinAccount')" 'False' "detections: UMFD-x is not"
    Assert-Equal "$((Invoke-Runtime $idx $det 'd6').'op.BuiltinAccount')" 'True' "detections: a SYSTEM subject is judged by the subject's SID"
    Assert-Equal "$((Invoke-Runtime $idx $det 'd7').'op.BuiltinAccount')" 'False' "detections: a fake SYSTEM target does not borrow another account's SID"
    $f = Invoke-Runtime $idx $det 'd8'
    Assert-Equal "$($f.'op.ServiceBinary')" 'c:\windows\system32\cmd.exe /c powershell -nop -enc aaaa' "detections: the service line is the whole ImagePath, not file.path cut at .exe"
    Assert-Equal "$($f.'op.ServiceBinaryLen')" '56' "detections: and its length is the whole line's"
    $f = Invoke-Runtime $idx $det 'd9'
    Assert-Equal "$(@($f.'op.CmdLine')[0].Length)" '300' "detections: op.CmdLine carries a command line too long for a doc value"
    Assert-Equal "$($f.'op.CmdLen')" '300' "detections: with its length"

    $f = Invoke-Runtime $idx $raw 'x1'
    Assert-Equal "$($f.'op.ProcWrongPlace')" 'False' "explorer.exe in SysWOW64 is Windows' own 32-bit copy, not the wrong place"

    $f = Invoke-Runtime $idx $raw 'e1'
    Assert-Equal "$($f.'op.HourUTC')" '00' "midnight is hour 00"
    Assert-True ($null -eq $f.'op.ProcPath' -and $null -eq $f.'op.CmdLen' -and $null -eq $f.'op.ProcWrongPlace') "an event with none of the fields gets none of them, and nothing throws"

    $f = Invoke-Runtime $idx $det 'd1'
    Assert-Equal "$($f.'op.ProcPath')" 'c:\users\eve\appdata\local\temp\svchost.exe' "detections: process.executable is the process path"
    Assert-Equal "$($f.'op.ProcWrongPlace')" 'True' "detections: the same wrong-place rule"
    Assert-Equal "$($f.'op.CmdLen')" '16' "detections: process.command_line's length"
    Assert-Equal "$($f.'op.HourUTC')" '03' "detections: the hour comes from @timestamp"
    $f = Invoke-Runtime $idx $det 'd2'
    Assert-Equal "$($f.'op.ProcWrongPlace')" 'False' "detections: a mixed-case System32 path is fine"
    $f = Invoke-Runtime $idx $det 'd3'
    Assert-Equal "$($f.'op.ServiceBinary')" 'c:\windows\temp\evil.exe' "detections: a service's file.path is its binary"
    Assert-Equal "$($f.'op.ServiceUserWritable')" 'True' "Windows\Temp is user-writable"
}
finally {
    try { Invoke-EsJson -Uri "$base/$idx" -Method Delete -Headers $h -TimeoutSec 30 | Out-Null } catch { }
}
