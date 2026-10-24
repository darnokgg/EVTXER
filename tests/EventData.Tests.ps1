# tests/EventData.Tests.ps1
#
# Every field of a detected event used to sit inside two flattened JSON blobs
# (hayabusa.details under Hayabusa's short names, hayabusa.extra), searchable
# only by typing the path, shown in Discover as one block of JSON, and not
# chartable. Since v37 each one is a field of its own under its real Windows
# name - winlog.event_data.*, the names Winlogbeat and Security Onion use -
# with Details' short names translated back through Hayabusa's own tables.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$hd = Join-Path ([IO.Path]::GetTempPath()) ("hdir-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path "$hd\rules\config", "$hd\rules\hayabusa\builtin" -Force | Out-Null
$bar = [string][char]0xA6
try {
    # Hayabusa's own formats: default_details.txt, and a rule with a details: line.
    [IO.File]::WriteAllText("$hd\rules\config\default_details.txt", (@(
        'Provider, EID, Details'
        "Microsoft-Windows-Security-Auditing, 4624, Type: %LogonType% $bar TgtUser: %TargetUserName% $bar SrcIP: %IpAddress%"
    ) -join "`n"), (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText("$hd\rules\hayabusa\builtin\r.yml", (@(
        'title: Custom'
        'id: 11111111-2222-3333-4444-555555555555'
        "details: 'Svc: %ServiceName% $bar Path: %ImagePath%'"
        'level: high'
    ) -join "`n"), (New-Object Text.UTF8Encoding($false)))

    # A rule past Windows' 260-character path limit - a deployment copy had one,
    # and reading it used to fail the whole conversion.
    $deep = '\\?\' + (Join-Path $hd ('rules\' + ('d' * 120) + '\' + ('e' * 120)))
    [void][IO.Directory]::CreateDirectory($deep)
    [IO.File]::WriteAllText("$deep\long.yml", (@(
        'title: Deep'
        'id: 99999999-2222-3333-4444-555555555555'
        "details: 'Usr: %SubjectUserName%'"
    ) -join "`n"), (New-Object Text.UTF8Encoding($false)))

    $m = Get-DetailsAliasMap $hd
    Assert-Equal $m['rule:99999999-2222-3333-4444-555555555555']['Usr'] 'SubjectUserName' "a rule whose path is over 260 characters is still read"
    Assert-Equal $m['Microsoft-Windows-Security-Auditing|4624']['TgtUser'] 'TargetUserName' "default_details.txt: TgtUser is TargetUserName on 4624"
    Assert-Equal $m['Microsoft-Windows-Security-Auditing|4624']['Type'] 'LogonType' "the first pair of a line is read too"
    Assert-Equal $m['rule:11111111-2222-3333-4444-555555555555']['Svc'] 'ServiceName' "a rule's own details: line is read"
    Assert-Equal (Get-DetailsAliasMap (Join-Path $hd 'nope')).Count 0 "no Hayabusa folder: an empty map, not an error"

    $logon = @{
        Provider = 'Microsoft-Windows-Security-Auditing'; EventID = 4624; RuleID = 'other'
        Details = @{ Type = 3; TgtUser = 'bob'; SrcIP = '10.0.0.5' }
        ExtraFieldInfo = @{ AuthenticationPackageName = 'NTLM'; WorkstationName = 'WS9' }
    } | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    $d = Get-EventData $logon $m
    Assert-Equal "$($d['TargetUserName'])/$($d['IpAddress'])/$($d['LogonType'])" 'bob/10.0.0.5/3' "Details come back under their real names"
    Assert-Equal $d['AuthenticationPackageName'] 'NTLM' "ExtraFieldInfo keeps its (already real) names"
    Assert-True (-not $d.Contains('TgtUser')) "no short name is left behind"

    $svc = @{ Provider = 'Service Control Manager'; EventID = 7045; RuleID = '11111111-2222-3333-4444-555555555555'
              Details = @{ Svc = 'evil'; Path = 'C:\x.exe' } } | ConvertTo-Json | ConvertFrom-Json
    $d = Get-EventData $svc $m
    Assert-Equal "$($d['ServiceName'])|$($d['ImagePath'])" 'evil|C:\x.exe' "a rule's own short names are translated by that rule's line"

    $deepDoc = @{ Provider = 'X'; EventID = 1; RuleID = '99999999-2222-3333-4444-555555555555'
                  Details = @{ Usr = 'eve' } } | ConvertTo-Json | ConvertFrom-Json
    Assert-Equal (Get-EventData $deepDoc $m)['SubjectUserName'] 'eve' "and its short names are translated"

    $plain = @{ Provider = 'Microsoft-Windows-PowerShell'; EventID = 4104; RuleID = 'x'
                Details = @{ Path = 'C:\s.ps1'; ScriptBlockText = 'iex' } } | ConvertTo-Json | ConvertFrom-Json
    $d = Get-EventData $plain $m
    Assert-Equal "$($d['Path'])|$($d['ScriptBlockText'])" 'C:\s.ps1|iex' "an event with no summary keeps its own field names (Path is real on 4104)"
    Assert-Equal (Get-EventData (@{ Details = '-' } | ConvertTo-Json | ConvertFrom-Json) $m).Count 0 "a Details that is not an object adds nothing"

    # ---- in the ECS document ----
    $ecs = ConvertTo-EcsDocument $logon 'id1' $m
    Assert-Equal $ecs.winlog.event_data['TargetUserName'] 'bob' "the ECS document carries winlog.event_data"
    Assert-True (-not $ecs.hayabusa.Contains('extra')) "hayabusa.extra is no longer written - all of it is in event_data"
    Assert-True ($ecs.hayabusa.Contains('details')) "Hayabusa's own summary (hayabusa.details) stays"

    # ---- the Python importer agrees ----
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { Write-Host "  [SKIP] python not found - twin comparison skipped" -ForegroundColor Yellow }
    else {
        $in = Join-Path $hd 'in.jsonl'; $out = Join-Path $hd 'out.jsonl'
        [IO.File]::WriteAllLines($in, [string[]]@(($logon, $svc, $plain, $deepDoc) | ForEach-Object { $_ | ConvertTo-Json -Depth 5 -Compress }))
        & { $ErrorActionPreference = 'Continue'; & $py.Source -I "$PSScriptRoot\..\scripts\hayabusa_to_ecs.py" $in -o $out --import-id t --hayabusa-dir $hd 2>$null }
        $pyDocs = @(Get-Content -LiteralPath $out -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json })
        $i = 0
        foreach ($doc in $logon, $svc, $plain, $deepDoc) {
            $mine   = (ConvertTo-EcsDocument $doc 't' $m).winlog.event_data
            $theirs = $pyDocs[$i].winlog.event_data
            $a = ($mine.Keys | Sort-Object | ForEach-Object { "$_=$($mine[$_])" }) -join ';'
            $b = ($theirs.PSObject.Properties | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ';'
            Assert-Equal $b $a "record ${i}: Python writes the same event_data"
            $i++
        }
    }
} finally {
    # Remove-Item cannot reach past 260 characters in PowerShell 5.1; rd can.
    cmd /c rd /s /q "\\?\$hd" 2>$null
    Remove-Item -LiteralPath $hd -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- the template maps every one of them, whatever its type ----
$t = Get-Content "$PSScriptRoot\..\code\index-template.json" -Raw | ConvertFrom-Json
$dyn = @($t.template.mappings.dynamic_templates | ForEach-Object { $_.PSObject.Properties.Value })
Assert-Equal (@($dyn | Where-Object { $_.path_match -eq 'winlog.event_data.*' -and $_.mapping.type -eq 'keyword' }).Count) 5 `
    "strings, numbers, booleans and dates under winlog.event_data all map as keyword - no type conflicts between events"
Assert-True (@($dyn | Where-Object { $_.mapping.ignore_above -ne 8191 }).Count -eq 0) "long values are kept but not indexed past 8191 characters (the 32 KB keyword limit)"
Assert-Equal $t.template.mappings.properties.winlog.properties.event_data.dynamic $true "event_data takes new fields, while the rest of the index stays strict"
Assert-True ([int]$t.template.settings.'mapping.total_fields.limit' -ge 10000) "the field limit leaves room for an ALL-logs collection"
