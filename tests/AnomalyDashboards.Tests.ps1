# tests/AnomalyDashboards.Tests.ps1
#
# The two Anomaly Hunt dashboards (2026-10-17) come from one generator,
# scripts\make_anomaly_dashboards.py: the same seven hunts on the raw-event
# data view (Security Onion) and on the detections data view (Security Onion
# and plain Elastic). This checks the generated objects: the right data view on
# every panel, every op.* field defined in scripts\anomaly_runtime_fields.py,
# all seven sections, and the descriptions an analyst relies on.
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Write-Host "  [SKIP] python not found - anomaly dashboard generator test skipped" -ForegroundColor Yellow; return }
$scripts = Join-Path $PSScriptRoot '..\scripts'
$out = Join-Path ([IO.Path]::GetTempPath()) ("anomaly-$PID.ndjson")
try {
    & { $ErrorActionPreference = 'Continue'; & $py.Source -I (Join-Path $scripts 'make_anomaly_dashboards.py') -o $out 2>$null } | Out-Null
    Assert-True (Test-Path -LiteralPath $out) "the generator writes its ndjson"
    $objs = @(Get-Content -LiteralPath $out -Encoding UTF8 | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
    $dash = @($objs | Where-Object { $_.type -eq 'dashboard' })
    Assert-Equal (($dash | ForEach-Object id | Sort-Object) -join ',') 'hayabusa-anomaly-dashboard,hayabusa-raw-anomaly-dashboard' "exactly the two Anomaly Hunt dashboards"
    Assert-Equal @($objs | Where-Object { $_.type -notin 'dashboard', 'lens' }).Count 0 "only lens and dashboard objects - the data views stay the existing ones"

    $views = @{
        'hayabusa-raw-anomaly-dashboard' = @{ Prefix = 'hayabusa-raw-anomaly-'; DataView = 'hayabusa-raw-dataview'; View = 'raw' }
        'hayabusa-anomaly-dashboard'     = @{ Prefix = 'hayabusa-anomaly-';     DataView = 'hayabusa-evtx-dataview'; View = 'detections' }
    }
    foreach ($d in $dash) {
        $v = $views[$d.id]
        $rt = (& { $ErrorActionPreference = 'Continue'; & $py.Source -I (Join-Path $scripts 'anomaly_runtime_fields.py') --view $v.View 2>$null }) -join "`n" | ConvertFrom-Json
        $defined = @($rt.PSObject.Properties.Name)
        $panelIds = @($d.references | Where-Object { $_.type -eq 'lens' } | ForEach-Object id)
        $lens = @($objs | Where-Object { $_.id -in $panelIds })
        Assert-Equal $lens.Count $panelIds.Count "$($d.id): every panel it places is generated"
        Assert-True ($lens.Count -ge 20) "$($d.id): a full dashboard ($($lens.Count) panels)"
        Assert-Equal @($lens | Where-Object { -not $_.id.StartsWith($v.Prefix) }).Count 0 "$($d.id): panel ids start with $($v.Prefix)"
        Assert-Equal @($lens | Where-Object { @($_.references | Where-Object { $_.id -ne $v.DataView }).Count }).Count 0 "$($d.id): every panel reads $($v.DataView) only"

        $used = @($lens | ForEach-Object { [regex]::Matches(($_ | ConvertTo-Json -Depth 30 -Compress), 'op\.[A-Za-z]+') | ForEach-Object Value } | Sort-Object -Unique)
        # op.HostApplication is the raw view's existing field (make_raw_hunt_dashboard.py).
        $missing = @($used | Where-Object { $_ -notin $defined -and $_ -ne 'op.HostApplication' })
        Assert-Equal ($missing -join ',') '' "$($d.id): every op.* field it uses is defined for the $($v.View) view"

        foreach ($n in 1..7) {
            Assert-True (@($lens | Where-Object { $_.attributes.title -like "$n.*" }).Count -ge 1) "$($d.id): section $n is there"
        }
        foreach ($l in $lens) {
            $t = $l.attributes.title; $desc = $l.attributes.description
            if ($t -match '^3\.' -or ($l | ConvertTo-Json -Depth 30 -Compress) -match 'op\.(HourUTC|DayUTC)') {
                Assert-True ($desc -match 'UTC') "$($d.id): '$t' says its hours/days are UTC"
            }
            if ($t -match '(?i)program|parent') {
                Assert-True ($desc -match 'Sysmon' -and $desc -match '4688') "$($d.id): '$t' names its sources (Sysmon, 4688)"
            }
            Assert-True ([bool]$desc) "$($d.id): '$t' has a description"
        }
        # The one nested table whose rows must both exist on every event: a
        # program start always has a process and (Sysmon 1 / 4688) a parent.
        $pc = @($lens | Where-Object { $_.attributes.title -like '1.*parent*' })
        Assert-Equal $pc.Count 1 "$($d.id): one parent > child table in section 1"
        $layer = $pc[0].attributes.state.datasourceStates.formBased.layers.layer1
        $rows = @($layer.columnOrder | Where-Object { $layer.columns.$_.isBucketed } | ForEach-Object { $layer.columns.$_.sourceField })
        Assert-Equal ($rows -join ' > ') 'op.ParentPath > op.ProcPath' "$($d.id): parent > child rows are the parent then the program"
        # Section 1 ranks by fewest machines: its first row is ordered by a distinct count, ascending.
        $first = $layer.columns.($layer.columnOrder[0])
        $orderCol = $layer.columns.($first.params.orderBy.columnId)
        Assert-True ($orderCol.operationType -eq 'unique_count' -and $first.params.orderDirection -eq 'asc') "$($d.id): 'only on one machine' ranks by fewest machines"
    }
    # Lab run, 2026-10-17: "-" (a local logon has no source IP) topped the
    # fan-out sources, and built-in accounts (SYSTEM, ANONYMOUS LOGON, DWM-n,
    # UMFD-n, sshd_n) crowded every account panel.
    foreach ($l in @($objs | Where-Object { $_.type -eq 'lens' -and $_.attributes.title -like '6.*source*' })) {
        # Real machines (2026-10-17): ::1 - a machine logging on to itself - topped
        # the sources; "-" is a local logon. All three must be NEGATED.
        Assert-True ($l.attributes.state.query.query -match 'not [\w.]+: \("-" or "::1" or "127\.0\.0\.1"\)') "'$($l.attributes.title)' leaves out '-' and loopback sources"    }
    # Real machines: the TaskScheduler log is OFF by default on Windows 10/11.
    foreach ($l in @($objs | Where-Object { $_.type -eq 'lens' -and $_.attributes.title -match 'scheduled task' })) {
        Assert-True ($l.attributes.description -match 'off by default') "'$($l.attributes.title)' says the task logs are off by default"
    }
    foreach ($l in @($objs | Where-Object { $_.type -eq 'lens' -and $_.attributes.title -match 'account' })) {
        $q = $l.attributes.state.query.query
        Assert-True ($q -match 'not op\.BuiltinAccount: true') "'$($l.attributes.title)' leaves out Windows' built-in accounts"
        Assert-True ($q -notmatch '\w-\*' -and $q -notmatch '_\*') "'$($l.attributes.title)' excludes no account by a name prefix (an attacker could hide behind one)"
    }
    # Final review, 2026-10-17: the longest lines must not be dropped by a
    # keyword's ignore_above (detections ranked process.command_line), and
    # section 1 must not cap the outlier off an alphabetical tie list.
    $long = @($objs | Where-Object { $_.type -eq 'lens' -and $_.attributes.title -eq '7. Longest command lines' })
    foreach ($l in $long) {
        $layer = $l.attributes.state.datasourceStates.formBased.layers.layer1
        Assert-Equal $layer.columns.($layer.columnOrder[0]).sourceField 'op.CmdLine' "$($l.id): ranks op.CmdLine, which has no ignore_above"
    }
    foreach ($l in @($objs | Where-Object { $_.type -eq 'lens' -and $_.attributes.title -like '1.*' })) {
        $layer = $l.attributes.state.datasourceStates.formBased.layers.layer1
        Assert-True ($layer.columns.($layer.columnOrder[0]).params.size -ge 500) "$($l.id): shows enough rows that the outlier is not cut off by name order"
    }
    $rawPs = @($objs | Where-Object { $_.id -like 'hayabusa-raw-anomaly-*' -and ($_ | ConvertTo-Json -Depth 30 -Compress) -match 'op\.HostApplication' })
    Assert-True ($rawPs.Count -ge 1) "the raw dashboard hunts PowerShell start lines (400) - always logged"
    Assert-Equal @($objs | Where-Object { $_.id -like 'hayabusa-anomaly-*' -and ($_ | ConvertTo-Json -Depth 30 -Compress) -match 'op\.HostApplication' }).Count 0 "the detections dashboard has no 400 start lines to hunt"
}
finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
