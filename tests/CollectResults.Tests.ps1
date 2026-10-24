# tests/CollectResults.Tests.ps1
#
# "Which IPs came back?" The summary's counts say how many, not which, so the
# collector returns one row per target and the Collect tab prints and saves it.
# Runs offline: .invalid never resolves (RFC 2606).
. "$PSScriptRoot\..\code\EvtxCollector.ps1"

# ---- the formatter: one coloured line per target ----
$rows = @(
    (New-CollectHostResult '10.0.0.5' 'CORP\admin' 'Success' 6 6 'C:\x\evtx\10.0.0.5_20260927_1412' '')
    (New-CollectHostResult '10.0.0.6' 'CORP\admin' 'Partial' 5 6 'C:\x\evtx\10.0.0.6_20260927_1412' 'missing: Security')
    (New-CollectHostResult '10.0.0.9' 'CORP\admin' 'Failed'  0 6 '' "Access is denied.`r`n  second line")
)
$lines = @(Format-CollectResults $rows)
Assert-Equal $lines.Count 3 "one line per target"
Assert-True ($lines[0].Text -match '^\s+OK\s+10\.0\.0\.5') "a success reads OK with its target"
Assert-True ($lines[0].Text -match '10\.0\.0\.5_20260927_1412$') "a success names its evidence folder"
Assert-True ($lines[0].Text -notlike '*C:*') "the folder is shown as its leaf, not the full path"
Assert-Equal $lines[0].Kind 'ok'   "a success is green"
Assert-Equal $lines[1].Kind 'warn' "a partial is amber"
Assert-Equal $lines[2].Kind 'err'  "a failure is red"
Assert-True ($lines[1].Text -match '5/6')              "a partial shows collected of requested"
Assert-True ($lines[2].Text -match 'FAILED.*denied')   "a failure shows why"
Assert-True ($lines[2].Text -notmatch "`n")            "a multi-line error is flattened to one line"
Assert-Equal @(Format-CollectResults @()).Count 0      "no targets, no lines"

# ---- the CSV: same rows, readable back ----
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("results-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $csv = Export-CollectResults $rows (Join-Path $tmp 'collection.csv')
    $back = @(Import-Csv -LiteralPath $csv)
    Assert-Equal $back.Count 3 "the CSV has a row per target"
    Assert-Equal $back[0].Target '10.0.0.5' "the CSV names the target"
    Assert-Equal $back[0].Outcome 'Success' "the CSV carries the outcome"
    Assert-Equal $back[0].Folder 'C:\x\evtx\10.0.0.5_20260927_1412' "the CSV keeps the full folder path"
    Assert-Equal $back[2].Account 'CORP\admin' "the CSV records the account used"

    # ---- the collector: every target gets a row, failed ones included ----
    $res = Invoke-EvtxCollection -Targets @('no-such-host-a1.invalid','no-such-host-b2.invalid') `
               -Method 'SMB' -Category 'DFIR' -CustomLogs @() `
               -Credential (New-CollectCredential 'admin' 'x') -Domain '' `
               -OutRoot $tmp -LogWriter { param($m) }
    $h = @($res.Hosts)
    Assert-Equal $h.Count 2 "the summary has a row per target"
    Assert-Equal $h[0].Target 'no-such-host-a1.invalid' "rows keep the target order"
    Assert-Equal $h[0].Outcome 'Failed' "an unreachable target is recorded as failed"
    Assert-Equal $h[0].Account 'no-such-host-a1.invalid\admin' "the row records the per-target account"
    Assert-True ([bool]$h[0].Detail) "a failed row says why"
}
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
