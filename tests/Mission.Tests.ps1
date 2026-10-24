# tests/Mission.Tests.ps1
#
# One index per mission, deleted when the mission ends.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

Assert-Equal (Get-MissionIndexName 'Op Falcon 2026') 'hayabusa-mission-op-falcon-2026' "a mission name becomes one fixed index name"
Assert-Equal (Get-MissionIndexName 'op-falcon') (Get-MissionIndexName 'OP-FALCON') "however it is typed"
Assert-True ((Get-MissionIndexName 'op-falcon') -notmatch '\d{8}') "with no date in it - every day and every host of the mission append to it"
Assert-True (Test-HayabusaIndexName (Get-MissionIndexName 'op/falcon#1')) "odd characters still give a valid, guarded name"
Assert-Equal (Get-MissionIndexName '  ') '' "no mission, no index"

# ---- what Delete may remove: exactly one hayabusa- index ----
Assert-True (Test-DeletableIndexName 'hayabusa-mission-op-falcon') "the mission's own index"
foreach ($bad in 'hayabusa-*', 'hayabusa-mission-a,logs-import-so', 'logs-import-so', '.kibana', 'hayabusa-mission-?', 'so-case', '', '_all', '*') {
    Assert-True (-not (Test-DeletableIndexName $bad)) "never '$bad' - a wildcard, a list or another product's data could go with it"
}

# ---- the mission survives a restart ----
$conf = Join-Path ([IO.Path]::GetTempPath()) ("mission-{0}.json" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
try {
    $s = Read-ToolSettings $conf; $s.MissionName = 'op-falcon'; Save-ToolSettings $s $conf
    Assert-Equal (Read-ToolSettings $conf).MissionName 'op-falcon' "the mission is remembered in settings.conf"
} finally { Remove-Item -LiteralPath $conf -ErrorAction SilentlyContinue }

# ---- the Settings tab ----
$set = Get-Content (Join-Path $PSScriptRoot '..\code\wpf-settings.ps1') -Raw
Assert-True ($set -match 'Read-TypedConfirmation' -and $set -match '\$typed\.Text\.Trim\(\) -ceq \$MustType') "deleting needs the index name typed, exactly"
Assert-True ($set -match "Test-DeletableIndexName \`$idx") "and only an index that passes the delete guard"
Assert-True ($set -match "Confirm-PcapBeforeNetwork `"delete the mission index") "it asks about the capture like every network action"
Assert-True ($set -match "New-LedgerRow -Action 'Delete index'") "and the deletion is in the activity log"
