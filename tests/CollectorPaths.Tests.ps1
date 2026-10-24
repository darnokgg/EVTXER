# tests/CollectorPaths.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$collector = Get-Content "$PSScriptRoot\..\code\EvtxCollector.ps1" -Raw

# ---- the staging folder is created on SOMEONE ELSE'S domain controller ----
# A directory called LOOT_Export sitting in C:\Windows\Temp on a client's DC
# opens incident tickets and reads terribly in a report. The name is operator
# -visible on a machine we do not own, so it is not cosmetic.
Assert-True ($collector -notmatch 'LOOT') "no LOOT anywhere in the collector"

# The literal lives in Get-EvtxStagingPaths, not here: one source of truth for
# a path that has to be created, written to, and purged in three places. So the
# collector must REFERENCE it and must not hard-code a staging path of its own,
# which is how the current and legacy names would drift apart again.
Assert-True ($collector -match 'Get-EvtxStagingPaths') `
    "the collector takes its staging folder from Get-EvtxStagingPaths"
Assert-True ($collector -notmatch [regex]::Escape('C:\Windows\Temp\')) `
    "the collector hard-codes no staging path of its own"

# The list of folders to purge is a function so the dual-name rule is testable
# rather than buried in a Remove-Item line.
$paths = Get-EvtxStagingPaths
Assert-True ($paths -contains 'C:\Windows\Temp\EVTX_Export') "staging paths include the current name"
Assert-True ($paths -contains 'C:\Windows\Temp\LOOT_Export') "staging paths include the legacy name, so old folders still get purged"
Assert-Equal $paths.Count 2 "exactly two staging paths - current and legacy"

# The first entry is the CURRENT name; the rest are legacy names to clean.
Assert-Equal $paths[0] 'C:\Windows\Temp\EVTX_Export' "the current name is first"

# Collection no longer writes to $paths[0] itself - it writes to a per-run
# folder derived from it, because one shared folder let a crashed run's
# leftovers be picked up by the next run as current evidence. That derivation
# is pinned in StagingCleanup.Tests.ps1, which asserts it more strictly than
# here (it requires the separator too), so this file does not repeat it.

# Both cleanup paths have to be reachable from the collector: the explicit
# list for the fixed legacy names, and the age sweep for per-run folders
# orphaned by a hard kill.
Assert-True ($collector -match 'Test-StaleStagingItem') `
    "the collector sweeps orphaned per-run staging items by age"
Assert-True ($collector -match 'New-EvtxStagingPath') `
    "the collector takes its per-run staging folder from New-EvtxStagingPath"
