# tests/StagingCleanup.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# Staging used to be one fixed folder, C:\Windows\Temp\EVTX_Export, reused by
# every run and cleaned only on the success path - the Remove-Item sat inside
# the try, so any host that threw kept its exports. Then:
#
#   * the next run's wevtutil epl fails for some log, Test-Path finds LAST
#     run's file still sitting there, and it gets copied back and analysed as
#     if it were current. Evidence from the wrong collection, silently.
#   * two examiners collecting the same host at once delete each other's
#     exports mid-transfer.
#
# A unique folder per run fixes both. The cost is that a hard kill (process
# terminated, laptop closed) now orphans something the fixed-name purge list
# will never match - and a stray artifact in C:\Windows\Temp on a client's
# domain controller is exactly what an investigation is meant to notice.
#
# So orphans get swept, and AGE is what makes the sweep safe: anything written
# recently belongs to a collection that is still running and may not even be
# ours. That single rule governs everything the sweep may delete, which is why
# it is one predicate and not three.

# ---- every run gets its own folder ----
$a = New-EvtxStagingPath
$b = New-EvtxStagingPath
Assert-True ($a -ne $b) "two runs never share a staging folder"

$base = (Get-EvtxStagingPaths)[0]
Assert-True ($a.StartsWith("$base`_")) "the per-run folder is the base name plus a run token"
Assert-True ($a -match '_[0-9a-f]{8}$')  "the run token is a short hex suffix"

# The base literal lives in Get-EvtxStagingPaths so the purge list and the
# write path cannot drift apart - that is the rule CollectorPaths pins.
Assert-Equal (Split-Path -Parent $a) (Split-Path -Parent $base) "per-run folders live beside the base name"

$now = Get-Date '2026-09-09 12:00:00'

# ---- per-run FOLDERS ----
Assert-True (Test-StaleStagingItem -Name 'EVTX_Export_a1b2c3d4' -LastWrite $now.AddHours(-48) -Now $now) `
    "a two-day-old orphaned folder is swept"
Assert-True (-not (Test-StaleStagingItem -Name 'EVTX_Export_a1b2c3d4' -LastWrite $now.AddMinutes(-5) -Now $now)) `
    "a folder written five minutes ago belongs to a running collection and is left alone"
Assert-True (-not (Test-StaleStagingItem -Name 'EVTX_Export_a1b2c3d4' -LastWrite $now.AddHours(-23) -Now $now)) `
    "a long collection still under the age limit is left alone"

# ---- per-run ZIP ARCHIVES ----
# The zip transfer builds "<staging>.zip" NEXT TO the staging folder, not
# inside it, so a directory-only sweep never saw it. It is also the largest
# thing this tool ever writes to a target - a multi-GB archive abandoned in
# C:\Windows\Temp on someone's domain controller - and the only code that
# removed it was on the normal path, so a session that dropped after
# Compress-Archive stranded it even without a hard kill.
Assert-True (Test-StaleStagingItem -Name 'EVTX_Export_a1b2c3d4.zip' -LastWrite $now.AddHours(-48) -Now $now) `
    "an abandoned per-run archive is swept, not just the folder"
Assert-True (-not (Test-StaleStagingItem -Name 'EVTX_Export_a1b2c3d4.zip' -LastWrite $now.AddMinutes(-5) -Now $now)) `
    "an archive still being written by a running collection is left alone"

# ---- the fixed legacy names ----
# These used to be deleted unconditionally on every successful cleanup. The
# name proves the folder is ours; it does NOT prove nobody is using it right
# now, and an older build of this collector running against the same host
# concurrently would have had its exports pulled out from under it. Same age
# rule as everything else - being ours is not a licence to delete it while it
# is in use.
Assert-True (Test-StaleStagingItem -Name 'EVTX_Export' -LastWrite $now.AddHours(-48) -Now $now) `
    "an old leftover from the fixed-name era is swept"
Assert-True (Test-StaleStagingItem -Name 'LOOT_Export' -LastWrite $now.AddHours(-48) -Now $now) `
    "the legacy LOOT_Export name is swept too"
Assert-True (-not (Test-StaleStagingItem -Name 'EVTX_Export' -LastWrite $now.AddMinutes(-2) -Now $now)) `
    "a fixed-name folder written two minutes ago is in use by another collector and is left alone"

# ---- clock skew ----
# A target clock running fast must not make everything look ancient, and must
# not make a genuine orphan look fresh either - future timestamps are simply
# not stale.
Assert-True (-not (Test-StaleStagingItem -Name 'EVTX_Export_a1b2c3d4' -LastWrite $now.AddHours(6) -Now $now)) `
    "a future timestamp is not treated as stale"

# ---- the sweep only ever touches things this tool names ----
# It runs against C:\Windows\Temp on a machine we do not own. Deleting anything
# we did not create there is unacceptable, so every match is anchored, never a
# substring.
Assert-True (-not (Test-StaleStagingItem -Name 'NotEVTX_Export_aaaaaaaa' -LastWrite $now.AddHours(-48) -Now $now)) `
    "a name that merely contains ours is not ours"
Assert-True (-not (Test-StaleStagingItem -Name 'EVTX_Export_a1b2c3d4.zip.bak' -LastWrite $now.AddHours(-48) -Now $now)) `
    "a name that merely starts with ours is not ours"
Assert-True (-not (Test-StaleStagingItem -Name 'EVTX_Export_zzz' -LastWrite $now.AddHours(-48) -Now $now)) `
    "a run token that is not hex is not one of ours"
Assert-True (-not (Test-StaleStagingItem -Name 'IIS_Logs' -LastWrite $now.AddHours(-48) -Now $now)) `
    "somebody else's ancient temp folder is never touched"
Assert-True (-not (Test-StaleStagingItem -Name 'Temp' -LastWrite $now.AddHours(-48) -Now $now)) `
    "an unrelated name is never touched"
