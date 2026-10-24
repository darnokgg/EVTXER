# tests/WinRmTransfer.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$max = Get-WinRmZipCeilingBytes

# ---- the normal case: one zip beats N base64 round-trips ----
Assert-Equal (Select-WinRmTransferMode -ExportedBytes (200MB) -RemotePsMajor 5) 'Zip' `
    "a normal DFIR export is zipped"

# ---- Compress-Archive arrived in PowerShell 5.0; older targets cannot zip ----
Assert-Equal (Select-WinRmTransferMode -ExportedBytes (200MB) -RemotePsMajor 4) 'PerFile' `
    "a PowerShell 4 target falls back to per-file"
Assert-Equal (Select-WinRmTransferMode -ExportedBytes (200MB) -RemotePsMajor 0) 'PerFile' `
    "an undetectable remote PowerShell version falls back to per-file"

# ---- PS 5.1 Compress-Archive tops out near 2 GB ----
Assert-Equal (Select-WinRmTransferMode -ExportedBytes (4GB) -RemotePsMajor 5) 'PerFile' `
    "an oversized export falls back to per-file"
Assert-True ($max -lt 2GB) "the ceiling stays below the 2 GB Compress-Archive limit"
Assert-Equal (Select-WinRmTransferMode -ExportedBytes $max -RemotePsMajor 5) 'Zip' `
    "an export exactly at the ceiling still zips"
Assert-Equal (Select-WinRmTransferMode -ExportedBytes ($max + 1) -RemotePsMajor 5) 'PerFile' `
    "one byte over the ceiling falls back to per-file"

# ---- an unmeasurable export must never be gambled on ----
Assert-Equal (Select-WinRmTransferMode -ExportedBytes 0 -RemotePsMajor 5) 'PerFile' `
    "an export whose size could not be measured falls back to per-file"
Assert-Equal (Select-WinRmTransferMode -ExportedBytes (-1) -RemotePsMajor 5) 'PerFile' `
    "a negative size falls back to per-file"
