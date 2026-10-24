# tests/Collector.Contract.Tests.ps1
. "$PSScriptRoot\..\code\EvtxCollector.ps1"
$cmd = Get-Command Invoke-EvtxCollection
foreach ($p in 'Targets','Method','Category','CustomLogs','Credential','Domain','OutRoot','LogWriter') {
    Assert-True $cmd.Parameters.ContainsKey($p) "has -$p parameter"
}
Assert-Equal ($cmd.Parameters['Method'].Attributes.ValidValues -join ',') 'SMB,WinRM,WinRM-HTTPS' "Method is SMB|WinRM|WinRM-HTTPS"
Assert-Equal ($cmd.Parameters['Category'].Attributes.ValidValues -join ',') 'DFIR,All,Custom' "Category is DFIR|All|Custom"

# ---- the WinRM path must actually use the transfer-mode decision ----
# Select-WinRmTransferMode is unit-tested on its own, so the realistic
# regression is not that it computes the wrong answer - it is that someone
# stops calling it, or drops the per-file fallback, and every host silently
# goes back to N base64 round-trips (or worse, fails outright on a PS 4 target).
$src = Get-Content "$PSScriptRoot\..\code\EvtxCollector.ps1" -Raw
Assert-True ($src -match 'Select-WinRmTransferMode') "the collector consults Select-WinRmTransferMode"
Assert-True ($src -match 'Compress-Archive')         "the collector can zip on the target"
Assert-True ($src -match 'Falling back to per-file') "a failed zip falls back to per-file copy"

# ---- the zip is cleaned up as deliberately as the folder it came from ----
# Compress-Archive writes "<staging>.zip" NEXT TO the staging folder, so the
# per-host cleanup has to name it explicitly - a folder sweep will never see
# it, and it is the largest artifact this tool ever leaves on a target.
Assert-True ($src -match '\.zip') "the collector knows the archive name it has to clean up"

# ---- Verify Access proves the transfer, not just the export ----
# wevtutil gli says the log is readable and the staging probe says the target
# can be written to, but neither sends a single byte back over WS-Man. WSMan
# envelope/transfer limits and a full local disk both fail at exactly that
# step, which used to mean they surfaced twenty minutes into a real
# collection - the thing Verify Access exists to prevent.
$verify = [regex]::Match($src, '(?s)function Test-CollectAccess.*').Value
Assert-True ($verify.Length -gt 0)              "Test-CollectAccess is present"
Assert-True ($verify -match '-FromSession')     "Verify Access pulls a sample file back over the session"
Assert-True ($verify -match 'Test-CopiedFile')  "Verify Access verifies what it pulled back, the same way collection does"
