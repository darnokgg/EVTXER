# Runs only the named test files, exactly the way tests\run-tests.ps1 does.
#   powershell -NoProfile -File tools\dev\run-some-tests.ps1 -Names JobQueue,Layout
# (A test file run on its own fails with "Assert-Equal not recognized".
#  SoImport.Tests' "two hosts' Security.evtx" check fails when that file runs
#  alone - also at v47 - and passes in the full suite.)
param([string]$Names)
$here = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'tests'
. "$here\Assert.ps1"
$want = @($Names -split ',' | ForEach-Object { "$($_.Trim()).Tests.ps1" })
Get-ChildItem "$here\*.Tests.ps1" | Where-Object { $want -contains $_.Name } | ForEach-Object {
    Write-Host "`n== $($_.Name) ==" -ForegroundColor Cyan
    try { $ErrorActionPreference = 'Stop'; . $_.FullName }
    catch {
        $script:Failures++
        Write-Host "  [FAIL] $($_.Exception.Message) at $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
    }
}
"failures: $script:Failures"
