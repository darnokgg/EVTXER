# tests/run-tests.ps1
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$here\Assert.ps1"
Get-ChildItem "$here\*.Tests.ps1" | ForEach-Object {
    Write-Host "`n== $($_.Name) ==" -ForegroundColor Cyan
    # Without this, a file that blows up entirely - a renamed function, a typo,
    # a missing dot-source - runs no assertions at all, adds nothing to
    # $script:Failures, and the run still reports ALL TESTS PASSED. An erroring
    # test file has to count as a failure, not as silence.
    try {
        $ErrorActionPreference = 'Stop'
        . $_.FullName
    }
    catch {
        $script:Failures++
        Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "         test file did not run to completion" -ForegroundColor Red
    }
}
Write-Host "`n$([string]::new('=',40))"
if ($script:Failures -eq 0) { Write-Host "ALL TESTS PASSED" -ForegroundColor Green; exit 0 }
else { Write-Host "$($script:Failures) FAILURE(S)" -ForegroundColor Red; exit 1 }
