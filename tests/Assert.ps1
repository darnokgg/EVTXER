# tests/Assert.ps1
$script:Failures = 0
function Assert-Equal($Actual, $Expected, $Msg) {
    if ($Actual -ceq $Expected) { Write-Host "  [PASS] $Msg" -ForegroundColor Green }
    else { $script:Failures++; Write-Host "  [FAIL] $Msg`n         expected: $Expected`n         actual  : $Actual" -ForegroundColor Red }
}
function Assert-True($Cond, $Msg) {
    if ($Cond) { Write-Host "  [PASS] $Msg" -ForegroundColor Green }
    else { $script:Failures++; Write-Host "  [FAIL] $Msg (condition was false)" -ForegroundColor Red }
}
function Assert-Throws([scriptblock]$Block, $Msg) {
    try { & $Block; $script:Failures++; Write-Host "  [FAIL] $Msg (no exception)" -ForegroundColor Red }
    catch { Write-Host "  [PASS] $Msg" -ForegroundColor Green }
}

# The launcher is now a WPF shell plus one file per tab, so "the tool's source"
# is all of them. A test that read only the shell would pass while the code it
# is guarding sat in a tab file.
function Get-ToolSourceFiles {
    $root = Split-Path -Parent $PSScriptRoot
    @(Join-Path $root 'code\HayabusaMissionTool.ps1') +
    @(Get-ChildItem -Path (Join-Path $root 'code\wpf-*.ps1') -File -ErrorAction SilentlyContinue |
      Sort-Object Name | Select-Object -ExpandProperty FullName)
}
function Get-ToolSource      { (Get-ToolSourceFiles | ForEach-Object { Get-Content $_ -Raw }) -join "`n" }
function Get-ToolSourceLines { Get-ToolSourceFiles | ForEach-Object { Get-Content $_ } }
