# tests/CsvOutput.Tests.ps1

# The CSV pass re-runs the scan the JSONL pass just logged. Without -q and -N
# the launch banner and the whole Results Summary print into the log twice.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
$csvLine = @(Get-Content "$PSScriptRoot\..\code\wpf-convert.ps1" | Where-Object { $_ -match '\$csvArgs\s*=' })[0]
Assert-True ($csvLine -match 'Get-HayabusaScanArgs .*-Format csv .*-Quiet') "the CSV pass asks for the quiet csv arguments"
$csvArgs = Get-HayabusaScanArgs -EvtxDir 'C:\e' -OutFile 'C:\o.csv' -Format csv -Quiet
Assert-True ($csvArgs -contains '-q') "the CSV pass is quiet (-q, no banner)"
Assert-True ($csvArgs -contains '-N') "the CSV pass skips the Results Summary (-N)"

# Discovered, not hard-coded: the binary is replaced on every Hayabusa upgrade,
# and a stale filename here turns a real failure into a silent [SKIP].
$exe = @(Get-ChildItem "$PSScriptRoot\..\code\hayabusa-x64" -Filter 'hayabusa*.exe' -File -ErrorAction SilentlyContinue)[0].FullName
# One harmless sample (a new local user), not the whole attack corpus: since
# Hayabusa 4.2.0 Windows Defender quarantines a CSV that quotes the corpus's
# Mimikatz command lines, and the test could no longer read its own output.
$evtx = "$PSScriptRoot\..\evtx-samples\hayabusa-sample-evtx-main\DeepBlueCLI\new-user-security.evtx"
if (-not $exe -or -not (Test-Path $exe) -or -not (Test-Path -LiteralPath $evtx)) {
    Write-Host "  [SKIP] hayabusa binary or evtx-samples absent - CSV output test skipped" -ForegroundColor Yellow
    return
}
$out = "$env:TEMP\csvtest_$PID.csv"
& $exe dfir-timeline -f $evtx -t csv -o $out -p super-verbose -w -O -b -C -q 2>$null | Out-Null
Assert-True (Test-Path $out) "CSV file produced"
Assert-True ((Get-Content $out -TotalCount 1) -match ',') "CSV has a header row"
Remove-Item $out -ErrorAction SilentlyContinue
