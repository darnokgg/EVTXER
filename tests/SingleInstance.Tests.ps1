# tests/SingleInstance.Tests.ps1
#
# One operator at a time per install. A second
# EVTXER on the same install is refused and told who has it open; another
# install is not blocked; a dead EVTXER never locks the install.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$a = Join-Path ([IO.Path]::GetTempPath()) ("inst-a-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$b = Join-Path ([IO.Path]::GetTempPath()) ("inst-b-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $a, $b -Force | Out-Null
$lib = Join-Path $PSScriptRoot '..\code\HayabusaLib.ps1'
$ready = Join-Path $a 'child-ready'
try {
    Assert-True ((Get-InstanceMutexName $a) -ne (Get-InstanceMutexName $b)) "each install has its own lock"
    Assert-Equal (Get-InstanceMutexName "$a\") (Get-InstanceMutexName $a.ToUpperInvariant()) "however its folder is spelled"
    Assert-True ((Get-InstanceMutexName $a) -like 'Global\*') "and it is Global, so another RDP session sees it too"

    # Another process takes install A and holds it for a while.
    $child = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList @('-NoProfile', '-Command',
        ". '$lib'; `$i = Enter-SingleInstance '$a'; if (`$i.Ok) { New-Item -ItemType File -Path '$ready' | Out-Null; Start-Sleep 20 }")
    foreach ($n in 1..60) { if (Test-Path -LiteralPath $ready) { break }; Start-Sleep -Milliseconds 250 }
    Assert-True (Test-Path -LiteralPath $ready) "the first EVTXER takes the install"

    $second = Enter-SingleInstance $a
    Assert-True (-not $second.Ok) "a second EVTXER on the same install is refused"
    Assert-True ($second.Holder -like "*$env:USERNAME*" -and $second.Holder -match "process $($child.Id)") "and told who has it open ($($second.Holder))"

    $other = Enter-SingleInstance $b
    Assert-True $other.Ok "another install on the same machine opens normally"
    $other.Mutex.Dispose()

    # The holder dies without cleaning up - a crash. The install is free.
    Stop-Process -Id $child.Id -Force; $child.WaitForExit(10000) | Out-Null
    $after = Enter-SingleInstance $a
    Assert-True $after.Ok "after the first EVTXER dies - even in a crash - the install opens again"
    $after.Mutex.Dispose()
} finally {
    Get-Process -Id $child.Id -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $a, $b -Recurse -Force -ErrorAction SilentlyContinue
}
$shell = Get-Content (Join-Path $PSScriptRoot '..\code\HayabusaMissionTool.ps1') -Raw
Assert-True ($shell.IndexOf('Enter-SingleInstance') -lt $shell.IndexOf('# ============================================================== XAML')) "the launcher checks before it builds any window"
