# tests/PipeSession.ps1 - a REAL PSSession without WinRM or admin: one to a
# second local powershell.exe over the named pipe Enter-PSHostProcess uses.
# PS 5.1 has no public way to wrap that runspace as a PSSession, hence the
# reflection - test-only. Dot-sourced by the tests that need a target.
function New-PipeSession {
    $p = Start-Process powershell -ArgumentList '-NoProfile', '-NoExit', '-Command', '$null' -PassThru -WindowStyle Hidden
    $ci = New-Object System.Management.Automation.Runspaces.NamedPipeConnectionInfo($p.Id)
    $rs = [runspacefactory]::CreateRunspace($ci)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ($true) {
        try { $rs.Open(); break }
        catch { if ([DateTime]::UtcNow -gt $deadline) { throw }; Start-Sleep -Milliseconds 300; $rs = [runspacefactory]::CreateRunspace($ci) }
    }
    $ctor = [System.Management.Automation.Runspaces.PSSession].GetConstructors('NonPublic,Instance') |
        Where-Object { $a = $_.GetParameters(); $a.Count -eq 1 -and $a[0].ParameterType.Name -eq 'RemoteRunspace' } |
        Select-Object -First 1
    [pscustomobject]@{ Session = $ctor.Invoke(@($rs)); Process = $p }
}
