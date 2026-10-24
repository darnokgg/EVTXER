# tests/SoImport.Integration.Tests.ps1
#
# The Raw Events tab's whole round trip against a REAL Security Onion manager:
# the same plink/pscp commands the tab runs (Get-PlinkArgs, Get-PscpArgs,
# Get-SoRemoteCommand), with sudo's password on stdin through the same
# process pump. Two hosts' Security.evtx (same name) are imported, then the
# same files again, which so-import-evtx must skip, and the staging folder
# must be gone afterwards.
#
#   $env:TEST_SO_HOST      the manager (tested on a throwaway Import node)
#   $env:TEST_SO_USER      an account that may sudo WITH a password
#   $env:TEST_SO_PASSWORD_FILE  a file holding the password (preferred - a
#                               secret in the environment reaches every child
#                               process), or $env:TEST_SO_PASSWORD
#   $env:TEST_SO_PORT      optional, 22
#
# Skips cleanly when TEST_SO_HOST is not set. Imports two small sample EVTX
# into that Security Onion's logs-import-so data stream - never point it at a
# production manager without asking.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$soHost = $env:TEST_SO_HOST
if (-not $soHost) { Write-Host "  [SKIP] TEST_SO_HOST not set - live Security Onion import test skipped" -ForegroundColor Yellow; return }
$soUser = $env:TEST_SO_USER
$soPass = if ($env:TEST_SO_PASSWORD_FILE) { (Get-Content -LiteralPath $env:TEST_SO_PASSWORD_FILE -Raw).Trim() } else { $env:TEST_SO_PASSWORD }
$soPort = if ($env:TEST_SO_PORT) { [int]$env:TEST_SO_PORT } else { 22 }
Initialize-ProcessPump

function Invoke-Pump([string]$Exe, [string[]]$Arguments, [string]$StdIn) {
    $p = New-Object EvtxerProcessPump($Exe, (ConvertTo-ProcessArgumentLine $Arguments), '', $StdIn)
    $lines = New-Object System.Collections.Generic.List[string]
    try {
        while ($true) {
            $done = $p.IsDone
            foreach ($l in $p.Drain()) { $lines.Add($l) }
            if ($done) { break }
            Start-Sleep -Milliseconds 100
        }
        [pscustomobject]@{ Code = $p.ExitCode; Lines = @($lines) }
    } finally { $p.Dispose() }
}

$plink = Find-PuttyTool plink; $pscp = Find-PuttyTool pscp
$probe = Invoke-Pump $plink (Get-PlinkArgs -HostName $soHost -Port $soPort -User $soUser -Command 'exit') $null
$key = Get-SshHostKeyFingerprint ($probe.Lines -join "`n")
Assert-True ($key -match '^SHA256:') "Fetch reads the manager's host key ($key)"

$pw = New-PasswordFile $soPass
$remote = New-SoImportStagingDir
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("soimp-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
try {
    $run = { param($cmd, [switch]$Sudo)
        $in = if ($Sudo) { "$soPass`n" } else { $null }
        Invoke-Pump $plink (Get-PlinkArgs -HostName $soHost -Port $soPort -User $soUser -HostKey $key -PasswordFile $pw -Command $cmd) $in }

    $t = & $run (Get-SoRemoteCommand Test) -Sudo
    $v = Get-SoTestVerdict $t.Lines
    Assert-True ($v.Ssh -and $v.Sudo -and $v.Importer) "TEST CONNECTION: SSH, sudo with the password on stdin, and so-import-evtx all OK"
    Assert-True (-not ($t.Lines -join "`n").Contains($soPass)) "the password never comes back in the output"

    $bad = Invoke-Pump $plink (Get-PlinkArgs -HostName $soHost -Port $soPort -User $soUser -HostKey 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' -PasswordFile $pw -Command 'echo EVTXER-SSH-OK') $null
    Assert-True ($bad.Code -ne 0 -and -not (Get-SoTestVerdict $bad.Lines).Ssh) "a wrong host key is refused - the pin is enforced"

    # Two "hosts", the same file name, different logs.
    $samples = @(Get-ChildItem "$PSScriptRoot\..\evtx-samples" -Recurse -Filter *.evtx -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.Length -gt 60KB -and $_.Length -lt 2MB } | Select-Object -First 2)
    Assert-Equal $samples.Count 2 "two sample EVTX to import"
    $files = @()
    foreach ($i in 0, 1) {
        $d = Join-Path $tmp "HOST$i`_20261015_1200"; New-Item -ItemType Directory -Path $d -Force | Out-Null
        Copy-Item -LiteralPath $samples[$i].FullName -Destination (Join-Path $d 'Security.evtx')
        $files += Get-Item -LiteralPath (Join-Path $d 'Security.evtx')
    }

    $s = & $run (Get-SoRemoteCommand Stage $remote)
    Assert-True ($s.Lines -match 'EVTXER-STAGED') "the staging folder is created"
    $n = 0
    foreach ($f in $files) {
        $n++
        $c = Invoke-Pump $pscp (Get-PscpArgs -HostName $soHost -Port $soPort -User $soUser -HostKey $key -PasswordFile $pw `
                                   -LocalFile $f.FullName -RemotePath "$remote/$(Get-SoImportRemoteName $n $f.FullName)") $null
        Assert-Equal $c.Code 0 "pscp copies file $n"
    }
    $ls = & $run "ls $remote"
    Assert-Equal @($ls.Lines | Where-Object { $_ -match '\.evtx$' }).Count 2 "both same-named files arrive, under different names"

    $imp = & $run (Get-SoRemoteCommand Import $remote) -Sudo
    $r = Get-SoImportResult $imp.Lines
    Assert-True $r.Complete "so-import-evtx completes"
    Assert-Equal ($r.Imported + $r.Skipped) 2 "both files are accounted for ($($r.Imported) imported, $($r.Skipped) skipped)"
    Assert-True ($r.Url -match '#/dashboards\?q=import\.id') "the link to the imported events is read"
    Assert-True ($r.WideUrl -ne $r.Url -and $r.WideUrl -match '&t=\d{4}%2F\d{2}%2F\d{2}%2000%3A00%3A00%20AM%20-%20\d{4}%2F\d{2}%2F\d{2}%2000%3A00%3A00%20AM&') "the real link is widened to reach the import time ($($r.WideUrl -replace '^.*&t=', 't='))"

    $again = & $run (Get-SoRemoteCommand Import $remote) -Sudo
    $r2 = Get-SoImportResult $again.Lines
    Assert-Equal "$($r2.Imported)/$($r2.Skipped)" '0/2' "the same files again: nothing imported twice"

    $cl = & $run (Get-SoRemoteCommand Clean $remote)
    Assert-True ($cl.Lines -match 'EVTXER-CLEANED') "the staging folder is removed"
    $gone = & $run "test -e $remote && echo STILL-THERE || echo GONE"
    Assert-True ($gone.Lines -contains 'GONE') "and is really gone"
} finally {
    Remove-Item -LiteralPath $pw -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
