# tests/CollectAccessResults.Tests.ps1
#
# Restore-CollectTrustedHosts returns what happened. Test-CollectAccess called
# it in a finally block without capturing it, so over WinRM the restore object
# leaked into the function's output: one failing target came back as two
# results, one of them "ready", and the tab reported "1 of 2 target(s) ready".
# The same uncaptured result also meant a failed revert went unreported.
#
# The helpers are mocked in a child scope: function lookup is dynamic, so
# Test-CollectAccess finds these, and nothing leaks into later test files.
. "$PSScriptRoot\..\code\EvtxCollector.ps1"

$accessCred = New-Object System.Management.Automation.PSCredential('admin', (ConvertTo-SecureString 'x' -AsPlainText -Force))

foreach ($case in @(
        @{ Name = 'revert failed';  Rev = @{ Ok = $false; Changed = $false; Reason = 'needs admin' }; Expect = '\[!!\] TrustedHosts NOT reverted' },
        @{ Name = 'reverted';       Rev = @{ Ok = $true;  Changed = $true;  Reason = '' };            Expect = 'TrustedHosts reverted' })) {
    & {
        function Add-CollectTrustedHosts     { [pscustomobject]@{ Value = '' } }
        function Restore-CollectTrustedHosts { [pscustomobject]$case.Rev }
        function Assert-CollectPortOpen      { throw 'WinRM port 5985 closed' }

        $accessLines = New-Object System.Collections.ArrayList
        $res = @(Test-CollectAccess -Targets @('host1.invalid') -Method WinRM -Credential $accessCred `
                    -LogWriter { param($m) [void]$accessLines.Add($m) })
        $text = $accessLines -join ''

        Assert-Equal $res.Count 1                     "$($case.Name): one target, one result - the restore object is not a result"
        Assert-Equal "$($res[0].Target)" 'host1.invalid' "$($case.Name): the result is the target"
        Assert-True ($res[0].Ok -eq $false)           "$($case.Name): the failing target is not ready"
        Assert-True ($text -match $case.Expect)       "$($case.Name): the revert outcome is logged"

        # A failed check is a failure, not a caution: [!!] reads red, [--] amber.
        Assert-True ($text -match '\[!!\] WinRM port 5985 closed') "$($case.Name): a failed check is marked [!!]"
        Assert-True ($text -notmatch '\[--\]')        "$($case.Name): no failed check is marked [--]"
    }
}
