# tests/CollectEmptyFolder.Tests.ps1
#
# A host that delivers nothing leaves no evidence folder. Found driving the
# real window (2026-10-16): a failed logon left an empty localhost_<time>
# folder in the drop folder and the activity log named it as the Output - and
# fifty unreachable targets would leave fifty of them beside the real ones.
#
# A real run: SMB to this machine's own C$ with an account that does not
# exist, so it fails at the logon and can lock nothing out.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
. "$PSScriptRoot\..\code\EvtxCollector.ps1"

$out = Join-Path ([IO.Path]::GetTempPath()) ("collect-empty-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
try {
    $cred = New-CollectCredential 'evtxer-no-such-user' 'not-a-password'
    $s = Invoke-EvtxCollection -Targets @('localhost') -Method SMB -Category DFIR -Credential $cred -Domain '' `
            -OutRoot $out -LogWriter { param($m) }
    Assert-Equal $s.Failed 1 "the logon fails, as it must"
    Assert-Equal @(Get-ChildItem -LiteralPath $out -Directory -ErrorAction SilentlyContinue).Count 0 "no empty host folder is left in the drop folder"
    Assert-Equal @($s.OutFolders).Count 0 "and none is reported as an output folder"
    Assert-Equal "$(@($s.Hosts)[0].Folder)" '' "so the activity log names no Output for it"
} finally {
    Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue
}
