# tests/BusyState.Tests.ps1
#
# "Is it frozen?" (operator, 2026-10-14). Each tab used to grey only its own
# buttons, so the other tabs' blue buttons stayed lit and ignored clicks in
# silence; some actions showed nothing at all while they ran. One switch now:
# Set-AppBusy disables every tab's content and shows a spinner.
$root = Split-Path -Parent $PSScriptRoot
$launcher = Get-Content (Join-Path $root 'code\HayabusaMissionTool.ps1') -Raw
$fn = [regex]::Match($launcher, '(?s)function Set-AppBusy.*?\r?\n\}').Value
Assert-True ($fn.Length -gt 0) "the shell has one busy switch"
Assert-True ($fn -match '\$script:Busy = \$On') "it owns the shared busy flag"
foreach ($t in 'tabCollect','tabConvert','tabUpload','tabTakajo','tabKibana','tabSettings') {
    Assert-True ($fn -match "\`$$t") "it locks $t"
}
Assert-True ($fn -match 'pnlBusy') "it shows the spinner"
Assert-True ($launcher -match "Things are cookin'") "with words a person reads"

# No tab sets the flag by hand any more - that is how one tab's job left the
# others' buttons live, and how Takajo's server start cleared another job's flag.
foreach ($f in Get-ChildItem (Join-Path $root 'code\wpf-*.ps1')) {
    $src = Get-Content $f.FullName -Raw
    Assert-True ($src -notmatch '\$script:Busy\s*=') "$($f.Name) goes through Set-AppBusy"
}

# Every action that waits on a network or a long job shows it.
$all = Get-ToolSource
foreach ($what in 'verifying access', 'testing ports', 'collecting EVTX', 'uploading to ELK',
                  'checking the Elasticsearch connection', 'importing dashboards', 'removing dashboards',
                  'Takajo automagic', 'Takajo HTML report',
                  'archiving EVTX', 'updating the Hayabusa rules', 'restoring the Hayabusa rules') {
    Assert-True ($all -match "Set-AppBusy \`$true '$what'") "'$what' shows the busy indicator"
}
Assert-True ($all -match "Set-AppBusy \`$true \`$\(if \(\`$fromEvtx\)") "the scan/convert shows it too"

# Guards: a handler that had none.
$up = Get-Content (Join-Path $root 'code\wpf-upload.ps1') -Raw
Assert-True ($up -match '(?s)\$btnVerify\.Add_Click\(\{\s*(#[^\n]*\n\s*)*if \(\$script:Busy\) \{ return \}') "Upload's VERIFY refuses mid-upload"

# A disabled primary button is grey, not dimmed blue.
$primary = [regex]::Match($launcher, '(?s)<Style x:Key="Primary".*?</Style>').Value
Assert-True ($primary -match '(?s)IsEnabled" Value="False">.*?TargetName="b" Property="Background"') "a disabled primary button changes colour, not just opacity"

# Re-entrancy (review, 2026-10-14): clearing busy re-enables every tab, so it
# must not pump the dispatcher itself, and it comes LAST in a handler's
# finally - a queued click pumped through earlier ran a second job nested
# inside the first one's wrap-up.
Assert-True ($fn -match '(?s)\} else \{.*?return\s*\}\s*Invoke-UiPump') "turning busy OFF does not pump; only turning it on does"
foreach ($f in 'wpf-convert.ps1', 'wpf-upload.ps1', 'wpf-collect.ps1', 'wpf-settings.ps1') {
    $src = Get-Content (Join-Path $root "code\$f") -Raw
    foreach ($m in [regex]::Matches($src, '(?s)finally \{((?:(?!\n    \}).)*)\n    \}')) {
        $body = $m.Groups[1].Value
        if ($body -notmatch 'Set-AppBusy \$false') { continue }
        Assert-True ($body.TrimEnd() -match 'Set-AppBusy \$false$') "$f clears busy as the last step of its finally"
    }
}
