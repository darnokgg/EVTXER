# tests/PopupDialog.Tests.ps1
#
# The Show command popup opened once and never again (2026-10-12): the main
# window predates the WPF Application object, so closing the first popup looked
# like the last window closing and the Application began shutting down. Every
# later ShowDialog then returned without showing. This opens the real popup
# twice, lifted from the launcher, with the launcher's own Application setup.
$root     = Split-Path -Parent $PSScriptRoot
$launcher = Get-Content (Join-Path $root 'code\HayabusaMissionTool.ps1') -Raw

Assert-True ($launcher -match "ShutdownMode = 'OnExplicitShutdown'") "the shell does not let a closing popup shut the Application down"

if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    Write-Host "  [SKIP] not STA - the live popup check needs powershell -File" -ForegroundColor Yellow
    return
}
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
$xaml = [regex]::Match($launcher, "(?s)\`$xaml = @'\r?\n(.*?)\r?\n'@").Groups[1].Value
$win  = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$xaml)))
$win.Left = -10000; $win.ShowInTaskbar = $false; $win.ShowActivated = $false
# The launcher's own setup lines, run as written.
$setup = [regex]::Match($launcher, "(?s)if \(-not \[System\.Windows\.Application\]::Current\).*?ShutdownMode = 'OnExplicitShutdown'").Value
. ([scriptblock]::Create($setup))
. ([scriptblock]::Create([regex]::Match($launcher, "(?s)function Show-CommandWindow.*?\r?\n\}\r?\n").Value))

$script:PopupsSeen = 0
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [timespan]::FromMilliseconds(400)
$timer.Add_Tick({
    foreach ($w in @($win.OwnedWindows)) { if ($w.IsVisible) { $script:PopupsSeen++; $w.Close() } }
})
$timer.Start()
$win.Add_ContentRendered({
    try {
        Show-CommandWindow 'first' 'intro' 'one'
        Show-CommandWindow 'second' 'intro' 'two'
        Show-CommandWindow 'third' 'intro' 'three'
    } finally { $timer.Stop(); $win.Close() }
})
[void]$win.ShowDialog()
Assert-Equal $script:PopupsSeen 3 "the popup opens every time, not just the first"
