# tests/CrashGuard.Tests.ps1

# One error escaping any WPF handler ended ShowDialog and closed the tool -
# measured 2026-10-06 with an [int]::Parse('x') in a click handler. These pin
# the three things that stop a single bug from becoming a lost session.

$root     = Split-Path -Parent $PSScriptRoot
$launcher = Get-Content (Join-Path $root 'code\HayabusaMissionTool.ps1') -Raw

# ---- the last-chance handler is registered, and before the window runs ----
$guardAt = $launcher.IndexOf('$win.Dispatcher.Add_UnhandledException(')
Assert-True ($guardAt -ge 0) "the launcher registers a dispatcher UnhandledException handler"
Assert-True ($guardAt -lt $launcher.IndexOf('[void]$win.ShowDialog()')) "it is registered before ShowDialog"

# ---- and it actually keeps the window alive ----
# The handler's OWN code, lifted from the launcher, against a real throwing
# click - not a copy of it that could drift.
$m = [regex]::Match($launcher, '(?s)\$win\.Dispatcher\.Add_UnhandledException\((\{.*?\r?\n\})\)')
Assert-True $m.Success "the handler's code can be read from the launcher"
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    Write-Host "  [SKIP] not STA - the live handler check needs powershell -File" -ForegroundColor Yellow
} elseif ($m.Success) {
    Add-Type -AssemblyName PresentationFramework
    $guard = & ([scriptblock]::Create($m.Groups[1].Value))
    $script:GuardLogged = @()
    function Write-Log([string]$Text, [string]$Kind = 'plain') { $script:GuardLogged += "$Kind|$Text" }

    $w = New-Object System.Windows.Window
    $w.Left = -10000; $w.Width = 50; $w.Height = 50; $w.ShowInTaskbar = $false; $w.ShowActivated = $false
    $b = New-Object System.Windows.Controls.Button
    $w.Content = $b
    $b.Add_Click({ [int]::Parse('not a number') | Out-Null })
    $w.Dispatcher.Add_UnhandledException($guard)
    $script:GuardStillOpen = $false
    $w.Add_ContentRendered({
        (New-Object System.Windows.Automation.Peers.ButtonAutomationPeer($b)).GetPattern('Invoke').Invoke()
        $w.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::ApplicationIdle,
                                  [Action]{ $script:GuardStillOpen = $w.IsVisible; $w.Close() }) | Out-Null
    })
    $threw = $false
    try { [void]$w.ShowDialog() } catch { $threw = $true }
    Remove-Item Function:\Write-Log

    Assert-True (-not $threw)           "a throwing click handler no longer ends ShowDialog"
    Assert-True $script:GuardStillOpen  "the window is still open after the error"
    Assert-True (@($script:GuardLogged | Where-Object { $_ -like 'err|UNEXPECTED ERROR*' }).Count -eq 1) "the error is logged once, in red"
    Assert-True (@($script:GuardLogged | Where-Object { $_ -match 'correct format' }).Count -eq 1) "the log carries the real exception message"
}

# ---- one broken tab cannot stop the tool starting ----
Assert-True ($launcher -match '(?s)try \{ \. \$path \}\s*catch \{ Write-Log') "each tab file is loaded inside try/catch"

# ---- a crash at startup stays on screen ----
$cmd = [IO.File]::ReadAllBytes((Join-Path $root 'EVTXER.cmd'))
$cmdText = [Text.Encoding]::ASCII.GetString($cmd)
Assert-True ($cmdText -match '(?i)if errorlevel 1') "the .cmd checks the exit code"
Assert-True ($cmdText -match '(?i)\bpause\b')       "and pauses so the error can be read"
Assert-Equal ([regex]::Matches($cmdText, "`r`n").Count) ([regex]::Matches($cmdText, "`n").Count) "the .cmd is still CRLF throughout"
