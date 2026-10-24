# tests/Layout.Tests.ps1
# The window was rebuilt in WPF. The WinForms version pinned every control to
# absolute coordinates, so growth only reached what was anchored and the log
# pane was a strip nobody could resize; these assertions pin the WPF equivalents
# of the rules that cost the most to learn.
$src = Get-ToolSource

# ---- the log sits beside the tabs, full height, on a draggable divider ----
# At the bottom it fought the tabs for vertical space, and the divider there
# was overruled by a fit-to-content routine on every resize. The operator asked
# for it on the side (2026-10-12).
Assert-True ($src -match 'GridSplitter')        "a splitter divides the tabs from the log"
Assert-True ($src -match 'ResizeDirection="Columns"') "it resizes columns: the log is beside the tabs"
Assert-True ($src -match 'ResizeBehavior="PreviousAndNext"') "dragging it moves the boundary, not one panel"
Assert-True ($src -match '<ColumnDefinition Width="\*" MinWidth="(\d+)"/>') "the tabs take the slack and have a floor"
Assert-True ($src -match 'x:Name="colLog" Width="\d+" MinWidth="(\d+)"') "the log column has a width and a floor"
Assert-True ($src -match 'layout\.conf') "the dragged width is remembered"
Assert-True ($src -notmatch 'function Update-TabFit') "no fit routine overrules the divider any more"

# ---- the window calls the tool EVTXER ----
Assert-True ($src -match 'Title="EVTXER"') "the window calls the tool EVTXER"

# ---- the log wraps at the pane's width ----
# The operator's call (2026-10-12): wrapped, every line is readable without
# scrolling sideways. The box-drawn summary tables keep their shape in the run
# log (logs\run_*.txt) instead.
Assert-True ($src -match 'x:Name="log"[^>]*HorizontalScrollBarVisibility="Disabled"') "the log wraps instead of scrolling sideways"
Assert-True ($src -notmatch 'Document\.PageWidth') "nothing widens the page past the pane"

# ---- the Convert tab stacks its cards ----
$conv = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'code\wpf-convert.ps1') -Raw
Assert-True ($conv.IndexOf('x:Name="btnConvert"') -lt $conv.IndexOf('Text="Where the files go"')) "the folder guide sits under the Convert card"
Assert-True ($conv -notmatch '<Border Grid\.Column="1"[^>]*>\s*<StackPanel>\s*<TextBlock Text="Where the files go"') "not beside it"

# ---- tab content scrolls instead of clipping ----
foreach ($tab in 'tabCollect', 'tabConvert', 'tabUpload', 'tabTakajo') {
    Assert-True ($src -match "ScrollViewer x:Name=`"$tab`"") "$tab scrolls rather than clipping"
}

# ---- fragments cannot reach the Window's resources ----
# Each tab's XAML is parsed detached, so a StaticResource in a fragment throws
# at load. The shell seeds the styles into the Application for them.
Assert-True ($src -match 'Application\]::Current\.Resources\.MergedDictionaries\.Add') `
    "the shell publishes its styles where the tab fragments can resolve them"

# ---- the off-domain warning is on the tab, not just in the docs ----
Assert-True ($src -match 'Off-domain target: leave Domain empty') "the note tells the operator to leave Domain empty off-domain"
Assert-True ($src -match 'txtCredDomain')                          "the Collect tab has a Domain field"
Assert-True ($src -match '-Domain \$state\.Domain')                 "the Domain field reaches the collector"
Assert-True ($src -match 'C`\$ admin share')                        "the note names the C`$ share SMB needs"
Assert-True ($src -match '(?i)winrm must be enabled')               "the note says WinRM must be enabled"

# ---- the launcher actually shows the window ----
# It once did not. The script built every control and exited: exit code 0, no
# error, nothing on screen. Every check during the WPF port rendered the window
# from a harness that supplied its own Show, so the one line the real launch
# depends on was the one line nothing exercised.
Assert-True ($src -match '\$win\.ShowDialog\(\)') "the launcher shows the window it just built"

# ---- native output is decoded as UTF-8 ----
# Takajo and Hayabusa draw tables with box-drawing characters. PowerShell
# decodes a native program's output with [Console]::OutputEncoding, which
# defaults to the OEM codepage, so without this every border arrives as mojibake
# ("Gou" soup) in the log pane. It was fixed once, then lost in the WPF rewrite.
Assert-True ($src -match '\[Console\]::OutputEncoding\s*=\s*\[System\.Text\.Encoding\]::UTF8') `
    "the launcher decodes native output as UTF-8"

# ---- the root holds ONLY the .cmd, so there is one thing to double-click ----
# Every script, the launcher included, lives in code\.
$root = Split-Path -Parent $PSScriptRoot
# Dot-prefixed files are gitignored local scratch (.gui-harness.tmp.ps1), never shipped.
$rootScripts = @(Get-ChildItem -Path (Join-Path $root '*.ps1') -File |
                 Where-Object { -not $_.Name.StartsWith('.') } | Select-Object -ExpandProperty Name)
Assert-Equal ($rootScripts -join ',') '' "no .ps1 is left in the root"
$cmd = Join-Path $root 'EVTXER.cmd'
Assert-True (Test-Path $cmd) "the double-click launcher is in the root"
$target = [regex]::Match((Get-Content $cmd -Raw), '%~dp0([^"]+\.ps1)').Groups[1].Value
Assert-True ($target -and (Test-Path (Join-Path $root $target))) "the .cmd points at a launcher that exists ($target)"
Assert-True ($target -like 'code\*') "the launcher it starts is in code"
# Two roots: AppRoot (code\) for the tool's own parts, Root (one up) for what
# the operator opens. Mixing them up either creates code\evtx, code\logs... or
# looks for the binaries beside the operator's data.
Assert-True ($src -match '\$script:AppRoot = Split-Path -Parent \$script:ScriptPath') "AppRoot is the launcher's folder"
Assert-True ($src -match '\$script:Root\s+= Split-Path -Parent \$script:AppRoot')   "Root is the folder above code"
Assert-True ((Get-ToolSourceFiles).Count -ge 6) "the launcher and tab files are found in code"

# ---- the root holds only what the operator opens; the tool's parts are in code\ ----
# The engine too: Find-Hayabusa and Find-Takajo live there, not in a tab.
$allSrc = $src + "`n" + (Get-Content (Join-Path $root 'code\HayabusaLib.ps1') -Raw)
foreach ($part in 'hayabusa-x64', 'takajo', 'assets', 'index-template.json') {
    Assert-True ($allSrc -match "Join-Path \`$script:AppRoot '$([regex]::Escape($part))") "$part is found under code\"
    Assert-True ($allSrc -notmatch "Join-Path \`$script:Root '$([regex]::Escape($part))") "$part is not looked for in the root"
}
Assert-True (Test-Path (Join-Path $root 'code\index-template.json')) "the index template ships in code\"
Assert-True (Test-Path (Join-Path $root 'code\assets'))              "the assets ship in code\"

# ---- the AGPL tools travel with their licence and source ----
$lic = Join-Path $root 'code\licenses'
foreach ($f in 'NOTICE.txt', 'AGPL-3.0.txt', 'DRL-1.1.txt', 'MIT.txt', 'PCRE-BSD.txt') {
    Assert-True (Test-Path (Join-Path $lic $f)) "code\licenses\$f ships"
}
$notice = Get-Content (Join-Path $lic 'NOTICE.txt') -Raw
foreach ($tool in 'hayabusa-x64', 'takajo') {
    $dir = Join-Path $root "code\$tool"
    if (-not (Test-Path $dir)) { continue }
    # An upgrade that forgets tools\dev\fetch_sources.py fails here.
    foreach ($exe in @(Get-ChildItem $dir -Filter '*-win-x64.exe')) {
        $name, $ver = ($exe.Name -replace '-win-x64\.exe$') -split '-', 2
        Assert-True (Test-Path (Join-Path $lic "$name-$ver-source.zip")) "the source of $($exe.Name) ships beside it"
        Assert-True ($notice -match "(?i)$name $([regex]::Escape($ver))") "NOTICE.txt names $name $ver"
    }
}
foreach ($gone in 'lib', 'assets') {
    Assert-True (-not (Test-Path (Join-Path $root $gone))) "no $gone\ folder is left in the root"
}

# ---- the window never opens larger than the screen ----
Assert-True ($src -match 'SystemParameters\]::WorkArea')          "the window never opens larger than the screen"

# ---- long jobs never run on the window's thread unattended ----
# Hayabusa prints nothing while it scans when piped, and a WinRM pull is one
# blocking Copy-Item: either one froze the window for as long as it ran.
$nc = (Get-ToolSourceLines | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
Assert-True ($nc -notmatch '& \$exe @') "no tab runs Hayabusa or Takajo inline any more"
Assert-True ($nc -notmatch '(?m)^\s*\$summary = Invoke-EvtxCollection') "the collection is not run on the UI thread"
Assert-True ($nc -match "Start-LibJob 'Invoke-EvtxCollection'") "the collection runs as a background job"
Assert-Equal ([regex]::Matches($nc, 'Invoke-ExternalTool -Label').Count) 4 "the scan, the CSV pass, Takajo and the Raw Events tab's host-key read all go through the runner"
Assert-True ((Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'code\wpf-soimport.ps1') -Raw) -match 'Run \{ param\(\$p\) Invoke-ExternalTool @p') "and so do its copies and remote commands, from Invoke-SoImport"
Assert-True ((Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'code\wpf-soimport.ps1') -Raw) -match 'Invoke-ExternalTool @p') "and its plink calls too"
Assert-True ($nc -match 'x:Name="btnCancel"') "there is a Cancel button"
Assert-True ($nc -match 'x:Name="chkConsole"') "there is the console-window option"

# ---- the Settings tab (phase 2, 2026-10-16) ----
# The drop folder and the archive come from code\settings.conf. The archive is
# never created at startup: it may be a share that is offline, and asking a
# dead server holds the window up before it has even opened.
$launcher = Get-Content (Join-Path $root 'code\HayabusaMissionTool.ps1') -Raw
Assert-True ($src -match 'ScrollViewer x:Name="tabSettings"') "the Settings tab scrolls rather than clipping"
Assert-True ($launcher -match "'wpf-settings\.ps1'") "the shell loads the Settings tab"
Assert-True ($launcher -match 'Get-FolderLayout \$script:Root \$script:Settings\.EvtxFolder \$script:Settings\.ArchiveFolder') "the folders follow the saved settings"
Assert-True ($launcher -match "Where-Object Name -ne 'Archive'") "the archive folder is not touched at startup"
Assert-True ($launcher.IndexOf('Read-ToolSettings') -lt $launcher.IndexOf('$script:LogFile =')) "the settings are read before the log folder is chosen"
$set = Get-Content (Join-Path $root 'code\wpf-settings.ps1') -Raw
# The tabs read $script:Folders.Evtx when they run; only the two boxes filled
# at startup hold a copy, and they must follow a change.
Assert-True ($set -match '\$txtEvtx\.Text -eq \$old')     "Convert's folder box follows a new drop folder"
Assert-True ($set -match '\$txtSoFolder\.Text -eq \$old') "and so does Raw Events'"
Assert-True ($set -match "Start-LibJob 'Compress-EvtxFolder'") "archiving runs in the background, not on the window's thread"
Assert-True ($set -match "MessageBox\]::Show\(\`$ask, 'Archive', 'YesNo'") "deleting evidence is confirmed first"
Assert-True ($set -match "New-LedgerRow -Action 'EVTX archive'") "every archived host folder is in the activity log"
# Found driving the real window: a CheckBox given a string Content reads its
# first underscore as an access key, so HOST_20261016_090000 showed as
# HOST20261016_090000 - a name that matches no folder on disk.
Assert-True ($set -notmatch 'CheckBox Content="\{Binding') "host folder names are shown literally, underscores and all"

# ---- text wraps with the window (hints were cut off) ----
# A horizontal StackPanel gives its children unlimited width, so a TextBlock
# in one never wraps, TextWrapping or not, and runs off the edge. A DockPanel
# (buttons docked left, the text filling the rest) wraps it.
foreach ($f in Get-ToolSourceFiles) {
    $x = Get-Content -LiteralPath $f -Raw
    foreach ($m in [regex]::Matches($x, '(?s)<StackPanel[^>]*Orientation="Horizontal"[^>]*>(.*?)</StackPanel>')) {
        foreach ($tb in [regex]::Matches($m.Groups[1].Value, '(?s)<TextBlock[^>]*>')) {
            $txt = [regex]::Match($tb.Value, 'Text="([^"]*)"').Groups[1].Value
            $named = $tb.Value -match 'x:Name="(lbl(Arch|Mission|Rules|Queue)[A-Za-z]*)"'
            Assert-True ($txt.Length -lt 30 -and -not $named) "$([IO.Path]::GetFileName($f)): '$($txt.Substring(0, [Math]::Min(40, $txt.Length)))$($matches[1])' is not in a row that cannot wrap"
        }
    }
}

# The run-log pop-up ("a setting to disable txt log popups
# after each pull, conversion etc"): one switch, on the Settings tab, saved -
# the log-pane checkbox it replaces came back ticked on every start.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
$launcher =Get-Content (Join-Path $root 'code\HayabusaMissionTool.ps1') -Raw
$set = Get-Content (Join-Path $root 'code\wpf-settings.ps1') -Raw
Assert-True ($launcher -notmatch 'chkOpenRunLog') "the unsaved log-pane checkbox is gone"
Assert-True ($launcher -match "\`$script:Settings\.OpenRunLog -ne 'off'") "a finished job opens its run log only while the setting is on"
Assert-True ($set -match 'x:Name="chkSetRunLog"' -and $set -match "\`$script:Settings\.OpenRunLog = ") "Settings has the switch, and changing it saves"
Assert-True ($set -match '\$chkSetRunLog\.Add_Unchecked' -and $set.IndexOf('$chkSetRunLog.IsChecked =') -lt $set.IndexOf('$chkSetRunLog.Add_Checked')) "saved on Checked/Unchecked, attached after the state is loaded"
Assert-Equal (Read-ToolSettings (Join-Path $env:TEMP 'no-such-settings.conf')).OpenRunLog 'on' "it is on by default, as before"
$rl = Join-Path ([IO.Path]::GetTempPath()) ("evtxer-runlog-{0}.conf" -f [guid]::NewGuid().ToString('N'))
try {
    $s = Read-ToolSettings $rl; $s.OpenRunLog = 'off'; Save-ToolSettings $s $rl
    Assert-Equal (Read-ToolSettings $rl).OpenRunLog 'off' "switched off, it stays off after a restart"
} finally { Remove-Item -LiteralPath $rl -Force -ErrorAction SilentlyContinue }

# The DFIR log list: four lines, and a button for the rest.
$col = Get-Content (Join-Path $root 'code\wpf-collect.ps1') -Raw
Assert-True ($col -match 'x:Name="btnDfirExpand"' -and $col -match "'btnDfirExpand'") "the DFIR list has its expand button, wired up"
Assert-True ($col -match '\$script:DfirShown = 4' -and $col -match "Select-Object -First \`$script:DfirShown") "and shows four logs until it is pressed"
