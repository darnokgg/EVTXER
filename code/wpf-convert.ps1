<#
.SYNOPSIS
    Convert (Hayabusa) tab - WPF fragment, dot-sourced by HayabusaWpf.ps1.

.DESCRIPTION
    A fragment, not a script: it creates no Window, loads no assemblies and
    dot-sources no libraries. HayabusaWpf.ps1 has already done all three, and
    already owns $tabConvert, $bar, $lblStatus, $script:Busy, $script:Folders,
    $script:Root, Write-Log and Invoke-UiPump.

    Ported 1:1 from the WinForms launcher (HayabusaMissionTool.ps1, the
    "# ---- page 1 ----" section and its handlers). Every comment that explains
    a real bug has been carried across verbatim, because the bug is still there.
#>

# ================================================================= XAML ======
$convertXaml = @'
<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
      xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
      Margin="4,8,12,8">
  <StackPanel>

    <!-- page 1: pick a source -->
    <Border Style="{StaticResource CardPanel}">
      <StackPanel>
        <Grid>
          <TextBlock Text="Source" Style="{StaticResource SectionHead}"/>
          <!-- Every tab marks the fields its buttons need with " *" and carries
               one of these in its top-right corner, so optional fields are no
               longer guesswork. -->
          <TextBlock Text="* = required" Style="{StaticResource Hint}"
                     HorizontalAlignment="Right" VerticalAlignment="Top"/>
        </Grid>

        <!-- GroupName is explicit: the two radios sit in different StackPanels,
             and WPF only auto-groups radios that share a parent. -->
        <RadioButton x:Name="rbEvtx" GroupName="convertMode" IsChecked="True"
                     Content="Scan an EVTX folder  (this tool runs Hayabusa with the correct flags)"
                     ToolTip="Hayabusa reads every .evtx under the folder (subfolders too) and keeps the events a rule matches; then they are converted to ECS for the Upload tab. Collected hosts are done by the QUEUE below - this is for EVTX from anywhere else."/>

        <Grid Margin="20,6,0,0">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="150"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

          <TextBlock Grid.Row="0" Grid.Column="0" Text="EVTX folder *" Margin="0,0,8,0"
                     ToolTip="Any local folder or share. Type or paste the path (quotes are fine), or Browse. + adds more folders (Ctrl-click several in its picker); all of them are scanned together into one result. A mapped drive letter is turned into its \\server\share path, because EVTXER runs as administrator and Windows hides your mapped drives from it."/>
          <TextBox   Grid.Row="0" Grid.Column="1" x:Name="txtEvtx" Margin="0,3"/>
          <Button    Grid.Row="0" Grid.Column="2" x:Name="btnEvtx" Content="Browse..." Margin="8,3,0,3"/>
          <!-- More folders, one scan (owner, 2026-10-27): Hayabusa takes -d
               once per folder. Rows are added here by Add-EvtxFolderRow. -->
          <Button    Grid.Row="0" Grid.Column="3" x:Name="btnAddEvtx" Content="+" MinWidth="34" FontWeight="Bold" Margin="6,3,0,3"
                     ToolTip="Add another EVTX folder - every folder listed is scanned together, into one result."/>
          <StackPanel Grid.Row="1" Grid.Column="1" Grid.ColumnSpan="3" x:Name="pnlMoreEvtx"/>

          <TextBlock Grid.Row="2" Grid.Column="0" Text="Hayabusa binary *" Margin="0,0,8,0"/>
          <TextBox   Grid.Row="2" Grid.Column="1" x:Name="txtExe" Margin="0,3"/>
          <Button    Grid.Row="2" Grid.Column="2" x:Name="btnExe" Content="Browse..." Margin="8,3,0,3"/>

          <TextBlock Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="2" x:Name="lblExe"
                     Style="{StaticResource Hint}" MinHeight="18" Margin="0,2,0,0" Text=""/>
        </Grid>

        <RadioButton x:Name="rbJsonl" GroupName="convertMode" Margin="0,14,0,0"
                     Content="Use an existing Hayabusa JSONL  (from another machine, or an air-gapped scan)"
                     ToolTip="Skip the scan: convert a results.jsonl that Hayabusa already wrote (JSONL, super-verbose profile, UTC) into ECS for the Upload tab."/>

        <Grid Margin="20,6,0,0">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="150"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

          <TextBlock Grid.Row="0" Grid.Column="0" Text="JSONL file *" Margin="0,0,8,0"/>
          <TextBox   Grid.Row="0" Grid.Column="1" x:Name="txtSrc" Margin="0,3"/>
          <Button    Grid.Row="0" Grid.Column="2" x:Name="btnBrowse" Content="Browse..." Margin="8,3,0,3"/>

          <TextBlock Grid.Row="1" Grid.Column="1" Grid.ColumnSpan="2" x:Name="lblFile"
                     Style="{StaticResource Hint}" MinHeight="18" Margin="0,2,0,0"
                     Text="No file selected."/>
        </Grid>
      </StackPanel>
    </Border>

    <!-- the one action on this tab, full width, with the folder guide under
         it rather than beside it: side by side, both cards were too narrow
         and the guide's right-hand column was cut off. -->
    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <TextBlock Text="Convert" Style="{StaticResource SectionHead}"/>
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Button x:Name="btnConvert" Grid.Column="0" Content="SCAN + CONVERT" Style="{StaticResource Primary}"
                  MinWidth="180"/>
          <Button x:Name="btnConvertCmd" Grid.Column="1" Content="Show command" Margin="10,0,0,0"
                  ToolTip="The same scan and conversion as PowerShell to paste by hand, if the tool breaks"/>
          <TextBlock x:Name="lblConv" Grid.Column="2" Style="{StaticResource Hint}" Margin="14,0,0,0"
                     VerticalAlignment="Center" Text="Not converted yet."/>
        </Grid>
        <CheckBox x:Name="chkCsv" Margin="0,12,0,0" IsChecked="False"
                  Content="Also write CSV (local analyst copy; upload still uses JSONL)"
                  ToolTip="Runs Hayabusa a second time to write results.csv beside the JSONL, to open in Excel or Timeline Explorer. Doubles the scan time; nothing else uses the CSV."/>
      </StackPanel>
    </Border>
    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <TextBlock Text="Where the files go" Style="{StaticResource SectionHead}"/>
        <!-- Nothing here said the queue already does this for collected hosts,
             so a newcomer scanned them twice (usability walk, 2026-10-21). -->
        <TextBlock Style="{StaticResource Hint}" TextWrapping="Wrap" Margin="0,0,0,8"
                   Text="Hosts brought in by the Collect tab are scanned and converted by the QUEUE below on their own. Use this tab for EVTX from anywhere else."/>
        <TextBlock x:Name="lblPaths" Style="{StaticResource Hint}"
                   FontFamily="Consolas" TextWrapping="NoWrap"/>
      </StackPanel>
    </Border>


  </StackPanel>
</Grid>
'@

$convertRoot = [Windows.Markup.XamlReader]::Load(
    (New-Object System.Xml.XmlNodeReader ([xml]$convertXaml)))
$tabConvert.Content = $convertRoot

# Every x:Name becomes a script-scoped variable of the same name, so the handler
# code below reads the same as it did against the WinForms controls. FindName is
# called on the PARSED FRAGMENT ROOT, not on $win: a fragment loaded separately
# is not in the window's name scope, so $win.FindName() returns $null for all of
# these.
foreach ($name in @('txtEvtx','txtExe','txtSrc','btnEvtx','btnExe','btnBrowse','btnAddEvtx','pnlMoreEvtx',
                    'btnConvert','btnConvertCmd','chkCsv','rbEvtx','rbJsonl',
                    'lblExe','lblFile','lblConv','lblPaths')) {
    Set-Variable -Name $name -Scope Script -Value $convertRoot.FindName($name)
}

# WinForms picked its status colours against a light grey form: Green,
# Firebrick, and a hand-mixed amber. This shell is dark, so each one is remapped
# onto the shell's own log palette - same semantics, readable contrast.
$script:ConvBrush = @{}
foreach ($kv in @{
        Muted   = '#A8AEB8'   # Theme.Muted
        Ok      = '#7EC87E'   # was 'Green'
        Err     = '#F2A0A0'   # was 'Firebrick'
        Warn    = '#E8C08A'   # was FromArgb(192, 112, 0)
        Caution = '#F2A0A0'   # was Theme.Caution, FromArgb(156, 43, 43)
    }.GetEnumerator()) {
    $b = (New-Object System.Windows.Media.BrushConverter).ConvertFromString($kv.Value)
    $b.Freeze()
    $script:ConvBrush[$kv.Key] = $b
}

$lblExe.Foreground   = $script:ConvBrush.Muted
$lblFile.Foreground  = $script:ConvBrush.Muted
$lblConv.Foreground  = $script:ConvBrush.Muted
$lblPaths.Foreground = $script:ConvBrush.Muted
$lblPaths.Text       = ((Get-PathGuide) -join [Environment]::NewLine)

# Defined in the WinForms launcher, not in HayabusaLib, so the fragment carries
# its own copy when the launcher is not in the picture.
if (-not (Get-Command New-ParentDirectory -ErrorAction SilentlyContinue)) {
    function New-ParentDirectory([string]$FilePath) {
        # output/ is gitignored, so output\takajo\ does not exist on a fresh
        # checkout and Takajo dies with "unable to open database file".
        $dir = Split-Path -Parent $FilePath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

# ============================================================= handlers ======
$btnBrowse.Add_Click({
    $d = New-Object Microsoft.Win32.OpenFileDialog
    $d.Filter = 'Hayabusa JSONL (*.jsonl;*.json)|*.jsonl;*.json|All files (*.*)|*.*'
    $d.Title = 'Select the Hayabusa JSONL file'
    if ($d.ShowDialog() -ne $true) { return }
    $txtSrc.Text = $d.FileName
    $script:EcsPath = $null
    $lblConv.Text = 'Not converted yet.'; $lblConv.Foreground = $script:ConvBrush.Muted
    try {
        $mb = (Get-Item $d.FileName).Length / 1MB
        $first = Get-Content $d.FileName -TotalCount 1
        $doc = $first | ConvertFrom-Json
        $names = $doc.PSObject.Properties.Name
        $missing = @('Timestamp','RuleTitle','Level') | Where-Object { $names -notcontains $_ }
        $ts = "$($doc.Timestamp)"
        if ($missing) {
            $lblFile.Text = ('{0:N1} MB - this does NOT look like Hayabusa output (missing: {1})' -f $mb, ($missing -join ', '))
            $lblFile.Foreground = $script:ConvBrush.Err
        } elseif (-not ($ts -match 'T' -and $ts.EndsWith('Z'))) {
            $lblFile.Text = ('{0:N1} MB - WARNING: timestamp is "{1}", not ISO-8601. Elasticsearch will reject these. Re-export with -O.' -f $mb, $ts)
            $lblFile.Foreground = $script:ConvBrush.Warn
        } else {
            $lblFile.Text = ('{0:N1} MB - valid Hayabusa JSONL, {1} top-level fields, ISO-8601 timestamps.' -f $mb, $names.Count)
            $lblFile.Foreground = $script:ConvBrush.Ok
        }
    } catch {
        $lblFile.Text = "Could not read file: $($_.Exception.Message)"
        $lblFile.Foreground = $script:ConvBrush.Err
    }
})

function Update-Mode {
    # IsChecked is nullable<bool> in WPF, so it is compared rather than trusted.
    $evtx = ($rbEvtx.IsChecked -eq $true)
    foreach ($c in @($txtEvtx, $btnEvtx, $btnAddEvtx, $pnlMoreEvtx, $txtExe, $btnExe)) { $c.IsEnabled = $evtx }
    foreach ($c in @($txtSrc, $btnBrowse))                   { $c.IsEnabled = -not $evtx }
    $btnConvert.Content = if ($evtx) { 'SCAN + CONVERT' } else { 'CONVERT' }
    if ($evtx) { Update-ExeState } else { $lblExe.Text = '' }
}

function Update-ExeState {
    $exe = $txtExe.Text.Trim()
    if (-not $exe) {
        $lblExe.Text = 'No Hayabusa binary found. Browse to it, or put hayabusa-<version>-win-x64.exe in code\hayabusa-x64\.'
        $lblExe.Foreground = $script:ConvBrush.Err
    } elseif (-not (Test-Path $exe)) {
        $lblExe.Text = "Not found: $exe"; $lblExe.Foreground = $script:ConvBrush.Err
    } else {
        $rules = Join-Path (Split-Path -Parent $exe) 'rules'
        # Count rules, not every file: the folder also carries .md and .txt,
        # which is why this used to report ~200 more than there are rules and
        # disagreed with every other count in the project.
        $n = if (Test-Path $rules) {
            @(Get-ChildItem $rules -Recurse -File -Include '*.yml','*.yaml' -ErrorAction SilentlyContinue).Count
        } else { 0 }
        if ($n -gt 0) {
            $lblExe.Text = ('Found, with {0:N0} rule files alongside it.' -f $n); $lblExe.Foreground = $script:ConvBrush.Ok
        } else {
            $lblExe.Text = 'Binary found but no "rules" folder beside it. Hayabusa needs its rules directory or it detects nothing.'
            $lblExe.Foreground = $script:ConvBrush.Warn
        }
    }
}

function Invoke-HayabusaScan {
    # Returns the JSONL path, or $null. The flags come from Get-HayabusaScanArgs
    # so the operator cannot omit -O and silently produce unparseable
    # timestamps. Runs through Invoke-ExternalTool, so the window stays alive
    # through a scan that prints nothing until it is done.
    $exe  = $txtExe.Text.Trim()
    $evtx = @(Get-ConvertEvtxFolders)
    $out  = Get-ScanOutputPath $script:Root
    New-ParentDirectory $out
    $html = Join-Path (Split-Path -Parent $out) 'results-summary.html'
    $files = @(Get-ChildItem -LiteralPath $evtx -Recurse -Filter *.evtx -File -ErrorAction SilentlyContinue)
    $detail = '{0} EVTX file(s), {1:N0} MB' -f $files.Count, (($files | Measure-Object Length -Sum).Sum / 1MB)
    if ($evtx.Count -gt 1) { $detail += ", from $($evtx.Count) folders" }

    $scanArgs = Get-HayabusaScanArgs -EvtxDir $evtx -OutFile $out -HtmlReport $html
    Write-Log "`n$('=' * 70)`nSCANNING with Hayabusa - $detail`n$exe $($scanArgs -join ' ')`n$('=' * 70)`n" 'info'
    $code = Invoke-ExternalTool -Label 'Hayabusa scan' -Exe $exe -Arguments $scanArgs `
                -WorkDir (Split-Path -Parent $exe) -Detail $detail
    if ($code -ne 0) {
        if (-not $script:CancelRequested) { Write-Log "Hayabusa exited with code $code.`n" 'err' }
        return $null
    }
    if (-not (Test-Path $out)) {
        Write-Log "Hayabusa produced no output. No detections, or the rules folder is missing.`n" 'err'
        return $null
    }
    if (Test-Path -LiteralPath $html) { Write-Log "Hayabusa results summary: $html`n" 'info' }

    if ($chkCsv.IsChecked -eq $true) {
        # Local analyst copy only -- never touches the JSONL/ECS/upload flow.
        # Quiet: the banner and Results Summary were just logged by the JSONL
        # pass.
        $csvOut = Join-Path $script:Folders.Hayabusa 'results.csv'
        $csvDir = Split-Path -Parent $csvOut
        if (-not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }
        $csvArgs = Get-HayabusaScanArgs -EvtxDir $evtx -OutFile $csvOut -Format csv -Quiet
        Write-Log "`n$('=' * 70)`nWRITING CSV copy with Hayabusa`n$exe $($csvArgs -join ' ')`n$('=' * 70)`n" 'info'
        $csvCode = Invoke-ExternalTool -Label 'Hayabusa CSV copy' -Exe $exe -Arguments $csvArgs `
                       -WorkDir (Split-Path -Parent $exe) -Detail $detail
        if ($csvCode -ne 0) {
            Write-Log "CSV scan exited with code $csvCode; JSONL output is unaffected.`n" 'err'
        } elseif (Test-Path $csvOut) {
            Write-Log "CSV written: $csvOut`n" 'info'
        } else {
            Write-Log "CSV scan produced no output.`n" 'err'
        }
    }

    return $out
}

# WinForms fired one CheckedChanged per radio; WPF splits it into Checked and
# Unchecked, so both are wired to keep the same "any change re-evaluates" rule.
$rbEvtx.Add_Checked({ Update-Mode })
$rbEvtx.Add_Unchecked({ Update-Mode })
$txtExe.Add_TextChanged({ if ($rbEvtx.IsChecked -eq $true) { Update-ExeState } })

$btnExe.Add_Click({
    $d = New-Object Microsoft.Win32.OpenFileDialog
    $d.Filter = 'Hayabusa (hayabusa*.exe)|hayabusa*.exe|All files (*.*)|*.*'
    $d.Title = 'Locate the Hayabusa binary'
    if ($d.ShowDialog() -eq $true) { $txtExe.Text = $d.FileName }
})

# Point the Convert tab at a folder of EVTX: counts what is in it, says so, and
# drops any ECS path left over from a previous conversion. Called by the Browse
# button and by the Collect tab when a collection finishes, so a freshly pulled
# set of logs never has to be located by hand.
function Set-EvtxFolder([string]$Path, [switch]$Quiet) {
    if (-not $Path) { return 0 }
    $txtEvtx.Text = $Path
    $rbEvtx.IsChecked = $true
    $script:EcsPath = $null
    $n = @(Get-ChildItem -LiteralPath $Path -Recurse -Filter *.evtx -File -ErrorAction SilentlyContinue).Count
    if ($n -gt 0) {
        $lblConv.Text = "$n .evtx file(s) found under this folder."; $lblConv.Foreground = $script:ConvBrush.Ok
    } else {
        $lblConv.Text = 'No .evtx files found under this folder.'; $lblConv.Foreground = $script:ConvBrush.Err
    }
    if (-not $Quiet) { Write-Log "Convert tab source set to $Path ($n .evtx file(s)).`n" 'info' }
    return $n
}

$btnEvtx.Add_Click({
    $p = Select-FolderPath 'Select the folder containing .evtx files' $(if ($txtEvtx.Text.Trim()) { $txtEvtx.Text } else { $script:Folders.Evtx })
    if ($p) { [void](Set-EvtxFolder $p -Quiet) }
})

# ---- more than one EVTX folder (owner, 2026-10-27: "a plus button to add a
# second evtx folder location") - all scanned together into one result ----
function Get-ConvertEvtxFolders {
    # The first box, then every added row, as typed (quotes and a mapped drive
    # this elevated window cannot see are dealt with); blanks dropped, each
    # folder once.
    $boxes = @($txtEvtx) + @($pnlMoreEvtx.Children | ForEach-Object { $_.Children[0] })
    $seen = @{}
    foreach ($b in $boxes) {
        $b.Text = Resolve-TypedPath $b.Text
        $t = $b.Text.Trim()
        if ($t -and -not $seen.ContainsKey($t.ToLowerInvariant())) { $seen[$t.ToLowerInvariant()] = 1; $t }
    }
}

function Add-EvtxFolderRow([string]$Path) {
    # TextBox | Browse... | - . No .GetNewClosure(): each button finds its row
    # through Tag.
    $row = New-Object System.Windows.Controls.Grid
    $row.Margin = '0,0,0,0'
    foreach ($w in '*', 'Auto', 'Auto') {
        $cd = New-Object System.Windows.Controls.ColumnDefinition
        $cd.Width = (New-Object System.Windows.GridLengthConverter).ConvertFromString($w)
        $row.ColumnDefinitions.Add($cd)
    }
    $box = New-Object System.Windows.Controls.TextBox
    $box.Margin = '0,3'; $box.Text = $Path
    $browse = New-Object System.Windows.Controls.Button
    $browse.Content = 'Browse...'; $browse.Margin = '8,3,0,3'; $browse.Tag = $box
    [System.Windows.Controls.Grid]::SetColumn($browse, 1)
    $remove = New-Object System.Windows.Controls.Button
    $remove.Content = [string][char]0x2212; $remove.MinWidth = 34; $remove.FontWeight = 'Bold'
    $remove.Margin = '6,3,0,3'; $remove.Tag = $row; $remove.ToolTip = 'Remove this folder from the scan'
    [System.Windows.Controls.Grid]::SetColumn($remove, 2)
    $browse.Add_Click({
        param($s)
        $p = Select-FolderPath 'Another folder containing .evtx files' $(if ($s.Tag.Text.Trim()) { $s.Tag.Text } else { $script:Folders.Evtx })
        if ($p) { $s.Tag.Text = $p; Update-EvtxCount }
    })
    $remove.Add_Click({ param($s) $pnlMoreEvtx.Children.Remove($s.Tag); Update-EvtxCount })
    $box.Add_LostFocus({ Update-EvtxCount })
    [void]$row.Children.Add($box); [void]$row.Children.Add($browse); [void]$row.Children.Add($remove)
    [void]$pnlMoreEvtx.Children.Add($row)
    return $box
}

function Update-EvtxCount {
    # The count under the folders covers every folder listed.
    $dirs = @(Get-ConvertEvtxFolders | Where-Object { Test-Path -LiteralPath $_ })
    if (-not $dirs.Count) { return }
    $n = @(Get-ChildItem -LiteralPath $dirs -Recurse -Filter *.evtx -File -ErrorAction SilentlyContinue).Count
    $where = if ($dirs.Count -gt 1) { "under these $($dirs.Count) folders" } else { 'under this folder' }
    if ($n -gt 0) { $lblConv.Text = "$n .evtx file(s) found $where."; $lblConv.Foreground = $script:ConvBrush.Ok }
    else { $lblConv.Text = "No .evtx files found $where."; $lblConv.Foreground = $script:ConvBrush.Err }
}

$btnAddEvtx.Add_Click({
    $p = Select-FolderPath 'Another folder containing .evtx files - Ctrl-click to pick several' $script:Folders.Evtx -Multiple
    if (-not $p) { return }
    foreach ($d in $p) { [void](Add-EvtxFolderRow $d) }
    Update-EvtxCount
})

$btnConvert.Add_Click({
    if ($script:Busy) { return }
    # Pasted with quotes, or a mapped drive this elevated window cannot see.
    $txtSrc.Text  = Resolve-TypedPath $txtSrc.Text
    $evtxDirs = @(Get-ConvertEvtxFolders)
    if ($rbEvtx.IsChecked -eq $true) {
        if (-not $evtxDirs.Count) {
            [void][System.Windows.MessageBox]::Show('Choose the folder containing your .evtx files.', 'No folder'); return
        }
        $missing = @($evtxDirs | Where-Object { -not (Test-Path -LiteralPath $_) })
        if ($missing.Count) {
            [void][System.Windows.MessageBox]::Show("Not found:`n`n$($missing -join "`n")", 'No folder'); return
        }
        if (-not (Test-Path $txtExe.Text)) {
            [void][System.Windows.MessageBox]::Show(
                "Locate the Hayabusa binary.`n`nWindows: hayabusa-<version>-win-x64.exe`n`nIts 'rules' folder must sit beside it.",
                'Hayabusa not found'); return
        }
    } elseif (-not (Test-Path $txtSrc.Text)) {
        [void][System.Windows.MessageBox]::Show('Choose a Hayabusa JSONL file first.', 'No file')
        return
    }
    # Read once: the radios are locked while busy, but the record should not
    # depend on that.
    $fromEvtx = ($rbEvtx.IsChecked -eq $true)
    $convTarget = if ($fromEvtx) { $evtxDirs -join '; ' } else { $txtSrc.Text.Trim() }
    Set-AppBusy $true $(if ($fromEvtx) { 'Hayabusa scan + convert' } else { 'ECS convert' })
    Start-UiJob $(if ($fromEvtx) { 'Hayabusa scan and convert' } else { 'ECS convert' })
    $convClock = [Diagnostics.Stopwatch]::StartNew()
    $convResult = 'FAILED'; $convDetail = ''; $convDocs = ''; $convOut = ''
    # This run's own id. $script:ImportId still holds the previous run's until
    # the scan succeeds, and a failed run must not be filed under it.
    $convImportId = ''
    try {
        if ($fromEvtx) {
            $scanned = Invoke-HayabusaScan
            if (-not $scanned) {
                if ($script:CancelRequested) { $convResult = 'Cancelled' } else { $convDetail = 'Hayabusa scan did not complete' }
                return
            }
            $txtSrc.Text = $scanned
            # How much of the evidence the detections cover. Hayabusa outputs
            # only events that matched a rule, which is easy to mistake for
            # "everything in the logs" - so the share is stated every time.
            $cov = $null
            if ($script:RunLog) { try { $cov = Get-HayabusaCoverage ([IO.File]::ReadAllText($script:RunLog)) } catch { } }
            if ($cov) {
                $convDetail = $cov.Text
                Write-Log "COVERAGE: $($cov.Text). Only events that match a rule are output; the rest are not in the upload. For every raw event, see so-import-evtx in README.txt.`n" 'info'
            }
        }
        $script:ImportId = (Get-Date -Format 'yyyyMMddHHmmss') + [guid]::NewGuid().ToString('N').Substring(0,8)
        $convImportId = $script:ImportId
        $out = Get-EcsOutputPath $txtSrc.Text
        Write-Log "`n$('=' * 70)`nCONVERTING $($txtSrc.Text)`nimport.id : $($script:ImportId)`n" 'info'
        $bar.IsIndeterminate = $false
        $bar.Maximum = 1000; $bar.Value = 0

        # The same function the manual command runs, so the two cannot differ.
        # The scanned folder holds the collections' manifests, whose footprints
        # mark our own activity. A JSONL from elsewhere simply matches none.
        $evtxDir = if ($rbEvtx.IsChecked -eq $true) { $evtxDirs } else { $script:Folders.Evtx }
        $conv = Convert-HayabusaJsonlToEcs -Source $txtSrc.Text -Destination $out -ImportId $script:ImportId `
                    -EvtxDir $evtxDir -OnProgress {
            param($done, $all)
            $bar.Value = if ($all -gt 0) { 1000.0 * $done / $all } else { 0 }
            $lblStatus.Text = "ECS convert - $('{0:N0}' -f $done) of $('{0:N0}' -f $all)"
            Invoke-UiPump
            [bool]$script:CancelRequested
        }
        if ($conv.Cancelled) {
            $convResult = 'Cancelled'
            Write-Log "ECS conversion cancelled; the partial file was removed.`n" 'warn'
            $lblConv.Text = 'Cancelled.'; $lblConv.Foreground = $script:ConvBrush.Warn
            return
        }
        $bar.Value = $bar.Maximum
        $n = $conv.Converted; $bad = $conv.Bad; $recovered = $conv.Recovered; $total = $conv.Total
        $convDocs = "$('{0:N0}' -f $n) documents"; $convOut = $out
        $convResult = if ($bad) { "DROPPED $bad lines" } else { 'Success' }
        Write-Log "documents : $('{0:N0}' -f $total)`nworkers   : $($conv.Workers) (every CPU core but one, up to $($script:EcsMaxWorkers))`n" 'info'
        if ($conv.Tagged) {
            Write-Log ("$('{0:N0}' -f $conv.Tagged) detection(s) are this tool's own collection activity, tagged " +
                       "'$($script:CollectionTag)'. In Kibana, add  NOT tags:$($script:CollectionTag)  to hide them.`n") 'info'
        }

        if ($recovered) {
            Write-Log "Recovered $('{0:N0}' -f $recovered) lines whose Details had an unnamed key (renamed to '(unnamed)').`n" 'info'
        }
        if ($bad) { Write-Log "WARNING: $bad lines could not be parsed and were skipped.`n" 'warn' }
        Write-Log "Converted $('{0:N0}' -f $n) documents -> $out`n" 'ok'
        $script:EcsPath = $out; $script:DocCount = $n
        # Hand the result straight to the Upload tab so the common path needs
        # no file picking at all.
        # Guarded: the Upload and Takajo tabs are separate fragments, and this
        # one has to keep working when they have not been dot-sourced yet.
        if ($script:txtSource) { $script:txtSource.Text = $out }
        if (Get-Command Update-SourceReadiness -ErrorAction SilentlyContinue) { Update-SourceReadiness }
        # Takajo wants the raw timeline, not the ECS file, so it gets $txtSrc.
        if ($script:txtTjSource) { $script:txtTjSource.Text = $txtSrc.Text }
        if (Get-Command Update-TakajoReadiness -ErrorAction SilentlyContinue) { Update-TakajoReadiness }
        if ($bad) {
            # Never report a lossy conversion as success -- a silently short
            # import is the failure mode this whole pipeline is built to prevent.
            $lblConv.Text = "Converted $('{0:N0}' -f $n) of $('{0:N0}' -f $total) - $bad DROPPED. Do not upload."
            $lblConv.Foreground = $script:ConvBrush.Caution
        } else {
            $lblConv.Text = "Converted $('{0:N0}' -f $n) documents. Ready to upload."
            $lblConv.Foreground = $script:ConvBrush.Ok
        }
    } catch {
        Write-Log "CONVERSION FAILED: $($_.Exception.Message)`n" 'err'
        $convDetail = (@($convDetail, $_.Exception.Message) | Where-Object { $_ }) -join '; '
    } finally {
        Stop-UiJob
        Write-Ledger @(New-LedgerRow -Action 'Convert' -Target $convTarget -Protocol $(if ($fromEvtx) { 'Hayabusa scan + ECS' } else { 'ECS' }) `
                          -Result $convResult -Files $convDocs -Seconds $convClock.Elapsed.TotalSeconds -Output $convOut `
                          -Details ((@($convDetail, $(if ($convImportId) { "import.id $convImportId" })) | Where-Object { $_ }) -join '; '))
        # Last: it re-enables every tab, and anything after it that pumps the
        # dispatcher (Write-Log does) could start a queued click's job inside
        # this one's finally.
        Set-AppBusy $false
    }
})

$btnConvertCmd.Add_Click({
    $out  = Get-ScanOutputPath $script:Root
    $dirs = @(Get-ConvertEvtxFolders)
    $scan = Get-ManualHayabusaCommand -Exe $txtExe.Text.Trim() -EvtxDir $dirs -OutFile $out `
                -HtmlReport (Join-Path (Split-Path -Parent $out) 'results-summary.html') -Csv:($chkCsv.IsChecked -eq $true)
    $src  = if ($rbJsonl.IsChecked -eq $true -and $txtSrc.Text.Trim()) { $txtSrc.Text.Trim() } else { $out }
    $ecs  = Get-ManualEcsCommand -LibPath (Join-Path $script:AppRoot 'HayabusaLib.ps1') -Source $src `
                -EvtxDir $(if ($rbEvtx.IsChecked -eq $true -and $dirs.Count) { $dirs } else { $script:Folders.Evtx })
    $text = if ($rbEvtx.IsChecked -eq $true) { "$scan`r`n`r`n$ecs" } else { $ecs }
    Show-CommandWindow 'Manual scan and conversion' `
        'What SCAN + CONVERT does, as PowerShell: the Hayabusa scan, then the ECS conversion the Upload tab needs.' $text
})

# ---- initial state (the launcher did this at the bottom of the file) ----
$txtExe.Text = Find-Hayabusa
Update-Mode

# Prefilled at startup when evtx\ already holds something - a previous session's
# collection, or files an examiner dropped there by hand. Quiet, because this is
# a default rather than something the operator just did.
if (-not $txtEvtx.Text -and (Test-Path -LiteralPath $script:Folders.Evtx)) {
    if (@(Get-ChildItem -LiteralPath $script:Folders.Evtx -Recurse -Filter *.evtx -File -ErrorAction SilentlyContinue).Count -gt 0) {
        [void](Set-EvtxFolder $script:Folders.Evtx -Quiet)
    }
}
