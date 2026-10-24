<#
.SYNOPSIS
    Takajo Analysis tab - WPF fragment, dot-sourced by HayabusaWpf.ps1.

.DESCRIPTION
    Takajo analyses Hayabusa's RAW timeline, so this tab is a sibling of Upload
    rather than a step after it: both consume the Hayabusa output, but
    different files. Upload wants ecs.jsonl, Takajo wants results.jsonl.

    Layout only lives here. Every decision about WHAT Takajo is told still
    lives in HayabusaLib.ps1 (Get-TakajoArgs, ConvertTo-TakajoRelativePath,
    Get-NextFreeFolder, Get-JsonlKind).
#>

# ============================================================== XAML =========
# DynamicResource, not StaticResource: this Grid is parsed on its own, before
# it is attached to the window, so the shell's styles do not exist yet at parse
# time. StaticResource would resolve during Load and throw; DynamicResource
# defers the lookup until the element is in the window's tree.
$takajoXaml = @'
<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
      xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
      Margin="2,10,10,10">
  <StackPanel>

    <!-- ===== the two inputs: the binary and the timeline it reads ===== -->
    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <Grid>
          <TextBlock Text="Takajo and its timeline" Style="{DynamicResource SectionHead}"/>
          <TextBlock Text="* = required" HorizontalAlignment="Right" VerticalAlignment="Top"
                     Style="{DynamicResource Hint}"/>
        </Grid>
        <!-- The tab never said what Takajo is (usability walk, 2026-10-21). -->
        <TextBlock Style="{DynamicResource Hint}" TextWrapping="Wrap" Margin="0,2,0,10"
                   Text="Takajo summarises Hayabusa's results offline - no Elastic or Kibana needed: CSV tables per topic (RUN AUTOMAGIC), or an HTML report to open in a browser (BUILD OFFLINE HTML). Handy on a stand-alone laptop or to hand a report to someone without Kibana."/>

        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="128"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" Text="Takajo binary *" Margin="0,0,10,0"/>
          <TextBox   x:Name="txtTakajo" Grid.Column="1" Margin="0,0,8,0"/>
          <Button    x:Name="btnTakajoBrowse" Grid.Column="2" Content="Browse..." MinWidth="96"/>
        </Grid>
        <TextBlock x:Name="lblTakajo" Style="{DynamicResource Hint}" Margin="128,6,0,14"/>

        <!-- The input selector. Same Get-JsonlKind as the Upload tab, opposite
             verdict: Takajo reads Hayabusa's raw fields (Timestamp, Details,
             TgtUser), so the ECS file is exactly the wrong input and is named
             as such rather than just refused. -->
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="128"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" Text="Timeline JSONL *" Margin="0,0,10,0"/>
          <TextBox   x:Name="txtTjSource" Grid.Column="1" Margin="0,0,8,0"/>
          <Button    x:Name="btnTjBrowse" Grid.Column="2" Content="Browse..." MinWidth="96"/>
        </Grid>
        <TextBlock x:Name="lblTjSource" Text="No timeline selected."
                   Style="{DynamicResource Hint}" Margin="128,6,0,0"/>
      </StackPanel>
    </Border>

    <!-- ===== automagic ===== -->
    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <TextBlock Text="Generate CSV results (automagic)" Style="{DynamicResource SectionHead}"/>
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="128"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

          <TextBlock Grid.Row="0" Grid.Column="0" Text="Output folder *" Margin="0,0,10,0"/>
          <TextBox   x:Name="txtTjOut" Grid.Row="0" Grid.Column="1" Margin="0,0,8,0"/>
          <Button    x:Name="btnTjOutBrowse" Grid.Row="0" Grid.Column="2" Content="Browse..." MinWidth="96"/>

          <TextBlock Grid.Row="1" Grid.Column="0" Text="Minimum level" Margin="0,8,10,0"/>
          <ComboBox  x:Name="cmbTjLevel" Grid.Row="1" Grid.Column="1" Width="170"
                     HorizontalAlignment="Left" Margin="0,12,0,0"/>

          <Button x:Name="btnTjAutomagic" Grid.Row="0" Grid.RowSpan="2" Grid.Column="3"
                  Content="RUN AUTOMAGIC" Style="{DynamicResource Primary}"
                  MinWidth="190" Margin="14,0,0,0" VerticalAlignment="Center"/>
        </Grid>

        <TextBlock x:Name="lblTjAuto" Text="Not run." Style="{DynamicResource Hint}" Margin="0,14,0,0"/>
        <TextBlock x:Name="lblTjAutoNote" Style="{DynamicResource Hint}" Margin="0,6,0,0"
                   Text="Each RUN AUTOMAGIC writes a NEW numbered folder (case-1, case-1-2, ...) - Takajo will not reuse one."/>
        <Button x:Name="btnTjCmd" Content="Show commands" HorizontalAlignment="Left" Margin="0,12,0,0"
                ToolTip="automagic and the HTML report as PowerShell to paste by hand, if the tool breaks"/>
      </StackPanel>
    </Border>

    <!-- ===== html report ===== -->
    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <TextBlock Text="HTML report and database" Style="{DynamicResource SectionHead}"/>
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="128"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

          <TextBlock Grid.Row="0" Grid.Column="0" Text="Hayabusa rules *" Margin="0,0,10,0"/>
          <TextBox   x:Name="txtTjRules" Grid.Row="0" Grid.Column="1" Margin="0,0,8,0"/>
          <Button    x:Name="btnTjRulesBrowse" Grid.Row="0" Grid.Column="2" Content="Browse..." MinWidth="96"/>

          <TextBlock Grid.Row="1" Grid.Column="0" Text="Report folder *" Margin="0,10,10,0"/>
          <TextBox   x:Name="txtTjHtml" Grid.Row="1" Grid.Column="1" Margin="0,10,8,0"/>
          <Button    x:Name="btnTjHtmlBrowse" Grid.Row="1" Grid.Column="2" Content="Browse..." MinWidth="96"
                     Margin="0,10,0,0"/>

          <CheckBox  x:Name="chkTjSqlite" Grid.Row="2" Grid.Column="1" Grid.ColumnSpan="2"
                     Content="Use SQLite instead of DuckDB" IsChecked="True" Margin="0,10,0,0"/>

          <Button x:Name="btnTjReport" Grid.Row="0" Grid.RowSpan="3" Grid.Column="3"
                  Content="BUILD OFFLINE HTML" Style="{DynamicResource Primary}"
                  MinWidth="190" Margin="14,0,0,0" VerticalAlignment="Center"/>
        </Grid>

        <!-- No html-server: it listens on every interface with no login and
             Takajo cannot be told otherwise. The offline report is the same
             report as plain files, opened from disk - nothing listens. -->
        <Grid Margin="0,12,0,0">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="128"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Button x:Name="btnTjOpen" Grid.Column="1" Content="OPEN REPORT"
                  ToolTip="Opens index.html from the report folder in your browser - straight from disk, no server"/>
          <TextBlock x:Name="lblTjHtml" Grid.Column="2" Style="{DynamicResource Hint}"
                     Margin="14,0,0,0" VerticalAlignment="Center" TextWrapping="Wrap"/>
        </Grid>
      </StackPanel>
    </Border>

  </StackPanel>
</Grid>
'@

$tjReader = New-Object System.Xml.XmlNodeReader ([xml]$takajoXaml)
$tjRoot   = [Windows.Markup.XamlReader]::Load($tjReader)
$tabTakajo.Content = $tjRoot

# Every x:Name becomes a variable of the same name, so handler code reads the
# same as it did against WinForms controls.
foreach ($tjName in @('txtTakajo','btnTakajoBrowse','lblTakajo',
                      'txtTjSource','btnTjBrowse','lblTjSource',
                      'txtTjOut','btnTjOutBrowse','cmbTjLevel','btnTjAutomagic','lblTjAuto',
                      'txtTjRules','btnTjRulesBrowse','chkTjSqlite',
                      'txtTjHtml','btnTjHtmlBrowse','btnTjReport','btnTjOpen',
                      'lblTjHtml','lblTjAutoNote','btnTjCmd')) {
    Set-Variable -Name $tjName -Scope Script -Value $tjRoot.FindName($tjName)
}

[void]$cmbTjLevel.Items.Add('informational')
[void]$cmbTjLevel.Items.Add('low')
[void]$cmbTjLevel.Items.Add('medium')
[void]$cmbTjLevel.Items.Add('high')
[void]$cmbTjLevel.Items.Add('critical')
$cmbTjLevel.SelectedIndex = 0

# Verdict colours. WinForms used the named colours Green and Firebrick on a
# grey form; on this dark surface both are near-unreadable, so the shell's own
# log palette supplies the equivalents and the Muted brush replaces
# $script:Theme.Muted.
function Get-TjBrush([string]$Key, [string]$Fallback) {
    $b = $null
    if ($win) { $b = $win.TryFindResource($Key) }
    if ($b) { return $b }
    return (New-Object System.Windows.Media.BrushConverter).ConvertFromString($Fallback)
}
$script:TjMuted = Get-TjBrush 'Muted'   '#A8AEB8'
$script:TjBad   = Get-TjBrush 'Caution' '#F2A0A0'
$script:TjOk    = (New-Object System.Windows.Media.BrushConverter).ConvertFromString('#7EC87E')

# ------------------------------------------------------- Takajo handlers ----
function Update-TakajoReadiness {
    $exe = $txtTakajo.Text.Trim()
    if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) {
        $lblTakajo.Text = "Found: $([IO.Path]::GetFileName($exe))"
        $lblTakajo.Foreground = $script:TjOk
    } else {
        $lblTakajo.Text = 'Takajo not found. Put the takajo win-x64 release in code\takajo\, or Browse to it.'
        $lblTakajo.Foreground = $script:TjBad
    }

    $path = $txtTjSource.Text.Trim()
    if (-not $path) {
        $script:TakajoKind = 'Missing'
        $lblTjSource.Text = 'No timeline selected. Convert on the Hayabusa tab, or Browse to a Hayabusa results.jsonl.'
        $lblTjSource.Foreground = $script:TjMuted
        return
    }
    $verdict = Get-JsonlKind $path
    $script:TakajoKind = $verdict.Kind
    switch ($verdict.Kind) {
        'RawHayabusa' {
            $lblTjSource.Text = "Ready: $([IO.Path]::GetFileName($path)) - Hayabusa timeline."
            $lblTjSource.Foreground = $script:TjOk
        }
        'Ecs' {
            # Naming the mistake is the point: both files sit in output\ and
            # only differ by a few characters in the name.
            $lblTjSource.Text = 'That is the ECS file for the ELK upload. Takajo needs the raw Hayabusa timeline (results.jsonl).'
            $lblTjSource.Foreground = $script:TjBad
        }
        default {
            $lblTjSource.Text = $verdict.Reason
            $lblTjSource.Foreground = $script:TjBad
        }
    }
}

function Test-TakajoReady {
    Update-TakajoReadiness
    $exe = $txtTakajo.Text.Trim()
    if (-not ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf))) {
        [void][System.Windows.MessageBox]::Show($lblTakajo.Text, 'Takajo not found'); return $false
    }
    if ($script:TakajoKind -ne 'RawHayabusa') {
        [void][System.Windows.MessageBox]::Show($lblTjSource.Text, 'Cannot analyse this file'); return $false
    }
    return $true
}

function Invoke-TakajoCommand([string[]]$TakajoArgs, [string]$What) {
    # Same shape as Invoke-HayabusaScan: the working directory MUST be the
    # takajo folder, because Takajo resolves conf/ and templates/ relative to
    # the current directory rather than to the executable.
    #
    # Returns the exit code. Counting output files is NOT a success test:
    # automagic refuses an existing --output folder and exits 1 without
    # touching it, so a second run would leave the first run's files sitting
    # there and the caller would report them as a fresh success.
    $exe = $txtTakajo.Text.Trim()
    Write-Log "$What`n" 'info'
    Write-Log ("takajo " + ($TakajoArgs -join ' ') + "`n")
    return (Invoke-ExternalTool -Label $What -Exe $exe -Arguments $TakajoArgs `
                -WorkDir (Split-Path -Parent $exe) -Detail ([IO.Path]::GetFileName($txtTjSource.Text.Trim())))
}

function New-ParentDirectory([string]$FilePath) {
    # output/ is gitignored, so output\takajo\ does not exist on a fresh
    # checkout and Takajo dies with "unable to open database file".
    $dir = Split-Path -Parent $FilePath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

$btnTakajoBrowse.Add_Click({
    $d = New-Object Microsoft.Win32.OpenFileDialog
    $d.Filter = 'Takajo executable (takajo*.exe)|takajo*.exe|All files (*.*)|*.*'
    if ($d.ShowDialog() -eq $true) {
        $txtTakajo.Text = $d.FileName; Update-TakajoReadiness
    }
})

$btnTjBrowse.Add_Click({
    $d = New-Object Microsoft.Win32.OpenFileDialog
    $d.Filter = 'Hayabusa JSONL (*.jsonl)|*.jsonl|All files (*.*)|*.*'
    $start = $script:Folders.Hayabusa
    if (Test-Path $start) { $d.InitialDirectory = $start }
    if ($d.ShowDialog() -eq $true) {
        $txtTjSource.Text = $d.FileName; Update-TakajoReadiness
    }
})
$txtTjSource.Add_LostFocus({ Update-TakajoReadiness })
$txtTakajo.Add_LostFocus({ Update-TakajoReadiness })

# WPF has no folder picker in .NET Framework, so the three folder browsers stay
# on the WinForms dialog the shell already loads the assembly for.
foreach ($pair in @(@($btnTjOutBrowse, $txtTjOut), @($btnTjHtmlBrowse, $txtTjHtml), @($btnTjRulesBrowse, $txtTjRules))) {
    $btn = $pair[0]; $box = $pair[1]
    $btn.Add_Click({
        $d = New-Object System.Windows.Forms.FolderBrowserDialog
        if ($box.Text -and (Test-Path -LiteralPath $box.Text)) { $d.SelectedPath = $box.Text }
        if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $box.Text = $d.SelectedPath }
    }.GetNewClosure())
}

$btnTjAutomagic.Add_Click({
    if ($script:Busy) { return }
    if (-not (Test-TakajoReady)) { return }
    Set-AppBusy $true 'Takajo automagic'
    Start-UiJob 'Takajo automagic'
    try {
        $tjDir = Split-Path -Parent $txtTakajo.Text.Trim()
        # automagic refuses a folder that already exists, so pick the next free
        # name and show it, rather than failing on every run after the first.
        $outDir = Get-NextFreeFolder $txtTjOut.Text.Trim()
        $txtTjOut.Text = $outDir
        New-ParentDirectory $outDir
        # automagic is the one subcommand that takes an ABSOLUTE --output.
        $a = Get-TakajoArgs -Command 'automagic' -TakajoDir $tjDir `
                -Timeline $txtTjSource.Text.Trim() -OutDir $outDir `
                -Level $cmbTjLevel.SelectedItem -ShowProgress:($chkConsole.IsChecked -eq $true)
        $code = Invoke-TakajoCommand $a 'Takajo automagic'
        $n = @(Get-ChildItem -LiteralPath $outDir -Recurse -File -ErrorAction SilentlyContinue).Count
        if ($code -eq 0 -and $n -gt 0) {
            $lblTjAuto.Text = "Done. $n file(s) in $outDir"
            $lblTjAuto.Foreground = $script:TjOk
        } else {
            $lblTjAuto.Text = "Takajo exited $code and produced $n file(s). See the log."
            $lblTjAuto.Foreground = $script:TjBad
        }
    } catch {
        $lblTjAuto.Text = "Failed: $($_.Exception.Message)"; $lblTjAuto.Foreground = $script:TjBad
        Write-Log "Takajo automagic failed: $($_.Exception.Message)`n" 'err'
    } finally {
        Stop-UiJob
        Set-AppBusy $false
    }
})

$btnTjReport.Add_Click({
    if ($script:Busy) { return }
    if (-not (Test-TakajoReady)) { return }
    Set-AppBusy $true 'Takajo HTML report'
    Start-UiJob 'Takajo html-report'
    try {
        $tjDir = Split-Path -Parent $txtTakajo.Text.Trim()
        $htmlDir = $txtTjHtml.Text.Trim()
        $db = Join-Path (Split-Path -Parent $htmlDir) 'takajo-report.sqlite'
        New-ParentDirectory $db
        New-ParentDirectory (Join-Path $htmlDir 'x')
        # html-report prepends "./" to --output, so Get-TakajoArgs turns the
        # folder into a path RELATIVE to the takajo directory. Only long flags
        # are emitted: -s is --skipProgressBar for automagic but --dboutput
        # here, so the short forms are not interchangeable.
        $a = Get-TakajoArgs -Command 'html-report' -TakajoDir $tjDir `
                -Timeline $txtTjSource.Text.Trim() -OutDir $htmlDir `
                -RulePath $txtTjRules.Text.Trim() -DbPath $db -Sqlite:($chkTjSqlite.IsChecked -eq $true) `
                -ShowProgress:($chkConsole.IsChecked -eq $true)
        $code = Invoke-TakajoCommand $a 'Takajo html-report'
        $n = @(Get-ChildItem -LiteralPath $htmlDir -Recurse -File -ErrorAction SilentlyContinue).Count
        if ($code -eq 0 -and $n -gt 0) {
            $lblTjHtml.Text = "Done. $n file(s). Open $htmlDir\index.html"
            $lblTjHtml.Foreground = $script:TjOk
        } else {
            $lblTjHtml.Text = "Takajo exited $code and produced $n file(s). See the log."
            $lblTjHtml.Foreground = $script:TjBad
        }
    } catch {
        $lblTjHtml.Text = "Failed: $($_.Exception.Message)"; $lblTjHtml.Foreground = $script:TjBad
        Write-Log "Takajo html-report failed: $($_.Exception.Message)`n" 'err'
    } finally {
        Stop-UiJob
        Set-AppBusy $false
    }
})

$btnTjOpen.Add_Click({
    # Straight from disk - the report is self-contained files, so nothing
    # has to listen on a port for it.
    $dir = $txtTjHtml.Text.Trim()
    $index = if ($dir) { Join-Path $dir 'index.html' } else { '' }
    if (-not $index -or -not (Test-Path -LiteralPath $index)) {
        $lblTjHtml.Text = "No report in that folder yet - BUILD OFFLINE HTML first."
        $lblTjHtml.Foreground = $script:TjBad
        return
    }
    try { Start-Process -FilePath $index -ErrorAction Stop }
    catch { Write-Log "Could not open $index - $($_.Exception.Message)`n" 'err' }
})

$btnTjCmd.Add_Click({
    $text = Get-ManualTakajoCommand -Exe $txtTakajo.Text.Trim() -Timeline $txtTjSource.Text.Trim() `
                -OutDir (Get-NextFreeFolder $txtTjOut.Text.Trim()) -Level $cmbTjLevel.SelectedItem `
                -RulePath $txtTjRules.Text.Trim() -HtmlDir $txtTjHtml.Text.Trim() -Sqlite:($chkTjSqlite.IsChecked -eq $true)
    Show-CommandWindow 'Manual Takajo' `
        'What RUN AUTOMAGIC and BUILD OFFLINE HTML do, as PowerShell. Takajo must run from its own folder - the first line goes there.' $text
})


# ------------------------------------------------------------- defaults ----
$txtTakajo.Text  = Find-Takajo
$txtTjOut.Text   = Join-Path $script:Folders.Takajo 'case-1'
$txtTjHtml.Text  = Join-Path $script:Folders.Takajo 'html'
$txtTjRules.Text = Join-Path $script:AppRoot 'hayabusa-x64\rules'
$tjDefaultTimeline = Get-ScanOutputPath $script:Root
if (Test-Path $tjDefaultTimeline) { $txtTjSource.Text = $tjDefaultTimeline }
Update-TakajoReadiness
