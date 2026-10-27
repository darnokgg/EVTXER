<#
.SYNOPSIS
    Settings tab - WPF fragment, dot-sourced by HayabusaMissionTool.ps1.

.DESCRIPTION
    Where the tool keeps the operator's evidence, and the Archive that moves
    it out once it has been processed.

    - EVTX drop folder: what Collect fills and Convert / Raw Events read.
      Every tab reads $script:Folders.Evtx when it runs, so a change applies at
      once; the two boxes that were pre-filled with the old folder follow it.
    - Archive folder: local, or \\server\share. No credentials are stored: if
      Windows Explorer can reach the share, so can the tool.
    - Archive: one verified zip per host folder, then the source is deleted.
      The work is Compress-EvtxFolder in HayabusaLib.ps1, run in a background
      runspace (Start-LibJob) so the window stays live.

    Saved in code\settings.conf (Read-ToolSettings / Save-ToolSettings).
#>

# ============================================================== XAML =========
$setXaml = @'
<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
      xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
      Margin="2,10,10,10">
  <StackPanel>

    <!-- Split: what an operator touches every mission
         first, what is set once per machine after it. The queue pane
         holds the automatic-processing switches. -->
    <WrapPanel Margin="4,0,0,8">
      <TextBlock Text="THIS MISSION" Foreground="{DynamicResource Muted}" FontWeight="SemiBold" FontSize="12"/>
      <TextBlock Text="check these at the start of every mission" Style="{DynamicResource Hint}" Margin="10,0,0,0"/>
    </WrapPanel>
    <Border Style="{DynamicResource CardPanel}">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="140"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Grid.ColumnSpan="3" Text="Mission" Style="{DynamicResource SectionHead}"/>
        <TextBlock Grid.Row="1" Grid.Column="0" Text="Mission name" Margin="0,0,10,0"/>
        <TextBox   Grid.Row="1" Grid.Column="1" x:Name="txtMission"/>
        <Button    Grid.Row="1" Grid.Column="2" x:Name="btnMissionUse" Content="Use on the Upload tab" Margin="8,0,0,0"/>
        <TextBlock Grid.Row="2" Grid.Column="1" Grid.ColumnSpan="2" x:Name="lblMission" Style="{DynamicResource Hint}" Margin="0,8,0,0" TextWrapping="Wrap"/>
        <DockPanel Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="2" Margin="0,10,0,0">
          <Button DockPanel.Dock="Left" x:Name="btnMissionDelete" Content="Delete mission index..."/>
          <TextBlock TextWrapping="Wrap" Style="{DynamicResource Hint}" Margin="12,0,0,0" VerticalAlignment="Center"
                     Text="When the mission is over. Needs a verified connection on the Upload tab."/>
        </DockPanel>
      </Grid>
    </Border>

    <Border Style="{DynamicResource CardPanel}">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="140"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Grid.ColumnSpan="4" Text="Accountability PCAP" Style="{DynamicResource SectionHead}"/>
        <TextBlock Grid.Row="1" Grid.ColumnSpan="4" Style="{DynamicResource Hint}" Margin="0,0,0,10"
                   Text="Capture your own traffic while EVTXER works, so every packet of the mission can be shown afterwards. Wireshark's dumpcap captures; every file is kept, a new one every 3 GB. The capture keeps running when EVTXER closes."/>
        <TextBlock Grid.Row="2" Grid.Column="0" Text="Wireshark folder" Margin="0,0,10,0"/>
        <TextBox   Grid.Row="2" Grid.Column="1" x:Name="txtPcapWs"/>
        <Button    Grid.Row="2" Grid.Column="2" x:Name="btnPcapWs" Content="Browse..." Margin="8,0,0,0"/>
        <TextBlock Grid.Row="3" Grid.Column="0" Text="Interface" Margin="0,8,10,0"/>
        <ComboBox  Grid.Row="3" Grid.Column="1" x:Name="cmbPcapIf" Margin="0,8,0,0" DisplayMemberPath="Label"/>
        <Button    Grid.Row="3" Grid.Column="2" x:Name="btnPcapIfRefresh" Content="Refresh" Margin="8,8,0,0"/>
        <TextBlock Grid.Row="4" Grid.Column="0" Text="PCAP folder" Margin="0,8,10,0"/>
        <TextBox   Grid.Row="4" Grid.Column="1" x:Name="txtPcapDir" Margin="0,8,0,0"/>
        <Button    Grid.Row="4" Grid.Column="2" x:Name="btnPcapDir" Content="Browse..." Margin="8,8,0,0"/>
        <Button    Grid.Row="4" Grid.Column="3" x:Name="btnPcapDirDefault" Content="Default" Margin="8,8,0,0"/>
        <StackPanel Grid.Row="5" Grid.Column="1" Grid.ColumnSpan="3" Margin="0,10,0,0">
          <CheckBox x:Name="chkPcapRemind"
                    Content="Before every network action, ask 'Is accountability PCAP started?' (not while a capture runs)"/>
          <CheckBox x:Name="chkPcapViewer" Margin="0,6,0,0"
                    Content="Open Wireshark to watch it live when a capture starts (a viewer only - closing it does not stop the capture)"/>
        </StackPanel>
        <StackPanel Grid.Row="6" Grid.Column="1" Grid.ColumnSpan="3" Margin="0,12,0,0">
          <TextBlock x:Name="lblPcapStatus" TextWrapping="Wrap"/>
          <StackPanel Orientation="Horizontal" Margin="0,8,0,0">
            <Button x:Name="btnPcapStart" Content="START CAPTURE" Style="{DynamicResource Primary}" MinWidth="160"/>
            <Button x:Name="btnPcapStop" Content="Stop capture" Margin="8,0,0,0"/>
            <Button x:Name="btnPcapWatch" Content="Watch in Wireshark" Margin="8,0,0,0"/>
            <Button x:Name="btnPcapRefresh" Content="Refresh" Margin="8,0,0,0"/>
          </StackPanel>
        </StackPanel>
      </Grid>
    </Border>

    <Border Style="{DynamicResource CardPanel}">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="140"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Grid.ColumnSpan="4" Text="Archive" Style="{DynamicResource SectionHead}"/>
        <TextBlock Grid.Row="1" Grid.ColumnSpan="4" Style="{DynamicResource Hint}" Margin="0,0,0,10"
                   Text="Moves the raw EVTX out of the drop folder once they are processed: one zip per host folder, holding its .evtx and their manifest. The zip is written as .partial, every file is read back and checked by SHA-256, and only then is it renamed and the host folder deleted. A failure or Cancel leaves the host folder untouched."/>
        <TextBlock Grid.Row="2" Grid.Column="0" Text="Archive folder" Margin="0,0,10,0"/>
        <TextBox   Grid.Row="2" Grid.Column="1" x:Name="txtSetArchive"/>
        <Button    Grid.Row="2" Grid.Column="2" x:Name="btnSetArchive" Content="Browse..." Margin="8,0,0,0"/>
        <Button    Grid.Row="2" Grid.Column="3" x:Name="btnSetArchiveDefault" Content="Default" Margin="8,0,0,0"/>
        <TextBlock Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="3" Style="{DynamicResource Hint}" Margin="0,8,0,10"
                   Text="A local folder or a share (\\server\share\folder). Nothing is stored to log on: if Windows Explorer can open the share as you, so can the tool."/>

        <TextBlock Grid.Row="4" Grid.Column="0" Text="Host folders" Margin="0,4,10,0" VerticalAlignment="Top"/>
        <ListBox   Grid.Row="4" Grid.Column="1" Grid.ColumnSpan="3" x:Name="lstArchive" Height="170"
                   SelectionMode="Multiple"
                   Background="#1A1D22" BorderBrush="#333941" BorderThickness="1" Foreground="#F2F2F2"
                   ScrollViewer.HorizontalScrollBarVisibility="Disabled">
          <!-- A selected row is only a shade darker, so each row shows a tick
               bound to its own selection: what will be archived is visible. -->
          <ListBox.ItemTemplate>
            <DataTemplate>
              <!-- A TextBlock, not Content="...": a string Content treats its
                   first underscore as an access key and drops it, and host
                   folders are named HOST_yyyyMMdd_HHmmss. -->
              <CheckBox Focusable="False"
                        IsChecked="{Binding IsSelected, RelativeSource={RelativeSource AncestorType=ListBoxItem}}">
                <TextBlock Text="{Binding Label}"/>
              </CheckBox>
            </DataTemplate>
          </ListBox.ItemTemplate>
        </ListBox>
        <DockPanel Grid.Row="5" Grid.Column="1" Grid.ColumnSpan="3" Margin="0,8,0,0">
          <Button DockPanel.Dock="Left" x:Name="btnArchAll" Content="Select all"/>
          <Button DockPanel.Dock="Left" x:Name="btnArchRefresh" Content="Refresh" Margin="8,0,0,0"/>
          <TextBlock TextWrapping="Wrap" x:Name="lblArchList" Style="{DynamicResource Hint}" Margin="12,0,0,0" VerticalAlignment="Center"/>
        </DockPanel>
        <StackPanel Grid.Row="6" Grid.Column="1" Grid.ColumnSpan="3" Margin="0,12,0,0">
          <Button x:Name="btnArchive" Content="ARCHIVE SELECTED" MinWidth="220" HorizontalAlignment="Left"
                  Style="{DynamicResource Primary}"/>
          <TextBlock x:Name="lblArchResult" Margin="0,10,0,0" TextWrapping="Wrap"/>
        </StackPanel>
      </Grid>
    </Border>

    <WrapPanel Margin="4,10,0,8">
      <TextBlock Text="SETUP" Foreground="{DynamicResource Muted}" FontWeight="SemiBold" FontSize="12"/>
      <TextBlock Text="once per machine, rarely changed" Style="{DynamicResource Hint}" Margin="10,0,0,0"/>
    </WrapPanel>
    <Border Style="{DynamicResource CardPanel}">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="140"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Grid.ColumnSpan="4" Text="EVTX drop folder" Style="{DynamicResource SectionHead}"/>
        <TextBlock Grid.Row="1" Grid.Column="0" Text="Folder" Margin="0,0,10,0"/>
        <TextBox   Grid.Row="1" Grid.Column="1" x:Name="txtSetEvtx"/>
        <Button    Grid.Row="1" Grid.Column="2" x:Name="btnSetEvtx" Content="Browse..." Margin="8,0,0,0"/>
        <Button    Grid.Row="1" Grid.Column="3" x:Name="btnSetEvtxDefault" Content="Default" Margin="8,0,0,0"/>
        <TextBlock Grid.Row="2" Grid.Column="1" Grid.ColumnSpan="3" Style="{DynamicResource Hint}" Margin="0,8,0,0"
                   Text="The Collect tab writes one folder per host here; Convert and Raw Events read from here. A change applies at once and is remembered."/>
      </Grid>
    </Border>

    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <TextBlock Text="Hayabusa rules" Style="{DynamicResource SectionHead}"/>
        <TextBlock x:Name="lblRules" TextWrapping="Wrap"/>
        <TextBlock Style="{DynamicResource Hint}" Margin="0,6,0,10" TextWrapping="Wrap"
                   Text="New detection rules come out every few days. UPDATE RULES fetches the latest from GitHub (needs internet). With no internet: on a connected machine open github.com/Yamato-Security/hayabusa-rules, Code, Download ZIP, bring the zip over and use Update from file. Either way the rules in use are kept as a backup, and they come back by themselves if the update fails."/>
        <StackPanel Orientation="Horizontal">
          <Button x:Name="btnRulesUpdate" Content="UPDATE RULES (internet)" Style="{DynamicResource Primary}" MinWidth="200"/>
          <Button x:Name="btnRulesFile" Content="Update from file..." Margin="8,0,0,0"/>
          <Button x:Name="btnRulesRestore" Content="Restore previous rules" Margin="8,0,0,0"/>
        </StackPanel>
      </StackPanel>
    </Border>

    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <TextBlock Text="Pop-up windows" Style="{DynamicResource SectionHead}"/>
        <CheckBox x:Name="chkSetRunLog" Content="Open each job's run log in Notepad when the job finishes"/>
        <TextBlock Style="{DynamicResource Hint}" Margin="0,6,0,0" TextWrapping="Wrap"
                   Text="Every collection, conversion, upload and import writes a run log either way. With this off, nothing pops up: the log pane names the file, and Logs folder (under the log) opens them all. Remembered on this machine."/>
      </StackPanel>
    </Border>

  </StackPanel>
</Grid>
'@

$setRoot = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$setXaml)))
$tabSettings.Content = $setRoot
foreach ($setName in @('txtSetEvtx','btnSetEvtx','btnSetEvtxDefault','txtSetArchive','btnSetArchive','btnSetArchiveDefault',
                       'lstArchive','btnArchAll','btnArchRefresh','lblArchList','btnArchive','lblArchResult',
                       'txtPcapWs','btnPcapWs','cmbPcapIf','btnPcapIfRefresh','txtPcapDir','btnPcapDir','btnPcapDirDefault',
                       'chkPcapRemind','chkPcapViewer','btnPcapWatch','lblPcapStatus','btnPcapStart','btnPcapStop','btnPcapRefresh',
                       'txtMission','btnMissionUse','lblMission','btnMissionDelete',
                       'lblRules','btnRulesUpdate','btnRulesFile','btnRulesRestore','chkSetRunLog')) {
    Set-Variable -Name $setName -Scope Script -Value $setRoot.FindName($setName)
}
$script:SetBrush = @{}
foreach ($pair in @{ ok = '#7EC87E'; err = '#F2A0A0' }.GetEnumerator()) {
    $b = (New-Object System.Windows.Media.BrushConverter).ConvertFromString($pair.Value); $b.Freeze()
    $script:SetBrush[$pair.Key] = $b
}

# ============================================================ helpers ========
function Save-SettingsTab {
    # The default is saved as '' rather than its path, so a copy of the tool
    # moved to another folder or machine still uses its own evtx\ and archive\.
    $def = Get-FolderLayout $script:Root
    $script:Settings.EvtxFolder    = if ($script:Folders.Evtx -eq $def.Evtx) { '' } else { $script:Folders.Evtx }
    $script:Settings.ArchiveFolder = if ($script:Folders.Archive -eq $def.Archive) { '' } else { $script:Folders.Archive }
    try { Save-ToolSettings $script:Settings $script:SettingsPath }
    catch { Write-Log "Could not save $script:SettingsPath - the change lasts until the tool closes: $($_.Exception.Message)`n" 'warn' }
}

function Update-ArchiveList {
    # Not a folder a queued job still needs: zipping and deleting it would
    # pull it out from under the queue.
    $lstArchive.ItemsSource = @(Get-ArchiveCandidates $script:Folders.Evtx | Where-Object { -not (Test-QueueHoldsFolder $script:Jobs $_.Path) })
    $n = @($lstArchive.ItemsSource).Count
    $lblArchList.Text = if ($n) { "$n host folder(s) in $($script:Folders.Evtx). Click to select." }
                        else    { "No host folders with .evtx in $($script:Folders.Evtx)." }
}

function Resolve-SettingsFolder([string]$Text, [string]$Current, $Box) {
    # The full, normalised path, or $null when there is nothing to change - and
    # then the box is put back to the folder in use.
    $full = ConvertTo-FolderSetting $Text
    if ($Text.Trim() -and -not $full) {
        [void][System.Windows.MessageBox]::Show("Use a full path, such as D:\evtx or \\server\share\evtx.", 'Settings')
    }
    if (-not $full -or $full -eq $Current) { $Box.Text = $Current; return $null }
    return $full
}

function Set-EvtxDropFolder([string]$Path) {
    $Path = Resolve-SettingsFolder $Path $script:Folders.Evtx $txtSetEvtx
    if (-not $Path) { return }
    try { New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null }
    catch {
        [void][System.Windows.MessageBox]::Show("Cannot use $Path as the drop folder:`n`n$($_.Exception.Message)", 'Settings')
        $txtSetEvtx.Text = $script:Folders.Evtx; return
    }
    $old = $script:Folders.Evtx
    $script:Folders.Evtx = $Path
    $txtSetEvtx.Text = $Path
    # The boxes that were showing the old default follow it; a folder the
    # operator chose on that tab stays theirs.
    if ($txtEvtx -and $txtEvtx.Text -eq $old) { $txtEvtx.Text = $Path }
    if ($txtSoFolder -and $txtSoFolder.Text -eq $old) {
        $txtSoFolder.Text = $Path
        if (Get-Command Update-SoFiles -ErrorAction SilentlyContinue) { [void](Update-SoFiles) }
    }
    Save-SettingsTab
    Update-ArchiveList
    Write-Log "EVTX drop folder is now $Path (was $old).`n" 'info'
}

function Set-ArchiveFolder([string]$Path) {
    # Not checked here: a share may be offline now and back by the time it is
    # used, and asking a dead server would hold the window up. Archiving says
    # so if it cannot reach it.
    $Path = Resolve-SettingsFolder $Path $script:Folders.Archive $txtSetArchive
    if (-not $Path) { return }
    $old = $script:Folders.Archive
    $script:Folders.Archive = $Path
    $txtSetArchive.Text = $Path
    Save-SettingsTab
    Write-Log "Archive folder is now $Path (was $old).`n" 'info'
}

function Select-SettingsFolder([string]$Description, [string]$Current) {
    $d = New-Object System.Windows.Forms.FolderBrowserDialog
    $d.Description = $Description
    if ($Current -and $Current -notlike '\\*' -and (Test-Path -LiteralPath $Current)) { $d.SelectedPath = $Current }
    if ($d.ShowDialog() -ne 'OK') { return $null }
    return $d.SelectedPath
}

# ============================================================ handlers =======
$btnSetEvtx.Add_Click({
    $p = Select-SettingsFolder 'EVTX drop folder: Collect writes here, Convert and Raw Events read from here' $script:Folders.Evtx
    if ($p) { Set-EvtxDropFolder $p }
})
$btnSetEvtxDefault.Add_Click({ Set-EvtxDropFolder (Get-FolderLayout $script:Root).Evtx })
$txtSetEvtx.Add_LostFocus({ Set-EvtxDropFolder $txtSetEvtx.Text })

$btnSetArchive.Add_Click({
    $p = Select-SettingsFolder 'Archive folder (a local folder or a network share)' $script:Folders.Archive
    if ($p) { Set-ArchiveFolder $p }
})
$btnSetArchiveDefault.Add_Click({ Set-ArchiveFolder (Get-FolderLayout $script:Root).Archive })
$txtSetArchive.Add_LostFocus({ Set-ArchiveFolder $txtSetArchive.Text })

$btnArchAll.Add_Click({ $lstArchive.SelectAll() })
$btnArchRefresh.Add_Click({ Update-ArchiveList })
# A collection adds host folders while this tab is out of sight. Selection
# events bubble up from every list inside the tabs, so only the tab strip's own
# change counts.
$tabs.Add_SelectionChanged({
    param($s, $e)
    if ($e.OriginalSource -eq $tabs -and $tabs.SelectedItem -and $tabs.SelectedItem.Content -eq $tabSettings -and -not $script:Busy) {
        Update-ArchiveList
        if (-not $script:PcapIfs.Count) { Update-PcapInterfaces }
        Update-PcapStatus
    }
})

$btnArchive.Add_Click({
    if ($script:Busy) { return }
    $picked = @($lstArchive.SelectedItems | Where-Object { -not (Test-QueueHoldsFolder $script:Jobs $_.Path) })
    if (-not $picked.Count) { [void][System.Windows.MessageBox]::Show('Select one or more host folders first.', 'Archive'); return }
    $dest = $script:Folders.Archive
    $bytes = [long]($picked | Measure-Object Bytes -Sum).Sum
    $ask = "Archive $($picked.Count) host folder(s) ($(Format-ByteSize $bytes)) to:`n`n  $dest`n`n" +
           "Each folder becomes one zip of its .evtx and manifest. Once the zip is verified, the folder is DELETED from the drop folder.`n`n" +
           "Convert (and upload) them first if you still need them here."
    if ([System.Windows.MessageBox]::Show($ask, 'Archive', 'YesNo', 'Warning') -ne 'Yes') { return }

    $lblArchResult.Text = ''
    $protocol = if ($dest -like '\\*') { 'SMB' } else { 'local disk' }
    $ok = 0; $bad = 0
    if ($dest -like '\\*' -and -not (Confirm-PcapBeforeNetwork "archive EVTX to $dest")) { return }
    Set-AppBusy $true 'archiving EVTX'
    Start-UiJob 'Archive EVTX'
    try {
        Write-Log "`n$('=' * 70)`nARCHIVE $($picked.Count) host folder(s) -> $dest`n$('=' * 70)`n" 'info'
        $i = 0
        foreach ($c in $picked) {
            if ($script:CancelRequested) { break }
            $i++
            Write-Log "[$i/$($picked.Count)] $($c.Name)`n" 'info'
            $outcome = 'FAILED'; $detail = ''; $r = $null
            $clock = [Diagnostics.Stopwatch]::StartNew()
            $job = Start-LibJob 'Compress-EvtxFolder' @{ Folder = $c.Path; ArchiveRoot = $dest }
            try {
                while ($true) {
                    $finished = $job.Handle.IsCompleted
                    $m = $null
                    while ($job.Lines.TryDequeue([ref]$m)) { Write-Log "$m`n" (Get-CollectLogKind $m) }
                    if ($finished) { break }
                    if ($script:CancelRequested) { $job.Progress.Cancel = $true }
                    $p = $job.Progress
                    $frac = if ($p.Total) { [double]$p.Done / $p.Total } else { -1 }
                    $pct = if ($frac -ge 0) { " $([int](100 * $frac))%" } else { '' }
                    Set-UiJobProgress "Archive $i/$($picked.Count)" "$($c.Name) - $($p.Step)$pct" $null $frac
                    Invoke-UiPump
                    Start-Sleep -Milliseconds 100
                }
                $r = Complete-LibJob $job
                $outcome = if ($r.Left.Count) { 'Partial' } else { 'Success' }
                $detail = if ($r.Left.Count) { "zip verified; could not delete from the drop folder: $($r.Left -join ', ')" } else { 'zip verified; host folder deleted' }
                $ok++
            } catch {
                $bad++
                $msg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
                $outcome = if ($msg -match 'Cancelled') { 'Cancelled' } else { 'FAILED' }
                $detail = "$($msg.TrimEnd('.')) - the host folder was not touched"
                Write-Log "  [!!] $($c.Name): $detail`n" 'err'
            } finally {
                Write-Ledger @(New-LedgerRow -Action 'EVTX archive' -Target $c.Name -Protocol $protocol -Result $outcome `
                                  -Files "$($c.Files) EVTX" -Bytes $c.Bytes -Seconds $clock.Elapsed.TotalSeconds `
                                  -Integrity $(if ($r) { 'SHA-256 of every file re-read from the zip: match' } else { '' }) `
                                  -Output $(if ($r) { $r.Zip } else { $dest }) -Details $detail)
            }
        }
        $lblArchResult.Text = "$ok archived to $dest$(if ($bad) { ", $bad not archived - see the log" })."
        $lblArchResult.Foreground = if ($bad) { $script:SetBrush.err } else { $script:SetBrush.ok }
    } finally {
        # A box still naming a host folder that has just gone (Collect hands
        # Convert the host folder it filled) goes back to the drop folder.
        foreach ($box in @($txtEvtx, $txtSoFolder)) {
            if ($box -and $box.Text -and -not (Test-Path -LiteralPath $box.Text)) { $box.Text = $script:Folders.Evtx }
        }
        Update-ArchiveList
        Stop-UiJob
        Set-AppBusy $false
    }
})

# ============================================================ rules ===
# The work is Update-HayabusaRules / Restore-HayabusaRules in HayabusaLib.ps1.
$script:RulesUpdating = $false
function Update-RulesLabel {
    $exe = Find-Hayabusa
    if (-not $exe) { $lblRules.Text = 'Hayabusa is missing from code\hayabusa-x64.'; return }
    $i = Get-RulesInfo (Join-Path (Split-Path -Parent $exe) 'rules')
    $lblRules.Text = "$('{0:N0}' -f $i.Count) rules - $(if ($i.From) { $i.From } else { 'as shipped with EVTXER' })$(if ($i.HasPrevious) { '. The rules from before are kept as a backup.' })"
    $btnRulesRestore.IsEnabled = $i.HasPrevious
}

function Invoke-RulesUpdate([string]$ZipFile) {
    if ($script:Busy) { return }
    $exe = Find-Hayabusa
    if (-not $exe) { [void][System.Windows.MessageBox]::Show('Hayabusa is missing from code\hayabusa-x64.', 'Hayabusa rules'); return }
    # A scan or conversion reads the rules: swapping them under one would
    # break it. The queue holds new ones from here on (Get-QueueBlockers) -
    # set BEFORE the PCAP question, whose window lets the queue's timer run.
    $script:RulesUpdating = $true
    if (-not $ZipFile -and -not (Confirm-PcapBeforeNetwork 'fetch the latest Hayabusa rules from GitHub')) { $script:RulesUpdating = $false; return }
    if ($script:QueueRun -and -not $script:QueueRun.Handle.IsCompleted) {
        $script:RulesUpdating = $false
        [void][System.Windows.MessageBox]::Show('A queued job is running. Update the rules when it has finished, or Cancel it in the queue first.', 'Hayabusa rules'); return
    }
    Set-AppBusy $true 'updating the Hayabusa rules'
    Start-UiJob 'Update Hayabusa rules'
    $result = 'FAILED'; $detail = ''
    try {
        Write-Log "`nUPDATING THE HAYABUSA RULES from $(if ($ZipFile) { $ZipFile } else { 'GitHub' })`n" 'info'
        $p = @{ HayabusaExe = $exe }
        if ($ZipFile) { $p.ZipFile = $ZipFile }
        $job = Start-LibJob 'Update-HayabusaRules' $p
        while ($true) {
            $finished = $job.Handle.IsCompleted
            $m = $null
            while ($job.Lines.TryDequeue([ref]$m)) { Write-Log "$m`n" (Get-CollectLogKind $m) }
            if ($finished) { break }
            if ($script:CancelRequested) { $job.Progress.Cancel = $true }
            Invoke-UiPump
            Start-Sleep -Milliseconds 100
        }
        $r = Complete-LibJob $job
        $result = 'Success'; $detail = "$($r.Before) -> $($r.After) rule files, $($r.From)"
        Write-Log "Hayabusa rules updated: $detail`n" 'ok'
    } catch {
        $detail = $_.Exception.Message
        Write-Log "RULES NOT UPDATED: $detail`n" 'err'
        [void][System.Windows.MessageBox]::Show("The rules were not updated:`n`n$detail`n`nThe rules in use were kept.", 'Hayabusa rules')
    } finally {
        $script:RulesUpdating = $false
        Update-RulesLabel
        Stop-UiJob
        Write-Ledger @(New-LedgerRow -Action 'Rules update' -Target $(if ($ZipFile) { [IO.Path]::GetFileName($ZipFile) } else { 'github.com (Yamato-Security/hayabusa-rules)' }) `
                          -Protocol $(if ($ZipFile) { 'file' } else { 'HTTPS (git)' }) -Result $result -Details $detail)
        Set-AppBusy $false
    }
}

$btnRulesUpdate.Add_Click({ Invoke-RulesUpdate '' })
$btnRulesFile.Add_Click({
    $d = New-Object Microsoft.Win32.OpenFileDialog
    $d.Title = 'The hayabusa-rules zip (github.com/Yamato-Security/hayabusa-rules, Code, Download ZIP)'
    $d.Filter = 'Zip (*.zip)|*.zip'
    if ($d.ShowDialog($win) -ne $true) { return }
    Invoke-RulesUpdate $d.FileName
})
$btnRulesRestore.Add_Click({
    if ($script:Busy) { return }
    if ([System.Windows.MessageBox]::Show('Put back the rules from before the last update? The current ones become the backup, so this can be undone.', 'Hayabusa rules', 'YesNo') -ne 'Yes') { return }
    $script:RulesUpdating = $true
    if ($script:QueueRun -and -not $script:QueueRun.Handle.IsCompleted) {
        $script:RulesUpdating = $false
        [void][System.Windows.MessageBox]::Show('A queued job is running. Restore the rules when it has finished.', 'Hayabusa rules'); return
    }
    Set-AppBusy $true 'restoring the Hayabusa rules'
    $result = 'FAILED'; $detail = ''
    try {
        $i = Restore-HayabusaRules (Split-Path -Parent (Find-Hayabusa))
        $result = 'Success'; $detail = "$($i.Count) rule files, $(if ($i.From) { $i.From } else { 'as shipped' })"
        Write-Log "Hayabusa rules restored: $detail.`n" 'ok'
    } catch {
        $detail = $_.Exception.Message
        Write-Log "Could not restore the rules: $detail`n" 'err'
    } finally {
        $script:RulesUpdating = $false
        Update-RulesLabel
        Write-Ledger @(New-LedgerRow -Action 'Rules restore' -Target 'local' -Result $result -Details $detail)
        Set-AppBusy $false
    }
})

# ======================================================= accountability PCAP ===
$script:PcapIfs = @()

function Update-PcapInterfaces {
    # dumpcap -D takes about a second, so it runs when asked, not at startup.
    $dumpcap = Find-Dumpcap $script:Settings.WiresharkFolder
    $script:PcapIfs = if ($dumpcap) { @(ConvertFrom-DumpcapInterfaces @(& $dumpcap -D 2>$null)) } else { @() }
    $cmbPcapIf.ItemsSource = $script:PcapIfs
    $pick = @($script:PcapIfs | Where-Object { $_.Device -eq $script:Settings.PcapInterface })[0]
    if ($pick) { $cmbPcapIf.SelectedItem = $pick }
    if (-not $dumpcap) { Write-Log "Wireshark's dumpcap.exe was not found - install Wireshark (with Npcap), or set its folder on the Settings tab.`n" 'warn' }
}

function Update-PcapStatus {
    $all = @(Get-RunningCaptures)
    $running = @($all | Where-Object { -not $_.IsViewer })
    $viewing = @($all | Where-Object { $_.IsViewer }).Count -gt 0
    if ($running.Count) {
        $what = foreach ($r in $running) {
            $names = @($r.Interfaces | ForEach-Object { $d = $_; $n = @($script:PcapIfs | Where-Object { $_.Device -eq $d })[0]; if ($n) { $n.Name } else { $d } })
            if ($names.Count) { "$($names -join ', ') -> $($r.File) (pid $($r.ProcessId))" }
            else { "pid $($r.ProcessId) - started elevated or by another user, so what it captures cannot be read" }
        }
        $lblPcapStatus.Text = "Capturing: $($what -join '; ')$(if ($viewing) { "`nWireshark is showing it live." })"
        $lblPcapStatus.Foreground = $script:SetBrush.ok
        # Already running: no second capture.
        $btnPcapStart.Visibility = 'Collapsed'; $btnPcapStop.Visibility = 'Visible'
    } else {
        $lblPcapStatus.Text = 'No capture running.'
        $lblPcapStatus.Foreground = $script:SetBrush.err
        $btnPcapStart.Visibility = 'Visible'; $btnPcapStop.Visibility = 'Collapsed'
    }
    $free = Get-FreeSpaceBytes (Get-PcapFolder)
    if ($free -ge 0 -and $free -lt 10GB) { $lblPcapStatus.Text += "`nOnly $(Format-ByteSize $free) free in the PCAP folder - the capture stops when the disk is full." }
    # The title-row pill at once, not at the next tick.
    Update-PcapPill
}

$btnPcapWs.Add_Click({
    $p = Select-SettingsFolder "Wireshark's folder (the one holding dumpcap.exe)" $txtPcapWs.Text
    if ($p) {
        if (-not (Test-Path -LiteralPath (Join-Path $p 'dumpcap.exe'))) { [void][System.Windows.MessageBox]::Show("No dumpcap.exe in $p.", 'Settings'); return }
        $script:Settings.WiresharkFolder = $p; $txtPcapWs.Text = $p; Save-SettingsTab; Update-PcapInterfaces
    }
})
$btnPcapIfRefresh.Add_Click({ Update-PcapInterfaces })
$cmbPcapIf.Add_SelectionChanged({
    if ($cmbPcapIf.SelectedItem -and $cmbPcapIf.SelectedItem.Device -ne $script:Settings.PcapInterface) {
        $script:Settings.PcapInterface = $cmbPcapIf.SelectedItem.Device
        Save-SettingsTab
        Write-Log "Capture interface: $($cmbPcapIf.SelectedItem.Name).`n" 'info'
    }
})
$btnPcapDir.Add_Click({
    $p = Select-SettingsFolder 'Where the accountability PCAP files go' (Get-PcapFolder)
    if ($p) { $script:Settings.PcapFolder = $p; $txtPcapDir.Text = $p; Save-SettingsTab; Update-PcapStatus }
})
$btnPcapDirDefault.Add_Click({ $script:Settings.PcapFolder = ''; $txtPcapDir.Text = Get-PcapFolder; Save-SettingsTab; Update-PcapStatus })
$chkPcapRemind.Add_Click({
    $script:Settings.PcapReminder = $(if ($chkPcapRemind.IsChecked -eq $true) { 'on' } else { 'off' })
    $script:Settings.PcapSnoozeUntil = ''
    Save-SettingsTab
})
$btnPcapStart.Add_Click({ if (-not $script:Busy) { [void](Start-AccountabilityCapture) } })
$btnPcapRefresh.Add_Click({ Update-PcapStatus })
$btnPcapWatch.Add_Click({ Open-CaptureViewer; Start-Sleep -Milliseconds 800; Update-PcapStatus })
$chkPcapViewer.Add_Click({
    $script:Settings.PcapViewer = $(if ($chkPcapViewer.IsChecked -eq $true) { 'on' } else { 'off' })
    Save-SettingsTab
})
$btnPcapStop.Add_Click({
    $running = @(Get-RunningCaptures | Where-Object { -not $_.IsViewer })
    if (-not $running.Count) { Update-PcapStatus; return }
    $list = ($running | ForEach-Object { "  pid $($_.ProcessId): $(if ($_.File) { $_.File } else { '(started elevated or by another program)' })" }) -join "`n"
    $ask = "Stop every dumpcap capture on this machine - including any not started by EVTXER (Wireshark's own, for one)?`n`n$list`n`nThe files written so far are kept."
    if ([System.Windows.MessageBox]::Show($ask, 'Accountability PCAP', 'YesNo', 'Warning') -ne 'Yes') { return }
    foreach ($r in $running) {
        $ok = $true
        try { Stop-Process -Id $r.ProcessId -ErrorAction Stop } catch { $ok = $false }
        Write-Ledger @(New-LedgerRow -Action 'PCAP stop' -Target ($r.Interfaces -join ' ') -Protocol 'dumpcap' `
                          -Result $(if ($ok) { 'Success' } else { 'FAILED' }) -Output $r.File `
                          -Details $(if ($ok) { "pid $($r.ProcessId)" } else { "pid $($r.ProcessId) - started elevated? Stop it from an administrator Task Manager." }))
        Write-Log $(if ($ok) { "Capture stopped (pid $($r.ProcessId)).`n" } else { "Could not stop capture pid $($r.ProcessId) - it was probably started elevated.`n" }) $(if ($ok) { 'ok' } else { 'err' })
    }
    Start-Sleep -Milliseconds 300
    Update-PcapStatus
})

# ================================================================ mission ===
# One index per mission, deleted when the mission ends.
function Update-MissionLabel {
    $idx = Get-MissionIndexName $txtMission.Text
    # "is deleted when the mission ends" read as automatic; nothing deletes it
    # but the button below (usability walk, 2026-10-21).
    $lblMission.Text = if ($idx) { "Every upload of this mission goes into $idx - one index, appended to. When the mission ends, delete it with 'Delete mission index...': nothing deletes it for you." }
                       else { "Name the mission (e.g. op-falcon). Its uploads all go into one index; when the mission ends, delete it with 'Delete mission index...' - nothing deletes it for you." }
}
function Set-MissionName {
    $name = $txtMission.Text.Trim()
    if ($name -eq $script:Settings.MissionName) { return }
    $script:Settings.MissionName = $name
    Save-SettingsTab
    Update-MissionLabel
    if ($name) { Write-Log "Mission: $name -> $(Get-MissionIndexName $name).`n" 'info' }
}
$txtMission.Add_LostFocus({ Set-MissionName })
$txtMission.Add_TextChanged({ Update-MissionLabel })
$btnMissionUse.Add_Click({
    Set-MissionName
    $idx = Get-MissionIndexName $txtMission.Text
    if (-not $idx) { [void][System.Windows.MessageBox]::Show('Name the mission first.', 'Mission'); return }
    if (-not $txtIndex) { return }
    $txtLabel.Text = $txtMission.Text.Trim(); $txtIndex.Text = $idx; $chkAppend.IsChecked = $true
    Write-Log "Upload tab set to the mission index $idx (appending allowed).`n" 'info'
})

function Read-TypedConfirmation([string]$Title, [string]$Text, [string]$MustType) {
    # A typed confirmation for what cannot be undone: the exact name, not a
    # click that habit answers.
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        SizeToContent="WidthAndHeight" MaxWidth="640" WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
        ResizeMode="NoResize" FontFamily="Segoe UI" FontSize="13" Background="#1E2126">
  <StackPanel Margin="20">
    <TextBlock x:Name="lblText" TextWrapping="Wrap" Margin="0,0,0,12"/>
    <TextBox x:Name="txtTyped" Margin="0,0,0,12"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="btnYes" Content="DELETE" Style="{StaticResource Primary}" MinWidth="110" IsEnabled="False"/>
      <Button x:Name="btnNo" Content="Cancel" Margin="10,0,0,0" MinWidth="90" IsCancel="True"/>
    </StackPanel>
  </StackPanel>
</Window>
'@
    $w = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$xaml)))
    $w.Owner = $win; $w.Title = $Title
    $w.FindName('lblText').Text = $Text
    $typed = $w.FindName('txtTyped'); $yes = $w.FindName('btnYes')
    $state = @{ Ok = $false }
    $typed.Add_TextChanged({ $yes.IsEnabled = ($typed.Text.Trim() -ceq $MustType) }.GetNewClosure())
    $yes.Add_Click({ $state.Ok = $true; $w.Close() }.GetNewClosure())
    $w.FindName('btnNo').Add_Click({ $w.Close() }.GetNewClosure())
    [void]$w.ShowDialog()
    return $state.Ok
}

$btnMissionDelete.Add_Click({
    if ($script:Busy) { return }
    Set-MissionName
    $idx = Get-MissionIndexName $txtMission.Text
    if (-not $idx) { [void][System.Windows.MessageBox]::Show('Name the mission first.', 'Mission'); return }
    if (-not (Test-DeletableIndexName $idx)) { [void][System.Windows.MessageBox]::Show("'$idx' is not an index this tool may delete.", 'Mission'); return }
    $uploading = @($script:Jobs | Where-Object { $_ -and $_.State -ne 'done' -and @($_.Steps)[$_.Step..99] -contains 'upload' })
    if ($uploading.Count) {
        [void][System.Windows.MessageBox]::Show("$($uploading.Count) job(s) in the queue still upload to the mission index. Let them finish, or remove them from the queue, first.", 'Mission'); return
    }
    # Verified, and still the same host, port and account: edited boxes after
    # a VERIFY would send the delete to a stack nobody checked (code review).
    if (-not $script:ConnOk -or $script:ConnKey -ne (Get-UploadConnKey)) {
        [void][System.Windows.MessageBox]::Show('Connect first: VERIFY CONNECTIVITY on the Upload tab, against the stack that holds the mission. If you changed the host, port, user or password since, verify again.', 'Mission'); return
    }
    if (-not (Confirm-PcapBeforeNetwork "delete the mission index $idx")) { return }
    $base = Get-EsBase; $h = Get-AuthHeader $txtUser.Text.Trim() (Get-UploadPassword)
    $docs = $null
    try { $docs = (Invoke-EsJson -Uri "$base/$idx/_count" -Headers $h -TimeoutSec 30).count }
    catch { [void][System.Windows.MessageBox]::Show("$idx was not found on $($txtHost.Text.Trim()) - nothing to delete.", 'Mission'); return }
    $text = "Delete the mission index $idx on $($txtHost.Text.Trim())?`n`nIt holds $('{0:N0}' -f $docs) detection(s). This cannot be undone - Kibana's dashboards stay, the data goes.`n`nType the index name to confirm:"
    if (-not (Read-TypedConfirmation 'Delete mission index' $text $idx)) { Write-Log "Mission index not deleted (cancelled).`n" 'info'; return }
    Set-AppBusy $true "deleting $idx"
    $result = 'FAILED'; $detail = ''
    try {
        Invoke-EsJson -Uri "$base/$idx" -Method Delete -Headers $h -TimeoutSec 60 | Out-Null
        $result = 'Success'; $detail = "$docs detection(s) deleted"
        Write-Log "Mission index $idx deleted ($('{0:N0}' -f $docs) detection(s)).`n" 'ok'
    } catch {
        $detail = $_.Exception.Message
        Write-Log "Could not delete ${idx}: $detail`n" 'err'
    } finally {
        Write-Ledger @(New-LedgerRow -Action 'Delete index' -Target $txtHost.Text.Trim() -Port (Get-UploadPort) -Protocol 'HTTPS' `
                          -Account (Get-EsAccountLabel $txtUser.Text) -Result $result -Output $idx -Details $detail)
        Set-AppBusy $false
    }
})

# ---- initial state ----
$txtSetEvtx.Text    = $script:Folders.Evtx
$txtSetArchive.Text = $script:Folders.Archive
if ($script:Settings.EvtxFolder -and -not (Test-Path -LiteralPath $script:Folders.Evtx)) {
    Write-Log "The saved EVTX drop folder $($script:Folders.Evtx) cannot be reached - Collect will fail until it is back or changed on the Settings tab.`n" 'warn'
}
Update-ArchiveList
$dumpcapNow = Find-Dumpcap ''
$txtPcapWs.Text  = $(if ($script:Settings.WiresharkFolder) { $script:Settings.WiresharkFolder } elseif ($dumpcapNow) { Split-Path -Parent $dumpcapNow } else { '' })
$txtPcapDir.Text = Get-PcapFolder
$chkPcapRemind.IsChecked = ($script:Settings.PcapReminder -ne 'off')
$chkPcapViewer.IsChecked = ($script:Settings.PcapViewer -ne 'off')
$chkSetRunLog.IsChecked = ($script:Settings.OpenRunLog -ne 'off')
# Read by Stop-UiJob when a job ends (a setting to stop the
# run-log pop-ups; the old log-pane checkbox was not remembered between runs).
# Checked/Unchecked, not Click: they fire for mouse, keyboard and UI
# Automation alike. Attached only now, so loading the state above saves nothing.
$saveRunLog = {
    $script:Settings.OpenRunLog = $(if ($chkSetRunLog.IsChecked -eq $true) { 'on' } else { 'off' })
    Save-SettingsTab
}
$chkSetRunLog.Add_Checked($saveRunLog)
$chkSetRunLog.Add_Unchecked($saveRunLog)
# An update or restore cut off by a crash or a killed window left the rules
# where Hayabusa does not read them: put back before anything scans.
$hb = Find-Hayabusa
if ($hb) {
    try { $healed = Repair-HayabusaRules (Split-Path -Parent $hb); if ($healed) { Write-Log "Hayabusa rules were missing after an interrupted update - $healed.`n" 'warn' } }
    catch { Write-Log "Hayabusa rules are missing and could not be put back: $($_.Exception.Message)`n" 'err' }
}
# Counting ~5,000 rule files waits until the window is up.
$lblRules.Text = 'Counting the rules...'
[void]$win.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::ApplicationIdle, [action]{ Update-RulesLabel })
Update-PcapStatus
$txtMission.Text = $script:Settings.MissionName
Update-MissionLabel
# The Upload tab starts on the mission's index when one is set.
if ($script:Settings.MissionName -and $txtIndex -and -not $txtIndex.Text.Trim()) {
    $txtLabel.Text = $script:Settings.MissionName; $txtIndex.Text = Get-MissionIndexName $script:Settings.MissionName; $chkAppend.IsChecked = $true
}
