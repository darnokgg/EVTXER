# Collect EVTX tab - WPF. Dot-sourced by HayabusaWpf.ps1, which owns the
# window, the log pane, Write-Log and Invoke-UiPump.
#
# Every behavioural comment here came with the control it explains; they record
# bugs that were paid for once already.

$script:CollectTargetFile = $null
# The loaded file's first host, for the account hint - read once on load, not
# on every keystroke in the boxes the hint follows.
$script:CollectTargetFirst = $null

$collectXaml = @'
<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
      xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Margin="2,4,10,4">
  <StackPanel>

    <Border Style="{StaticResource CardPanel}">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="220"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock x:Name="lblTargets" Grid.Row="0" Grid.Column="0" Style="{StaticResource SectionHead}"
                   Text="Targets *  (one per line, or comma-separated)"/>
        <TextBlock Grid.Row="0" Grid.Column="1" Style="{StaticResource Hint}" HorizontalAlignment="Right"
                   Text="* = required"/>

        <TextBox x:Name="txtTargets" Grid.Row="1" Grid.Column="0" Height="54"
                 AcceptsReturn="True" VerticalScrollBarVisibility="Auto"
                 FontFamily="Consolas" Margin="0,0,12,0"/>
        <StackPanel Grid.Row="1" Grid.Column="1">
          <Button x:Name="btnLoadTargets" Content="Load target file..."/>
          <!-- The box shows three lines; this opens the whole list, big,
               scrollable and editable. -->
          <Button x:Name="btnExpandTargets" Content="Expand list..." Margin="0,8,0,0"
                  ToolTip="See and edit every target in a large window"/>
          <TextBlock x:Name="lblTargetCount" Style="{StaticResource Hint}" Margin="0,8,0,0" TextWrapping="Wrap"/>
          <TextBlock x:Name="lblLoadedFile" Style="{StaticResource Hint}" Margin="0,4,0,0" Text="" TextWrapping="Wrap"/>
        </StackPanel>
      </Grid>
    </Border>

    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <Border Grid.Column="0" Margin="0,0,5,9" VerticalAlignment="Stretch" Style="{StaticResource CardPanel}">
        <StackPanel>
          <TextBlock x:Name="lblMethodHead" Style="{StaticResource SectionHead}" Text="Collection Method *"/>

          <RadioButton x:Name="rbSmb" Content="SMB (port 445)" GroupName="method"/>
          <TextBlock x:Name="lblSmbCaption" Style="{StaticResource Hint}" Margin="24,3,0,0"/>
          <TextBlock x:Name="lblSmbCaution" Foreground="{StaticResource Caution}" FontSize="12"
                     Margin="24,3,0,12" TextWrapping="Wrap"/>

          <RadioButton x:Name="rbWinRM" Content="WinRM (port 5985)" GroupName="method"/>
          <TextBlock x:Name="lblWinRmCaption" Style="{StaticResource Hint}" Margin="24,3,0,12"/>
          <!-- What THIS PC still lacks for plain WinRM (Get-LocalWinRmProblems),
               shown as soon as WinRM is picked, not after VERIFY fails. -->
          <TextBlock x:Name="lblWinRmLocal" Foreground="{StaticResource Warn}" FontSize="12"
                     Margin="24,-6,0,12" TextWrapping="Wrap" Visibility="Collapsed"/>

          <RadioButton x:Name="rbWinRMHttps" Content="WinRM over HTTPS (port 5986)" GroupName="method"/>
          <TextBlock x:Name="lblWinRmHttpsCaption" Style="{StaticResource Hint}" Margin="24,3,0,0"/>
          <!-- Live only under WinRM over HTTPS (the binding). Off by default:
               unticked, the certificate proves the target is
               the machine that was typed in. Self-signed certificates and IP
               targets need it ticked, and the refusal hint says so. -->
          <CheckBox x:Name="chkSkipCertCheck" Margin="24,6,0,0"
                    IsEnabled="{Binding IsChecked, ElementName=rbWinRMHttps}"
                    Content="Skip certificate check (self-signed certificate or IP target)"/>
          <!-- What a collection leaves on a target - measured on a test workstation,
               2026-10-20 (before/after snapshot): nothing else changed. -->
          <TextBlock Style="{StaticResource Hint}" Margin="0,12,0,0" TextWrapping="Wrap"
                     Text="On the target: one network logon (event 4624) per connection, and with WinRM a temporary copy of the logs in C:\Windows\Temp that is deleted afterwards. Nothing is installed or changed there."/>
        </StackPanel>
      </Border>
      <Border Grid.Column="1" Margin="5,0,0,9" VerticalAlignment="Stretch" Style="{StaticResource CardPanel}">
        <StackPanel>
          <TextBlock Style="{StaticResource SectionHead}" Text="Log Category"/>

          <RadioButton x:Name="rbDfir" GroupName="cat" Content="DFIR (recommended default)" IsChecked="True"/>
          <StackPanel x:Name="pnlDfirLogs" Margin="24,6,0,12">
            <TextBlock x:Name="lblDfirLogs"/>
            <TextBlock x:Name="lblDfirCol1" Style="{StaticResource Hint}" Margin="0,4,0,0"/>
            <TextBlock x:Name="lblDfirCol2" Style="{StaticResource Hint}" Visibility="Collapsed"/>
            <Button x:Name="btnDfirExpand" HorizontalAlignment="Left" Margin="0,6,0,0" Padding="10,2"
                    ToolTip="The DFIR preset's full list of logs - the same list COLLECT pulls"/>
          </StackPanel>

          <RadioButton x:Name="rbAll" Content="All" GroupName="cat"/>
          <TextBlock x:Name="lblAllWarning" Foreground="{StaticResource Warn}" FontSize="12"
                     Margin="24,3,0,12" TextWrapping="Wrap"
                     Text="ALL pulls every .evtx on the host - expect 2-20+ GB per host."/>

          <RadioButton x:Name="rbCustom" Content="Custom" GroupName="cat"/>


          <!-- The notes sit UNDER the list, not beside it. Beside it they took
               300 of the card's ~430px and left the channel names showing about
               eight characters each, with a horizontal scrollbar to read the
               rest - in a card whose whole purpose is choosing between names
               that differ only at the end. -->
          <StackPanel x:Name="pnlCustom" Margin="24,8,0,0" Visibility="Collapsed">
            <TextBlock x:Name="lblCustomHint" TextWrapping="Wrap"
                       Text="Select the logs to collect. Click a name to read what it is for."/>
            <ListBox x:Name="clbLogs" Height="132" Margin="0,6,0,0"
                     Background="#1A1D22" BorderBrush="#333941" BorderThickness="1"
                     Foreground="#F2F2F2" HorizontalContentAlignment="Stretch"
                     ScrollViewer.HorizontalScrollBarVisibility="Disabled"
                     ScrollViewer.VerticalScrollBarVisibility="Auto"/>
            <TextBlock x:Name="lblLogNotes" Style="{StaticResource Hint}" Margin="0,8,0,0"
                       MinHeight="34" VerticalAlignment="Top"/>
          </StackPanel>
        </StackPanel>
      </Border>
    </Grid>


    <Border Style="{StaticResource CardPanel}">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="260"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Grid.ColumnSpan="4" Style="{StaticResource SectionHead}" Text="Collection Credentials"/>

        <!-- One field decides the account prefix, because HOST\user versus
             DOMAIN\user was the most common collection failure. Empty means
             off-domain: each target logs in as TARGET\user. -->
        <TextBlock x:Name="lblCredDomain" Grid.Row="1" Grid.Column="0" Text="Domain" Margin="0,0,12,8"/>
        <TextBox   x:Name="txtCredDomain" Grid.Row="1" Grid.Column="1" Margin="0,0,12,8"/>
        <TextBlock Grid.Row="1" Grid.Column="2" Grid.ColumnSpan="2" Style="{StaticResource Hint}" Margin="6,0,0,8"
                   Text="CORP or corp.local - or type user@corp.local as the username. Empty for workgroup targets."
                   TextWrapping="Wrap"/>

        <TextBlock x:Name="lblCredUser" Grid.Row="2" Grid.Column="0" Text="Username *" Margin="0,0,12,0"/>
        <TextBox   x:Name="txtCredUser" Grid.Row="2" Grid.Column="1" Margin="0,0,12,0"/>
        <TextBlock x:Name="lblCredPass" Grid.Row="2" Grid.Column="2" Text="Password" Margin="6,0,12,0"/>
        <Grid Grid.Row="2" Grid.Column="3" HorizontalAlignment="Left">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="220"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <PasswordBox x:Name="txtCredPass"/>
            <TextBox     x:Name="txtCredPassPlain" Visibility="Collapsed"/>
          </Grid>
          <CheckBox x:Name="chkShowCredPass" Grid.Column="1" Content="Show" Margin="10,0,0,0"/>
        </Grid>

        <TextBlock x:Name="lblCredHint" Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="3" Style="{StaticResource Hint}"
                   Margin="0,6,0,0"/>
      </Grid>
    </Border>

    <Grid Margin="2,2,2,8">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <Button x:Name="btnCollect"      Grid.Column="0" Content="COLLECT" Style="{StaticResource Primary}"/>
      <Button x:Name="btnVerifyAccess" Grid.Column="1" Content="VERIFY ACCESS" Margin="10,0,0,0"/>
      <Button x:Name="btnTestPorts"    Grid.Column="2" Content="TEST PORTS" Margin="10,0,0,0"/>
      <Button x:Name="btnRetry"        Grid.Column="3" Content="RETRY FAILED" Margin="10,0,0,0"
              IsEnabled="False"/>
      <Button x:Name="btnCollectCmd"   Grid.Column="4" Content="Show command" Margin="10,0,0,0"
              ToolTip="The same collection as PowerShell to paste by hand, if the tool breaks"/>
      <TextBlock x:Name="lblCollectStatus" Grid.Column="5" Style="{StaticResource Hint}" Margin="16,0,0,0"
                 Text="Ready. Collected logs land in evtx\&lt;hostname&gt;_&lt;timestamp&gt;\"/>
    </Grid>

    <!-- An off-domain (workgroup) target fails for reasons the error messages
         hide: domain credentials mean nothing to it, SMB needs an admin share
         Windows Home does not have, and WinRM ships disabled on workstations.
         Stated up front, because each one costs a failed run to discover. -->
    <TextBlock x:Name="lblOffDomain" Foreground="{StaticResource Warn}" FontSize="12" Margin="2,0,2,10"/>
  </StackPanel>
</Grid>
'@

$collectRoot = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$collectXaml)))
$tabCollect.Content = $collectRoot
foreach ($n in @('lblTargets','txtTargets','btnLoadTargets','lblLoadedFile','btnExpandTargets','lblTargetCount','lblMethodHead','rbSmb',
                 'lblSmbCaution','lblSmbCaption','rbWinRM','lblWinRmCaption',
                 'rbWinRMHttps','lblWinRmHttpsCaption','lblWinRmLocal','chkSkipCertCheck','rbDfir',
                 'rbAll','lblAllWarning','rbCustom','pnlDfirLogs','lblDfirLogs','lblDfirCol1','lblDfirCol2','btnDfirExpand',
                 'pnlCustom','lblCustomHint','clbLogs','lblLogNotes','lblCredUser','txtCredUser',
                 'lblCredDomain','txtCredDomain','lblCredPass','txtCredPass','txtCredPassPlain','chkShowCredPass','lblCredHint',
                 'btnCollect','btnVerifyAccess','btnTestPorts','btnRetry','btnCollectCmd','lblCollectStatus','lblOffDomain')) {
    Set-Variable -Name $n -Scope Script -Value $collectRoot.FindName($n)
}

# Caption text lives in HayabusaLib so its wording is covered by tests -
# specifically that the SMB caution is about the log DATA, not the password.
$smbText   = Get-MethodCaption 'SMB'
$winrmText = Get-MethodCaption 'WinRM'
$lblSmbCaution.Text   = $smbText.Caution
$lblSmbCaption.Text   = $smbText.Caption
$lblWinRmCaption.Text = $winrmText.Caption
$lblWinRmHttpsCaption.Text = (Get-MethodCaption 'WinRM-HTTPS').Caption

# The list below names every preset channel in full; a one-line summary of
# sixteen channels could not fit beside the radio and was removed.
$lblDfirLogs.Text    = 'DFIR preset collects these {0} logs:' -f $script:DfirPreset.Count
# One column: at half the tab's width, two columns wrapped the longer channel
# names mid-name and the block read as noise. Four lines until asked for the
# rest (all sixteen pushed the card's other choices down).
$script:DfirShown = 4
$script:DfirExpanded = $false
function Update-DfirList {
    $all  = @($script:DfirPreset)
    $show = if ($script:DfirExpanded) { $all } else { @($all | Select-Object -First $script:DfirShown) }
    $lblDfirCol1.Text = ($show | ForEach-Object { "- $_" }) -join "`r`n"
    $btnDfirExpand.Visibility = if ($all.Count -gt $script:DfirShown) { 'Visible' } else { 'Collapsed' }
    $btnDfirExpand.Content = if ($script:DfirExpanded) { 'Show fewer' }
                             else { "Show all $($all.Count) logs ($($all.Count - $script:DfirShown) more)" }
}
$btnDfirExpand.Add_Click({ $script:DfirExpanded = -not $script:DfirExpanded; Update-DfirList })
Update-DfirList

$lblOffDomain.Text = "Off-domain target: leave Domain empty and use a local admin account (password required) - SMB needs the C`$ admin share, WinRM must be enabled at the target's console."

# Says exactly which account each target will be asked for, computed by the
# same Resolve-CollectUsername the collector uses, so the hint cannot lie.
function Update-CollectCredHint {
    $user = $txtCredUser.Text.Trim()
    $dom  = $txtCredDomain.Text.Trim()
    $lblCredHint.Text =
        if (-not $user) {
            if ($dom) { "Logs in as $(Resolve-CollectUsername '<user>' $dom '') on every target" }
            else      { "No domain: logs in as <target>\<user> - a local account on each target" }
        } else {
            $first = @(ConvertTo-HostList $txtTargets.Text) | Select-Object -First 1
            if (-not $first) { $first = $script:CollectTargetFirst }
            if (-not $first) { $first = '<target>' }
            $resolved = Resolve-CollectUsername $user $dom $first
            if ($resolved -eq $user) { "Logs in as $user on every target (explicit account, Domain ignored)" }
            elseif ($dom)            { "Logs in as $resolved on every target" }
            else                     { "Logs in as $resolved - each target's own name as the prefix" }
        }
}
$txtCredUser.Add_TextChanged({ Update-CollectCredHint })
$txtCredDomain.Add_TextChanged({ Update-CollectCredHint })
$txtTargets.Add_TextChanged({ Update-CollectCredHint; Update-TargetCount })
function Format-TargetCount([string]$Text, [string]$File) {
    $n = @(ConvertTo-HostList $Text $File).Count
    "$n target$(if ($n -ne 1) { 's' })"
}
function Update-TargetCount {
    # What the collection will actually visit: the box and a loaded file,
    # each host once.
    $c = Format-TargetCount $txtTargets.Text $script:CollectTargetFile
    $lblTargetCount.Text = if ($c -ne '0 targets') { $c } else { '' }
}

# ---- the Targets window ----
$script:TargetsWinXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Targets" Width="640" Height="580" MinWidth="420" MinHeight="320"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
        UseLayoutRounding="True" FontFamily="Segoe UI" FontSize="13" Background="#1E2126">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <TextBlock Style="{StaticResource Hint}" TextWrapping="Wrap" Margin="0,0,0,10"
               Text="Every target, one per line: IP addresses or host names. Scroll, type, paste or delete here; OK puts the list back in the Collect tab."/>
    <TextBox x:Name="txtBigTargets" Grid.Row="1" AcceptsReturn="True" TextWrapping="NoWrap"
             VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
             VerticalContentAlignment="Top" FontFamily="Consolas" FontSize="14"/>
    <DockPanel Grid.Row="2" Margin="0,12,0,0">
      <Button DockPanel.Dock="Right" x:Name="btnBigCancel" Content="Cancel" MinWidth="80" Margin="8,0,0,0"/>
      <Button DockPanel.Dock="Right" x:Name="btnBigOk" Content="OK" Style="{StaticResource Primary}" MinWidth="80"/>
      <Button DockPanel.Dock="Left" x:Name="btnBigTidy" Content="Tidy: sort, remove duplicates"
              ToolTip="One per line, each once, IP addresses in number order, then names A-Z"/>
      <TextBlock x:Name="lblBigCount" Style="{StaticResource Hint}" Margin="12,0,12,0" VerticalAlignment="Center" TextWrapping="Wrap"/>
    </DockPanel>
  </Grid>
</Window>
'@
function Show-TargetsWindow {
    # Opens with what the collection would visit - the box and any loaded
    # file - one per line. OK writes it all back into the box and unloads the
    # file, so a host deleted here is really gone.
    $w = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$script:TargetsWinXaml)))
    $w.Owner = $win
    $script:BigTargets = $w.FindName('txtBigTargets'); $script:BigCount = $w.FindName('lblBigCount')
    $script:BigTargets.Text = (@(ConvertTo-HostList $txtTargets.Text $script:CollectTargetFile) -join "`r`n")
    $script:BigOk = $false
    $script:BigTargets.Add_TextChanged({ $script:BigCount.Text = Format-TargetCount $script:BigTargets.Text })
    $w.FindName('btnBigTidy').Add_Click({ $script:BigTargets.Text = Format-TargetList $script:BigTargets.Text })
    $w.FindName('btnBigOk').Add_Click({ $script:BigOk = $true; $script:BigWin.Close() })
    $w.FindName('btnBigCancel').Add_Click({ $script:BigWin.Close() })
    $script:BigWin = $w
    $script:BigCount.Text = Format-TargetCount $script:BigTargets.Text
    [void]$script:BigTargets.Focus()
    [void]$w.ShowDialog()
    if ($script:BigOk) {
        $txtTargets.Text = $script:BigTargets.Text
        if ($script:CollectTargetFile) {
            $script:CollectTargetFile = $null; $script:CollectTargetFirst = $null
            $lblLoadedFile.Text = 'The loaded file is now part of the list above.'
        }
        Update-TargetCount
    }
}
$btnExpandTargets.Add_Click({ if (-not $script:Busy) { Show-TargetsWindow } })

# WinForms had CheckedListBox. WPF has no such control, so each row IS a
# CheckBox: the ListBox still gives selection (for the notes pane) and the
# checked state lives on the item itself.
$script:LogCatalog = @(Get-LogCatalog)
foreach ($entry in $script:LogCatalog) {
    $cb = New-Object System.Windows.Controls.CheckBox
    # The name goes in a wrapping TextBlock, because the longest channel
    # ("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational") needs
    # 456px in a list that is 429px wide, and these names differ at the END -
    # clipping one is the same as not showing it.
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.Text = $entry.LogName
    $tb.TextWrapping = 'Wrap'
    $cb.Content = $tb
    # And the name lives on .Tag, because .Content is now a control: a caller
    # reading Content would collect a log called
    # "System.Windows.Controls.TextBlock".
    $cb.Tag = $entry.LogName
    [void]$clbLogs.Items.Add($cb)
}
$clbLogs.Add_SelectionChanged({
    if ($clbLogs.SelectedIndex -ge 0 -and $clbLogs.SelectedIndex -lt $script:LogCatalog.Count) {
        $entry = $script:LogCatalog[$clbLogs.SelectedIndex]
        $lblLogNotes.Text = "$($entry.LogName) - $($entry.Notes)"
    }
})

# A masked box with no way to look at it means a typo only shows up as a failed
# logon. WPF's PasswordBox cannot unmask itself, so Show swaps in a plain
# TextBox holding the same value - and the value is read back through
# Get-CollectPassword so no caller has to know which one is visible.
$chkShowCredPass.Add_Checked({
    $txtCredPassPlain.Text = $txtCredPass.Password
    $txtCredPassPlain.Visibility = 'Visible'
    $txtCredPass.Visibility = 'Collapsed'
})
$chkShowCredPass.Add_Unchecked({
    $txtCredPass.Password = $txtCredPassPlain.Text
    $txtCredPass.Visibility = 'Visible'
    $txtCredPassPlain.Visibility = 'Collapsed'
})
function Get-CollectPassword {
    if ($chkShowCredPass.IsChecked -eq $true) { $txtCredPassPlain.Text } else { $txtCredPass.Password }
}

$btnLoadTargets.Add_Click({
    $d = New-Object Microsoft.Win32.OpenFileDialog
    $d.Filter = 'Text files (*.txt;*.csv;*.lst)|*.txt;*.csv;*.lst|All files (*.*)|*.*'
    $d.Title  = 'Select a file containing target hosts (one per line)'
    if (Test-Path -LiteralPath $script:Folders.Targets) { $d.InitialDirectory = $script:Folders.Targets }
    if ($d.ShowDialog() -ne $true) { return }
    $script:CollectTargetFile = $d.FileName
    $script:CollectTargetFirst = @(ConvertTo-HostList '' $d.FileName) | Select-Object -First 1
    $lblLoadedFile.Text = "Loaded: $($d.FileName)"
    Update-CollectCredHint
    Update-TargetCount
})

function Update-CollectCategory {
    $isCustom = $rbCustom.IsChecked -eq $true
    $isDfir   = $rbDfir.IsChecked -eq $true
    $pnlCustom.Visibility   = if ($isCustom) { 'Visible' } else { 'Collapsed' }
    $clbLogs.IsEnabled      = $isCustom
    $pnlDfirLogs.Visibility = if ($isDfir) { 'Visible' } else { 'Collapsed' }
}
$rbDfir.Add_Checked({ Update-CollectCategory })
$rbAll.Add_Checked({ Update-CollectCategory })
$rbCustom.Add_Checked({ Update-CollectCategory })

# A label marked red for a missing field went back to normal only on the next
# button press, so a filled-in form still looked wrong (usability walk,
# 2026-10-21). Filling a field clears its red at once; nothing turns red here.
function Clear-CollectHighlightFilled {
    $ready = Get-CollectFormReadiness (Get-CollectFormState)
    foreach ($key in $script:CollectFieldLabels.Keys) {
        $ctl = $script:CollectFieldLabels[$key]
        if ($ctl -and $ready.Missing -notcontains $key -and $ctl.Foreground -eq $script:BrushCaution) { $ctl.Foreground = $script:BrushInk }
    }
}
# Plain WinRM's two needs on THIS PC, said when it is picked.
function Update-WinRmLocal {
    $p = @(Get-LocalWinRmProblems $(if ($rbWinRM.IsChecked -eq $true) { 'WinRM' } else { '' }))
    $lblWinRmLocal.Text = ($p | ForEach-Object { "This PC: $_" }) -join "`n"
    $lblWinRmLocal.Visibility = if ($p.Count) { 'Visible' } else { 'Collapsed' }
}
foreach ($rb in @($rbSmb, $rbWinRM, $rbWinRMHttps)) {
    $rb.Add_Checked({ Update-WinRmLocal; Clear-CollectHighlightFilled })
}
$txtTargets.Add_TextChanged({ Clear-CollectHighlightFilled })
$txtCredUser.Add_TextChanged({ Clear-CollectHighlightFilled })

# Reads the Collect tab into the shape Test-CollectReadiness expects. The
# method is '' when neither radio is picked - the old
# `if ($rbWinRM.Checked) { 'WinRM' } else { 'SMB' }` read "nothing chosen" as
# SMB, which is how an unmade choice became an unencrypted collection.
function Get-CollectFormState {
    $method = if ($rbWinRM.IsChecked -eq $true) { 'WinRM' }
              elseif ($rbWinRMHttps.IsChecked -eq $true) { 'WinRM-HTTPS' }
              elseif ($rbSmb.IsChecked -eq $true) { 'SMB' } else { '' }
    $category = if ($rbAll.IsChecked -eq $true) { 'All' } elseif ($rbCustom.IsChecked -eq $true) { 'Custom' } else { 'DFIR' }
    [pscustomobject]@{
        Targets    = @(ConvertTo-HostList $txtTargets.Text $script:CollectTargetFile)
        Method     = $method
        SkipCertCheck = ($method -eq 'WinRM-HTTPS' -and $chkSkipCertCheck.IsChecked -eq $true)
        Category   = $category
        CustomLogs = @($clbLogs.Items | Where-Object { $_.IsChecked -eq $true } | ForEach-Object { "$($_.Tag)" })
        Username   = $txtCredUser.Text.Trim()
        Domain     = $txtCredDomain.Text.Trim()
    }
}

# Every gap painted in one pass, and every one of them cleared again when it is
# filled. Telling the operator about one missing field per click is how a
# four-field form takes four clicks to submit.
$script:CollectFieldLabels = @{
    Targets    = $lblTargets
    Method     = $lblMethodHead
    Username   = $lblCredUser
    CustomLogs = $lblCustomHint
}
$script:BrushInk     = $win.FindResource('Ink')
$script:BrushMuted   = $win.FindResource('Muted')
$script:BrushCaution = $win.FindResource('Caution')
$script:BrushOk      = (New-Object System.Windows.Media.BrushConverter).ConvertFromString('#7EC87E')
$script:BrushWarn    = $win.FindResource('Warn')

function Set-CollectHighlight([string[]]$Missing) {
    foreach ($key in $script:CollectFieldLabels.Keys) {
        $ctl = $script:CollectFieldLabels[$key]
        if (-not $ctl) { continue }
        $ctl.Foreground = if ($Missing -contains $key) { $script:BrushCaution } else { $script:BrushInk }
    }
}

# Kerberos needs a hostname; a bare IP falls back to NTLM and the target's
# identity goes unverified. Shown when the operator is about to connect, which
# is when it can still change what they type.
function Write-CollectAuthNote($Targets, [bool]$SkipCertCheck) {
    $note = Get-TargetAuthNote $Targets
    if ($note) { Write-Log "$note`n" 'warn' }
    if ($SkipCertCheck) {
        Write-Log "NOTE: certificate check skipped - the session is still encrypted, but nothing proves the target is the machine you typed.`n" 'warn'
    }
}

# Both click handlers opened with the same read-check-paint-bail block. One
# copy, because two drifting copies of a pre-flight check is how a button ends
# up enforcing something the other one does not.
# The one place the form is judged complete - the buttons and the live
# red-label clearing both ask here, so they cannot disagree.
function Get-CollectFormReadiness($State) {
    return (Test-CollectReadiness -Targets $State.Targets -Method $State.Method `
                -Username $State.Username `
                -Category $State.Category -CustomLogs $State.CustomLogs)
}

function Get-ReadyCollectFormState([switch]$LogRefusal) {
    $state = Get-CollectFormState
    $ready = Get-CollectFormReadiness $state
    Set-CollectHighlight $ready.Missing
    if (-not $ready.Ready) {
        $lblCollectStatus.Text = "Fill the fields marked in red: $($ready.Missing -join ', ')"
        $lblCollectStatus.Foreground = $script:BrushCaution
        # Only Collect logs the refusal: Verify Access repaints and says
        # nothing, because the operator is still filling the form in.
        if ($LogRefusal) { Write-Log "Not started - missing: $($ready.Missing -join ', ')`n" 'err' }
        return $null
    }
    return $state
}

$btnVerifyAccess.Add_Click({
    if ($script:Busy) { return }
    $state = Get-ReadyCollectFormState
    if (-not $state) { return }

    $cred = New-CollectCredential $state.Username (Get-CollectPassword)
    if (-not (Confirm-PcapBeforeNetwork 'verify access to the targets')) { return }
    Set-AppBusy $true 'verifying access'
    $lblCollectStatus.Text = 'Verifying access...'; $lblCollectStatus.Foreground = $script:BrushMuted
    try {
        Write-Log "`nVERIFY ACCESS - $($state.Method) - $($state.Targets.Count) target(s)`n" 'info'
        # The IP note comes from Test-CollectAccess itself; only the skip note
        # is said here (it was printed twice - usability walk, 2026-10-21).
        if ($state.SkipCertCheck) { Write-CollectAuthNote @() $true }
        $res = @(Test-CollectAccess -Targets $state.Targets -Method $state.Method -Credential $cred -Domain $state.Domain `
            -SkipCertificateCheck:$state.SkipCertCheck -LogWriter { param($m) Write-Log $m (Get-CollectLogKind $m) })
        $good = @($res | Where-Object { $_.Ok }).Count
        $port = Get-CollectPort $state.Method
        Write-Ledger @($res | ForEach-Object {
            New-LedgerRow -Action 'Verify access' -Target $_.Target -Port $port -Protocol $state.Method -Account $_.Account `
                -Result $(if ($_.Ok) { 'OK' } else { 'Failed' }) `
                -Details $(if ($_.Ok) { 'all checks passed' } else { (@($_.Checks) | Select-Object -Last 2) -join ' / ' })
        })
        $lblCollectStatus.Text = "$good of $($res.Count) target(s) ready to collect."
        $lblCollectStatus.Foreground = if ($good -eq $res.Count) { $script:BrushOk } else { $script:BrushCaution }
    }
    catch {
        # Failed on THIS PC before any target was asked (not elevated, WinRM
        # service stopped): say that plainly, and still leave the activity-log
        # row every access check owes (usability walk, 2026-10-21).
        $why = Get-CollectFailureText $_.Exception
        Write-Log "Verify failed: $why`n" 'err'
        $lblCollectStatus.Text = 'Verify failed. See the log.'; $lblCollectStatus.Foreground = $script:BrushCaution
        Write-Ledger @($state.Targets | ForEach-Object {
            New-LedgerRow -Action 'Verify access' -Target $_ -Port (Get-CollectPort $state.Method) -Protocol $state.Method `
                -Account (Resolve-CollectUsername $state.Username $state.Domain $_) -Result 'Failed' -Details $why
        })
    }
    finally {
        $cred = $null
        Set-AppBusy $false
    }
})

$btnTestPorts.Add_Click({
    if ($script:Busy) { return }
    $targets = @((Get-CollectFormState).Targets)
    if ($targets.Count -eq 0) {
        Set-CollectHighlight @('Targets')
        $lblCollectStatus.Text = 'Enter at least one target.'; $lblCollectStatus.Foreground = $script:BrushCaution
        return
    }
    if (-not (Confirm-PcapBeforeNetwork "test the targets' ports")) { return }
    Set-AppBusy $true 'testing ports'
    $lblCollectStatus.Text = 'Testing ports...'; $lblCollectStatus.Foreground = $script:BrushMuted
    try {
        Write-Log "`nTEST PORTS - $($targets.Count) target(s)`n" 'info'
        $res = @(Test-CollectPorts -Targets $targets -LogWriter { param($m) Write-Log $m (Get-CollectLogKind $m) })
        Write-Ledger @(foreach ($r in $res) {
            foreach ($m in 'SMB', 'WinRM', 'WinRM-HTTPS') {
                New-LedgerRow -Action 'Port test' -Target $r.Target -Port (Get-CollectPort $m) -Protocol $m `
                    -Result $(if ($r.$m) { 'Open' } else { 'Not open' })
            }
        })
        $smb   = @($res | Where-Object { $_.SMB }).Count
        $winrm = @($res | Where-Object { $_.WinRM }).Count
        $https = @($res | Where-Object { $_.'WinRM-HTTPS' }).Count
        $none  = @($res | Where-Object { -not $_.SMB -and -not $_.WinRM -and -not $_.'WinRM-HTTPS' }).Count
        $lblCollectStatus.Text = "Of $($res.Count): SMB open on $smb, WinRM on $winrm, WinRM HTTPS on $https, none on $none."
        $lblCollectStatus.Foreground = if ($none -eq 0) { $script:BrushOk } else { $script:BrushCaution }
    }
    catch {
        Write-Log "Port test failed: $($_.Exception.Message)`n" 'err'
        $lblCollectStatus.Text = 'Port test failed. See the log.'; $lblCollectStatus.Foreground = $script:BrushCaution
    }
    finally {
        Set-AppBusy $false
    }
})

# Hosts the last run did not fully collect. Kept so RETRY can re-run exactly
# those without the operator editing the target list by hand.
$script:RetryTargets = @()

function Update-RetryButton {
    $n = @($script:RetryTargets).Count
    $btnRetry.IsEnabled = ($n -gt 0)
    $btnRetry.Content   = if ($n -gt 0) { "RETRY $n FAILED" } else { 'RETRY FAILED' }
}

function Invoke-Collection([string[]]$Targets) {
    $state = Get-ReadyCollectFormState -LogRefusal
    if (-not $state) { return }

    $user = $state.Username
    $pass = Get-CollectPassword
    # Passed in by RETRY, read from the form by COLLECT.
    $targets = if ($Targets) { @($Targets) } else { $state.Targets }
    $method = $state.Method
    $category = $state.Category
    $customLogs = $state.CustomLogs
    Write-CollectAuthNote $targets $state.SkipCertCheck

    if ($category -eq 'All') {
        $confirm = [System.Windows.MessageBox]::Show(
            "ALL pulls every .evtx file on each target host.`n`nThis can be 2-20+ GB per host and take a long time. Continue?",
            'Confirm ALL collection', 'YesNo', 'Warning')
        if ($confirm -ne 'Yes') { return }
    }

    # Space, before anything is transferred. A collection that fills the disk
    # half way through costs the whole transfer window and leaves a folder that
    # looks like evidence but is not. The estimate is a rule of thumb, so this
    # warns and asks rather than refusing - an operator who knows the target is
    # a quiet VM should not be argued with.
    $estimate = Get-CollectSpaceEstimate -Category $category -TargetCount $targets.Count -LogCount $customLogs.Count
    $space    = Test-CollectSpace -FreeBytes (Get-FreeSpaceBytes $script:Folders.Evtx) -NeedBytes $estimate.Bytes
    if ($space.Level -eq 'Ok') {
        Write-Log "Disk: $($space.Message)`n"
    } else {
        Write-Log "Disk: $($space.Message)`n" $(if ($space.Level -eq 'Short') { 'err' } else { 'warn' })
        if ($space.Level -eq 'Short') {
            $go = [System.Windows.MessageBox]::Show(
                "$($space.Message)`n`nCollect anyway?", 'Not enough free space', 'YesNo', 'Warning')
            if ($go -ne 'Yes') {
                $lblCollectStatus.Text = 'Cancelled - not enough free space.'
                $lblCollectStatus.Foreground = $script:BrushCaution
                return
            }
        }
    }

    # Built fresh from the fields on every click and nulled in the finally block
    # below, so the plaintext password does not linger in memory.
    $cred = New-CollectCredential $user $pass

    if (-not (Confirm-PcapBeforeNetwork 'collect EVTX from the targets')) { return }
    Set-AppBusy $true 'collecting EVTX'
    $lblCollectStatus.Text = 'Collecting...'; $lblCollectStatus.Foreground = $script:BrushMuted
    Start-UiJob 'Collect EVTX'
    try {
        $outRoot = $script:Folders.Evtx
        Write-Log "`n$('=' * 70)`nCOLLECTING EVTX from $($targets.Count) target(s) via $method ($category)`nOutput: $outRoot`n$('=' * 70)`n" 'info'

        # In a background runspace, not on this thread: a WinRM pull of a
        # large archive is one Copy-Item that blocks for minutes, and nothing
        # redraws the window while it does. Lines and progress come back
        # through the job's queue and table.
        # HostDone: each host's folder as soon as it is in, for the job queue.
        $job = Start-LibJob 'Invoke-EvtxCollection' -Script $script:EvtxCollectorPath -Parameters @{
            Targets = $targets; Method = $method; Category = $category; CustomLogs = $customLogs
            Credential = $cred; Domain = $state.Domain; OutRoot = $outRoot
            SkipCertificateCheck = [bool]$state.SkipCertCheck
        } -Progress ([hashtable]::Synchronized(@{ Cancel = $false; HostCount = 0
                         HostDone = (New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]') }))
        $cancelSent = $false
        while ($true) {
            $finished = $job.Handle.IsCompleted
            $m = $null
            while ($job.Lines.TryDequeue([ref]$m)) { Write-Log "$m`n" (Get-CollectLogKind $m) }
            while ($job.Progress.HostDone.TryDequeue([ref]$m)) {
                # The queue is extra: a problem there must not stop the collection.
                try { if (Get-Command Add-QueueFolder -ErrorAction SilentlyContinue) { Add-QueueFolder $m } }
                catch { Write-Log "Could not queue $m - add it from the queue's Add folders... button: $($_.Exception.Message)`n" 'warn' }
            }
            if ($finished) { break }
            if ($script:CancelRequested -and -not $cancelSent) {
                $cancelSent = $true
                $job.Progress.Cancel = $true
                Write-Log "Stopping - a WinRM export, archive or download is interrupted where it is (an SMB copy finishes its current file). The target is still cleaned up and TrustedHosts restored.`n" 'warn'
            }
            # How much of the file in flight has landed so far.
            $landed = [long]0
            $inFlight = [string]$job.Progress.DownloadPath
            if ($inFlight) { try { $landed = ([IO.FileInfo]$inFlight).Length } catch { } }
            $view = Get-CollectProgressView $job.Progress $landed
            Set-UiJobProgress 'Collecting' $view.Text $null $view.Fraction
            Invoke-UiPump
            Start-Sleep -Milliseconds 100
        }
        $summary = Complete-LibJob $job

        # Attempted equals Succeeded + Partial + Failed + Skipped. It did not
        # before: the collector's catch incremented nothing, so hosts that threw
        # simply vanished from the arithmetic.
        $worst = if ($summary.Failed -or $summary.Skipped) { 'err' }
                 elseif ($summary.Partial)                 { 'warn' }
                 else                                      { 'ok' }
        Write-Log "`nAttempted : $($summary.Attempted)`nSucceeded : $($summary.Succeeded)`nPartial   : $($summary.Partial)`nFailed    : $($summary.Failed)`nSkipped   : $($summary.Skipped)`nFiles     : $($summary.Files.Count)`n" $worst
        foreach ($p in @($summary.Problems)) { Write-Log "  ! $p`n" 'warn' }

        # Which targets actually came back, one line each, and the same as a
        # CSV beside the evidence - the counts above say how many, not which.
        $hostRows = @($summary.Hosts)
        $port = Get-CollectPort $method
        Write-Ledger @($hostRows | ForEach-Object {
            New-LedgerRow -Action 'Collect' -Target $_.Target -Port $port -Protocol $method -Account $_.Account `
                -Result $_.Outcome -Files "$($_.Collected)/$($_.Requested) logs" -Bytes $_.Bytes -Seconds $_.Seconds `
                -Integrity $_.Integrity -LeftOnTarget $_.LeftOnTarget -Output $_.Folder -Details $_.Detail
        })
        # The Upload tab's case label follows what was collected, unless the
        # operator typed one. See Get-TargetsLabel.
        $gotFiles = @($hostRows | Where-Object { $_.Collected -gt 0 } | ForEach-Object { $_.Target })
        if ($gotFiles.Count -and (Get-Command Set-UploadLabelSuggestion -ErrorAction SilentlyContinue)) {
            Set-UploadLabelSuggestion (Get-TargetsLabel $gotFiles)
        }
        if ($hostRows.Count -gt 0) {
            Write-Log "`nRESULTS BY TARGET`n" 'info'
            foreach ($line in Format-CollectResults $hostRows) { Write-Log "$($line.Text)`n" $line.Kind }
            try {
                $csv = Join-Path $outRoot ("collection_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
                Write-Log "Results saved: $(Export-CollectResults $hostRows $csv)`n" 'info'
            }
            catch { Write-Log "Could not save the results CSV: $($_.Exception.Message)`n" 'warn' }
        }
        Write-Log "Full log: $script:LogFile`n" 'info'

        # Whatever did not fully arrive is offered for a second attempt. The
        # collector hands back bare hostnames for exactly this.
        $script:RetryTargets = @($summary.Retry)
        Update-RetryButton
        if ($script:RetryTargets.Count -gt 0) {
            Write-Log "Retry available for: $($script:RetryTargets -join ', ')`n" 'warn'
        }

        # Hand the evidence to the Convert tab rather than making the operator
        # find it again. One host means its own folder; several means the evtx
        # root, which is the only single path covering the whole run - Hayabusa
        # scans recursively either way. Nothing is set when nothing was
        # collected, so a failed run cannot point the next step at an empty
        # folder. Set-EvtxFolder lives in the Convert fragment; the guard keeps
        # this tab working if that one was not loaded.
        $outFolders = @($summary.OutFolders)
        if ($summary.Files.Count -gt 0 -and (Get-Command Set-EvtxFolder -ErrorAction SilentlyContinue)) {
            $handOff = if ($outFolders.Count -eq 1) { $outFolders[0] } else { $script:Folders.Evtx }
            [void](Set-EvtxFolder $handOff)
        }

        # Green used to be unconditional, so a run where every host failed read
        # exactly like a clean one. The colour follows the worst outcome.
        $lblCollectStatus.Text = "Done: $($summary.Succeeded)/$($summary.Attempted) succeeded, $($summary.Files.Count) file(s)."
        if ($summary.Failed -or $summary.Skipped) {
            $lblCollectStatus.Text += " $($summary.Failed) failed, $($summary.Skipped) skipped."
            $lblCollectStatus.Foreground = $script:BrushCaution
        } elseif ($summary.Partial) {
            $lblCollectStatus.Text += " $($summary.Partial) partial."
            $lblCollectStatus.Foreground = $script:BrushWarn
        } else {
            $lblCollectStatus.Foreground = $script:BrushOk
        }
    } catch {
        # The job's own exception arrives wrapped ("Exception calling
        # "EndInvoke" with "1" argument(s): ..."); the operator gets the cause.
        $why = Get-CollectFailureText $_.Exception
        Write-Log "COLLECTION FAILED: $why`n" 'err'
        Write-Ledger @($targets | ForEach-Object {
            New-LedgerRow -Action 'Collect' -Target $_ -Port (Get-CollectPort $method) -Protocol $method `
                -Account (Resolve-CollectUsername $user $state.Domain $_) -Result 'Failed' -Details $why
        })
        $lblCollectStatus.Text = "Failed: $why"; $lblCollectStatus.Foreground = $script:BrushCaution
    } finally {
        $cred = $null; $pass = $null
        Stop-UiJob
        Update-RetryButton
        # Last - see the Convert tab's finally.
        Set-AppBusy $false
    }
}

$btnCollect.Add_Click({
    if ($script:Busy) { return }
    Invoke-Collection
})

$btnRetry.Add_Click({
    if ($script:Busy) { return }
    $again = @($script:RetryTargets)
    if ($again.Count -eq 0) { return }
    # Read from the form as usual, but collect only these hosts. The credentials
    # are whatever is in the boxes NOW, which is the point: the usual reason a
    # host failed is that the first account could not reach it.
    Write-Log "`nRETRY - $($again.Count) host(s): $($again -join ', ')`n" 'info'
    Invoke-Collection $again
})

$btnCollectCmd.Add_Click({
    # Built from whatever the form holds now; blank fields become <PLACEHOLDERS>.
    $state = Get-CollectFormState
    $text = Get-ManualCollectCommand -Method $state.Method -Targets $state.Targets -Category $state.Category `
                -CustomLogs $state.CustomLogs -Username $state.Username -Domain $state.Domain `
                -OutRoot $script:Folders.Evtx -SkipCertificateCheck:$state.SkipCertCheck
    Show-CommandWindow 'Manual collection' `
        "What COLLECT does, as PowerShell. Paste it into an elevated PowerShell on this machine. It asks for the password." $text
})

Update-RetryButton

Update-CollectCategory
Update-CollectCredHint
