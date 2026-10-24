<#
.SYNOPSIS
    Raw Events tab - WPF fragment, dot-sourced by HayabusaMissionTool.ps1.

.DESCRIPTION
    Hayabusa uploads only the events a rule matched. This tab sends the
    collected EVTX themselves to a Security Onion manager and runs Security
    Onion's own importer there (so-import-evtx), so EVERY event is searchable
    in Security Onion, beside the Hayabusa detections.

    Steps, each through PuTTY's plink/pscp (code\putty): stage a private
    folder on the manager, copy the files into it under unique names, run
    sudo so-import-evtx on them, delete the folder - always, even after a
    failure or Cancel. The password never appears on a command line or in the
    log: plink/pscp read it from a file only this account can read
    (New-PasswordFile), sudo reads it from stdin.

    What the importer does, and every command string, lives in
    HayabusaLib.ps1 (Get-SoRemoteCommand, Get-SoImportResult, ...).
#>

# ============================================================== XAML =========
$soXaml = @'
<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
      xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
      Margin="2,10,10,10">
  <StackPanel>

    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <TextBlock Text="Every raw event, into Security Onion" Style="{DynamicResource SectionHead}"/>
        <TextBlock TextWrapping="Wrap" Style="{DynamicResource Hint}"
                   Text="Hayabusa uploads only the events a rule matched. This sends the EVTX files themselves to the Security Onion manager and runs its own importer (so-import-evtx), so every event becomes searchable there. Security Onion 2.4 files them under the time of the IMPORT (the event's own time is in event.created) - the link shown afterwards covers both. A file already imported is skipped, so sending the same logs twice adds nothing. They land in Security Onion's own logs-import-so data stream, each import with its own import.id. Security Onion only: a plain Elastic stack has no so-import-evtx."/>
      </StackPanel>
    </Border>

    <Border Style="{DynamicResource CardPanel}">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="140"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Grid.Column="0" Grid.ColumnSpan="2"
                   Text="Security Onion manager (SSH)" Style="{DynamicResource SectionHead}"/>

        <TextBlock Grid.Row="1" Grid.Column="0" Text="Manager host / IP *" Margin="0,9,10,6" VerticalAlignment="Top"/>
        <WrapPanel Grid.Row="1" Grid.Column="1" Margin="0,0,0,4">
          <TextBox x:Name="txtSoHost" Width="260" Margin="0,0,14,4"/>
          <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
            <TextBlock Text="SSH port *" Margin="0,0,10,0" VerticalAlignment="Center"/>
            <TextBox x:Name="txtSoPort" Width="70" Text="22"/>
          </StackPanel>
        </WrapPanel>

        <TextBlock Grid.Row="2" Grid.Column="0" Text="Username *" Margin="0,9,10,6" VerticalAlignment="Top"/>
        <StackPanel Grid.Row="2" Grid.Column="1" Margin="0,0,0,4">
        <!-- Wraps: in a narrow window the password moves under the
             username instead of being squeezed off the edge. -->
        <WrapPanel>
          <TextBox x:Name="txtSoUser" Width="200" Margin="0,0,16,4"/>
          <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
            <TextBlock Text="Password *" Margin="0,0,10,0" VerticalAlignment="Center"/>
            <Grid Width="200">
              <PasswordBox x:Name="txtSoPass"/>
              <TextBox     x:Name="txtSoPassPlain" Visibility="Collapsed"/>
            </Grid>
            <CheckBox x:Name="chkShowSoPass" Content="Show" Margin="12,0,0,0" VerticalAlignment="Center"/>
            <TextBlock Text="(SSH and sudo)" Margin="10,0,0,0" VerticalAlignment="Center"
                       Style="{DynamicResource Hint}"/>
          </StackPanel>
        </WrapPanel>
        <!-- A line of its own: beside the password it ran off the tab. -->
        <DockPanel Margin="0,6,0,0">
          <CheckBox DockPanel.Dock="Left" x:Name="chkRememberSoPass" Content="Remember password" VerticalAlignment="Center"
                    ToolTip="Saved only after a successful check, encrypted with Windows (DPAPI) for your Windows account on this machine - no other account or computer can read it. Untick and check again, or press Forget, to remove it."/>
          <Button DockPanel.Dock="Left" x:Name="btnForgetSoPass" Content="Forget" Margin="10,0,0,0" Padding="8,1"/>
          <TextBlock Text="Remember: encrypted for your Windows account on this machine (DPAPI), after a successful check" Margin="10,0,0,0" VerticalAlignment="Center" TextWrapping="Wrap"
                     Style="{DynamicResource Hint}"/>
        </DockPanel>
        </StackPanel>

        <TextBlock Grid.Row="3" Grid.Column="0" Text="Host key *" Margin="0,0,10,6"/>
        <Grid Grid.Row="3" Grid.Column="1" Margin="0,0,0,4">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBox x:Name="txtSoHostKey" Grid.Column="0"/>
          <Button x:Name="btnSoFetch" Grid.Column="1" Content="Fetch" Margin="8,0,0,0"/>
        </Grid>
        <TextBlock Grid.Row="4" Grid.Column="1" TextWrapping="Wrap" Style="{DynamicResource Hint}" Margin="0,0,0,8"
                   Text="SHA256:... - the server's SSH fingerprint, pinned like the Upload tab's certificate. Confirm it once with the admin (on the manager: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)."/>

        <StackPanel Grid.Row="5" Grid.Column="1" Orientation="Horizontal">
          <Button x:Name="btnSoTest" Content="TEST CONNECTION"/>
          <TextBlock x:Name="lblSoConn" Margin="12,0,0,0" VerticalAlignment="Center" TextWrapping="Wrap"
                     Style="{DynamicResource Hint}" Text="Not tested."/>
        </StackPanel>
      </Grid>
    </Border>

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
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Grid.Column="0" Grid.ColumnSpan="3"
                   Text="EVTX to import" Style="{DynamicResource SectionHead}"/>
        <TextBlock Grid.Row="1" Grid.Column="0" Text="Folder *" Margin="0,0,10,0"/>
        <TextBox   Grid.Row="1" Grid.Column="1" x:Name="txtSoFolder"/>
        <Button    Grid.Row="1" Grid.Column="2" x:Name="btnSoBrowse" Content="Browse..." Margin="8,0,0,0"/>
        <TextBlock Grid.Row="2" Grid.Column="1" Grid.ColumnSpan="2" x:Name="lblSoFiles" Margin="0,8,0,0"
                   Style="{DynamicResource Hint}" TextWrapping="Wrap" Text=""/>
      </Grid>
    </Border>

    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <Button x:Name="btnSoImport" Content="IMPORT TO SECURITY ONION" MinWidth="240" HorizontalAlignment="Left"
                Style="{DynamicResource Primary}"/>
        <TextBlock x:Name="lblSoResult" Margin="0,12,0,0" Text="" TextWrapping="Wrap"/>
        <TextBlock x:Name="lnkSo" Margin="0,8,0,0" Visibility="Collapsed" TextWrapping="Wrap">
          <Hyperlink x:Name="hlSo" NavigateUri="about:blank"
                     Foreground="{DynamicResource Accent}"><Run x:Name="runSo" Text=""/></Hyperlink>
        </TextBlock>
        <StackPanel x:Name="pnlSoHostLinks" Margin="0,10,0,0" Visibility="Collapsed"/>
      </StackPanel>
    </Border>

  </StackPanel>
</Grid>
'@

$soReader = New-Object System.Xml.XmlNodeReader ([xml]$soXaml)
$soRoot   = [Windows.Markup.XamlReader]::Load($soReader)
$tabSoImport.Content = $soRoot
foreach ($soName in @('txtSoHost','txtSoPort','txtSoUser','txtSoPass','txtSoPassPlain','chkShowSoPass','chkRememberSoPass','btnForgetSoPass',
                      'txtSoHostKey','btnSoFetch',
                      'btnSoTest','lblSoConn','txtSoFolder','btnSoBrowse','lblSoFiles',
                      'btnSoImport','lblSoResult','lnkSo','hlSo','runSo','pnlSoHostLinks')) {
    Set-Variable -Name $soName -Scope Script -Value $soRoot.FindName($soName)
}

$script:SoBrush = @{}
foreach ($pair in @{ ok = '#7EC87E'; err = '#F2A0A0'; warn = '#E8C08A'; muted = '#A8AEB8' }.GetEnumerator()) {
    $b = (New-Object System.Windows.Media.BrushConverter).ConvertFromString($pair.Value); $b.Freeze()
    $script:SoBrush[$pair.Key] = $b
}
$script:SoConfPath = Join-Path $script:AppRoot 'soimport.conf'

# ============================================================ helpers ========
# Whichever box is visible holds the password - see PasswordToggle.Tests.ps1.
function Get-SoPassword {
    if ($chkShowSoPass.IsChecked -eq $true) { return $txtSoPassPlain.Text }
    return $txtSoPass.Password
}
$chkShowSoPass.Add_Checked({
    $txtSoPassPlain.Text = $txtSoPass.Password
    $txtSoPass.Visibility = 'Collapsed'
    $txtSoPassPlain.Visibility = 'Visible'
})
$chkShowSoPass.Add_Unchecked({
    $txtSoPass.Password = $txtSoPassPlain.Text
    $txtSoPassPlain.Visibility = 'Collapsed'
    $txtSoPass.Visibility = 'Visible'
})

function Get-SoPort {
    $p = 0
    if ([int]::TryParse($txtSoPort.Text.Trim(), [ref]$p) -and $p -gt 0 -and $p -lt 65536) { return $p }
    return 22
}

function Test-SoReady {
    # Filled in enough for an import to start - the queue's raw step and the
    # SO pill. The login itself is only checked when an import runs.
    return [bool]($txtSoHost.Text.Trim() -and $txtSoUser.Text.Trim() -and (Get-SoPassword) -and
                  (Get-SshHostKeyFingerprint $txtSoHostKey.Text))
}

function Test-SoFields([switch]$NeedKey) {
    # What a step needs before it may start. Says what is missing, in one box.
    $missing = @()
    if (-not $txtSoHost.Text.Trim()) { $missing += 'Manager host' }
    if (-not $txtSoUser.Text.Trim()) { $missing += 'Username' }
    if (-not (Get-SoPassword))       { $missing += 'Password' }
    if ($NeedKey -and -not (Get-SshHostKeyFingerprint $txtSoHostKey.Text)) { $missing += 'Host key (Fetch it)' }
    if (-not (Find-PuttyTool plink) -or -not (Find-PuttyTool pscp)) { $missing += 'code\putty\plink.exe and pscp.exe' }
    if ($missing) {
        [void][System.Windows.MessageBox]::Show("Fill in first:`n`n  " + ($missing -join "`n  "), 'Raw Events')
        return $false
    }
    return $true
}

function Invoke-SoPlink([string]$Label, [string]$Command, [string]$PasswordFile,
                        [System.Collections.Generic.List[string]]$Capture, [switch]$Sudo, [switch]$NoCancel) {
    # One remote command. With -Sudo the password goes to plink's stdin, which
    # plink hands to the remote command, where sudo -S reads it.
    $a = Get-PlinkArgs -HostName $txtSoHost.Text.Trim() -Port (Get-SoPort) -User $txtSoUser.Text.Trim() `
            -HostKey (Get-SshHostKeyFingerprint $txtSoHostKey.Text) -PasswordFile $PasswordFile -Command $Command
    $p = @{ Label = $Label; Exe = (Find-PuttyTool plink); Arguments = $a; WorkDir = $script:AppRoot
            Detail = $txtSoHost.Text.Trim(); Mask = @(Get-SoPassword) }
    if ($null -ne $Capture) { $p.Capture = $Capture }
    if ($Sudo)    { $p.StandardInput = (Get-SoPassword) + "`n" }
    if ($NoCancel) { $p.NoCancel = $true }
    return (Invoke-ExternalTool @p)
}

function Update-SoFiles {
    $files = @(Get-SoImportFiles $txtSoFolder.Text.Trim())
    if (-not $txtSoFolder.Text.Trim()) {
        $lblSoFiles.Text = 'Choose the folder the Collect tab filled (one subfolder per host), or any folder of .evtx.'
        $lblSoFiles.Foreground = $script:SoBrush.muted
    } elseif ($files.Count -eq 0) {
        $lblSoFiles.Text = 'No .evtx files under this folder.'; $lblSoFiles.Foreground = $script:SoBrush.err
    } else {
        $bytes = ($files | Measure-Object Length -Sum).Sum
        $hosts = @($files | ForEach-Object { $_.DirectoryName } | Sort-Object -Unique).Count
        $lblSoFiles.Text = "$($files.Count) .evtx file(s) in $hosts folder(s), $(Format-ByteSize $bytes)."
        $lblSoFiles.Foreground = $script:SoBrush.ok
    }
    return ,$files
}

# ============================================================ handlers =======
$btnSoBrowse.Add_Click({
    $d = New-Object System.Windows.Forms.FolderBrowserDialog
    $d.Description = 'Select the folder holding the .evtx files to import'
    $d.SelectedPath = if ($txtSoFolder.Text -and (Test-Path -LiteralPath $txtSoFolder.Text)) { $txtSoFolder.Text } else { $script:Folders.Evtx }
    if ($d.ShowDialog() -ne 'OK') { return }
    $txtSoFolder.Text = $d.SelectedPath
    [void](Update-SoFiles)
})
$txtSoFolder.Add_LostFocus({ [void](Update-SoFiles) })

$btnSoFetch.Add_Click({
    if ($script:Busy) { return }
    if (-not $txtSoHost.Text.Trim()) { [void][System.Windows.MessageBox]::Show('Enter the manager host first.', 'Raw Events'); return }
    if (-not (Find-PuttyTool plink)) { [void][System.Windows.MessageBox]::Show('code\putty\plink.exe is missing.', 'Raw Events'); return }
    if (-not (Confirm-PcapBeforeNetwork 'read the Security Onion SSH host key')) { return }
    Set-AppBusy $true 'reading the SSH host key'
    Start-UiJob 'Read SSH host key'
    $fp = ''
    try {
        # No -hostkey and -batch: plink refuses the unknown server and names
        # its key. Nothing is sent but the connection itself.
        $out = New-Object System.Collections.Generic.List[string]
        $a = Get-PlinkArgs -HostName $txtSoHost.Text.Trim() -Port (Get-SoPort) -User $(if ($txtSoUser.Text.Trim()) { $txtSoUser.Text.Trim() } else { 'probe' }) -Command 'exit'
        [void](Invoke-ExternalTool -Label 'Read SSH host key' -Exe (Find-PuttyTool plink) -Arguments $a -WorkDir $script:AppRoot -Capture $out)
        $fp = Get-SshHostKeyFingerprint ($out -join "`n")
        if ($fp) {
            $txtSoHostKey.Text = $fp
            Write-Log "Security Onion SSH host key: $fp - confirm it with the manager's admin before trusting it.`n" 'info'
        } else {
            Write-Log "No host key read from $($txtSoHost.Text.Trim()):$(Get-SoPort) - nothing answered on SSH there (PuTTY's own message is just above). Check the host, and that port $(Get-SoPort) is open from this PC.`n" 'err'
        }
    } finally {
        Stop-UiJob
        Write-Ledger @(New-LedgerRow -Action 'SO host key read' -Target $txtSoHost.Text.Trim() -Port (Get-SoPort) -Protocol 'SSH' `
                          -Account $txtSoUser.Text.Trim() -Result $(if ($fp) { 'Success' } else { 'FAILED' }) -Details $fp)
        Set-AppBusy $false
    }
})

$btnSoTest.Add_Click({
    if ($script:Busy) { return }
    if (-not (Test-SoFields -NeedKey)) { return }
    if (-not (Confirm-PcapBeforeNetwork 'test the Security Onion connection')) { return }
    Set-AppBusy $true 'testing the Security Onion connection'
    Start-UiJob 'Test Security Onion'
    $pw = New-PasswordFile (Get-SoPassword)
    $result = 'FAILED'; $clock = [Diagnostics.Stopwatch]::StartNew()
    try {
        $out = New-Object System.Collections.Generic.List[string]
        [void](Invoke-SoPlink 'Test Security Onion' (Get-SoRemoteCommand Test) $pw $out -Sudo)
        $v = Get-SoTestVerdict @($out)
        $parts = @()
        $parts += if ($v.Ssh) { 'SSH OK' } else { 'SSH FAILED (host, port, user, password or host key)' }
        if ($v.Ssh) { $parts += if ($v.Sudo) { 'sudo OK' } else { 'sudo FAILED (wrong password, or the user may not sudo)' } }
        if ($v.Ssh) { $parts += if ($v.Importer) { 'so-import-evtx found' } else { 'so-import-evtx NOT found - is this a Security Onion manager?' } }
        $ok = $v.Ssh -and $v.Sudo -and $v.Importer
        $lblSoConn.Text = $parts -join ' - '
        $lblSoConn.Foreground = if ($ok) { $script:SoBrush.ok } else { $script:SoBrush.err }
        $result = if ($ok) { 'Success' } else { 'FAILED' }
        # Only a password that just worked is remembered - a typo never is.
        if ($ok) { Set-RememberedSoPassword }
    } finally {
        Remove-Item -LiteralPath $pw -Force -ErrorAction SilentlyContinue
        Stop-UiJob
        Write-Ledger @(New-LedgerRow -Action 'SO import test' -Target $txtSoHost.Text.Trim() -Port (Get-SoPort) -Protocol 'SSH' `
                          -Account $txtSoUser.Text.Trim() -Result $result -Seconds $clock.Elapsed.TotalSeconds -Details $lblSoConn.Text)
        Set-AppBusy $false
    }
})

$hlSo.Add_RequestNavigate({
    param($sender, $e)
    if ($script:SoUrl) { Start-Process $script:SoUrl }
    $e.Handled = $true
})

$btnSoImport.Add_Click({
    if ($script:Busy) { return }
    if (-not (Test-SoFields -NeedKey)) { return }
    $files = Update-SoFiles
    if ($files.Count -eq 0) { [void][System.Windows.MessageBox]::Show('No .evtx files to import in that folder.', 'Raw Events'); return }
    $lblSoResult.Text = ''; $lnkSo.Visibility = 'Collapsed'; $pnlSoHostLinks.Visibility = 'Collapsed'; $script:SoUrl = $null

    if (-not (Confirm-PcapBeforeNetwork 'send raw EVTX to Security Onion')) { return }
    Set-AppBusy $true 'importing raw events to Security Onion'
    Start-UiJob 'Import to Security Onion'
    $hostName = $txtSoHost.Text.Trim()
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $s = $null
    try {
        # The same import the job queue runs (Invoke-SoImport). Its programs
        # go through this window's runner, so Cancel works as it always did.
        $s = Invoke-SoImport -Files $files -HostName $hostName -Port (Get-SoPort) -User $txtSoUser.Text.Trim() `
                 -HostKey (Get-SshHostKeyFingerprint $txtSoHostKey.Text) -Password (Get-SoPassword) `
                 -Run { param($p) Invoke-ExternalTool @p -WorkDir $script:AppRoot } `
                 -IsCancelled { $script:CancelRequested } -Log { param($t, $k) Write-Log $t $k }
        if ($s.Outcome -in 'Success', 'Partial') {
            $r = $s.Result
            $lblSoResult.Text = "Import complete: $($s.Detail).$(if ($r.TimeRange) { "`nThe events themselves (UTC) - $($r.TimeRange)" })" +
                                "`nSecurity Onion 2.4 files them under the time of the import; their own time is in event.created." +
                                "`nThey can take 30 seconds or more to appear.`n$(Get-WhereToLook 'raw')"
            Write-Log "$(Get-WhereToLook 'raw')`n" 'info'
            $lblSoResult.Foreground = if ($r.Warnings) { $script:SoBrush.warn } else { $script:SoBrush.ok }
            if ($r.Url) {
                $script:SoUrl = $r.WideUrl
                try { $hlSo.NavigateUri = New-Object System.Uri($r.Url) } catch { }
                $runSo.Text = 'Open the imported events in Security Onion'
                $lnkSo.Visibility = 'Visible'
            }
            # Each machine's two links, named as its own events name it.
            try { Show-HostLinks $pnlSoHostLinks @(Get-EvtxHostNames $txtSoFolder.Text.Trim()) }
            catch { Write-Log "Could not build the host links: $($_.Exception.Message)`n" 'warn' }
        } else {
            $lblSoResult.Text = "Not imported: $($s.Error)"
            $lblSoResult.Foreground = $script:SoBrush.err
        }
    } finally {
        Stop-UiJob
        Write-Ledger @(New-LedgerRow -Action 'SO import' -Target $hostName -Port (Get-SoPort) -Protocol 'SSH (pscp + so-import-evtx)' `
                          -Account $txtSoUser.Text.Trim() -Result $(if ($s) { $s.Outcome } else { 'FAILED' }) `
                          -Files "$(if ($s) { $s.Sent } else { 0 })/$($files.Count) EVTX" -Bytes $(if ($s) { $s.Bytes } else { 0 }) `
                          -Seconds $clock.Elapsed.TotalSeconds -LeftOnTarget $(if ($s) { $s.Left } else { '' }) `
                          -Output $(if ($script:SoUrl) { $script:SoUrl } else { '' }) -Details $(if ($s) { $s.Detail } else { '' }))
        Set-AppBusy $false
    }
})

# ---- persisted settings (never the password) ----
if (Test-Path -LiteralPath $script:SoConfPath) {
    try {
        $c = Get-Content -LiteralPath $script:SoConfPath -Raw | ConvertFrom-Json
        if ($c.host)    { $txtSoHost.Text = $c.host }
        if ($c.port)    { $txtSoPort.Text = $c.port }
        if ($c.user)    { $txtSoUser.Text = $c.user }
        if ($c.hostkey) { $txtSoHostKey.Text = $c.hostkey }
    } catch { }
}
if (-not $txtSoFolder.Text) { $txtSoFolder.Text = $script:Folders.Evtx }
[void](Update-SoFiles)

if ($win) {
    $win.Add_Closing({
        try {
            @{ host = $txtSoHost.Text.Trim(); port = $txtSoPort.Text.Trim(); user = $txtSoUser.Text.Trim()
               hostkey = $txtSoHostKey.Text.Trim() } | ConvertTo-Json | Set-Content -Path $script:SoConfPath -Encoding utf8
        } catch { }
    })
}

# ---- remembered password (DPAPI, opt-in) - as on the Upload tab ----
function Set-RememberedSoPassword {
    $h = $txtSoHost.Text.Trim(); $u = $txtSoUser.Text.Trim()
    if (-not $h -or -not $u) { return }
    try {
        if ($chkRememberSoPass.IsChecked -eq $true) {
            Save-RememberedSecret 'ssh' $h $u (Get-SoPassword)
            Write-Log "SSH password for $u@$h remembered for $env:USERNAME on this machine (Windows DPAPI).`n" 'info'
        } elseif (Get-RememberedSecret 'ssh' $h $u) {
            Remove-RememberedSecret 'ssh' $h $u
            Write-Log "Remembered SSH password for $u@$h removed.`n" 'info'
        }
    } catch { Write-Log "Could not remember the password: $($_.Exception.Message)`n" 'warn' }
}
$script:SoFilledFor = ''
function Restore-RememberedSoPassword {
    # As on the Upload tab: a filled-in password is cleared once the host or
    # user changes, so it is never tried against another server.
    $key = "$($txtSoHost.Text.Trim().ToLowerInvariant())|$($txtSoUser.Text.Trim())"
    if ($script:SoFilledFor -and $script:SoFilledFor -ne $key) {
        $txtSoPass.Password = ''; $txtSoPassPlain.Text = ''; $chkRememberSoPass.IsChecked = $false
        $script:SoFilledFor = ''
    }
    if (Get-SoPassword) { return }
    $secret = Get-RememberedSecret 'ssh' $txtSoHost.Text.Trim() $txtSoUser.Text.Trim()
    if ($secret) {
        $txtSoPass.Password = $secret; $txtSoPassPlain.Text = $secret
        $chkRememberSoPass.IsChecked = $true
        $script:SoFilledFor = $key
        Write-Log "Remembered SSH password filled in for $($txtSoUser.Text.Trim())@$($txtSoHost.Text.Trim()).`n" 'info'
    }
}
$btnForgetSoPass.Add_Click({
    Remove-RememberedSecret 'ssh' $txtSoHost.Text.Trim() $txtSoUser.Text.Trim()
    $chkRememberSoPass.IsChecked = $false
    Write-Log "Forgot any remembered SSH password for $($txtSoUser.Text.Trim())@$($txtSoHost.Text.Trim()).`n" 'info'
})
$txtSoHost.Add_LostFocus({ Restore-RememberedSoPassword })
$txtSoUser.Add_LostFocus({ Restore-RememberedSoPassword })
Restore-RememberedSoPassword
