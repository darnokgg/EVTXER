<#
.SYNOPSIS
    "Upload to ELK" tab, WPF. Dot-sourced by HayabusaWpf.ps1.

.DESCRIPTION
    A fragment, not a script: it creates no window, loads no assemblies and
    dot-sources no library. The shell has already done all three, and has
    already given us $tabUpload (a ScrollViewer), Write-Log, Invoke-UiPump,
    $bar, $lblStatus, $script:Root and $script:Folders.

    Every x:Name below is the WinForms variable name minus the '$', so the
    handlers read the same as they did against WinForms controls and a diff
    against HayabusaMissionTool.ps1 stays legible.
#>

# ------------------------------------------------------------ tab state -----
# Upload-only state the WinForms launcher declared at the top of the file.
# Guarded, because another tab's fragment may already have named the shared
# ones (the Convert tab writes $script:EcsPath / $script:ImportId and then
# calls Update-SourceReadiness, which is defined here).
if ($null -eq $script:ConfPath)  { $script:ConfPath  = Join-Path $script:AppRoot 'importer.conf' }
if ($null -eq $script:Template)  { $script:Template  = Join-Path $script:AppRoot 'index-template.json' }
if ($null -eq $script:BatchSize) { $script:BatchSize = 2000 }
if ($null -eq $script:ConnOk)    { $script:ConnOk    = $false }
if ($null -eq $script:Taken)     { $script:Taken     = @() }
if ($null -eq $script:DocCount)  { $script:DocCount  = 0 }

# The WinForms tab wrote 'Green' / 'Firebrick' / Theme.Muted straight onto a
# LIGHT surface. This shell's surface is dark, where #008000 reads 2.1:1 and is
# effectively invisible, so each verdict colour maps to the shell's own log
# palette - the one set of values that was already contrast-checked against
# #1E2126. The MEANING of each colour is unchanged.
$script:UpBrush = @{}
foreach ($pair in @{ ok = '#7EC87E'; err = '#F2A0A0'; warn = '#E8C08A'; muted = '#A8AEB8' }.GetEnumerator()) {
    $b = (New-Object System.Windows.Media.BrushConverter).ConvertFromString($pair.Value)
    $b.Freeze()
    $script:UpBrush[$pair.Key] = $b
}

# ==================================================================== XAML ===
# StaticResource is resolved while XamlReader.Load runs, and at that moment
# this Grid is not yet attached to the Window - so every key the shell defines
# has to be referenced as DynamicResource or the parse throws. Implicit styles
# (TextBox, Button, CheckBox, RadioButton) need no such help: WPF resolves
# those by walking the logical tree when the element is attached.
$uploadXaml = @'
<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
      xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
      Margin="4,8,14,8">
  <StackPanel>

    <!-- == Upload tab: the source being uploaded, and whether it is usable ==
         The wizard gated on "did you walk through Step 1 this session", which
         could not tell a correct file from a wrong one. This gates on the file
         itself, so an ecs.jsonl produced on another machine is a first-class
         input. -->
    <Border Style="{DynamicResource CardPanel}">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="130"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Grid.Column="0" Grid.ColumnSpan="2"
                   Text="Source" Style="{DynamicResource SectionHead}"/>
        <TextBlock Grid.Row="0" Grid.Column="2" Text="* = required"
                   Style="{DynamicResource Hint}" HorizontalAlignment="Right"
                   VerticalAlignment="Top"/>

        <TextBlock Grid.Row="1" Grid.Column="0" Text="Source JSONL *" Margin="0,0,10,0"/>
        <TextBox   Grid.Row="1" Grid.Column="1" x:Name="txtSource"/>
        <Button    Grid.Row="1" Grid.Column="2" x:Name="btnSourceBrowse"
                   Content="Browse..." Margin="8,0,0,0"/>

        <TextBlock Grid.Row="2" Grid.Column="1" Grid.ColumnSpan="2" x:Name="lblSource"
                   Style="{DynamicResource Hint}" Margin="0,8,0,0"
                   Text="Nothing loaded. Convert on the Hayabusa tab, or Browse to an existing ecs.jsonl."/>
      </Grid>
    </Border>

    <!-- == page 2, part one: the Elasticsearch connection == -->
    <Border Style="{DynamicResource CardPanel}">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="130"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Grid.Column="0" Grid.ColumnSpan="2"
                   Text="Elasticsearch connection" Style="{DynamicResource SectionHead}"/>

        <TextBlock Grid.Row="1" Grid.Column="0" Text="Host / IP *" Margin="0,0,10,6"/>
        <Grid Grid.Row="1" Grid.Column="1" Margin="0,0,0,4">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBox x:Name="txtHost" Grid.Column="0" Width="260" HorizontalAlignment="Left"/>
          <TextBlock Grid.Column="1" Text="Port *" Margin="14,0,10,0"/>
          <TextBox x:Name="txtPort" Grid.Column="2" Width="80" Text="9200"/>
        </Grid>

        <TextBlock Grid.Row="2" Grid.Column="0" Text="Username" Margin="0,9,10,6" VerticalAlignment="Top"
                   ToolTip="Leave it empty to log in with an Elasticsearch API key: paste the key into the next box."/>
        <StackPanel Grid.Row="2" Grid.Column="1" Margin="0,0,0,4">
        <!-- Wraps: in a narrow window the password moves under the
             username instead of being squeezed off the edge. -->
        <WrapPanel>
          <TextBox x:Name="txtUser" Width="250" Margin="0,0,16,4"
                   ToolTip="Leave it empty to log in with an Elasticsearch API key: paste the key into the next box."/>
          <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
          <TextBlock Text="Password or API key *" Margin="0,0,10,0" VerticalAlignment="Center"/>
        <!-- A masked box with no way to look at it means a typo only shows up
             as a failed logon. A WPF PasswordBox cannot unmask itself, so the
             plaintext lives in a second box stacked in the same cell and only
             one of the two is ever visible. -->
          <Grid Width="230">
            <PasswordBox x:Name="txtPass"/>
            <TextBox     x:Name="txtPassPlain" Visibility="Collapsed"/>
          </Grid>
          <CheckBox x:Name="chkShowPass" Content="Show" Margin="12,0,0,0" VerticalAlignment="Center"/>
          </StackPanel>
        </WrapPanel>
        <!-- A line of its own: beside the password it ran off the tab. -->
        <DockPanel Margin="0,6,0,0">
          <CheckBox DockPanel.Dock="Left" x:Name="chkRememberPass" Content="Remember password" VerticalAlignment="Center"
                    ToolTip="Saved only after a successful check, encrypted with Windows (DPAPI) for your Windows account on this machine - no other account or computer can read it. Untick and check again, or press Forget, to remove it."/>
          <Button DockPanel.Dock="Left" x:Name="btnForgetPass" Content="Forget" Margin="10,0,0,0" Padding="8,1"/>
          <TextBlock Text="Remember: encrypted for your Windows account on this machine (DPAPI), after a successful check" Margin="10,0,0,0" VerticalAlignment="Center" TextWrapping="Wrap"
                     Style="{DynamicResource Hint}"/>
        </DockPanel>
        </StackPanel>

        <!-- Security Onion's certificate is signed by nothing Windows trusts,
             so plain chain validation can never pass and the old default was to
             accept every certificate - encrypted, but authenticating nobody.
             Pinning needs no CA: it remembers the exact certificate and refuses
             any other. -->
        <StackPanel Grid.Row="4" Grid.Column="1" Orientation="Horizontal" Margin="0,4,0,6">
          <RadioButton x:Name="rbTlsPin" GroupName="upTls" IsChecked="True"
                       Content="Pin the certificate fingerprint (recommended)"/>
          <RadioButton x:Name="rbTlsSkip" GroupName="upTls" Margin="24,4,0,4"
                       Foreground="{DynamicResource Caution}"
                       Content="Skip verification (no protection against an active MITM)"/>
        </StackPanel>

        <TextBlock Grid.Row="5" Grid.Column="0" Text="Fingerprint *" Margin="0,0,10,0"/>
        <Grid Grid.Row="5" Grid.Column="1">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBox x:Name="txtPin" Grid.Column="0" Width="470" HorizontalAlignment="Left"/>
          <Button  x:Name="btnFetch" Grid.Column="1" Content="Fetch" Margin="8,0,0,0"/>
        </Grid>
        <TextBlock Grid.Row="6" Grid.Column="1" x:Name="lblPinHint" Margin="0,6,0,10"
                   Style="{DynamicResource Hint}" Text="SHA-256. Confirm it once."/>

        <Grid Grid.Row="7" Grid.Column="1">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Button x:Name="btnVerify" Grid.Column="0" Content="VERIFY CONNECTIVITY"/>
          <TextBlock x:Name="lblConn" Grid.Column="1" Margin="14,0,0,0"
                     Style="{DynamicResource Hint}" Text="Not verified."/>
        </Grid>
      </Grid>
    </Border>

    <!-- == page 2, part two: which index the batch lands in == -->
    <!-- Index and upload are stacked, full width. Side by side, the upload
         card was squeezed until its button read UPLOA / D TO / ELK. -->
    <Border Style="{DynamicResource CardPanel}">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="130"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Grid.Column="0" Grid.ColumnSpan="2"
                   Text="Target index" Style="{DynamicResource SectionHead}"/>

        <TextBlock Grid.Row="1" Grid.Column="0" Text="Case / label" Margin="0,0,10,6"/>
        <StackPanel Grid.Row="1" Grid.Column="1" Orientation="Horizontal" Margin="0,0,0,4">
          <TextBox x:Name="txtLabel" Width="150"/>
          <Button  x:Name="btnGen" Content="Generate name" Margin="10,0,0,0"/>
          <TextBlock Text="e.g. case42, dc01" Style="{DynamicResource Hint}" Margin="10,0,0,0"/>
        </StackPanel>

        <TextBlock Grid.Row="2" Grid.Column="0" Text="Index name *" Margin="0,0,10,0"/>
        <StackPanel Grid.Row="2" Grid.Column="1" Orientation="Horizontal">
          <TextBox x:Name="txtIndex" Width="260"/>
          <Button  x:Name="btnCheck" Content="Check availability" Margin="10,0,0,0"/>
        </StackPanel>

        <TextBlock Grid.Row="3" Grid.Column="1" x:Name="lblIdx" Margin="0,8,0,0"
                   Style="{DynamicResource Hint}"
                   Text="Verify connectivity, then generate a name."/>

        <CheckBox Grid.Row="4" Grid.Column="1" x:Name="chkAppend" Margin="0,8,0,0"
                  Content="Allow appending to an index that already has documents"/>
      </Grid>
    </Border>
    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <StackPanel Orientation="Horizontal">
          <Button x:Name="btnUpload" Content="UPLOAD TO ELK" MinWidth="180"
                  Style="{DynamicResource Primary}"/>
          <!-- Off: a detection already in the index is left as it is (409).
               On: it is replaced by this upload's copy of it - for a re-upload
               after a newer conversion added fields. Never doubles either way. -->
          <CheckBox x:Name="chkRefresh" IsChecked="False" Margin="16,0,0,0" VerticalAlignment="Center"
                    Content="Update detections already in the index"
                    ToolTip="Re-uploading after a newer conversion? Tick this so the stored detections get the new fields. Nothing is doubled either way."/>
        </StackPanel>
        <TextBlock x:Name="lblResult" Margin="0,12,0,0" Text="" TextWrapping="Wrap"/>
        <!-- Filled in after a successful upload with a link carrying the data
             view, the import.id and the batch's own time span - the three
             things an operator would otherwise have to know and type. Hidden
             until there is something to open. -->
        <TextBlock x:Name="lnkKibana" Margin="0,8,0,0" Visibility="Collapsed" TextWrapping="Wrap">
          <Hyperlink x:Name="hlKibana" NavigateUri="about:blank"
                     Foreground="{DynamicResource Accent}"><Run x:Name="runKibana" Text=""/></Hyperlink>
        </TextBlock>
        <StackPanel x:Name="pnlUpHostLinks" Margin="0,10,0,0" Visibility="Collapsed"/>
      </StackPanel>
    </Border>


  </StackPanel>
</Grid>
'@

$uploadRoot = [Windows.Markup.XamlReader]::Load(
    (New-Object System.Xml.XmlNodeReader ([xml]$uploadXaml)))
$tabUpload.Content = $uploadRoot

# Every x:Name becomes a $script: variable of the same name, so handler code
# reads the same as it did against WinForms controls.
foreach ($name in @('txtSource','btnSourceBrowse','lblSource',
                    'txtHost','txtPort','txtUser','txtPass','txtPassPlain','chkShowPass','chkRememberPass','btnForgetPass',
                    'rbTlsPin','rbTlsSkip','txtPin','btnFetch','lblPinHint',
                    'btnVerify','lblConn',
                    'txtLabel','btnGen','txtIndex','btnCheck','lblIdx','chkAppend',
                    'btnUpload','chkRefresh','lblResult','lnkKibana','hlKibana','runKibana','pnlUpHostLinks')) {
    Set-Variable -Name $name -Scope Script -Value $uploadRoot.FindName($name)
}

# ---------------------------------------------------------------- password ---
# The masked box and the plain box are two controls showing one secret, so the
# value is read through here rather than off whichever one happens to be
# visible. The plaintext is never written to the log or to importer.conf.
function Get-UploadPassword {
    if ($chkShowPass.IsChecked -eq $true) { return $txtPassPlain.Text }
    return $txtPass.Password
}
$chkShowPass.Add_Checked({
    $txtPassPlain.Text = $txtPass.Password
    $txtPass.Visibility = 'Collapsed'
    $txtPassPlain.Visibility = 'Visible'
})
$chkShowPass.Add_Unchecked({
    $txtPass.Password = $txtPassPlain.Text
    $txtPassPlain.Visibility = 'Collapsed'
    $txtPass.Visibility = 'Visible'
})

# ------------------------------------------------------- upload readiness ---
# Replaces the wizard's Next-button gating. That only knew "did the operator
# walk through Step 1 in this session", which cannot tell a correct file from
# a wrong one. This asks the file.
function Update-SourceReadiness {
    $path = $txtSource.Text.Trim()
    if (-not $path) {
        $script:SourceKind = 'Missing'
        $lblSource.Text = 'Nothing loaded. Convert on the Hayabusa tab, or Browse to an existing ecs.jsonl.'
        $lblSource.Foreground = $script:UpBrush.muted
        return
    }

    $verdict = Get-JsonlKind $path
    $script:SourceKind = $verdict.Kind

    if ($verdict.Kind -eq 'Ecs') {
        # Counting 32k lines is instant and only happens on Browse or after a
        # conversion, never per keystroke.
        $n = 0
        try { foreach ($null in [IO.File]::ReadLines($path)) { $n++ } } catch { $n = 0 }
        $script:DocCount = $n
        $script:EcsPath  = $path
        # Adopt the id the file was converted with. Minting a new one here
        # would name an id that appears in none of its documents.
        $fileImportId = Get-JsonlImportId $path
        if ($fileImportId) { $script:ImportId = $fileImportId }
        $lblSource.Text = "Ready: $([IO.Path]::GetFileName($path)) - ECS JSONL, $('{0:N0}' -f $n) document(s)."
        $lblSource.Foreground = $script:UpBrush.ok
    } else {
        $script:EcsPath = $null
        $lblSource.Text = $verdict.Reason
        $lblSource.Foreground = $script:UpBrush.err
    }
}

# -------------------------------------------------------------- handlers ----
function Get-UploadPort { if ($txtPort.Text.Trim()) { $txtPort.Text.Trim() } else { '9200' } }
function Get-EsBase { "https://$($txtHost.Text.Trim()):$(Get-UploadPort)" }
function Get-UploadConnKey {
    # The certificate trust is part of what VERIFY checked: switching to Skip,
    # or another pin, afterwards needs a new VERIFY - and the job queue, which
    # uploads later and unattended, waits for it (security review, v48).
    $tls = if ($rbTlsSkip.IsChecked -eq $true) { 'skip' } else { "pin $(ConvertTo-Thumbprint $txtPin.Text)" }
    Get-ConnectionFingerprint "$(Get-EsBase) $tls" $txtUser.Text.Trim() (Get-UploadPassword)
}

function Update-TakenIndices {
    try {
        $h = Get-AuthHeader $txtUser.Text.Trim() (Get-UploadPassword)
        $r = Invoke-EsJson -Uri "$(Get-EsBase)/_cat/indices/hayabusa*?format=json&h=index" -Headers $h -TimeoutSec 30
        $script:Taken = @($r | ForEach-Object { $_.index })
        Write-Log "Existing hayabusa-* indices: $($script:Taken.Count)$(if ($script:Taken) { ' -> ' + (($script:Taken | Select-Object -First 6) -join ', ') })`n"
    } catch { $script:Taken = @() }
}

$btnSourceBrowse.Add_Click({
    $d = New-Object Microsoft.Win32.OpenFileDialog
    $d.Filter = 'ECS JSONL (*.jsonl)|*.jsonl|All files (*.*)|*.*'
    $start = $script:Folders.Hayabusa
    if (Test-Path $start) { $d.InitialDirectory = $start }
    if ($d.ShowDialog() -ne $true) { return }
    $txtSource.Text = $d.FileName
    Update-SourceReadiness
})
# WinForms' Leave; WPF's LostFocus is the same moment.
$txtSource.Add_LostFocus({ Update-SourceReadiness })

function Set-TlsTrustFromUi {
    # Returns $false and says why, rather than quietly degrading to trust-all
    # when the pin is missing or malformed.
    #
    # Set-TlsTrust (HayabusaLib) installs a COMPILED Add-Type class as the
    # certificate callback, never a PowerShell scriptblock: .NET calls it on a
    # worker thread with no runspace, where even { $true } throws "There is no
    # Runspace available to run scripts in this thread" and every HTTPS request
    # fails. Nothing here may be "simplified" into a scriptblock.
    if ($rbTlsSkip.IsChecked -eq $true) { Set-TlsTrust -Mode 'Skip'; return $true }
    try { Set-TlsTrust -Mode 'Pin' -PinnedThumbprint $txtPin.Text; return $true }
    catch {
        [void][System.Windows.MessageBox]::Show($_.Exception.Message, 'Certificate pin missing')
        return $false
    }
}

$btnFetch.Add_Click({
    $hostName = $txtHost.Text.Trim()
    if (-not $hostName) {
        [void][System.Windows.MessageBox]::Show('Enter the Elasticsearch host or IP first.', 'Missing host')
        return
    }
    if (-not (Confirm-PcapBeforeNetwork 'fetch the Elasticsearch certificate')) { return }
    $portNum = 9200
    if ($txtPort.Text.Trim()) { [void][int]::TryParse($txtPort.Text.Trim(), [ref]$portNum) }
    # Every network touch has its activity-log row - a fetch is a TLS
    # handshake with the stack (usability walk, 2026-10-21).
    $fetchResult = 'Failed'; $fetchDetail = ''
    try {
        $tp = Get-ServerCertThumbprint $hostName $portNum
        $txtPin.Text = $tp
        $rbTlsPin.IsChecked = $true
        Write-Log ("Certificate fingerprint at {0}:{1}" -f $hostName, $portNum) 'info'
        Write-Log ("  " + $tp + [Environment]::NewLine)
        Write-Log ("Confirm this against the certificate on the Elasticsearch server. It is saved, and every later connection must present the same certificate or the upload stops." + [Environment]::NewLine)
        $fetchResult = 'Success'; $fetchDetail = "SHA-256 $tp"
    } catch {
        $fetchDetail = Get-ConnectionHint $_.Exception.Message $hostName $portNum
        Write-Log "Could not read the certificate: $fetchDetail`n" 'err'
        [void][System.Windows.MessageBox]::Show($fetchDetail, 'Could not read certificate')
    } finally {
        Write-Ledger @(New-LedgerRow -Action 'Certificate fetch' -Target $hostName -Port $portNum -Protocol 'HTTPS (Elasticsearch)' `
                          -Result $fetchResult -Details $fetchDetail)
    }
})

# WinForms' PerformClick has no WPF equivalent that is worth the RoutedEvent
# dance, so the two handlers that other code invokes live in named functions
# and their Click handlers are one line.
function Invoke-CheckIndexName {
    $idx = $txtIndex.Text.Trim()
    # One guard, tested in IndexGuard.Tests.ps1. It covers the prefix and the
    # character rules together, which used to be two checks that could disagree.
    if (-not (Test-HayabusaIndexName $idx)) {
        $lblIdx.Text = "Name must start with 'hayabusa-' and be lowercase letters, digits, dot, dash or underscore."
        $lblIdx.Foreground = $script:UpBrush.err; return
    }
    $mission = Get-MissionIndexName $script:Settings.MissionName
    # Without a verified connection nothing was asked: "is free" was a guess
    # shown in green (usability walk, 2026-10-21).
    if (-not $script:ConnOk) {
        $lblIdx.Text = "'$idx' is a valid name - not checked against Elasticsearch yet (VERIFY CONNECTIVITY first)."
        $lblIdx.Foreground = $script:UpBrush.warn
    } else {
        Update-TakenIndices
        if ($idx -eq $mission) {
            # The mission's own index is appended to all mission long.
            $lblIdx.Text = if ($script:Taken -contains $idx) { "'$idx' is this mission's index - uploads are added to it." }
                           else { "'$idx' is this mission's index - the first upload creates it." }
            $lblIdx.Foreground = $script:UpBrush.ok
        } elseif ($script:Taken -contains $idx) {
            $lblIdx.Text = "'$idx' ALREADY EXISTS. Uploading into it would mix this case with existing data. Press 'Generate name'."
            $lblIdx.Foreground = $script:UpBrush.err
        } else {
            $lblIdx.Text = "'$idx' is free."; $lblIdx.Foreground = $script:UpBrush.ok
        }
    }
    # With a mission named, warn when uploading elsewhere.
    if ($mission -and $idx -ne $mission) {
        $lblIdx.Text += "`nNot the mission index ($mission): the queue uploads there, and 'Delete mission index' will not remove this one."
        if ($lblIdx.Foreground -eq $script:UpBrush.ok) { $lblIdx.Foreground = $script:UpBrush.warn }
    }
}

function Invoke-GenerateIndexName {
    # With a mission named, its index IS the name - the
    # queue uploads there and 'Delete mission index' removes it at the end.
    $mission = Get-MissionIndexName $script:Settings.MissionName
    if ($mission) { $txtIndex.Text = $mission; Invoke-CheckIndexName; return }
    if ($script:ConnOk) { Update-TakenIndices }
    $txtIndex.Text = New-IndexName $txtLabel.Text $script:Taken
    Invoke-CheckIndexName
}

$btnVerify.Add_Click({
    # Guarded like every other action: it used to be clickable mid-upload,
    # where it re-installed TLS trust and reset the verified connection.
    if ($script:Busy) { return }
    $missing = Get-MissingConnectionFields $txtHost.Text $txtUser.Text (Get-UploadPassword) -ApiKeyOk
    if ($missing.Count) {
        [void][System.Windows.MessageBox]::Show("Enter the $($missing -join ', ').", 'Missing connection details')
        return
    }
    if (-not (Set-TlsTrustFromUi)) { return }
    if (-not (Confirm-PcapBeforeNetwork 'check the Elasticsearch connection')) { return }
    Set-AppBusy $true 'checking the Elasticsearch connection'
    $verifyResult = 'FAILED'; $verifyDetail = ''
    try {
        $h = Get-AuthHeader $txtUser.Text.Trim() (Get-UploadPassword)
        $r = Invoke-EsJson -Uri "$(Get-EsBase)/" -Headers $h -TimeoutSec 20
        $hh = Invoke-EsJson -Uri "$(Get-EsBase)/_cluster/health" -Headers $h -TimeoutSec 20
        $lblConn.Text = "OK  $($r.cluster_name) / Elasticsearch $($r.version.number)`nhealth=$($hh.status)  nodes=$($hh.number_of_nodes)"
        $lblConn.Foreground = $script:UpBrush.ok
        $script:ConnOk = $true
        $script:ConnKey = Get-UploadConnKey
        Write-Log "Connected: $($r.cluster_name) ES $($r.version.number) ($($hh.status))`n" 'ok'
        $verifyResult = 'OK'; $verifyDetail = "$($r.cluster_name), Elasticsearch $($r.version.number), health $($hh.status)"
        # Only a password that just worked is remembered - a typo never is.
        Set-RememberedUploadPassword
        Update-TakenIndices
        if (-not $txtIndex.Text.Trim()) { Invoke-GenerateIndexName }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match '401') {
            $msg = if ($txtUser.Text.Trim()) { 'HTTP 401 - username or password is wrong.' }
                   else { 'HTTP 401 - the API key is wrong, expired or revoked (Username is empty, so the password box is sent as an API key).' }
        } else {
            $msg = Get-ConnectionHint $msg $txtHost.Text.Trim() (Get-UploadPort)
        }
        $lblConn.Text = $msg; $lblConn.Foreground = $script:UpBrush.err
        $script:ConnOk = $false
        $verifyDetail = $msg
        Write-Log "Connection failed: $msg`n" 'err'
    } finally {
        Write-Ledger @(New-LedgerRow -Action 'Verify connection' -Target $txtHost.Text.Trim() -Port (Get-UploadPort) `
                          -Protocol 'HTTPS (Elasticsearch)' -Account (Get-EsAccountLabel $txtUser.Text) -Result $verifyResult -Details $verifyDetail)
        Set-AppBusy $false
    }
})

# Once connected these list the indices on Elasticsearch, so they ask about
# the capture like every other network action; offline they only check the name.
$btnGen.Add_Click({ if (-not $script:ConnOk -or (Confirm-PcapBeforeNetwork 'list the indices on Elasticsearch')) { Invoke-GenerateIndexName } })
$btnCheck.Add_Click({ if (-not $script:ConnOk -or (Confirm-PcapBeforeNetwork 'list the indices on Elasticsearch')) { Invoke-CheckIndexName } })

# Elasticsearch only takes lowercase names, and a capital typed into a
# generated name used to be refused only at UPLOAD, by a popup that was easy to
# miss - while the previous upload's green "Success" stayed on screen. Lowercased
# as it is typed and its format checked live; availability still needs the
# server, so that stays on Check availability.
$txtIndex.Add_TextChanged({
    $t = $txtIndex.Text
    $low = $t.ToLowerInvariant()
    if ($t -cne $low) {
        $caret = $txtIndex.CaretIndex
        $txtIndex.Text = $low
        $txtIndex.CaretIndex = [Math]::Min($caret, $low.Length)
        return
    }
    $n = $low.Trim()
    if (-not $n) { return }
    if (Test-HayabusaIndexName $n) {
        $lblIdx.Text = "'$n' is a valid name. Press Check availability to make sure it is not taken."
        $lblIdx.Foreground = $script:UpBrush.muted
    } else {
        $lblIdx.Text = "Not a valid name: it must start with 'hayabusa-' and use only a-z, 0-9, dot, dash or underscore (no spaces)."
        $lblIdx.Foreground = $script:UpBrush.err
    }
})

# The Collect tab hands over the targets it just collected (Get-TargetsLabel).
# A label the operator typed is never replaced - only an empty one, or one the
# tool filled in itself last time.
$script:AutoLabel = ''
function Set-UploadLabelSuggestion([string]$Label) {
    if (-not $Label) { return }
    $current = $txtLabel.Text.Trim()
    if ($current -and $current -ne $script:AutoLabel) { return }
    $script:AutoLabel = $Label
    $txtLabel.Text = $Label
    Write-Log "Upload tab: Case / label set to '$Label' from the collected targets. Generate a name to use it.`n" 'info'
}

$hlKibana.Add_RequestNavigate({
    param($sender, $e)
    if ($script:KibanaUrl) { Start-Process $script:KibanaUrl }
    $e.Handled = $true
})

function Set-KibanaLink {
    # Everything here is best-effort: the upload has already succeeded and been
    # verified by this point, so nothing in this function is allowed to turn a
    # good upload into a reported failure.
    param([string]$Base, $Headers, [string]$Index)

    $script:KibanaUrl = $null
    $lnkKibana.Visibility = 'Collapsed'
    try {
        # The batch's own time span. Without it the link opens Discover on the
        # last 15 minutes, which shows nothing and looks broken.
        $aggBody = '{"size":0,"query":{"term":{"import.id":"' + $script:ImportId + '"}},' +
                   '"aggs":{"lo":{"min":{"field":"@timestamp"}},"hi":{"max":{"field":"@timestamp"}}}}'
        $span = Invoke-EsJson -Uri "$Base/$Index/_search" -Method Post -Headers $Headers `
                    -ContentType 'application/json' -Body $aggBody -TimeoutSec 60
        $from = $span.aggregations.lo.value_as_string
        $to   = $span.aggregations.hi.value_as_string
        if (-not $from -or -not $to) {
            Write-Log "Could not read the batch time range; no Kibana link offered.`n" 'warn'
            return
        }

        # Kibana's saved objects live in the .kibana index, so the data view id
        # is readable over the Elasticsearch credentials we already hold - no
        # separate Kibana/Kratos login needed just to build a link.
        # 500, not 20: this box already has more than 20 index-patterns and ours
        # was not in the first page, so the link silently never appeared.
        $dvBody = '{"size":500,"query":{"bool":{"must":[{"term":{"type":"index-pattern"}}]}},' +
                  '"_source":["index-pattern.title"]}'
        $dvResp = Invoke-EsJson -Uri "$Base/.kibana*/_search" -Method Post -Headers $Headers `
                    -ContentType 'application/json' -Body $dvBody -TimeoutSec 60

        # An account without read on .kibana (the least-privilege upload role)
        # gets no 403 here: the wildcard just matches nothing, so zero shards
        # are searched. Without this check that reads as "no data view exists"
        # and tells the operator to widen one that is already fine.
        if ([int]$dvResp._shards.total -eq 0) {
            $lblResult.Text += "`nNo Kibana link: this account cannot see Kibana's data views. Open Discover and pick a data view covering hayabusa-* (the imported dashboards bring one)."
            Write-Log "No Kibana link: this account cannot read Kibana's saved objects (normal for the least-privilege upload role).`n" 'info'
            return
        }

        $match = $null
        foreach ($hit in $dvResp.hits.hits) {
            $title = $hit._source.'index-pattern'.title
            if (Test-IndexCoveredByPattern $Index $title) {
                # id comes back as "index-pattern:<id>"; Kibana wants the id alone.
                $match = [pscustomobject]@{ Id = ($hit._id -replace '^index-pattern:', ''); Title = $title }
                # Remembered (importer.conf) for the host links, here and on
                # the Raw Events tab.
                $script:DetectionsDataViewId = $match.Id
                break
            }
        }

        if (-not $match) {
            # The trap this check exists for: the data view was hayabusa-evtx-*
            # while the guard only requires hayabusa-, so mission indices were
            # invisible. A link to a data view that cannot see the index is
            # worse than no link.
            $lblResult.Text += "`nNo Kibana data view covers '$Index', so it will not appear in Discover. Widen a data view to hayabusa-* first."
            Write-Log "No Kibana data view matches '$Index' - not offering a link.`n" 'warn'
            return
        }

        $portNum = 443
        [void][int]::TryParse($txtPort.Text.Trim(), [ref]$portNum)
        # The Kibana UI is on 443, not on Elasticsearch's port.
        $script:KibanaUrl = New-DiscoverUrl -HostName $txtHost.Text.Trim() -DataViewId $match.Id `
                                -ImportId $script:ImportId -From $from -To $to -Port 443
        $runKibana.Text = "Open these $('{0:N0}' -f $script:indexedCount) document(s) in Kibana  ($($match.Title), $from to $to)"
        # RequestNavigate never fires on a Hyperlink whose NavigateUri is null,
        # and the real URL is what the handler opens anyway.
        try { $hlKibana.NavigateUri = New-Object System.Uri($script:KibanaUrl) } catch { }
        $lnkKibana.Visibility = 'Visible'
        Write-Log "Kibana: $($script:KibanaUrl)`n" 'info'
    } catch {
        Write-Log "Could not build the Kibana link: $($_.Exception.Message)`n" 'warn'
    }
}

function Show-UploadHostLinks([string]$Base, $Headers, [string]$Index) {
    # The machines in this batch, every name form each was seen under - the
    # index says, so a host that wrote both WIN10 and WIN10.corp.local gets
    # both. Best-effort like the Kibana link: the upload has already worked.
    $pnlUpHostLinks.Visibility = 'Collapsed'
    try {
        $body = '{"size":0,"query":{"term":{"import.id":"' + $script:ImportId + '"}},' +
                '"aggs":{"h":{"terms":{"field":"host.name","size":10000}}}}'
        $resp = Invoke-EsJson -Uri "$Base/$Index/_search" -Method Post -Headers $Headers `
                    -ContentType 'application/json' -Body $body -TimeoutSec 60
        $names = @($resp.aggregations.h.buckets | ForEach-Object { [string]$_.key })
        if ($names.Count) { Show-HostLinks $pnlUpHostLinks $names }
    } catch {
        Write-Log "Could not list the hosts for their links: $($_.Exception.Message)`n" 'warn'
    }
}

# A refusal is written where the result goes, not only in a popup: the popup
# was easy to miss, and the previous upload's green "Success" then sat there
# reading like this upload had worked.
function Show-UploadRefusal([string]$Message, [string]$Title) {
    $lblResult.Text = "Not uploaded: $Message"
    $lblResult.Foreground = $script:UpBrush.err
    Write-Log "Upload not started: $Message`n" 'err'
    [void][System.Windows.MessageBox]::Show($Message, $Title)
}

$btnUpload.Add_Click({
    if ($script:Busy) { return }
    $lblResult.Text = ''; $lnkKibana.Visibility = 'Collapsed'; $pnlUpHostLinks.Visibility = 'Collapsed'

    # The gate: upload only a file that is identifiably our ECS JSONL, whether
    # it came from this session's conversion or was browsed to. Re-checked here
    # rather than trusting the label, in case the file changed underneath.
    Update-SourceReadiness
    if ($script:SourceKind -ne 'Ecs') {
        Show-UploadRefusal $lblSource.Text 'Cannot upload this file'
        return
    }
    # What was verified, not merely that something once was: a host, user or
    # password edited after VERIFY would otherwise go out unchecked.
    if (-not $script:ConnOk -or $script:ConnKey -ne (Get-UploadConnKey)) {
        Show-UploadRefusal 'Press VERIFY CONNECTIVITY and confirm it succeeds. If you changed the host, port, username or password since, verify again.' 'Verify first'
        return
    }
    $idxCheck = $txtIndex.Text.Trim()
    if (-not (Test-HayabusaIndexName $idxCheck)) {
        Show-UploadRefusal "'$idxCheck' is not a valid index name. It must start with 'hayabusa-' and contain only lowercase letters, digits, dot, dash or underscore. This guard keeps the tool out of the stack's own indices (Security Onion, Elastic, ...)." 'Invalid index'
        return
    }
    # The mission's index is appended to by design (the queue does the same).
    if ($script:Taken -contains $idxCheck -and -not ($chkAppend.IsChecked -eq $true) -and
        $idxCheck -ne (Get-MissionIndexName $script:Settings.MissionName)) {
        Show-UploadRefusal "'$idxCheck' already exists. Generate a new name, or tick 'Allow appending'." 'Index exists'
        return
    }

    # Ahead of the busy flag: a refused pin must leave the button usable.
    if (-not (Set-TlsTrustFromUi)) { return }
    # A browsed ecs.jsonl never went through this session's conversion, so it
    # carries no import.id and the result line would print an empty filter.
    if (-not $script:ImportId) {
        $script:ImportId = (Get-Date -Format 'yyyyMMddHHmmss') + [guid]::NewGuid().ToString('N').Substring(0,8)
    }
    if (-not (Confirm-PcapBeforeNetwork 'upload detections to Elasticsearch')) { return }
    Set-AppBusy $true 'uploading to ELK'
    # What the status line and the activity log say at the end. Starts as a
    # failure so that any early return or throw is recorded as one - the status
    # used to read "Finished" whatever had happened.
    $uploadOutcome = 'FAILED'; $uploadDetail = ''
    $script:indexedCount = 0
    try {
        $base = Get-EsBase
        $idx  = $txtIndex.Text.Trim()
        $h    = Get-AuthHeader $txtUser.Text.Trim() (Get-UploadPassword)

        # ---- hayabusa-* guard: never relax this, even for a shared/append upload ----
        # Checked again here on purpose. This is the last point before the
        # write, and it is the only one that runs no matter how the upload was
        # reached.
        if (-not (Test-HayabusaIndexName $idx)) {
            Write-Log "`nRefusing to write to '$idx'. An index name must start with 'hayabusa-' and contain only lowercase letters, digits, dot, dash or underscore.`n" 'err'
            return
        }

        # Checked, streamed and counted back by Publish-EcsFile - the same
        # function the job queue uploads with, so the two cannot differ.
        $refresh = ($chkRefresh.IsChecked -eq $true)
        $pub = Publish-EcsFile -Base $base -Headers $h -Index $idx -Path $script:EcsPath -Template (Get-Content $script:Template -Raw) `
                   -ImportId $script:ImportId -BatchSize $script:BatchSize -Overwrite:$refresh `
                   -Log { param($t, $k) Write-Log $t $k } `
                   -OnCheck { param($n) $lblStatus.Text = "Checking the batch: $('{0:N0}' -f $n) of $('{0:N0}' -f $script:DocCount) line(s)"; Invoke-UiPump } `
                   -OnBatch {
            param($t, $docs)
            $done = $t.Created + $t.Updated + $t.Duplicate + $t.Failed
            $bar.Maximum = [Math]::Max($docs, 1)
            $bar.Value = [Math]::Min($done, $bar.Maximum)
            $lblStatus.Text = "Uploading $('{0:N0}' -f $done) of $('{0:N0}' -f $docs): new $('{0:N0}' -f $t.Created), updated $('{0:N0}' -f $t.Updated), already in index $('{0:N0}' -f $t.Duplicate), failed $($t.Failed)"
            # Keeps the window (and its spinner) alive between requests.
            Invoke-UiPump
        }
        $script:indexedCount = $pub.Created; $script:dupCount = $pub.Duplicate; $updated = $pub.Updated
        $script:failedCount = $pub.Failed; $script:errList = @($pub.Errors)
        $uploadOutcome = $pub.Outcome; $uploadDetail = $pub.Detail
        $bar.Value = $bar.Maximum

        if ($pub.Outcome -eq 'Refused') {
            $lblResult.Text = "Not uploaded: $($pub.Detail)"; $lblResult.Foreground = $script:UpBrush.err
        } elseif ($pub.Outcome -eq 'MISMATCH') {
            $lblResult.Text = "MISMATCH - do not trust this index yet: $($pub.Detail). See the log."
            $lblResult.Foreground = $script:UpBrush.err
        } else {
            $lblResult.Text = "Success: $('{0:N0}' -f $script:indexedCount) new detection(s) in '$idx'$(if ($updated) { ", $('{0:N0}' -f $updated) updated" }), $('{0:N0}' -f $script:dupCount) already there (not doubled)."
            $lblResult.Foreground = $script:UpBrush.ok
            # Read back from Elasticsearch itself, so the tool states that the
            # index exists and what it holds, not just that the requests went out.
            try {
                $ci = @(Invoke-EsJson -Uri "$base/_cat/indices/${idx}?format=json&h=index,health,docs.count,store.size" -Headers $h -TimeoutSec 30)[0]
                Write-Log "Elasticsearch confirms index '$($ci.index)': $($ci.'docs.count') document(s), $($ci.'store.size'), health $($ci.health). In Kibana: Stack Management > Index Management, search 'hayabusa'.`n" 'ok'
                $lblResult.Text += "`nConfirmed by Elasticsearch: '$($ci.index)' holds $($ci.'docs.count') document(s) ($($ci.'store.size'))."
            } catch {
                Write-Log "Could not read '$idx' back from Elasticsearch: $($_.Exception.Message)`n" 'warn'
            }
            $lblResult.Text += "`n$(Get-WhereToLook 'detections')"
            Write-Log "$(Get-WhereToLook 'detections')`n" 'info'
            # The link opens this upload's import.id, which a batch of nothing
            # but duplicates has not one document under.
            if ($script:indexedCount + $updated -gt 0) {
                Set-KibanaLink -Base $base -Headers $h -Index $idx
                Show-UploadHostLinks -Base $base -Headers $h -Index $idx
            }
            else { Write-Log "Nothing new in this batch, so no Kibana link.`n" 'info' }
        }
    } catch {
        Write-Log "`nUPLOAD FAILED: $($_.Exception.Message)`n" 'err'
        $lblResult.Text = "Upload failed: $($_.Exception.Message)"; $lblResult.Foreground = $script:UpBrush.err
        $uploadDetail = $_.Exception.Message
    } finally {
        $lblStatus.Text = "Upload: $uploadOutcome"
        if ($uploadOutcome -ne 'Success') { $lblStatus.Foreground = $win.FindResource('Caution') }
        Write-Ledger @(New-LedgerRow -Action 'Upload' -Target $txtHost.Text.Trim() -Port (Get-UploadPort) `
                          -Protocol 'HTTPS (Elasticsearch)' -Account (Get-EsAccountLabel $txtUser.Text) -Result $uploadOutcome `
                          -Files "$('{0:N0}' -f $script:indexedCount) documents" -Output $txtIndex.Text.Trim() `
                          -Details ((@($uploadDetail, "source $($script:EcsPath)", "import.id $($script:ImportId)") | Where-Object { $_ }) -join '; '))
        # Last - see the Convert tab's finally.
        Set-AppBusy $false
    }
})

# ---- persisted settings (never the password) ----
if (Test-Path $script:ConfPath) {
    try {
        $c = Get-Content $script:ConfPath -Raw | ConvertFrom-Json
        if ($c.host)  { $txtHost.Text  = $c.host }
        if ($c.port)  { $txtPort.Text  = $c.port }
        if ($c.user)  { $txtUser.Text  = $c.user }
        if ($c.label) { $txtLabel.Text = $c.label }
        if ($c.label_auto -eq $true) { $script:AutoLabel = [string]$c.label }
        if ($c.pin) { $txtPin.Text = $c.pin }
        if ($c.dataview_id) { $script:DetectionsDataViewId = [string]$c.dataview_id }
        # The Dashboards tab's 443 pin. That tab is not built yet, so it is
        # handed over here and applied when the tab loads.
        $script:SavedWebPin = [string]$c.web_pin
        # Skip is restored only when it was explicitly chosen last run. An
        # absent or unrecognised value lands on Pin, never on trust-all.
        if ($c.tls_mode -eq 'Skip') { $rbTlsSkip.IsChecked = $true } else { $rbTlsPin.IsChecked = $true }
    } catch { }
}
# Password is session-only: never prefilled from an env var or config, never
# persisted. The user re-enters it each time the tool runs.

if ($win) {
    $win.Add_Closing({
        try {
            # A certificate fingerprint is public, and remembering it is the whole
            # point - the next run compares against it. The password still never
            # reaches this file.
            @{ host = $txtHost.Text; port = $txtPort.Text; user = $txtUser.Text
               label = $txtLabel.Text
               label_auto = [bool]($script:AutoLabel -and $txtLabel.Text.Trim() -eq $script:AutoLabel)
               tls_mode = $(if ($rbTlsSkip.IsChecked -eq $true) { 'Skip' } else { 'Pin' })
               pin = $txtPin.Text.Trim()
               dataview_id = [string]$script:DetectionsDataViewId
               web_pin = $(if ($txtKbPin) { $txtKbPin.Text.Trim() } else { [string]$script:SavedWebPin }) } |
                ConvertTo-Json | Set-Content -Path $script:ConfPath -Encoding utf8
        } catch { }
    })
}

Update-SourceReadiness

# ---- remembered password (DPAPI, opt-in) ----
# Passwords are kept only "if you can create a safe storage for it". See
# Save-RememberedSecret: per Windows account and machine, in the user's
# profile, never in this folder.
function Set-RememberedUploadPassword {
    $h = $txtHost.Text.Trim(); $u = $txtUser.Text.Trim()
    if (-not $h) { return }
    # No username = an API key, remembered for the host alone.
    $what = if ($u) { "Password for $u@$h" } else { "API key for $h" }
    try {
        if ($chkRememberPass.IsChecked -eq $true) {
            Save-RememberedSecret 'es' $h $u (Get-UploadPassword)
            Write-Log "$what remembered for $env:USERNAME on this machine (Windows DPAPI).`n" 'info'
        } elseif (Get-RememberedSecret 'es' $h $u) {
            Remove-RememberedSecret 'es' $h $u
            Write-Log "Remembered $what removed.`n" 'info'
        }
    } catch { Write-Log "Could not remember the password: $($_.Exception.Message)`n" 'warn' }
}
$script:UpFilledFor = ''
function Restore-RememberedUploadPassword {
    # Fills an empty password box when this host and user have one stored.
    # A password this filled in belongs to that host and user only: once
    # either changes it is cleared, or VERIFY would send it to the new server
    # (code review, 2026-10-16). One the operator typed is theirs to keep.
    $key = "$($txtHost.Text.Trim().ToLowerInvariant())|$($txtUser.Text.Trim())"
    if ($script:UpFilledFor -and $script:UpFilledFor -ne $key) {
        $txtPass.Password = ''; $txtPassPlain.Text = ''; $chkRememberPass.IsChecked = $false
        $script:UpFilledFor = ''
    }
    if (Get-UploadPassword) { return }
    $secret = Get-RememberedSecret 'es' $txtHost.Text.Trim() $txtUser.Text.Trim()
    if ($secret) {
        $txtPass.Password = $secret; $txtPassPlain.Text = $secret
        $chkRememberPass.IsChecked = $true
        $script:UpFilledFor = $key
        Write-Log "Remembered password filled in for $($txtUser.Text.Trim())@$($txtHost.Text.Trim()). Press VERIFY CONNECTIVITY.`n" 'info'
    }
}
$btnForgetPass.Add_Click({
    Remove-RememberedSecret 'es' $txtHost.Text.Trim() $txtUser.Text.Trim()
    $chkRememberPass.IsChecked = $false
    Write-Log "Forgot any remembered password for $($txtUser.Text.Trim())@$($txtHost.Text.Trim()).`n" 'info'
})
$txtHost.Add_LostFocus({ Restore-RememberedUploadPassword })
$txtUser.Add_LostFocus({ Restore-RememberedUploadPassword })
Restore-RememberedUploadPassword
