<#
.SYNOPSIS
    The job queue pane - WPF fragment, dot-sourced by HayabusaMissionTool.ps1.

.DESCRIPTION
    Under the tabs and the log, so it is in sight whatever tab is open. Every host the Collect tab brings in becomes one job, and the
    steps ticked on this pane run by themselves, one job at a time (the
    switches moved here from the Settings tab on 2026-10-18 - the queue is
    the main path, the tabs the manual one): a Hayabusa scan of that folder -> ECS -> upload to the mission
    index -> raw import to Security Onion -> archive.

    Each step runs off the window's thread (Invoke-QueueStep in a runspace,
    Start-LibJob); a DispatcherTimer here starts the steps and collects their
    results. The tick never pumps the dispatcher itself (Write-Log
    -Background): a click run from inside it would start a foreground job
    nested in the tick, and the queue would stall behind that job.

    The queue is logs\queue.json (Read-JobQueue / Save-JobQueue), each job's
    own output logs\queue\<host folder>_<id>.log, and every step writes an
    activity-log row. The rules - order, waiting, colours - are in
    HayabusaLib.ps1 and tested in tests\JobQueue.Tests.ps1.
#>

# ============================================================== XAML =========
$queueXaml = @'
<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
      xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <Grid.RowDefinitions>
    <RowDefinition Height="Auto"/>
    <RowDefinition Height="*"/>
  </Grid.RowDefinitions>
  <!-- Two lines: what the queue holds (wrapping), then the buttons, which
       wrap onto a second row in a narrow window rather than crushing the text. -->
  <StackPanel Grid.Row="0" Margin="2,0,2,6">
    <DockPanel>
      <TextBlock DockPanel.Dock="Left" Text="QUEUE" Style="{StaticResource SectionHead}" Margin="0" VerticalAlignment="Center"/>
      <TextBlock x:Name="lblQueue" Style="{StaticResource Hint}" Margin="12,0,0,0" VerticalAlignment="Center" TextWrapping="Wrap"/>
    </DockPanel>
    <!-- What runs by itself, beside the queue it controls. The long words
         are in the tooltips. -->
    <WrapPanel Margin="0,6,0,0">
      <TextBlock Text="Runs by itself:" Style="{StaticResource Hint}" VerticalAlignment="Center" Margin="0,0,10,0"/>
      <CheckBox x:Name="chkAutoConvert" Tag="AutoConvert" Content="Convert" VerticalAlignment="Center"
                ToolTip="A Hayabusa scan of each collected host folder, then ECS."/>
      <CheckBox x:Name="chkAutoUpload" Tag="AutoUpload" Content="Upload" Margin="14,0,0,0" VerticalAlignment="Center"
                ToolTip="To the mission index. Needs Convert, the mission name (Settings tab) and VERIFY CONNECTIVITY (Upload tab) - the Mission and ELK pills at the top turn green."/>
      <CheckBox x:Name="chkAutoRaw" Tag="AutoRaw" Content="Raw import to SO" Margin="14,0,0,0" VerticalAlignment="Center"
                ToolTip="Every event into Security Onion. Needs the Raw Events tab filled in, host key included - the SO pill at the top turns green."/>
      <CheckBox x:Name="chkAutoArchive" Tag="AutoArchive" Content="Archive when done" Margin="14,0,0,0" VerticalAlignment="Center"
                ToolTip="A verified zip into the archive folder (Settings tab), then the host folder's EVTX are deleted."/>
    </WrapPanel>
    <WrapPanel Margin="0,6,0,0">
      <Button x:Name="btnQUp" Content="Move up" Padding="10,3" ToolTip="Earlier in the queue"/>
      <Button x:Name="btnQDown" Content="Move down" Padding="10,3" Margin="6,0,0,0" ToolTip="Later in the queue"/>
      <Button x:Name="btnQNext" Content="Run next" Padding="10,3" Margin="6,0,0,0" ToolTip="To the top: runs as soon as the step running now is finished"/>
      <Button x:Name="btnQRetry" Content="Retry" Padding="10,3" Margin="14,0,0,0" ToolTip="A failed job starts again at the step that failed"/>
      <Button x:Name="btnQCancel" Content="Cancel" Padding="10,3" Margin="6,0,0,0" ToolTip="Stops the running job; Retry resumes it at that step"/>
      <Button x:Name="btnQRemove" Content="Remove" Padding="10,3" Margin="6,0,0,0" ToolTip="Takes a job out of the queue. Its files stay where they are."/>
      <Button x:Name="btnQClear" Content="Clear done" Padding="10,3" Margin="6,0,0,0" ToolTip="Takes every finished job off the list"/>
      <Button x:Name="btnQAdd" Content="Add folders..." Padding="10,3" Margin="14,0,0,0" ToolTip="Queue host folders already in the EVTX drop folder"/>
      <Button x:Name="btnQLog" Content="Open log" Padding="10,3" Margin="6,0,0,0" ToolTip="Everything the selected job's steps printed"/>
      <Button x:Name="btnQHide" Content="Hide" Padding="10,3" Margin="14,0,0,0"/>
    </WrapPanel>
  </StackPanel>
  <Border x:Name="pnlQueueList" Grid.Row="1" Background="#1A1D22" BorderBrush="#333941" BorderThickness="1" CornerRadius="4">
    <Grid>
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="*"/>
      </Grid.RowDefinitions>
      <Grid Margin="9,6,9,4" TextElement.Foreground="#A8AEB8">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="34"/>
          <ColumnDefinition Width="240"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="190"/>
          <ColumnDefinition Width="96"/>
          <ColumnDefinition Width="70"/>
        </Grid.ColumnDefinitions>
        <TextBlock Text="#"/>
        <TextBlock Grid.Column="1" Text="Host folder"/>
        <TextBlock Grid.Column="2" Text="Stage"/>
        <TextBlock Grid.Column="3" Text="Progress" Margin="12,0,0,0"/>
        <TextBlock Grid.Column="4" Text="Detections" HorizontalAlignment="Right"/>
        <TextBlock Grid.Column="5" Text="Time" HorizontalAlignment="Right"/>
      </Grid>
      <ListBox x:Name="lstQueue" Grid.Row="1" Background="Transparent" BorderThickness="0" Foreground="#F2F2F2"
               SelectionMode="Single" HorizontalContentAlignment="Stretch"
               ScrollViewer.HorizontalScrollBarVisibility="Disabled">
        <ListBox.ItemTemplate>
          <DataTemplate>
            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="34"/>
                <ColumnDefinition Width="240"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="190"/>
                <ColumnDefinition Width="96"/>
                <ColumnDefinition Width="70"/>
              </Grid.ColumnDefinitions>
              <TextBlock Text="{Binding Pos}" Foreground="#A8AEB8"/>
              <TextBlock Grid.Column="1" Text="{Binding Name}" TextTrimming="CharacterEllipsis" ToolTip="{Binding Folder}"/>
              <DockPanel Grid.Column="2">
                <Border DockPanel.Dock="Left" Width="10" Height="10" CornerRadius="2" Margin="0,0,8,0"
                        VerticalAlignment="Center" Background="{Binding Brush}"/>
                <TextBlock Text="{Binding Stage}" Foreground="{Binding Brush}" TextTrimming="CharacterEllipsis" ToolTip="{Binding Stage}"/>
              </DockPanel>
              <!-- How far the whole job is. A step that cannot measure itself
                   shows a moving bar (IsIndeterminate) instead of a number. -->
              <DockPanel Grid.Column="3" Margin="12,0,0,0">
                <TextBlock DockPanel.Dock="Right" Width="44" TextAlignment="Right" Text="{Binding PctText}" Foreground="#A8AEB8"/>
                <ProgressBar Height="8" Maximum="100" VerticalAlignment="Center" Foreground="{Binding Brush}"
                             Value="{Binding Pct, Mode=OneWay}" IsIndeterminate="{Binding Busy, Mode=OneWay}"/>
              </DockPanel>
              <TextBlock Grid.Column="4" Text="{Binding Detections}" HorizontalAlignment="Right"/>
              <TextBlock Grid.Column="5" Text="{Binding Time}" HorizontalAlignment="Right"/>
            </Grid>
          </DataTemplate>
        </ListBox.ItemTemplate>
      </ListBox>
    </Grid>
  </Border>
</Grid>
'@

$queueRoot = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$queueXaml)))
$queueHost.Content = $queueRoot
foreach ($qName in @('lblQueue','btnQUp','btnQDown','btnQNext','btnQRetry','btnQCancel','btnQRemove','btnQClear',
                     'btnQAdd','btnQLog','btnQHide','pnlQueueList','lstQueue',
                     'chkAutoConvert','chkAutoUpload','chkAutoRaw','chkAutoArchive')) {
    Set-Variable -Name $qName -Scope Script -Value $queueRoot.FindName($qName)
}
# One handler for the four switches: each box's Tag is its setting's name.
# A change applies to jobs queued from then on.
$autoSwitch = {
    param($box)
    $script:Settings.($box.Tag) = $(if ($box.IsChecked -eq $true) { 'on' } else { 'off' })
    $chkAutoUpload.IsEnabled = ($chkAutoConvert.IsChecked -eq $true)
    Show-Queue
    # Saved by the Settings tab, which keeps a default folder as '' - if
    # that tab failed to load, the change holds for this session only.
    if (Get-Command Save-SettingsTab -ErrorAction SilentlyContinue) { Save-SettingsTab }
}
foreach ($box in @($chkAutoConvert, $chkAutoUpload, $chkAutoRaw, $chkAutoArchive)) { $box.Add_Click($autoSwitch) }
$chkAutoConvert.IsChecked = ($script:Settings.AutoConvert -eq 'on')
$chkAutoUpload.IsChecked  = ($script:Settings.AutoUpload -eq 'on')
$chkAutoUpload.IsEnabled  = ($script:Settings.AutoConvert -eq 'on')
$chkAutoRaw.IsChecked     = ($script:Settings.AutoRaw -eq 'on')
$chkAutoArchive.IsChecked = ($script:Settings.AutoArchive -eq 'on')

# ============================================================ state ==========
$script:QueuePath    = Join-Path $script:Folders.Logs 'queue.json'
$script:QueueLogDir  = Join-Path $script:Folders.Logs 'queue'
$script:Jobs         = @(Read-JobQueue $script:QueuePath)
$script:QueueRun     = $null      # the step running now: Start-LibJob's object plus Job, Clock, LogFile
$script:QueueTicking = $false
$script:QueueStopped = $false     # set while the window closes
$script:QueuePcapAsked = $false   # the PCAP question was answered (any button) for the queue this session
$script:QueuePcapClosed = $false  # ...or closed: network steps wait until Retry asks it again
$script:QueueToldWhere = @{}      # 'upload'/'raw' -> where to look was said once this session
$script:QueueView    = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
$script:QueueBrushes = @{}
$lstQueue.ItemsSource = $script:QueueView

# A row that tells the list when one of its values changes, so a row is
# updated in place every second instead of being rebuilt - a rebuilt row
# restarts its moving bar, and the bar then jumps instead of moving.
# Compiled: PowerShell objects do not raise change notifications.
if (-not ('EvtxerQueueRow' -as [type])) {
    Add-Type -ErrorAction Stop @"
using System.ComponentModel;
public sealed class EvtxerQueueRow : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler PropertyChanged;
    private void Set<T>(ref T field, T value, string name)
    {
        if (object.Equals(field, value)) return;
        field = value;
        PropertyChangedEventHandler h = PropertyChanged;
        if (h != null) h(this, new PropertyChangedEventArgs(name));
    }
    private string _id, _pos, _name, _folder, _stage, _det, _time, _pctText;
    private object _brush; private double _pct; private bool _busy;
    public string Id { get { return _id; } set { Set(ref _id, value, "Id"); } }
    public string Pos { get { return _pos; } set { Set(ref _pos, value, "Pos"); } }
    public string Name { get { return _name; } set { Set(ref _name, value, "Name"); } }
    public string Folder { get { return _folder; } set { Set(ref _folder, value, "Folder"); } }
    public string Stage { get { return _stage; } set { Set(ref _stage, value, "Stage"); } }
    public object Brush { get { return _brush; } set { Set(ref _brush, value, "Brush"); } }
    public double Pct { get { return _pct; } set { Set(ref _pct, value, "Pct"); } }
    public bool Busy { get { return _busy; } set { Set(ref _busy, value, "Busy"); } }
    public string PctText { get { return _pctText; } set { Set(ref _pctText, value, "PctText"); } }
    public string Detections { get { return _det; } set { Set(ref _det, value, "Detections"); } }
    public string Time { get { return _time; } set { Set(ref _time, value, "Time"); } }
}
"@
}

# ============================================================ helpers ========
function Get-QueueBrush([string]$Hex) {
    # One frozen brush per colour: a new one every second would count as a
    # change and repaint every row.
    if (-not $script:QueueBrushes.ContainsKey($Hex)) {
        $b = (New-Object System.Windows.Media.BrushConverter).ConvertFromString($Hex); $b.Freeze()
        $script:QueueBrushes[$Hex] = $b
    }
    return $script:QueueBrushes[$Hex]
}

function Save-Queue {
    try { Save-JobQueue $script:Jobs $script:QueuePath }
    catch { Write-Log -Background "[Queue] Could not save $($script:QueuePath): $($_.Exception.Message)`n" 'warn' }
}

function Get-QueueLogPath($Job) { Join-Path $script:QueueLogDir "$($Job.Name)_$($Job.Id).log" }

function Get-SelectedQueueJob {
    $id = if ($lstQueue.SelectedItem) { $lstQueue.SelectedItem.Id } else { '' }
    return @($script:Jobs | Where-Object { $_.Id -eq $id }) | Select-Object -First 1
}

function Show-Queue {
    # Rows are updated in place; the list is rebuilt only when jobs come,
    # go or change order, so it neither flickers nor loses its place.
    $script:Jobs = @(Get-QueueOrder $script:Jobs)
    $same = $script:Jobs.Count -eq $script:QueueView.Count
    for ($i = 0; $same -and $i -lt $script:Jobs.Count; $i++) { if ($script:QueueView[$i].Id -ne $script:Jobs[$i].Id) { $same = $false } }
    if (-not $same) {
        $selId = if ($lstQueue.SelectedItem) { $lstQueue.SelectedItem.Id } else { '' }
        $script:QueueView.Clear()
        foreach ($j in $script:Jobs) { $r = New-Object EvtxerQueueRow; $r.Id = $j.Id; $script:QueueView.Add($r) }
        if ($selId) { $lstQueue.SelectedItem = @($script:QueueView | Where-Object { $_.Id -eq $selId }) | Select-Object -First 1 }
    }
    $n = 0
    for ($i = 0; $i -lt $script:Jobs.Count; $i++) {
        $j = $script:Jobs[$i]; $r = $script:QueueView[$i]
        $running = $j.State -eq 'running' -and $script:QueueRun -and $script:QueueRun.Job.Id -eq $j.Id
        $stage = Get-QueueStage $j
        $prog = Get-QueueJobProgress $j $(if ($running) { $script:QueueRun.Progress } else { $null })
        $secs = [double]$j.Seconds
        if ($running) { $secs += $script:QueueRun.Clock.Elapsed.TotalSeconds }
        $r.Pos = switch ($j.State) { 'running' { [string][char]0x25B6 } 'done' { [string][char]0x2713 } default { $n++; "$n" } }
        $r.Name = $j.Name; $r.Folder = $j.Folder
        $r.Stage = if ($prog.Detail) { "$($stage.Text) - $($prog.Detail)" } else { $stage.Text }
        $r.Brush = Get-QueueBrush $stage.Colour
        $r.Pct = $prog.Pct; $r.Busy = $prog.Busy; $r.PctText = "$([Math]::Floor($prog.Pct))%"
        $r.Detections = if ($j.Detections -ge 0) { '{0:N0}' -f [long]$j.Detections } else { '-' }
        $r.Time = if ($secs -gt 0) { Format-JobDuration ([timespan]::FromSeconds($secs)) } else { '' }
    }
    $count = @{}
    foreach ($j in $script:Jobs) { $count[$j.State] = 1 + [int]$count[$j.State] }
    $parts = @(foreach ($s in 'running', 'queued', 'waiting', 'failed') { if ($count[$s]) { "$($count[$s]) $s" } })
    $lblQueue.Text = if ($script:Jobs.Count) { (@("$([int]$count['done']) of $($script:Jobs.Count) hosts done") + $parts) -join ' - ' }
                     elseif (@(Get-QueueSteps $script:Settings).Count) { 'Empty. Every host the Collect tab brings in is queued here and processed by itself.' }
                     else { 'Empty, and nothing is ticked to run by itself (Runs by itself, above).' }
}

function Add-QueueFolder([string]$Folder) {
    # A collected host folder, as a job with the steps switched on now.
    $steps = @(Get-QueueSteps $script:Settings)
    if (-not $steps.Count) { return }
    if (Test-QueueHoldsFolder $script:Jobs $Folder) {
        Write-Log -Background "[Queue] $(Split-Path -Leaf $Folder) is already in the queue.`n" 'info'; return
    }
    $job = New-QueueJob $Folder $steps (Join-Path $script:Folders.Hayabusa 'jobs')
    $script:Jobs = @($script:Jobs) + $job
    Write-Log -Background "[Queue] $($job.Name) queued: $(($steps | ForEach-Object { $script:QueueStepText[$_].Short }) -join ', ').`n" 'info'
    Save-Queue
    Show-Queue
}

function Get-QueueBlockers {
    # Step -> what the operator has to do before it can run. Read from the
    # tabs each time, so a job goes on by itself once it is done.
    $b = @{}
    if (-not (Find-Hayabusa)) { $b.scan = 'Hayabusa is missing from code\hayabusa-x64' }
    if ($script:RulesUpdating) { $b.scan = $b.ecs = 'the Hayabusa rules are being updated (Settings tab)' }
    if (-not (Get-MissionIndexName $script:Settings.MissionName)) { $b.upload = 'name the mission on the Settings tab' }
    elseif (-not $script:ConnOk -or $script:ConnKey -ne (Get-UploadConnKey)) { $b.upload = 'press VERIFY CONNECTIVITY on the Upload tab' }
    if (-not (Test-SoReady)) {
        $b.raw = 'fill in the Raw Events tab - host, user, password and host key'
    } elseif (-not (Find-PuttyTool plink) -or -not (Find-PuttyTool pscp)) { $b.raw = 'code\putty\plink.exe and pscp.exe are missing' }
    # Closing the PCAP question cancels, as it does for every other network
    # action: nothing more goes out until the operator says so.
    if ($script:QueuePcapClosed) {
        $why = 'the accountability PCAP question was closed - press Retry to be asked again'
        foreach ($s in 'upload', 'raw') { if (-not $b[$s]) { $b[$s] = $why } }
        if ($script:Folders.Archive -like '\\*') { $b.archive = $why }
    }
    return $b
}

function Test-QueueReadsRules {
    # Only a scan or a conversion reads the rules. An upload, raw import or
    # archive can run through a rules update; new scans wait on RulesUpdating.
    $r = $script:QueueRun
    if (-not $r -or $r.Handle.IsCompleted) { return $false }
    return ([string]@($r.Job.Steps)[$r.Job.Step]) -in 'scan', 'ecs'
}

function Save-QueueLines($Run) {
    $buf = New-Object System.Collections.Generic.List[string]
    $m = $null
    while ($Run.Lines.TryDequeue([ref]$m)) { $buf.Add($m) }
    if ($buf.Count) { try { [IO.File]::AppendAllLines($Run.LogFile, [string[]]$buf.ToArray()) } catch { } }
}

function Start-QueueStep($Job) {
    $step = [string]@($Job.Steps)[$Job.Step]
    # The question every network action asks, answered once a session for
    # the queue - and not while a foreground job is running.
    $network = $step -in 'upload', 'raw' -or ($step -eq 'archive' -and $script:Folders.Archive -like '\\*')
    if ($network -and -not $script:QueuePcapAsked) {
        if ($script:Busy) { return }
        if (-not (Confirm-PcapBeforeNetwork 'send queued results over the network (upload, raw import, archive to a share)')) {
            $script:QueuePcapClosed = $true
            return
        }
        $script:QueuePcapAsked = $true
    }
    $ctx = @{ HayabusaExe = (Find-Hayabusa); TemplatePath = $script:Template; ArchiveRoot = $script:Folders.Archive }
    if ($step -eq 'upload') {
        # The connection VERIFY checked, with the certificate trust it checked
        # it under. The trust is one setting for the whole process, and other
        # tabs set their own, so it is put back to the Upload tab's here.
        if (-not (Set-TlsTrustFromUi)) { return }
        $ctx.EsBase = Get-EsBase; $ctx.EsHeaders = Get-AuthHeader $txtUser.Text.Trim() (Get-UploadPassword)
        $ctx.Index = Get-MissionIndexName $script:Settings.MissionName
        $ctx.EsHost = $txtHost.Text.Trim(); $ctx.EsPort = Get-UploadPort; $ctx.EsUser = Get-EsAccountLabel $txtUser.Text
    }
    if ($step -eq 'raw') {
        $ctx.SoHost = $txtSoHost.Text.Trim(); $ctx.SoPort = Get-SoPort; $ctx.SoUser = $txtSoUser.Text.Trim()
        $ctx.SoHostKey = Get-SshHostKeyFingerprint $txtSoHostKey.Text; $ctx.SoPassword = Get-SoPassword
    }
    New-Item -ItemType Directory -Path $script:QueueLogDir -Force -ErrorAction SilentlyContinue | Out-Null
    # The activity-log rows are made in the runspace, which has no launcher.
    $ctx.ToolVersion = $script:ToolVersion
    $run = Start-LibJob 'Invoke-QueueStep' @{ Job = $Job; Context = $ctx }
    $Job.State = 'running'; $Job.Note = ''
    $run | Add-Member -NotePropertyName Job -NotePropertyValue $Job
    $run | Add-Member -NotePropertyName Clock -NotePropertyValue ([Diagnostics.Stopwatch]::StartNew())
    $run | Add-Member -NotePropertyName LogFile -NotePropertyValue (Get-QueueLogPath $Job)
    $script:QueueRun = $run
    Write-Log -Background "[Queue] $($Job.Name): $($script:QueueStepText[$step].Run)...`n" 'info'
    Save-Queue
}

function Complete-QueueStep($Run) {
    $job = $Run.Job
    $res = $null; $err = ''
    try { $res = Complete-LibJob $Run } catch { $err = $_.Exception.Message }
    Save-QueueLines $Run
    $script:QueueRun = $null
    $step = [string]@($job.Steps)[$job.Step]
    $what = $script:QueueStepText[$step].Run
    $job.Seconds = [int]([double]$job.Seconds + $Run.Clock.Elapsed.TotalSeconds)
    if ($res -and $res.Ledger) { Write-Ledger @($res.Ledger) }
    if ($res -and $res.Ok) {
        if ($null -ne $res.Detections) { $job.Detections = [long]$res.Detections }
        $job.Step++
        while ($job.Step -lt @($job.Steps).Count -and @($res.Skip) -contains [string]@($job.Steps)[$job.Step]) { $job.Step++ }
        $job.Note = ''
        Write-Log -Background "[Queue] $($job.Name): $what - $($res.Summary)`n" 'ok'
        # A low-disk warning stays in sight over a long run: its own amber
        # line, and on the row ("Done - LOW DISK ...") - not only at the end
        # of a green one (review, 2026-10-26).
        if ($res.Warning) {
            $job.Note = "LOW DISK on the manager - $($res.Warning)"
            Write-Log -Background "[Queue] $($job.Name): LOW DISK on the manager - $($res.Warning)`n" 'warn'
        }
        # Where the data now shows - once a session per kind, not per host.
        if ($step -in 'upload', 'raw' -and -not $script:QueueToldWhere[$step]) {
            $script:QueueToldWhere[$step] = $true
            Write-Log -Background "[Queue] $(Get-WhereToLook $(if ($step -eq 'upload') { 'detections' } else { 'raw' }))`n" 'info'
        }
        if ($job.Step -ge @($job.Steps).Count) {
            $job.State = 'done'; $job.Finished = (Get-Date).ToString('s')
            Write-Log -Background "[Queue] $($job.Name) done in $(Format-JobDuration ([timespan]::FromSeconds($job.Seconds))).`n" 'ok'
        } else { $job.State = 'queued' }
        # Its folder is gone once archived; what showed it follows.
        if ($step -eq 'archive') {
            foreach ($box in @($txtEvtx, $txtSoFolder)) {
                if ($box -and $box.Text -and -not (Test-Path -LiteralPath $box.Text)) { $box.Text = $script:Folders.Evtx }
            }
            if (Get-Command Update-ArchiveList -ErrorAction SilentlyContinue) { Update-ArchiveList }
        }
    } else {
        $job.State = 'failed'
        $job.Note = if ($res) { $res.Summary } else { $err }
        Write-Log -Background "[Queue] $($job.Name): $what FAILED - $($job.Note). Its log: $($Run.LogFile)`n" 'err'
    }
    Save-Queue
}

function Step-Queue {
    $run = $script:QueueRun
    if ($run) {
        Save-QueueLines $run
        if (-not $run.Handle.IsCompleted) { Show-Queue; return }
        Complete-QueueStep $run
    }
    if ($script:QueueStopped) { Show-Queue; return }
    if (Update-QueueBlockers $script:Jobs (Get-QueueBlockers)) { Save-Queue }
    $next = @(Get-QueueOrder $script:Jobs | Where-Object { $_.State -eq 'queued' }) | Select-Object -First 1
    if ($next) { Start-QueueStep $next }
    Show-Queue
}

function Confirm-QueueClose {
    # Asked by the window's Closing handler before anything else is stopped.
    # $true = go ahead and close.
    $run = $script:QueueRun
    if ($run -and -not $run.Handle.IsCompleted) {
        $what = $script:QueueStepText[[string]@($run.Job.Steps)[$run.Job.Step]].Run
        # so-import-evtx is never stopped half way, and the staged copies on
        # the manager are removed only when it ends: closing now would leave
        # evidence in the manager's /tmp (code review).
        if ([string]@($run.Job.Steps)[$run.Job.Step] -eq 'raw') {
            [void][System.Windows.MessageBox]::Show("A raw import to Security Onion is running ($($run.Job.Name)). It cannot be stopped half way, and its copies on the manager are removed only when it ends. Close EVTXER once the queue shows it finished.", 'Job queue')
            return $false
        }
        $ask = "A queued job is running: $($run.Job.Name) - $what.`n`nClose EVTXER anyway? The step stops now, and the job starts again at this step the next time EVTXER opens."
        if ([System.Windows.MessageBox]::Show($ask, 'Job queue', 'YesNo', 'Warning') -ne 'Yes') { return $false }
        $script:QueueStopped = $true
        $run.Progress.Cancel = $true
        # Long enough for Hayabusa or the ECS workers to be stopped and the
        # step to say so. so-import-evtx is never stopped half way; if it is
        # still running then, the job is simply resumed next time.
        [void]$run.Handle.AsyncWaitHandle.WaitOne(20000)
        if ($run.Handle.IsCompleted) {
            Complete-QueueStep $run
            # Stopped by the close, not by the operator: it goes on by
            # itself next time, as the question said. (Found driving the real
            # window - it was left 'Cancelled', waiting for a Retry.)
            if ($run.Job.State -eq 'failed') {
                $run.Job.State = 'queued'
                $run.Job.Note = "Interrupted - EVTXER closed during '$what'; it starts there again."
                Save-Queue
            }
        }
    }
    $script:QueueStopped = $true
    $script:QueueTimer.Stop()
    return $true
}

# ============================================================ handlers =======
$btnQUp.Add_Click({   $j = Get-SelectedQueueJob; if ($j) { $script:Jobs = @(Move-QueueJob $script:Jobs $j.Id 'up');   Save-Queue; Show-Queue } })
$btnQDown.Add_Click({ $j = Get-SelectedQueueJob; if ($j) { $script:Jobs = @(Move-QueueJob $script:Jobs $j.Id 'down'); Save-Queue; Show-Queue } })
$btnQNext.Add_Click({ $j = Get-SelectedQueueJob; if ($j) { $script:Jobs = @(Move-QueueJob $script:Jobs $j.Id 'next'); Save-Queue; Show-Queue } })
$btnQRetry.Add_Click({
    $script:QueuePcapClosed = $false
    $j = Get-SelectedQueueJob
    if ($j -and $j.State -in 'failed', 'waiting') {
        $j.State = 'queued'; $j.Note = ''
        Write-Log "[Queue] $($j.Name): retried.`n" 'info'
        Save-Queue; Show-Queue
    }
})
$btnQCancel.Add_Click({
    $j = Get-SelectedQueueJob
    if (-not $j) { $j = $script:QueueRun.Job }
    if ($script:QueueRun -and $j -and $j.Id -eq $script:QueueRun.Job.Id) {
        $script:QueueRun.Progress.Cancel = $true
        Write-Log "[Queue] $($j.Name): stopping...`n" 'warn'
    }
})
$btnQRemove.Add_Click({
    $j = Get-SelectedQueueJob
    if (-not $j -or $j.State -eq 'running') { return }
    $script:Jobs = @($script:Jobs | Where-Object { $_.Id -ne $j.Id })
    Write-Log "[Queue] $($j.Name) removed from the queue. Its files were not touched.`n" 'info'
    Save-Queue; Show-Queue
    if (Get-Command Update-ArchiveList -ErrorAction SilentlyContinue) { Update-ArchiveList }
})
$btnQClear.Add_Click({
    $script:Jobs = @($script:Jobs | Where-Object { $_.State -ne 'done' })
    Save-Queue; Show-Queue
})
$btnQLog.Add_Click({
    $j = Get-SelectedQueueJob
    $f = if ($j) { Get-QueueLogPath $j } else { '' }
    if ($f -and (Test-Path -LiteralPath $f)) { Start-Process notepad.exe -ArgumentList ('"{0}"' -f $f) }
    elseif (Test-Path -LiteralPath $script:QueueLogDir) { Start-Process explorer.exe -ArgumentList ('"{0}"' -f $script:QueueLogDir) }
})
$btnQAdd.Add_Click({
    if (-not @(Get-QueueSteps $script:Settings).Count) {
        [void][System.Windows.MessageBox]::Show('Nothing is ticked to run by itself. Tick at least one step under the QUEUE heading first.', 'Job queue'); return
    }
    $free = @(Get-ArchiveCandidates $script:Folders.Evtx | Where-Object { -not (Test-QueueHoldsFolder $script:Jobs $_.Path) })
    if (-not $free.Count) { [void][System.Windows.MessageBox]::Show("No host folders with .evtx in $($script:Folders.Evtx) that are not already queued.", 'Job queue'); return }
    $pickXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Add host folders to the queue" Width="620" Height="420"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
        UseLayoutRounding="True" FontFamily="Segoe UI" FontSize="13" Background="#1E2126">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <ListBox x:Name="lstPick" SelectionMode="Multiple" Background="#1A1D22" BorderBrush="#333941" Foreground="#F2F2F2">
      <ListBox.ItemTemplate>
        <DataTemplate>
          <CheckBox Focusable="False"
                    IsChecked="{Binding IsSelected, RelativeSource={RelativeSource AncestorType=ListBoxItem}}">
            <TextBlock Text="{Binding Label}"/>
          </CheckBox>
        </DataTemplate>
      </ListBox.ItemTemplate>
    </ListBox>
    <StackPanel Grid.Row="1" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
      <Button x:Name="btnPickAll" Content="Select all" MinWidth="90"/>
      <Button x:Name="btnPickOk" Content="QUEUE THEM" Style="{StaticResource Primary}" MinWidth="130" Margin="10,0,0,0"/>
      <Button x:Name="btnPickCancel" Content="Cancel" MinWidth="80" Margin="10,0,0,0"/>
    </StackPanel>
  </Grid>
</Window>
'@
    $w = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$pickXaml)))
    $w.Owner = $win
    $pick = $w.FindName('lstPick'); $pick.ItemsSource = $free
    $chosen = @{ Ok = $false }
    $w.FindName('btnPickAll').Add_Click({ $pick.SelectAll() }.GetNewClosure())
    $w.FindName('btnPickOk').Add_Click({ $chosen.Ok = $true; $w.Close() }.GetNewClosure())
    $w.FindName('btnPickCancel').Add_Click({ $w.Close() }.GetNewClosure())
    $w.Add_Closing({ $chosen.Items = @($pick.SelectedItems) }.GetNewClosure())
    [void]$w.ShowDialog()
    if ($chosen.Ok) { foreach ($c in @($chosen.Items)) { Add-QueueFolder $c.Path } }
})
$btnQHide.Add_Click({
    if ($pnlQueueList.Visibility -eq 'Visible') {
        $script:QueueRowHeight = $rowQueue.Height
        $pnlQueueList.Visibility = 'Collapsed'; $splitQueue.Visibility = 'Collapsed'
        $rowQueue.Height = [System.Windows.GridLength]::Auto
        $btnQHide.Content = 'Show'
    } else {
        $pnlQueueList.Visibility = 'Visible'; $splitQueue.Visibility = 'Visible'
        if ($script:QueueRowHeight) { $rowQueue.Height = $script:QueueRowHeight }
        $btnQHide.Content = 'Hide'
    }
})

# ============================================================ start ==========
foreach ($j in @($script:Jobs | Where-Object { $_.Note -like 'Interrupted*' })) {
    Write-Log "[Queue] $($j.Name): $($j.Note)`n" 'warn'
}
Show-Queue
$script:QueueTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:QueueTimer.Interval = [timespan]::FromSeconds(1)
$script:QueueTimer.Add_Tick({
    # Never twice at once: Write-Ledger or the PCAP question can run the
    # dispatcher from inside a tick.
    if ($script:QueueTicking) { return }
    $script:QueueTicking = $true
    try { Step-Queue }
    catch { Write-Log -Background "[Queue] $($_.Exception.Message)`n" 'err' }
    finally { $script:QueueTicking = $false }
})
$script:QueueTimer.Start()
