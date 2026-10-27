<#
.SYNOPSIS
    Guide tab - WPF fragment, dot-sourced by HayabusaMissionTool.ps1.

.DESCRIPTION
    A cheat sheet for the crew (owner, 2026-10-26): a short answer to each
    thing that is not obvious, More... opening the README chapter, and one
    search box over the cheat sheet and the whole README.txt. The README is
    the one beside EVTXER.cmd, read when searched, so it is always the
    manual that shipped with this copy. The entries and the search are
    HayabusaLib's (Get-GuideEntries, Get-ReadmeChapters, Find-ReadmeChapters),
    tested in tests\Guide.Tests.ps1. Set-AppBusy does not lock this tab:
    reading while a job runs is the point.
#>

# ============================================================== XAML =========
$guideXaml = @'
<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
      xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
      Margin="2,10,10,10">
  <StackPanel>
    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <TextBlock Text="Guide" Style="{DynamicResource SectionHead}"/>
        <TextBlock Style="{DynamicResource Hint}" TextWrapping="Wrap"
                   Text="Short answers to what is not obvious. Type to search these and the whole README; each More button opens that README chapter. README.txt beside EVTXER.cmd is the full manual."/>
        <TextBox x:Name="txtGuideSearch" Margin="0,10,0,0" ToolTip="Words to look for - every word must be there, in any case"/>
      </StackPanel>
    </Border>
    <TextBlock x:Name="lblGuideNone" Visibility="Collapsed" Margin="4,0,0,10" Style="{DynamicResource Hint}"
               Text="Nothing found in the cheat sheet or the README."/>
    <ItemsControl x:Name="lstGuide">
      <ItemsControl.ItemTemplate>
        <DataTemplate>
          <Border Style="{DynamicResource CardPanel}">
            <StackPanel>
              <TextBlock Text="{Binding Group}" Style="{DynamicResource Hint}"/>
              <TextBlock Text="{Binding Title}" FontWeight="SemiBold" FontSize="14" TextWrapping="Wrap" Margin="0,2,0,6"/>
              <TextBlock Text="{Binding Answer}" TextWrapping="Wrap"/>
              <!-- A TextBlock, not Content: a string Content eats its first
                   underscore as an access key. -->
              <Button HorizontalAlignment="Left" Margin="0,10,0,0" Padding="10,3"><TextBlock Text="{Binding More}"/></Button>
            </StackPanel>
          </Border>
        </DataTemplate>
      </ItemsControl.ItemTemplate>
    </ItemsControl>
    <StackPanel x:Name="pnlGuideReadme" Visibility="Collapsed">
      <TextBlock Text="In the README" Style="{DynamicResource SectionHead}" Margin="4,6,0,8"/>
      <ItemsControl x:Name="lstGuideReadme">
        <ItemsControl.ItemTemplate>
          <DataTemplate>
            <Button HorizontalAlignment="Left" Margin="0,0,0,6" Padding="10,3"><TextBlock Text="{Binding Label}"/></Button>
          </DataTemplate>
        </ItemsControl.ItemTemplate>
      </ItemsControl>
    </StackPanel>
  </StackPanel>
</Grid>
'@

$guideRoot = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$guideXaml)))
$tabGuide.Content = $guideRoot
foreach ($gName in @('txtGuideSearch', 'lblGuideNone', 'lstGuide', 'pnlGuideReadme', 'lstGuideReadme')) {
    Set-Variable -Name $gName -Scope Script -Value $guideRoot.FindName($gName)
}

$script:GuideEntries = @(Get-GuideEntries)
$script:ReadmePath = Join-Path $script:Root 'README.txt'

function Get-GuideReadme {
    # Read when used: a README edited or replaced in this copy is what is searched.
    try { return @(Get-ReadmeChapters ([IO.File]::ReadAllText($script:ReadmePath))) } catch { return @() }
}

function Update-Guide {
    $q = $txtGuideSearch.Text
    $shown = @($script:GuideEntries | Where-Object { Test-GuideMatch $_ $q })
    $hits = @(if ((Get-SearchWords $q).Count) { Find-ReadmeChapters (Get-GuideReadme) $q })
    $lstGuide.ItemsSource = $shown
    $lstGuideReadme.ItemsSource = $hits
    $pnlGuideReadme.Visibility = $(if ($hits.Count) { 'Visible' } else { 'Collapsed' })
    $lblGuideNone.Visibility = $(if (-not $shown.Count -and -not $hits.Count) { 'Visible' } else { 'Collapsed' })
}

function Show-ReadmeChapter([string]$Title, [string]$Query) {
    # The chapter in a reading window, scrolled to the first word searched for.
    $c = @(Get-GuideReadme | Where-Object { $_.Title -eq $Title })[0]
    if (-not $c) {
        [void][System.Windows.MessageBox]::Show("Chapter '$Title' was not found - is README.txt there and complete? ($script:ReadmePath)", 'Guide'); return
    }
    $readXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="880" Height="680" WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
        UseLayoutRounding="True" FontFamily="Segoe UI" FontSize="13" Background="#1E2126">
  <TextBox x:Name="txtRead" Margin="12" IsReadOnly="True" FontFamily="Consolas" TextWrapping="NoWrap" AcceptsReturn="True"
           VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" IsInactiveSelectionHighlightEnabled="True"
           VerticalContentAlignment="Top"/>
</Window>
'@
    $rw = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$readXaml)))
    $rw.Owner = $win
    $rw.Icon = $win.Icon
    $rw.Title = "README - $Title"
    $rt = $rw.FindName('txtRead')
    $rt.Text = $c.Body
    $first = @(Get-SearchWords $Query)[0]
    $at = if ($first) { $c.Body.ToLowerInvariant().IndexOf($first) } else { -1 }
    if ($at -ge 0) {
        $len = $first.Length
        $rw.Add_ContentRendered({
            [void]$rt.Focus()
            $rt.Select($at, $len)
            $rt.ScrollToLine([Math]::Max(0, $rt.GetLineIndexFromCharacterIndex($at) - 3))
        }.GetNewClosure())
    }
    $rw.Show()
}

$txtGuideSearch.Add_TextChanged({ Update-Guide })
# One handler per list for every More... / chapter button in it.
$lstGuide.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler]{
    param($gs, $ge)
    $it = $ge.OriginalSource.DataContext
    if ($it -and $it.Chapter) { Show-ReadmeChapter $it.Chapter $txtGuideSearch.Text }
})
$lstGuideReadme.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler]{
    param($gs, $ge)
    $it = $ge.OriginalSource.DataContext
    if ($it -and $it.Title) { Show-ReadmeChapter $it.Title $txtGuideSearch.Text }
})
Update-Guide
