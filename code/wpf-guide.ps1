<#
.SYNOPSIS
    Guide tab - WPF fragment, dot-sourced by HayabusaMissionTool.ps1.

.DESCRIPTION
    A cheat sheet for the crew (owner, 2026-10-26): a short answer to each
    thing that is not obvious, More... opening the README chapter, and one
    search box over the cheat sheet and the whole README.txt, whose hits show
    the matching lines. README opens the whole manual in a reading window:
    its chapters on the left, every mention of another chapter a link
    (owner, 2026-10-29: "the search sucks - a README button, and hyperlink
    to the chapters"). The README is
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
                   Text="Short answers to what is not obvious. Type to search these and the whole README; a line found in the README opens it there. README opens the whole manual, with its chapters to click."/>
        <Grid Margin="0,10,0,0">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBox x:Name="txtGuideSearch" Grid.Column="0" ToolTip="Words to look for - every word must be there, in any case"/>
          <Button x:Name="btnGuideReadme" Grid.Column="1" Margin="10,0,0,0" Padding="14,3" Style="{DynamicResource Primary}"
                  ToolTip="The whole README.txt in a reading window: chapters on the left, links between them, Ctrl+F to find"><TextBlock Text="README"/></Button>
        </Grid>
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
            <StackPanel Margin="0,0,0,10">
              <Button HorizontalAlignment="Left" Padding="10,3"><TextBlock Text="{Binding Label}"/></Button>
              <!-- The lines that hold the words; each opens the README at that line. -->
              <ItemsControl ItemsSource="{Binding Snippets}" Margin="14,4,0,0">
                <ItemsControl.ItemTemplate>
                  <DataTemplate>
                    <Button HorizontalAlignment="Left" Margin="0,2,0,0" Padding="6,1" Background="Transparent" BorderThickness="0"
                            Cursor="Hand" ToolTip="Open the README at this line">
                      <TextBlock Text="{Binding Shown}" TextWrapping="Wrap" Foreground="{DynamicResource Accent}" TextDecorations="Underline"/>
                    </Button>
                  </DataTemplate>
                </ItemsControl.ItemTemplate>
              </ItemsControl>
            </StackPanel>
          </DataTemplate>
        </ItemsControl.ItemTemplate>
      </ItemsControl>
    </StackPanel>
  </StackPanel>
</Grid>
'@

$guideRoot = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$guideXaml)))
$tabGuide.Content = $guideRoot
foreach ($gName in @('txtGuideSearch', 'btnGuideReadme', 'lblGuideNone', 'lstGuide', 'pnlGuideReadme', 'lstGuideReadme')) {
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

function Show-Readme([string]$Title = '', [string]$Line = '', [string]$Query = '') {
    # The whole README in a reading window: its chapters on the left, every
    # mention of another chapter in the text a link to it (Split-ReadmeLine),
    # Ctrl+F to find. Opened at $Title - at the very $Line when a search hit
    # was clicked, else at the first line holding a word of $Query - and that
    # line marked.
    if (-not (Test-Path -LiteralPath $script:ReadmePath)) {
        [void][System.Windows.MessageBox]::Show("README.txt was not found beside EVTXER.cmd ($script:ReadmePath).", 'Guide'); return
    }
    $lines = [IO.File]::ReadAllLines($script:ReadmePath)
    $chapters = @(Get-GuideReadme)
    $keys = Get-ReadmeLinkKeys $chapters
    $readXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="1180" Height="780" WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
        UseLayoutRounding="True" FontFamily="Segoe UI" FontSize="13" Background="#1E2126">
  <Grid Margin="10">
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="300"/>
      <ColumnDefinition Width="*"/>
    </Grid.ColumnDefinitions>
    <DockPanel Grid.Column="0" Margin="0,0,10,0">
      <TextBlock DockPanel.Dock="Top" Text="Chapters" Foreground="#A8AEB8" Margin="2,0,0,6"/>
      <ListBox x:Name="lstToc" Background="#252930" Foreground="#E3E6EA" BorderThickness="0"
               ScrollViewer.HorizontalScrollBarVisibility="Disabled">
        <ListBox.ItemTemplate>
          <DataTemplate><TextBlock Text="{Binding}" TextWrapping="Wrap" Margin="0,2,0,2"/></DataTemplate>
        </ListBox.ItemTemplate>
      </ListBox>
    </DockPanel>
    <FlowDocumentReader x:Name="rdr" Grid.Column="1" ViewingMode="Scroll" IsFindEnabled="True"
                        IsPageViewEnabled="False" IsTwoPageViewEnabled="False" IsPrintEnabled="False"
                        Background="#1E2126" Foreground="#E3E6EA"/>
  </Grid>
</Window>
'@
    $rw = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$readXaml)))
    $rw.Owner = $win
    $rw.Icon = $win.Icon
    $rw.Title = 'README - EVTXER manual'
    $toc = $rw.FindName('lstToc')
    $rdr = $rw.FindName('rdr')
    $accent = (New-Object System.Windows.Media.BrushConverter).ConvertFromString('#85C7F2')
    $mark = (New-Object System.Windows.Media.BrushConverter).ConvertFromString('#5C4A1E')

    $doc = New-Object System.Windows.Documents.FlowDocument
    $doc.FontFamily = 'Consolas'; $doc.FontSize = 13; $doc.PagePadding = '14,8,14,8'
    $doc.Background = $rdr.Background; $doc.Foreground = $rdr.Foreground
    # As wide as the longest line, so nothing wraps (the README is laid out
    # in columns) and nothing scrolls sideways that need not.
    $widest = ($lines | Measure-Object -Property Length -Maximum).Maximum
    $doc.PageWidth = [Math]::Max(600, 7.6 * $widest + 60)
    $paras = New-Object System.Collections.Generic.List[object]
    $heads = @{}
    # Set below; the links, made first, read it when clicked - a hashtable,
    # so a closure taken now still sees it.
    $nav = @{ Go = $null }
    $current = ''
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        $p = New-Object System.Windows.Documents.Paragraph
        $p.Margin = '0'
        $isHead = $l.Trim() -and $i + 1 -lt $lines.Count -and $lines[$i + 1] -match '^-{4,}$'
        if ($isHead) {
            $current = $l.Trim(); $heads[$current] = $p
            $p.FontWeight = 'Bold'; $p.Foreground = $accent; $p.Margin = '0,6,0,0'
            $p.Inlines.Add((New-Object System.Windows.Documents.Run $l))
        } elseif (-not $l) {
            $p.Inlines.Add((New-Object System.Windows.Documents.Run ' '))
        } else {
            foreach ($seg in @(Split-ReadmeLine $l $keys $current)) {
                if ($seg.Link) {
                    $h = New-Object System.Windows.Documents.Hyperlink (New-Object System.Windows.Documents.Run $seg.Text)
                    $h.Foreground = $accent; $h.Tag = $seg.Link; $h.ToolTip = "Go to $($seg.Link)"
                    $h.Add_Click({ param($s) & $nav.Go ([string]$s.Tag) '' }.GetNewClosure())
                    $p.Inlines.Add($h)
                } else {
                    $p.Inlines.Add((New-Object System.Windows.Documents.Run $seg.Text))
                }
            }
        }
        $doc.Blocks.Add($p); $paras.Add([pscustomobject]@{ Para = $p; Text = $l.Trim(); Chapter = $current })
    }
    $rdr.Document = $doc

    # To a chapter (or one line of it), shown at the TOP of the view: where
    # the line is now, measured, and the reader's own scroll moved by that
    # much (BringIntoView stops as soon as a line is anywhere in sight).
    $findScroll = {
        param($node)
        if ($node -is [System.Windows.Controls.ScrollViewer]) { return $node }
        for ($c = 0; $c -lt [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($node); $c++) {
            $f = & $findScroll ([System.Windows.Media.VisualTreeHelper]::GetChild($node, $c))
            if ($f) { return $f }
        }
        return $null
    }
    $nav.Go = {
        param([string]$To, [string]$AtLine)
        $idx = -1
        if ($AtLine) {
            for ($k = 0; $k -lt $paras.Count; $k++) { if ($paras[$k].Chapter -eq $To -and $paras[$k].Text -eq $AtLine) { $idx = $k; break } }
        }
        if ($idx -lt 0 -and $heads.ContainsKey($To)) {
            for ($k = 0; $k -lt $paras.Count; $k++) { if ($paras[$k].Para -eq $heads[$To]) { $idx = $k; break } }
        }
        if ($idx -lt 0) { return }
        if ($AtLine) { $paras[$idx].Para.Background = $mark }
        $target = $paras[[Math]::Max($idx - 1, 0)].Para
        $sv = & $findScroll $rdr
        if (-not $sv) { $target.BringIntoView(); return }
        $target.BringIntoView()      # laid out first, so it can be measured
        $sv.UpdateLayout()
        $top = $target.ContentStart.GetCharacterRect([System.Windows.Documents.LogicalDirection]::Forward).Top
        $sv.ScrollToVerticalOffset([Math]::Max(0, $sv.VerticalOffset + $top - 6))
        $sv.ScrollToHorizontalOffset(0)
    }.GetNewClosure()

    $toc.ItemsSource = @($chapters | ForEach-Object Title)
    $toc.Add_SelectionChanged({ if ($toc.SelectedItem) { & $nav.Go ([string]$toc.SelectedItem) '' } }.GetNewClosure())

    # Where to open: the clicked line, else the first line of the chapter
    # holding a searched word.
    $openAt = $Line
    if (-not $openAt -and $Title -and $Query) {
        $first = @(Get-SearchWords $Query)[0]
        $hit = @($paras | Where-Object { $_.Chapter -eq $Title -and $_.Text -and $_.Text -ne $Title -and $_.Text.ToLowerInvariant().Contains($first) })[0]
        if ($hit) { $openAt = $hit.Text }
    }
    if ($Title) {
        # The reader lays its pages out after the window shows, a little at a
        # time: the jump is repeated a few times, a quarter second apart, and
        # settles once the text is there (measured - the first try alone
        # opened at the top).
        $tries = @{ Left = 6 }
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds(250)
        $timer.Add_Tick({
            & $nav.Go $Title $openAt
            $tries.Left--
            if ($tries.Left -le 0) { $timer.Stop() }
        }.GetNewClosure())
        $rw.Add_ContentRendered({ $timer.Start() }.GetNewClosure())
        $rw.Add_Closed({ $timer.Stop() }.GetNewClosure())
    }
    $rw.Show()
}

$txtGuideSearch.Add_TextChanged({ Update-Guide })
$btnGuideReadme.Add_Click({ Show-Readme })
# One handler per list for every More... / chapter / line button in it.
$lstGuide.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler]{
    param($gs, $ge)
    $it = $ge.OriginalSource.DataContext
    if ($it -and $it.Chapter) { Show-Readme -Title $it.Chapter -Query $txtGuideSearch.Text }
})
$lstGuideReadme.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler]{
    param($gs, $ge)
    $it = $ge.OriginalSource.DataContext
    if (-not $it -or -not $it.Title) { return }
    # A line found (it has Line), or the chapter itself.
    if ($it.PSObject.Properties.Name -contains 'Line') { Show-Readme -Title $it.Title -Line $it.Line }
    else { Show-Readme -Title $it.Title -Query $txtGuideSearch.Text }
})
Update-Guide
