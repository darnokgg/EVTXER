<#
.SYNOPSIS
    EVTXER. WPF shell: theme, window, tabs and the shared log.

.DESCRIPTION
    The UI layer only. Every decision about WHAT the tool does still lives in
    HayabusaLib.ps1 and EvtxCollector.ps1; this file decides how it looks and
    routes clicks into those functions.

    WPF rather than WinForms for two reasons that are not cosmetic:
      * WinForms draws in device pixels. On a 150% display the whole window is
        bitmap-scaled by Windows and every glyph is soft. WPF composes in
        device-independent units, so text stays crisp at any scaling.
      * Rounded corners, drop shadows, gradients and hover transitions are
        declarative here. In WinForms each one is a hand-rolled OnPaint.

    PowerShell 5.1 ships with .NET Framework, so PresentationFramework is
    already on every Windows 10/11 box - nothing to install.
#>

# PowerShell decodes a native program's output with [Console]::OutputEncoding,
# which defaults to the OEM codepage (437). Takajo and Hayabusa write UTF-8, so
# without this their table borders arrive as "Γöé" instead of "│" and fill the log
# with mojibake. Lost once already in the WinForms-to-WPF rewrite, which is why
# a test now asserts it. No console at all (launched hidden) makes the setter
# throw; the GUI works without it.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
# Only for FolderBrowserDialog: WPF has no folder picker of its own in .NET
# Framework, and the Vista-style dialog needs a Shell COM interop dance that
# earns nothing here.
Add-Type -AssemblyName System.Windows.Forms

. "$PSScriptRoot\HayabusaLib.ps1"
. "$PSScriptRoot\EvtxCollector.ps1"

$script:ScriptPath = $MyInvocation.MyCommand.Path
if (-not $script:ScriptPath) { $script:ScriptPath = Join-Path (Get-Location) 'code\HayabusaMissionTool.ps1' }
# Two roots. AppRoot is code\ - the tool's own parts (scripts, hayabusa-x64,
# takajo, assets, index template, saved settings). Root is the folder above
# it - only what the operator opens (input, evtx, output, logs, dashboards).
$script:AppRoot = Split-Path -Parent $script:ScriptPath
$script:Root    = Split-Path -Parent $script:AppRoot
if (-not $script:Root) { $script:Root = (Get-Location).Path }

$script:ToolVersion = '76'
# The Settings tab can move the EVTX drop folder and the archive; both are
# saved in code\settings.conf, beside importer.conf.
$script:SettingsPath = Join-Path $script:AppRoot 'settings.conf'
$script:Settings = Read-ToolSettings $script:SettingsPath
$script:Folders = Get-FolderLayout $script:Root $script:Settings.EvtxFolder $script:Settings.ArchiveFolder
# Not the archive: it may be a share that is offline right now, and asking a
# dead server holds the window up for half a minute. Archiving creates it.
foreach ($dir in ($script:Folders.PSObject.Properties | Where-Object Name -ne 'Archive').Value) {
    try { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null } catch { }
}
$script:LogFile = Join-Path $script:Folders.Logs ("mission_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

# One operator at a time per install. Before any window:
# a second copy must not start collecting into the same folders.
$script:Instance = Enter-SingleInstance $script:AppRoot
if (-not $script:Instance.Ok) {
    [void][System.Windows.MessageBox]::Show(
        "EVTXER is already open by $($script:Instance.Holder).`n`nOne operator at a time per copy of the tool - ask them to close it, or use another copy.",
        'EVTXER')
    exit
}

# ============================================================== XAML =========
# Colours are the supplied palette: Dust Grey, Alabaster Grey, Sky Blue,
# Dim Grey, Charcoal. The surface is dark because a tool that spends its life
# beside a terminal should not be the brightest thing on the screen, and the
# palette's two greys then become the text rather than the background.
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="EVTXER" Height="960" Width="1420"
        MinHeight="560" MinWidth="960"
        WindowStartupLocation="CenterScreen"
        UseLayoutRounding="True" TextOptions.TextFormattingMode="Display"
        FontFamily="Segoe UI" FontSize="13" Background="#1E2126">
  <Window.Resources>
    <!-- palette -->
    <SolidColorBrush x:Key="Surface"     Color="#1E2126"/>
    <SolidColorBrush x:Key="Card"        Color="#262A31"/>
    <SolidColorBrush x:Key="CardEdge"    Color="#333941"/>
    <SolidColorBrush x:Key="Ink"         Color="#F2F2F2"/>
    <SolidColorBrush x:Key="Muted"       Color="#A8AEB8"/>
    <SolidColorBrush x:Key="Accent"      Color="#85C7F2"/>
    <SolidColorBrush x:Key="AccentDeep"  Color="#5AA7D8"/>
    <SolidColorBrush x:Key="AccentInk"   Color="#10222E"/>
    <SolidColorBrush x:Key="Caution"     Color="#F2A0A0"/>
    <SolidColorBrush x:Key="Warn"        Color="#E8C08A"/>
    <SolidColorBrush x:Key="FieldBack"   Color="#1A1D22"/>

    <!-- a card: the rounded, slightly raised panel every section sits on -->
    <Style x:Key="CardPanel" TargetType="Border">
      <Setter Property="Background" Value="{StaticResource Card}"/>
      <Setter Property="BorderBrush" Value="{StaticResource CardEdge}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="8"/>
      <Setter Property="Padding" Value="11"/>
      <Setter Property="Margin" Value="0,0,0,7"/>
      <Setter Property="Effect">
        <Setter.Value>
          <DropShadowEffect BlurRadius="12" ShadowDepth="2" Direction="270" Opacity="0.35" Color="#000000"/>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- The title row's status pills (Mission, ELK, SO, PCAP): grey until
         Update-ReadyPills / Update-PcapPill colour them. -->
    <Style x:Key="Pill" TargetType="Border">
      <Setter Property="Background" Value="#2A2F36"/>
      <Setter Property="BorderBrush" Value="#4A505A"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="12"/>
      <Setter Property="Padding" Value="10,3,14,3"/>
      <Setter Property="Margin" Value="0,2,8,2"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="PillDot" TargetType="Ellipse">
      <Setter Property="Width" Value="10"/>
      <Setter Property="Height" Value="10"/>
      <Setter Property="Fill" Value="#6B717B"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="PillText" TargetType="TextBlock">
      <Setter Property="Margin" Value="8,0,0,0"/>
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="MaxWidth" Value="240"/>
      <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
      <!-- The window's TextBlock style wraps; a pill never does. -->
      <Setter Property="TextWrapping" Value="NoWrap"/>
    </Style>

    <Style x:Key="SectionHead" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Margin" Value="0,0,0,7"/>
    </Style>

    <Style TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>

    <Style x:Key="Hint" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>

    <!-- inputs: no 3D frame, one hairline that lights up on focus -->
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{StaticResource FieldBack}"/>
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="CaretBrush" Value="{StaticResource Accent}"/>
      <Setter Property="BorderBrush" Value="{StaticResource CardEdge}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,6"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="b" CornerRadius="6" Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsKeyboardFocused" Value="True">
                <Setter TargetName="b" Property="BorderBrush" Value="{StaticResource Accent}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.5"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="PasswordBox">
      <Setter Property="Background" Value="{StaticResource FieldBack}"/>
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="CaretBrush" Value="{StaticResource Accent}"/>
      <Setter Property="BorderBrush" Value="{StaticResource CardEdge}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,6"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="PasswordBox">
            <Border x:Name="b" CornerRadius="6" Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsKeyboardFocused" Value="True">
                <Setter TargetName="b" Property="BorderBrush" Value="{StaticResource Accent}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- secondary button: quiet until hovered -->
    <Style TargetType="Button">
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="Background" Value="#2E343C"/>
      <Setter Property="BorderBrush" Value="{StaticResource CardEdge}"/>
      <Setter Property="Padding" Value="14,7"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" CornerRadius="6" Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="#3A424C"/>
                <Setter TargetName="b" Property="BorderBrush" Value="{StaticResource AccentDeep}"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="b" Property="Background" Value="#22272E"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.45"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- the one action per tab: sky blue, with the gloss coming from a soft
         vertical gradient rather than a 2003-style glass highlight -->
    <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Foreground" Value="{StaticResource AccentInk}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="20,9"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" CornerRadius="6" BorderThickness="1" BorderBrush="{StaticResource AccentDeep}">
              <Border.Background>
                <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
                  <GradientStop Color="#9CD3F6" Offset="0"/>
                  <GradientStop Color="#85C7F2" Offset="0.55"/>
                  <GradientStop Color="#6FB6E6" Offset="1"/>
                </LinearGradientBrush>
              </Border.Background>
              <Border.Effect>
                <DropShadowEffect BlurRadius="10" ShadowDepth="1" Direction="270" Opacity="0.4" Color="#000000"/>
              </Border.Effect>
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Opacity" Value="0.92"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="b" Property="Opacity" Value="0.8"/>
              </Trigger>
              <!-- Grey and flat, not 40% sky blue: a dimmed blue button read as
                   live, so the operator clicked it and thought the tool froze. -->
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="b" Property="Background" Value="#353A42"/>
                <Setter TargetName="b" Property="BorderBrush" Value="#454B54"/>
                <Setter TargetName="b" Property="Effect" Value="{x:Null}"/>
                <Setter Property="Foreground" Value="#7D838C"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Margin" Value="0,3"/>
    </Style>
    <!-- Retemplated: the stock radio on this dark surface drew an UNSELECTED
         option as a solid white disc and the selected one as a ring - every
         choice read inverted (usability walk, 2026-10-21). Now the Windows
         convention: an empty ring, and a filled accent dot for the choice. -->
    <Style TargetType="RadioButton">
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Margin" Value="0,4"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <StackPanel Orientation="Horizontal" Background="Transparent">
              <Grid Width="16" Height="16" VerticalAlignment="Center">
                <Ellipse x:Name="ring" Stroke="{StaticResource Muted}" StrokeThickness="1.5" Fill="Transparent"/>
                <Ellipse x:Name="dot" Width="8" Height="8" Fill="{StaticResource Accent}" Visibility="Collapsed"/>
              </Grid>
              <ContentPresenter Margin="8,0,0,0" VerticalAlignment="Center" RecognizesAccessKey="True"/>
            </StackPanel>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="ring" Property="Stroke" Value="{StaticResource Ink}"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="dot" Property="Visibility" Value="Visible"/>
                <Setter TargetName="ring" Property="Stroke" Value="{StaticResource Accent}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.5"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <!-- The stock ComboBox template is the light Aero one: on this surface it
         rendered as a white slab with unreadable text, so it is retemplated. -->
    <Style TargetType="ComboBox">
      <Setter Property="Padding" Value="8,4"/>
      <Setter Property="Background" Value="{StaticResource FieldBack}"/>
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="BorderBrush" Value="{StaticResource CardEdge}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBox">
            <Grid>
              <Border x:Name="b" CornerRadius="6" Background="{TemplateBinding Background}"
                      BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1"/>
              <ToggleButton Background="Transparent" BorderThickness="0" Focusable="False" ClickMode="Press"
                            IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}">
                <ToggleButton.Template>
                  <ControlTemplate TargetType="ToggleButton">
                    <Border Background="Transparent">
                      <Path HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,10,0"
                            Data="M 0 0 L 4 4 L 8 0 Z" Fill="{StaticResource Muted}"/>
                    </Border>
                  </ControlTemplate>
                </ToggleButton.Template>
              </ToggleButton>
              <ContentPresenter Margin="{TemplateBinding Padding}" VerticalAlignment="Center"
                                Content="{TemplateBinding SelectionBoxItem}" IsHitTestVisible="False"/>
              <Popup IsOpen="{TemplateBinding IsDropDownOpen}" Placement="Bottom" AllowsTransparency="True"
                     Focusable="False" PopupAnimation="Slide">
                <Border Background="#22262C" BorderBrush="{StaticResource CardEdge}" BorderThickness="1"
                        CornerRadius="6" MinWidth="{TemplateBinding ActualWidth}">
                  <StackPanel IsItemsHost="True"/>
                </Border>
              </Popup>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="BorderBrush" Value="{StaticResource AccentDeep}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="ComboBoxItem">
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="Padding" Value="10,6"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBoxItem">
            <Border x:Name="b" Background="Transparent" Padding="{TemplateBinding Padding}">
              <ContentPresenter/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="#333A44"/>
              </Trigger>
              <Trigger Property="IsHighlighted" Value="True">
                <Setter TargetName="b" Property="Background" Value="#333A44"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="ListBoxItem">
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="Padding" Value="6,3"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ListBoxItem">
            <Border x:Name="b" Background="Transparent" Padding="{TemplateBinding Padding}">
              <ContentPresenter/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="#2E343C"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="b" Property="Background" Value="#333A44"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Tab strip: browser-style tabs (plain labels did
         not read as tabs). Each tab is a box with rounded top corners; the
         others sit darker, the selected one takes the page colour with an
         accent line on top and covers the strip's base line, so it reads as
         joined to the page below. -->
    <Style TargetType="TabItem">
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Grid x:Name="g" Margin="0,3,3,0">
              <Border x:Name="b" Background="#181B1F" BorderBrush="{StaticResource CardEdge}"
                      BorderThickness="1,1,1,0" CornerRadius="7,7,0,0" Padding="16,7">
                <ContentPresenter ContentSource="Header" HorizontalAlignment="Center"/>
              </Border>
              <Border x:Name="accent" Height="2" VerticalAlignment="Top" Margin="1,1,1,0"
                      CornerRadius="6,6,0,0" Background="Transparent"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="#22262C"/>
                <Setter Property="Foreground" Value="{StaticResource Ink}"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="g" Property="Margin" Value="0,0,3,-1"/>
                <Setter TargetName="b" Property="Padding" Value="16,9,16,9"/>
                <Setter TargetName="b" Property="Background" Value="{StaticResource Surface}"/>
                <Setter TargetName="b" Property="BorderBrush" Value="#4A525E"/>
                <Setter TargetName="accent" Property="Background" Value="{StaticResource Accent}"/>
                <Setter Property="Foreground" Value="{StaticResource Ink}"/>
                <Setter Property="FontWeight" Value="SemiBold"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Scrollbars. The stock template is the light Aero one: a white trough
         with a grey thumb, which on this surface looks like a rendering fault
         rather than a control. Slim, dark, and it brightens on hover. -->
    <Style TargetType="ScrollBar">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Width" Value="10"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ScrollBar">
            <Grid Background="#1E2126">
              <Track x:Name="PART_Track" IsDirectionReversed="True">
                <Track.Thumb>
                  <Thumb>
                    <Thumb.Template>
                      <ControlTemplate TargetType="Thumb">
                        <Border x:Name="t" CornerRadius="5" Margin="2,0" Background="#3A424C"/>
                        <ControlTemplate.Triggers>
                          <Trigger Property="IsMouseOver" Value="True">
                            <Setter TargetName="t" Property="Background" Value="#5A6572"/>
                          </Trigger>
                        </ControlTemplate.Triggers>
                      </ControlTemplate>
                    </Thumb.Template>
                  </Thumb>
                </Track.Thumb>
                <!-- The page-up/page-down strips still have to exist, or a click
                     in the trough does nothing; they are just invisible. -->
                <Track.IncreaseRepeatButton>
                  <RepeatButton Command="ScrollBar.PageDownCommand" Opacity="0" Focusable="False"/>
                </Track.IncreaseRepeatButton>
                <Track.DecreaseRepeatButton>
                  <RepeatButton Command="ScrollBar.PageUpCommand" Opacity="0" Focusable="False"/>
                </Track.DecreaseRepeatButton>
              </Track>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="Orientation" Value="Horizontal">
                <Setter Property="Height" Value="10"/>
                <Setter Property="Width" Value="Auto"/>
                <Setter TargetName="PART_Track" Property="IsDirectionReversed" Value="False"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="ProgressBar">
      <Setter Property="Height" Value="6"/>
      <Setter Property="Background" Value="#2A2F36"/>
      <Setter Property="Foreground" Value="{StaticResource Accent}"/>
      <Setter Property="BorderThickness" Value="0"/>
    </Style>
  </Window.Resources>

  <Grid Margin="16,12,16,12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*" MinHeight="300"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition x:Name="rowQueue" Height="210"/>
    </Grid.RowDefinitions>

    <!-- title row -->
    <DockPanel Grid.Row="0" Margin="2,0,2,6">
      <StackPanel DockPanel.Dock="Left" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,24,0">
        <TextBlock Text="EVTXER" FontSize="15" FontWeight="SemiBold"
                   Foreground="{StaticResource Ink}"/>
        <TextBlock x:Name="lblVersion" Text="v7" Margin="10,0,0,0" VerticalAlignment="Center"
                   Foreground="{StaticResource Muted}" FontSize="12"/>
      </StackPanel>
      <!-- Is the mission ready, at a glance. Mission, ELK
           and SO are green when set up and grey when not; PCAP is red with a
           pulsing dot while dumpcap records - an empty space is easy to miss,
           so nothing hides. Each opens the tab that fixes it. Kept current by
           Update-ReadyPills and Update-PcapPill. The busy pill comes last, so
           it appearing moves nothing. -->
      <WrapPanel VerticalAlignment="Center">
        <Border x:Name="pnlPillMission" Style="{StaticResource Pill}">
          <StackPanel Orientation="Horizontal">
            <Ellipse x:Name="dotPillMission" Style="{StaticResource PillDot}"/>
            <TextBlock x:Name="lblPillMission" Style="{StaticResource PillText}" Text="No mission"/>
          </StackPanel>
        </Border>
        <Border x:Name="pnlPillElk" Style="{StaticResource Pill}">
          <StackPanel Orientation="Horizontal">
            <Ellipse x:Name="dotPillElk" Style="{StaticResource PillDot}"/>
            <TextBlock x:Name="lblPillElk" Style="{StaticResource PillText}" Text="ELK not verified"/>
          </StackPanel>
        </Border>
        <Border x:Name="pnlPillSo" Style="{StaticResource Pill}">
          <StackPanel Orientation="Horizontal">
            <Ellipse x:Name="dotPillSo" Style="{StaticResource PillDot}"/>
            <TextBlock x:Name="lblPillSo" Style="{StaticResource PillText}" Text="SO not set"/>
          </StackPanel>
        </Border>
        <Border x:Name="pnlPcap" Style="{StaticResource Pill}">
          <StackPanel Orientation="Horizontal">
            <Ellipse x:Name="dotPcap" Style="{StaticResource PillDot}"/>
            <TextBlock x:Name="lblPcap" Style="{StaticResource PillText}" Text="No PCAP"/>
          </StackPanel>
        </Border>
        <!-- Shown whenever anything runs (Set-AppBusy). The 4px bar beside
             the log was the only sign before, and nobody could tell working
             from frozen. A slot of fixed width, and Hidden rather than
             Collapsed: it coming and going wrapped the row in a narrow
             window and moved the whole window down (review, 2026-10-18). -->
        <Grid Width="380" Margin="0,2,0,2">
        <Border x:Name="pnlBusy" HorizontalAlignment="Left" VerticalAlignment="Center" Visibility="Hidden"
                Background="#23384A" BorderBrush="{StaticResource Accent}" BorderThickness="1"
                CornerRadius="12" Padding="10,3,14,3">
          <StackPanel Orientation="Horizontal">
            <Ellipse x:Name="spinner" Width="14" Height="14" StrokeThickness="2.5" Stroke="{StaticResource Accent}"
                     StrokeDashArray="9 5.4" RenderTransformOrigin="0.5,0.5" VerticalAlignment="Center">
              <Ellipse.RenderTransform><RotateTransform/></Ellipse.RenderTransform>
            </Ellipse>
            <TextBlock x:Name="lblBusy" Margin="8,0,0,0" Foreground="{StaticResource Ink}" FontWeight="SemiBold"
                       VerticalAlignment="Center" Text="Things are cookin'..." MaxWidth="320" TextTrimming="CharacterEllipsis" TextWrapping="NoWrap"/>
          </StackPanel>
        </Border>
        </Grid>
      </WrapPanel>
    </DockPanel>

    <!-- Tabs on the left, the log on the right at full height. Under the tabs
         the log fought them for vertical space, and the summary tables
         Hayabusa and Takajo print need height more than width. -->
    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*" MinWidth="560"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition x:Name="colLog" Width="460" MinWidth="280"/>
      </Grid.ColumnDefinitions>

      <TabControl x:Name="tabs" Grid.Column="0" Background="Transparent" BorderThickness="0,1,0,0"
                  BorderBrush="#4A525E" Padding="0,6,0,0">
        <!-- Short names fit one row (owner, 2026-10-26: two rows swapped places
             when a tab in the other row was clicked); the full name is the tooltip. -->
        <TabItem Header="Collect" ToolTip="Collect EVTX from remote hosts"><ScrollViewer x:Name="tabCollect" VerticalScrollBarVisibility="Auto"/></TabItem>
        <TabItem Header="Convert" ToolTip="Convert: a Hayabusa scan, then ECS"><ScrollViewer x:Name="tabConvert" VerticalScrollBarVisibility="Auto"/></TabItem>
        <TabItem Header="Upload" ToolTip="Upload to ELK (Elasticsearch)"><ScrollViewer x:Name="tabUpload" VerticalScrollBarVisibility="Auto"/></TabItem>
        <TabItem Header="Takajo" ToolTip="Takajo analysis and reports"><ScrollViewer x:Name="tabTakajo" VerticalScrollBarVisibility="Auto"/></TabItem>
        <TabItem Header="Dashboards" ToolTip="Kibana dashboards"><ScrollViewer x:Name="tabKibana" VerticalScrollBarVisibility="Auto"/></TabItem>
        <TabItem Header="Raw Events" ToolTip="Raw events to Security Onion"><ScrollViewer x:Name="tabSoImport" VerticalScrollBarVisibility="Auto"/></TabItem>
        <TabItem Header="Settings" ToolTip="This mission, then setup"><ScrollViewer x:Name="tabSettings" VerticalScrollBarVisibility="Auto"/></TabItem>
        <TabItem Header="Guide" ToolTip="Cheat sheet, and a search over the README"><ScrollViewer x:Name="tabGuide" VerticalScrollBarVisibility="Auto"/></TabItem>
      </TabControl>

      <!-- The divider. A visible grip, because a transparent splitter is one
           nobody finds; it lights up under the mouse. -->
      <GridSplitter Grid.Column="1" Width="12" HorizontalAlignment="Center" VerticalAlignment="Stretch"
                    ResizeDirection="Columns" ResizeBehavior="PreviousAndNext" Cursor="SizeWE"
                    Focusable="False" Margin="2,40,2,0">
        <GridSplitter.Template>
          <ControlTemplate TargetType="GridSplitter">
            <Grid Background="Transparent">
              <Border Width="1" Background="{StaticResource CardEdge}" HorizontalAlignment="Center"/>
              <Border x:Name="grip" Width="6" Height="64" CornerRadius="3" Background="#3A424C"
                      HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="grip" Property="Background" Value="{StaticResource AccentDeep}"/>
              </Trigger>
              <Trigger Property="IsDragging" Value="True">
                <Setter TargetName="grip" Property="Background" Value="{StaticResource Accent}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </GridSplitter.Template>
      </GridSplitter>

      <Grid Grid.Column="2">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- what is running, for how long, and a way to stop it -->
        <Grid Grid.Row="0" Margin="2,8,2,6" MinHeight="30">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock x:Name="lblStatus" Text="Ready" Style="{StaticResource Hint}" VerticalAlignment="Center"/>
          <Button x:Name="btnCancel" Grid.Column="1" Content="CANCEL" Visibility="Collapsed"
                  Margin="8,0,0,0" Padding="14,5" Foreground="{StaticResource Caution}"/>
        </Grid>
        <StackPanel Grid.Row="1" Margin="2,0,2,8">
          <ProgressBar x:Name="bar" HorizontalAlignment="Stretch"/>
          <CheckBox x:Name="chkConsole" Margin="0,10,0,0"
                    Content="Run Hayabusa and Takajo in their own console window"
                    ToolTip="Shows their own progress bar and ETA. The log here then only records start, finish and exit code."/>
          <StackPanel Orientation="Horizontal" Margin="0,8,0,0">
            <Button x:Name="btnLedger" Content="Open activity log" Padding="12,4"
                    ToolTip="Every port test, access check, collection, conversion, upload and archive, across all sessions (logs\activity_log.csv). Opens a copy, so Excel never locks the real one."/>
            <Button x:Name="btnLedgerExport" Content="Export..." Padding="12,4" Margin="8,0,0,0"
                    ToolTip="Save a copy of the whole activity log to hand over: .csv for Excel, or .txt to read. The live log keeps growing in logs\."/>
            <Button x:Name="btnNetworkLog" Content="Network log..." Padding="12,4" Margin="8,0,0,0"
                    ToolTip="Save the network log (.csv for Excel): one row per action that went over the network - date/time, target IP, command run, success, what was pulled or sent, duration, notes."/>
            <Button x:Name="btnLogsFolder" Content="Logs folder" Padding="12,4" Margin="8,0,0,0"
                    ToolTip="Open logs\ in Explorer - for troubleshooting: this session's log (mission_*.log), every Hayabusa/Takajo run log (run_*.txt), the queue's job logs (queue\) and the activity log."/>
          </StackPanel>
        </StackPanel>

        <!-- The log. Lines wrap at the pane's width (operator's call,
             2026-10-12); the box-drawn summary tables keep their shape in the
             run log instead. -->
        <Border Grid.Row="2" Style="{StaticResource CardPanel}" Padding="0" Margin="0">
          <Grid>
            <RichTextBox x:Name="log" Background="Transparent" BorderThickness="0"
                         Foreground="{StaticResource Ink}" FontFamily="Consolas" FontSize="12.5"
                         IsReadOnly="True" VerticalScrollBarVisibility="Auto"
                         HorizontalScrollBarVisibility="Disabled" Padding="10,8">
              <RichTextBox.Resources>
                <!-- The square where the two scrollbars meet is painted with
                     this system brush: white, on a dark pane, by default. -->
                <SolidColorBrush x:Key="{x:Static SystemColors.ControlBrushKey}" Color="#1E2126"/>
              </RichTextBox.Resources>
            </RichTextBox>
          </Grid>
        </Border>
      </Grid>
    </Grid>

    <!-- The job queue, under both the tabs and the log, so it is in sight
         whatever tab is open. Built by wpf-queue.ps1.
         The divider above it drags it taller or shorter. -->
    <GridSplitter x:Name="splitQueue" Grid.Row="2" Height="12" HorizontalAlignment="Stretch" VerticalAlignment="Center"
                  ResizeDirection="Rows" ResizeBehavior="PreviousAndNext" Cursor="SizeNS" Focusable="False">
      <GridSplitter.Template>
        <ControlTemplate TargetType="GridSplitter">
          <Grid Background="Transparent">
            <Border Height="1" Background="{StaticResource CardEdge}" VerticalAlignment="Center"/>
            <Border x:Name="grip" Height="6" Width="64" CornerRadius="3" Background="#3A424C"
                    HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Grid>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True">
              <Setter TargetName="grip" Property="Background" Value="{StaticResource AccentDeep}"/>
            </Trigger>
            <Trigger Property="IsDragging" Value="True">
              <Setter TargetName="grip" Property="Background" Value="{StaticResource Accent}"/>
            </Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </GridSplitter.Template>
    </GridSplitter>
    <ContentControl x:Name="queueHost" Grid.Row="3"/>
  </Grid>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$win    = [Windows.Markup.XamlReader]::Load($reader)

# Every x:Name becomes a variable of the same name, so handler code reads the
# same as it did against WinForms controls.
foreach ($name in @('tabs','tabCollect','tabConvert','tabUpload','tabTakajo','tabKibana','tabSoImport','tabSettings','tabGuide',
                    'log','bar','lblStatus','lblVersion',
                    'colLog','btnCancel','chkConsole',
                    'pnlBusy','spinner','lblBusy','pnlPcap','dotPcap','lblPcap','pnlPillMission','dotPillMission','lblPillMission',
                    'pnlPillElk','dotPillElk','lblPillElk','pnlPillSo','dotPillSo','lblPillSo','btnLedger','btnLedgerExport','btnNetworkLog','btnLogsFolder',
                    'rowQueue','splitQueue','queueHost')) {
    Set-Variable -Name $name -Scope Script -Value $win.FindName($name)
}

# Each tab's XAML is parsed on its own, detached from the window, so a
# StaticResource in it can only be resolved through the Application's
# resources - a fragment cannot see the Window it is about to be put inside.
# Seeding them here is what lets every tab use CardPanel/Primary/Hint.
if (-not [System.Windows.Application]::Current) { $null = New-Object System.Windows.Application }
[System.Windows.Application]::Current.Resources.MergedDictionaries.Add($win.Resources)
# The main window was built BEFORE this Application existed, so the
# Application does not count it as one of its windows. With the default
# OnLastWindowClose, closing the first popup (Show command) looked like the
# last window closing, and every later ShowDialog returned at once without
# showing anything. Measured 2026-10-12. The tool ends when ShowDialog below
# returns, so nothing here needs the Application to shut itself down.
[System.Windows.Application]::Current.ShutdownMode = 'OnExplicitShutdown'

$win.Title = "EVTXER v$script:ToolVersion"
$lblVersion.Text = "v$script:ToolVersion"

$iconFile = Join-Path $script:AppRoot 'assets\app.ico'
if (Test-Path -LiteralPath $iconFile) {
    # Read once and let go (OnLoad): a BitmapImage on a file path keeps the
    # file locked, and a release replacing the assets folder fails.
    try {
        $ico = New-Object System.Windows.Media.Imaging.BitmapImage
        $ico.BeginInit()
        $ico.UriSource = New-Object System.Uri($iconFile)
        $ico.CacheOption = 'OnLoad'
        $ico.EndInit()
        $win.Icon = $ico
    } catch { }
}

# ---------------------------------------------------------------- plumbing ---
# WinForms had Application.DoEvents. The WPF equivalent is a nested dispatcher
# frame: queue a marker at Background priority and pump until it runs, which
# lets layout, input and rendering catch up mid-handler. Every long operation
# still runs on the UI thread, exactly as before - this keeps the window alive
# while it does.
function Invoke-UiPump {
    $frame = New-Object System.Windows.Threading.DispatcherFrame
    # DispatcherOperationCallback, not [action]: the callback has to TAKE the
    # frame as its argument and return a value, and PowerShell cannot bind a
    # parameterised scriptblock to a no-arg delegate.
    $stop = [System.Windows.Threading.DispatcherOperationCallback]{ param($f) $f.Continue = $false; $null }
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.BeginInvoke(
        [System.Windows.Threading.DispatcherPriority]::Background, $stop, $frame) | Out-Null
    [System.Windows.Threading.Dispatcher]::PushFrame($frame)
}

$script:LogColours = @{
    plain = '#F2F2F2'
    ok    = '#7EC87E'
    err   = '#F2A0A0'
    warn  = '#E8C08A'
    info  = '#85C7F2'
}

function Write-Log([string]$Text, [string]$Kind = 'plain',
                   # From the job queue's timer: no pump (a click run inside the
                   # tick would start a job nested in it, and the queue would
                   # stall behind that job), and not into a foreground job's run
                   # log, which is that job's alone.
                   [switch]$Background) {
    $hex = if ($script:LogColours.ContainsKey($Kind)) { $script:LogColours[$Kind] } else { $script:LogColours.plain }
    # Counted for the status line: an action whose log shows errors must not
    # end on a plain "Finished" (usability walk, 2026-10-21).
    if ($Kind -eq 'err' -and $script:Busy -and -not $Background) { $script:ActionErrors++ }
    $run = New-Object System.Windows.Documents.Run $Text
    $run.Foreground = (New-Object System.Windows.Media.BrushConverter).ConvertFromString($hex)
    # One Paragraph for the whole log: a Paragraph per line would put WPF's
    # default paragraph spacing between every line of a log.
    # $script: explicitly. PowerShell resolves variables through the CALLER
    # chain and is case-insensitive, so a caller with any variable named $log
    # would be found before this one - which is exactly how every collection
    # once died on its first log line.
    if (-not $script:LogParagraph) {
        $script:LogParagraph = New-Object System.Windows.Documents.Paragraph
        $script:LogParagraph.Margin = New-Object System.Windows.Thickness 0
        $script:log.Document.Blocks.Clear()
        $script:log.Document.Blocks.Add($script:LogParagraph)
    }
    $script:LogParagraph.Inlines.Add($run)
    $script:log.ScrollToEnd()

    try {
        if (-not (Test-Path -LiteralPath $script:LogFile)) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $script:LogFile) -Force | Out-Null
            [IO.File]::AppendAllText($script:LogFile, "EVTXER v$script:ToolVersion - started $(Get-Date -Format s) on $env:COMPUTERNAME`r`n")
        }
        [IO.File]::AppendAllText($script:LogFile, ($Text -replace "(?<!`r)`n", "`r`n"))
        # And into this job's own run log, while one is running.
        if ($script:RunLog -and -not $Background) { [IO.File]::AppendAllText($script:RunLog, ($Text -replace "(?<!`r)`n", "`r`n")) }
    } catch { }
    if (-not $Background) { Invoke-UiPump }
}

if (-not (Test-Path -LiteralPath (Join-Path $script:AppRoot 'index-template.json'))) {
    Write-Log "code\index-template.json is missing - the Upload tab cannot create an index until it is restored.`n" 'warn'
}

# ---------------------------------------------------------------- long jobs ---
# Hayabusa, Takajo and the collection used to run inline, and Hayabusa prints
# nothing between "Scanning in progress" and its summary when piped - so the
# window froze for the whole scan and nobody could tell working from hung. A
# job now runs in the background while this thread loops: draining output into
# the log, ticking elapsed and CPU time on the status line, pumping the window.
$script:CancelRequested = $false
$script:RunLog   = $null
$script:JobClock = $null
$script:ActivePump    = $null
$script:ActiveConsole = $null

function Start-UiJob([string]$Name) {
    $script:CancelRequested = $false
    $script:JobClock = [Diagnostics.Stopwatch]::StartNew()
    try {
        $script:RunLog = Get-RunLogPath $script:Folders.Logs $Name (Get-Date)
        [IO.File]::WriteAllText($script:RunLog,
            "EVTXER v$script:ToolVersion - $Name - started $(Get-Date -Format s) on $env:COMPUTERNAME`r`n")
    } catch { $script:RunLog = $null }
    $btnCancel.IsEnabled = $true; $btnCancel.Visibility = 'Visible'
    $bar.IsIndeterminate = $true
    $lblStatus.Text = $Name
}

function Stop-UiJob {
    $btnCancel.Visibility = 'Collapsed'
    $bar.IsIndeterminate = $false
    $took = if ($script:JobClock) { Format-JobDuration $script:JobClock.Elapsed } else { '' }
    $script:JobClock = $null
    $runLog = $script:RunLog
    if ($runLog) { Write-Log "Run log: $runLog`n" 'info' }
    $script:RunLog = $null
    $lblStatus.Text = if ($script:CancelRequested) { "Cancelled after $took" }
                      elseif ($script:ActionErrors) { "Finished with errors after $took - see the log" }
                      else { "Finished in $took" }
    if ($script:ActionErrors -and -not $script:CancelRequested) { $lblStatus.Foreground = $win.FindResource('Caution') }
    # Settings > Pop-up windows, remembered in code\settings.conf (it was a
    # log-pane checkbox that came back ticked on every start).
    if ($runLog -and $script:Settings.OpenRunLog -ne 'off' -and (Test-Path -LiteralPath $runLog)) {
        try { Start-Process notepad.exe -ArgumentList ('"{0}"' -f $runLog) } catch { }
    }
}

# ---------------------------------------------------------------- busy ---
# One switch for "something is running", used by every action that takes more
# than a blink. Each tab used to grey only its own buttons, so the blue buttons
# on the other tabs stayed lit, ignored clicks in silence, and the tool looked
# frozen. Now every tab's content is disabled (inputs too - a radio flipped
# mid-scan used to change what the scan did), the cursor shows the app is
# working, and a spinner sits in the title row where the eye lands.
#
# The spinner and the bar are animated by this same UI thread, so they stall
# during any stretch that does not pump. The long stretches pump; if the
# spinner ever stops, that is the place to add an Invoke-UiPump.
function Set-AppBusy([bool]$On, [string]$What = '') {
    $script:Busy = $On
    foreach ($t in @($tabCollect, $tabConvert, $tabUpload, $tabTakajo, $tabKibana, $tabSoImport, $tabSettings)) {
        if ($t -and $t.Content) { $t.Content.IsEnabled = -not $On }
    }
    $rotate = $spinner.RenderTransform
    if ($On) {
        # The status line belongs to THIS action from here on: a failed check
        # used to leave the previous job's "Finished in ..." standing.
        $script:ActionErrors = 0
        $script:ActionWhat = "$What..."
        $lblStatus.ClearValue([System.Windows.Controls.TextBlock]::ForegroundProperty)
        $lblStatus.Text = $script:ActionWhat
        $lblBusy.Text = if ($What) { "Things are cookin' - $What" } else { "Things are cookin'..." }
        $pnlBusy.Visibility = 'Visible'
        $spin = New-Object System.Windows.Media.Animation.DoubleAnimation(0, 360,
                    (New-Object System.Windows.Duration ([timespan]::FromSeconds(1.1))))
        $spin.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
        $rotate.BeginAnimation([System.Windows.Media.RotateTransform]::AngleProperty, $spin)
        [System.Windows.Input.Mouse]::OverrideCursor = [System.Windows.Input.Cursors]::AppStarting
        $win.Title = "EVTXER v$script:ToolVersion - working: $What"
    } else {
        $rotate.BeginAnimation([System.Windows.Media.RotateTransform]::AngleProperty, $null)
        $pnlBusy.Visibility = 'Hidden'
        [System.Windows.Input.Mouse]::OverrideCursor = $null
        # The version stays in the title: README tells operators to quote it.
        $win.Title = "EVTXER v$script:ToolVersion"
        # An action that ran no long job (a check, a fetch) still says how it
        # ended; one that did has already said it in Stop-UiJob.
        if ($script:ActionWhat -and $lblStatus.Text -eq $script:ActionWhat) {
            $w0 = $script:ActionWhat.TrimEnd('.')
            if ($script:ActionErrors) { $lblStatus.Text = "Failed: $w0 - see the log"; $lblStatus.Foreground = $win.FindResource('Caution') }
            else { $lblStatus.Text = "Done: $w0" }
        }
        $script:ActionWhat = $null
        # A bar left full after the last job made the next one's quiet first
        # phase look finished.
        if (-not $bar.IsIndeterminate) { $bar.Value = 0 }
        # No pump here: the tabs are live again, and pumping inside the
        # caller's finally would let a queued click start a second job
        # nested in the first. The window repaints when the handler returns.
        return
    }
    Invoke-UiPump
}

# --------------------------------------------------------- status pills ---
# The title row: Mission, ELK, SO, PCAP. A timer calls
# both updates every few seconds; like the queue's tick they never pump and
# log only with -Background, once.
$script:PillBrush = @{}
foreach ($pair in @{ dotrec = '#FF5A52'; bgrec = '#3A2326'; edgerec = '#E5534B'
                     dotok = '#7EC87E'; bgok = '#1F3324'; edgeok = '#4E8F57'
                     dotoff = '#6B717B'; bgoff = '#2A2F36'; edgeoff = '#4A505A' }.GetEnumerator()) {
    $script:PillBrush[$pair.Key] = (New-Object System.Windows.Media.BrushConverter).ConvertFromString($pair.Value)
}
function Set-PillLook($Panel, $Dot, $Label, [ValidateSet('rec', 'ok', 'off')][string]$Look, [string]$Text, [string]$Tip) {
    $Label.Text = $Text
    $Panel.ToolTip = $Tip
    $Dot.Fill = $script:PillBrush["dot$Look"]
    $Panel.Background = $script:PillBrush["bg$Look"]
    $Panel.BorderBrush = $script:PillBrush["edge$Look"]
    $Label.Foreground = $(if ($Look -eq 'off') { $win.Resources['Muted'] } else { $win.Resources['Ink'] })
}

# PCAP: read from the machine (Get-PcapPill over Get-RunningCaptures), so a
# capture that died, or one Wireshark started, shows as it is. Get-Process is
# cheap, the command-line read behind Get-RunningCaptures is not, so that
# read happens only when the set of dumpcap processes changed.
$script:PcapPillPids = $null
function Update-PcapPill {
    try {
        $pids = @(Get-Process -Name dumpcap -ErrorAction SilentlyContinue | ForEach-Object { $_.Id } | Sort-Object) -join ','
        if ($pids -eq $script:PcapPillPids) { return }
        # Remembered first: a read that fails is retried when the processes
        # change, not redone on the UI thread every tick.
        $script:PcapPillPids = $pids
        $p = Get-PcapPill @(if ($pids) { Get-RunningCaptures })
        Set-PillLook $pnlPcap $dotPcap $lblPcap $(if ($p.On) { 'rec' } else { 'off' }) $p.Text $p.Tip
        if ($p.On) {
            $pulse = New-Object System.Windows.Media.Animation.DoubleAnimation(1.0, 0.25,
                         (New-Object System.Windows.Duration ([timespan]::FromSeconds(0.9))))
            $pulse.AutoReverse = $true
            $pulse.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
            $dotPcap.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $pulse)
        } else {
            $dotPcap.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $null)
        }
    } catch {
        # Once, not every tick; the next change of dumpcap processes tries again.
        if (-not $script:PcapPillFailed) { Write-Log -Background "PCAP pill: $($_.Exception.Message)`n" 'warn' }
        $script:PcapPillFailed = $true
    }
}

# Mission, ELK, SO: the same facts the queue waits on (Get-QueueBlockers),
# read from the tabs - cheap, so every tick.
function Update-ReadyPills {
    try {
        # Each tab's fact on its own: a tab that failed to load (already in
        # the log) greys only its own pill, the others still agree with the queue.
        $elkOk = $false; $soReady = $false
        try { $elkOk = [bool]($script:ConnOk -and $script:ConnKey -eq (Get-UploadConnKey)) } catch { }
        try { $soReady = [bool](Test-SoReady) } catch { }
        $pills = Get-ReadinessPills -MissionName $script:Settings.MissionName `
                     -MissionIndex (Get-MissionIndexName $script:Settings.MissionName) `
                     -ElkOk $elkOk -ElkHost "$($txtHost.Text)".Trim() -SoReady $soReady -SoHost "$($txtSoHost.Text)".Trim()
        foreach ($p in $pills) {
            Set-PillLook (Get-Variable "pnlPill$($p.Key)" -ValueOnly) (Get-Variable "dotPill$($p.Key)" -ValueOnly) `
                         (Get-Variable "lblPill$($p.Key)" -ValueOnly) $(if ($p.On) { 'ok' } else { 'off' }) $p.Text "$($p.Tip) Click to open that tab."
        }
    } catch {
        if (-not $script:ReadyPillsFailed) { Write-Log -Background "Status pills: $($_.Exception.Message)`n" 'warn' }
        $script:ReadyPillsFailed = $true
    }
}

# A click opens the tab that fixes it. $tabSettings and the others are the
# ScrollViewer inside each TabItem; WPF ignores a SelectedItem that is not
# one of its items, hence .Parent.
$pnlPcap.Add_MouseLeftButtonUp({ $tabs.SelectedItem = $tabSettings.Parent })
$pnlPillMission.Add_MouseLeftButtonUp({ $tabs.SelectedItem = $tabSettings.Parent })
$pnlPillElk.Add_MouseLeftButtonUp({ $tabs.SelectedItem = $tabUpload.Parent })
$pnlPillSo.Add_MouseLeftButtonUp({ $tabs.SelectedItem = $tabSoImport.Parent })

# ------------------------------------------------------- activity ledger ---
# See Add-LedgerRows. logs\, beside the mission logs, outside code\ so a
# re-copy of the tool never touches it.
$script:LedgerPath = Join-Path $script:Folders.Logs 'activity_log.csv'
function Write-Ledger([object[]]$Rows) {
    if (-not @($Rows).Count) { return }
    try {
        $w = Add-LedgerRows $Rows $script:LedgerPath
        if ($w.Pending) {
            Write-Log "The activity log is open in another program (Excel?). $(@($Rows).Count) row(s) kept in $(Split-Path -Leaf $w.Path); they are added to it on the next write once it is closed.`n" 'warn'
        }
    } catch {
        Write-Log "Could not write the activity log: $($_.Exception.Message)`n" 'warn'
    }
}

$btnLedger.Add_Click({
    if (-not (Test-Path -LiteralPath $script:LedgerPath)) {
        Write-Log "No activity recorded yet - $script:LedgerPath is created by the first port test, check, collection or upload.`n" 'info'
        return
    }
    # A copy: Excel locks whatever it opens, and a locked ledger would push
    # the next rows into the pending file.
    try {
        $view = Join-Path ([IO.Path]::GetTempPath()) ("activity_log_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Copy-Item -LiteralPath $script:LedgerPath -Destination $view -Force -ErrorAction Stop
        Start-Process $view
        Write-Log "Opened a copy of the activity log. The live file is $script:LedgerPath`n" 'info'
    } catch {
        Write-Log "Could not open the activity log: $($_.Exception.Message)`n" 'err'
    }
})

$btnLedgerExport.Add_Click({
    # The live file never moves - it is append-only and every session adds to
    # it. This saves a copy wherever the operator says (a USB stick, a share).
    $d = New-Object Microsoft.Win32.SaveFileDialog
    $d.Title = 'Export the activity log'
    $d.Filter = 'Excel / CSV (*.csv)|*.csv|Readable text (*.txt)|*.txt'
    $d.FileName = "activity_log_{0}_{1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss')
    $d.AddExtension = $true
    if ($d.ShowDialog($win) -ne $true) { return }
    try {
        $n = Export-ActivityLog $script:LedgerPath $d.FileName
        Write-Log "Activity log exported: $n action(s) to $($d.FileName)`n" 'ok'
    } catch {
        Write-Log "Could not export the activity log: $($_.Exception.Message)`n" 'err'
    }
})

$btnNetworkLog.Add_Click({
    # The activity log re-shaped into the network-log columns - see Export-NetworkLog.
    $d = New-Object Microsoft.Win32.SaveFileDialog
    $d.Title = 'Save the network log'
    $d.Filter = 'Excel / CSV (*.csv)|*.csv'
    $d.FileName = "network_log_{0}_{1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss')
    $d.AddExtension = $true
    if ($d.ShowDialog($win) -ne $true) { return }
    try {
        $n = Export-NetworkLog $script:LedgerPath $d.FileName
        Write-Log "Network log saved: $n network action(s) to $($d.FileName)`n" 'ok'
    } catch {
        Write-Log "Could not save the network log: $($_.Exception.Message)`n" 'err'
    }
})

# Chosen over a Logs tab: the logs are for
# troubleshooting, and Explorer already lists, sorts and opens them.
$btnLogsFolder.Add_Click({
    New-Item -ItemType Directory -Path $script:Folders.Logs -Force | Out-Null
    Start-Process explorer.exe -ArgumentList "`"$($script:Folders.Logs)`""
})

function Set-UiJobProgress([string]$Label, [string]$Detail, $Cpu, [double]$Fraction = -1) {
    $elapsed = if ($script:JobClock) { $script:JobClock.Elapsed } else { [timespan]::Zero }
    $lblStatus.Text = Get-JobStatusText -Label $Label -Elapsed $elapsed -Cpu $Cpu -Detail $Detail
    if ($Fraction -ge 0) {
        $bar.IsIndeterminate = $false
        $bar.Maximum = 1000
        $bar.Value = [Math]::Min(1000, [Math]::Max(0, $Fraction * 1000))
    } else {
        $bar.IsIndeterminate = $true
    }
}

function Invoke-ExternalTool {
    # Runs Hayabusa or Takajo and returns its exit code; -1 when cancelled or
    # when the console window was closed before it finished. The working
    # directory is the caller's to choose: Takajo resolves conf/ and
    # templates/ against it.
    param([string]$Label, [string]$Exe, [string[]]$Arguments, [string]$WorkDir, [string]$Detail,
          # Written to the program's stdin (sudo's password for the Raw Events
          # tab). Forces the in-window pump: a console window could not be fed.
          [string]$StandardInput,
          # Every output line is also added here, for a caller that parses it.
          [System.Collections.Generic.List[string]]$Capture,
          # Text that must never reach the log (the password) is masked.
          [string[]]$Mask,
          # Cancel waits for this one instead of killing it - for a step that
          # must not stop half way (so-import-evtx marks each file imported as
          # it goes, so a half-imported file would never be sent again).
          [switch]$NoCancel)

    # A console window can neither be fed stdin nor have its output captured,
    # so a caller that needs either always gets the in-window pump.
    if ($chkConsole.IsChecked -eq $true -and -not $StandardInput -and $null -eq $Capture) {
        # A real console: the program draws its own progress bar and ETA,
        # which it hides whenever its output is captured.
        $rcFile = Join-Path ([IO.Path]::GetTempPath()) ("evtxer-rc-{0}.txt" -f [guid]::NewGuid().ToString('N'))
        $wrapper = New-ConsoleRunScript -Exe $Exe -Arguments $Arguments -ExitCodeFile $rcFile -Title "$Label - EVTXER"
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapper))
        $script:ActiveConsole = Start-Process powershell.exe -WorkingDirectory $WorkDir -PassThru `
            -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc)
        Write-Log "Running in its own console window. Its progress and summary are shown there.`n" 'info'
        $cancelled = $false
        try {
            while ($null -eq (Read-ExitCodeFile $rcFile) -and -not $script:ActiveConsole.HasExited) {
                if ($script:CancelRequested -and -not $cancelled) {
                    $cancelled = $true
                    & taskkill.exe /T /F /PID $script:ActiveConsole.Id 2>&1 | Out-Null
                }
                Set-UiJobProgress $Label "running in the console window" $null
                Invoke-UiPump
                Start-Sleep -Milliseconds 100
            }
        } finally { $script:ActiveConsole = $null }
        if ($cancelled) { Write-Log "$Label cancelled.`n" 'warn'; return -1 }
        $code = Read-ExitCodeFile $rcFile
        if ($null -eq $code) {
            Write-Log "The console window was closed before $Label finished.`n" 'err'; return -1
        }
        Remove-Item -LiteralPath $rcFile -Force -ErrorAction SilentlyContinue
        Write-Log "$Label finished in its console window, exit code $code.`n" $(if ($code -eq 0) { 'ok' } else { 'err' })
        return $code
    }

    Initialize-ProcessPump
    $pump = New-Object EvtxerProcessPump($Exe, (ConvertTo-ProcessArgumentLine $Arguments), $WorkDir, $StandardInput)
    $script:ActivePump = $pump
    $cancelled = $false
    try {
        while ($true) {
            # Read IsDone BEFORE draining: the last lines can land after the
            # process has exited, and this way they are always drained.
            $done = $pump.IsDone
            foreach ($line in $pump.Drain()) {
                $clean = $line -replace '\x1b?\[[0-9;]*m', ''
                foreach ($m in @($Mask | Where-Object { $_ })) { $clean = $clean.Replace($m, '********') }
                if ($null -ne $Capture) { $Capture.Add($clean) }
                if ($clean.Trim()) { Write-Log "$clean`n" }
            }
            if ($done) { break }
            if ($script:CancelRequested -and -not $cancelled) {
                $cancelled = $true
                if ($NoCancel) { Write-Log "$Label cannot be stopped half way - waiting for it to finish.`n" 'warn' }
                else {
                    Write-Log "Stopping $Label...`n" 'warn'
                    $pump.Kill()
                }
            }
            Set-UiJobProgress $Label $Detail $pump.CpuTime
            Invoke-UiPump
            Start-Sleep -Milliseconds 80
        }
        if ($cancelled -and -not $NoCancel) { Write-Log "$Label cancelled.`n" 'warn'; return -1 }
        return $pump.ExitCode
    } finally {
        $script:ActivePump = $null
        $pump.Dispose()
    }
}

# ------------------------------------------------------------ host links ---
# After an upload or a raw import, each machine's two
# links - its Hayabusa detections in Kibana, its raw events in Security Onion -
# shown here, in the tool, over everything ever collected from it. The URLs
# are built in HayabusaLib.ps1 (New-HostDetectionsUrl, New-HostRawUrl); this
# only draws them. The Kibana side needs the detections data view's id, which
# the Upload tab finds and remembers in importer.conf; the Security Onion side
# needs the manager from the Raw Events tab.
$script:DetectionsDataViewId = ''

function Show-HostLinks($Panel, [string[]]$Names) {
    $Panel.Children.Clear()
    $kHost  = if ($txtHost)   { $txtHost.Text.Trim() }   else { '' }
    $soHost = if ($txtSoHost) { $txtSoHost.Text.Trim() } else { '' }
    $rows = @(foreach ($s in @(Get-HostLinkSet $Names)) {
        [pscustomobject]@{
            Key        = $s.Key
            Detections = $(if ($kHost -and $script:DetectionsDataViewId) { New-HostDetectionsUrl -KibanaHost $kHost -DataViewId $script:DetectionsDataViewId -Names $s.Names } else { '' })
            Raw        = $(if ($soHost) { New-HostRawUrl -SoHost $soHost -Names $s.Names } else { '' })
        }
    })
    if (-not $rows.Count) { $Panel.Visibility = 'Collapsed'; return }
    $muted = (New-Object System.Windows.Media.BrushConverter).ConvertFromString('#A8AEB8')
    $accent = (New-Object System.Windows.Media.BrushConverter).ConvertFromString('#85C7F2')
    $head = New-Object System.Windows.Controls.TextBlock
    $head.Text = "Each host, everything ever collected from it ($($rows.Count) host(s)):"
    $head.Foreground = $muted; $head.Margin = '0,0,0,4'
    [void]$Panel.Children.Add($head)
    Write-Log "Host links - everything ever collected from each host:`n" 'info'
    foreach ($r in $rows) {
        $line = New-Object System.Windows.Controls.TextBlock
        $line.TextWrapping = 'Wrap'; $line.Margin = '0,2,0,0'
        $line.Inlines.Add((New-Object System.Windows.Documents.Run ("{0}   " -f $r.Key)))
        foreach ($side in @(@('Hayabusa detections', $r.Detections, 'detections: no Kibana data view known yet - upload once'),
                            @('Raw events', $r.Raw, 'raw events: set the Security Onion manager on the Raw Events tab'))) {
            if ($side[1]) {
                $h = New-Object System.Windows.Documents.Hyperlink (New-Object System.Windows.Documents.Run $side[0])
                $h.Foreground = $accent
                $h.Tag = $side[1]
                $h.ToolTip = $side[1]
                $h.Add_Click({ param($s) try { Start-Process $s.Tag } catch { Write-Log "Could not open the link: $($_.Exception.Message)`n" 'err' } })
                $line.Inlines.Add($h)
            } else {
                $n = New-Object System.Windows.Documents.Run "($($side[2]))"
                $n.Foreground = $muted
                $line.Inlines.Add($n)
            }
            $line.Inlines.Add((New-Object System.Windows.Documents.Run '     '))
        }
        [void]$Panel.Children.Add($line)
        if ($r.Detections) { Write-Log "  $($r.Key) detections: $($r.Detections)`n" }
        if ($r.Raw)        { Write-Log "  $($r.Key) raw events: $($r.Raw)`n" }
    }
    $Panel.Visibility = 'Visible'
}

# ------------------------------------------------------ accountability PCAP ---
# Before EVTXER touches the network the operator should be
# capturing their own traffic. The decisions (2026-10-16) live in HayabusaLib
# (Get-DumpcapArgs, Test-PcapReminderDue); this is the window's part: the
# question before each network action, and starting dumpcap.
function Get-PcapFolder {
    if ($script:Settings.PcapFolder) { return $script:Settings.PcapFolder }
    return $script:Folders.Pcap
}

function Start-AccountabilityCapture {
    # True when a capture is running afterwards. dumpcap is started as a
    # process of its own (new hidden console), so closing EVTXER - or its
    # console - does not stop it.
    $dumpcap = Find-Dumpcap $script:Settings.WiresharkFolder
    if (-not $dumpcap) {
        [void][System.Windows.MessageBox]::Show("Wireshark's dumpcap.exe was not found. Install Wireshark, or set its folder on the Settings tab.", 'Accountability PCAP')
        return $false
    }
    $iface = $script:Settings.PcapInterface
    if (-not $iface) {
        [void][System.Windows.MessageBox]::Show('Choose the capture interface on the Settings tab first.', 'Accountability PCAP')
        return $false
    }
    $folder = Get-PcapFolder
    $result = 'FAILED'; $detail = ''; $how = 'dumpcap'
    $dcArgs = Get-DumpcapArgs -Interface $iface -OutFolder $folder
    try {
        New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop | Out-Null
        # A one-second trial run says whether Npcap lets this user capture -
        # a hidden capture that dies cannot say why.
        Write-Log "Checking that dumpcap may capture on $iface (one second)...`n"
        $trial = Join-Path ([IO.Path]::GetTempPath()) ("evtxer-pcap-trial-{0}.pcapng" -f [guid]::NewGuid().ToString('N'))
        $said = (& $dumpcap -i $iface -a duration:1 -w $trial -q 2>&1 | Out-String)
        Remove-Item -LiteralPath $trial -Force -ErrorAction SilentlyContinue
        $before = @(Get-RunningCaptures | ForEach-Object ProcessId)
        if ($LASTEXITCODE -ne 0 -and (Test-NpcapRefused $said)) {
            # Npcap is installed for administrators only: one UAC prompt.
            $how = 'dumpcap, elevated'
            Write-Log "Npcap lets only administrators capture here - Windows will ask to run dumpcap elevated.`n" 'warn'
            Start-Process -FilePath $dumpcap -ArgumentList (ConvertTo-ProcessArgumentLine $dcArgs) -Verb RunAs -WindowStyle Hidden -ErrorAction Stop
        } elseif ($LASTEXITCODE -ne 0) {
            throw "dumpcap could not capture on that interface: $($said.Trim())"
        } else {
            Start-Process -FilePath $dumpcap -ArgumentList (ConvertTo-ProcessArgumentLine $dcArgs) -WindowStyle Hidden -ErrorAction Stop
        }
        $mine = $null
        foreach ($i in 1..20) {
            Invoke-UiPump
            $mine = @(Get-RunningCaptures | Where-Object { $before -notcontains $_.ProcessId -and -not $_.IsViewer })[0]
            if ($mine) { break }
            Start-Sleep -Milliseconds 250
        }
        if (-not $mine) { throw 'dumpcap did not keep running - see Wireshark / Npcap' }
        $result = 'Success'
        $detail = "pid $($mine.ProcessId); every file kept, a new one every 3 GB"
        Write-Log "Accountability capture started on $iface -> $folder ($how).`n" 'ok'
        if ($script:Settings.PcapViewer -ne 'off') { Open-CaptureViewer }
        $free = Get-FreeSpaceBytes $folder
        if ($free -ge 0 -and $free -lt 10GB) { Write-Log "Only $(Format-ByteSize $free) free where the capture is written - it stops when the disk is full.`n" 'warn' }
        return $true
    } catch {
        $detail = $_.Exception.Message
        Write-Log "Accountability capture NOT started: $detail`n" 'err'
        [void][System.Windows.MessageBox]::Show("The capture did not start:`n`n$detail", 'Accountability PCAP')
        return $false
    } finally {
        # The name a person knows (Wi-Fi) beside the device dumpcap needs.
        $known = @($script:PcapIfs | Where-Object { $_.Device -eq $iface })[0]
        $label = if ($known) { "$($known.Name) ($iface)" } else { $iface }
        Write-Ledger @(New-LedgerRow -Action 'PCAP start' -Target $label -Protocol $how -Result $result `
                          -Output ($dcArgs[$dcArgs.IndexOf('-w') + 1]) -Details $detail)
        if (Get-Command Update-PcapStatus -ErrorAction SilentlyContinue) { Update-PcapStatus }
    }
}

function Open-CaptureViewer {
    # Wireshark on the capture interface, to SEE it working. Not the
    # recording: closing it changes nothing (see Get-WiresharkViewerArgs).
    $ws = Find-Wireshark $script:Settings.WiresharkFolder
    if (-not $ws) { Write-Log "Wireshark.exe was not found beside dumpcap - no live view (the capture itself runs).`n" 'warn'; return }
    if (-not $script:Settings.PcapInterface) { return }
    try {
        New-Item -ItemType Directory -Path $script:ViewerFolder -Force | Out-Null
        Start-Process -FilePath $ws -ArgumentList (ConvertTo-ProcessArgumentLine (Get-WiresharkViewerArgs $script:Settings.PcapInterface)) -ErrorAction Stop
        Write-Log "Wireshark opened to show the capture live. It is only a viewer - close it whenever you like; the recording keeps going.`n" 'info'
    } catch { Write-Log "Could not open Wireshark: $($_.Exception.Message)`n" 'warn' }
}

function Confirm-PcapBeforeNetwork([string]$What) {
    # Asked before the first network action of a session, unless a capture is
    # already running, the reminder is off, or it was put off until tomorrow.
    # Once answered "continue without capture" it stays quiet until EVTXER
    # restarts (nine asks in one walk trained a reflex
    # click; the PCAP pill shows the state). Closing the window cancels the
    # action; any of the three buttons lets it go ahead.
    if (-not (Test-PcapReminderDue $script:Settings @(Get-RunningCaptures | Where-Object { -not $_.IsViewer }).Count `
                -AnsweredThisSession:([bool]$script:PcapAnswered))) { return $true }
    $askXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Accountability PCAP" SizeToContent="WidthAndHeight" MaxWidth="620"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False" ResizeMode="NoResize"
        UseLayoutRounding="True" FontFamily="Segoe UI" FontSize="13" Background="#1E2126">
  <StackPanel Margin="20">
    <TextBlock Text="Is accountability PCAP started?" Style="{StaticResource SectionHead}" FontSize="16"/>
    <TextBlock x:Name="lblAskWhat" Margin="0,4,0,16" TextWrapping="Wrap"/>
    <StackPanel Orientation="Horizontal">
      <Button x:Name="btnAskStart" Content="START CAPTURE" Style="{StaticResource Primary}" MinWidth="150"/>
      <Button x:Name="btnAskOk" Content="Continue without capture" Margin="10,0,0,0" MinWidth="80"
              ToolTip="Not asked again until EVTXER is restarted - the PCAP pill at the top shows whether a capture runs"/>
      <Button x:Name="btnAskSnooze" Content="Don't remind me until tomorrow" Margin="10,0,0,0"/>
    </StackPanel>
  </StackPanel>
</Window>
'@
    $w = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$askXaml)))
    $w.Owner = $win
    $w.FindName('lblAskWhat').Text = "About to $What. No capture (dumpcap) is running on this machine."
    $choice = @{ Value = 'cancel' }
    $w.FindName('btnAskStart').Add_Click({ $choice.Value = 'start'; $w.Close() }.GetNewClosure())
    $w.FindName('btnAskOk').Add_Click({ $choice.Value = 'ok'; $w.Close() }.GetNewClosure())
    $w.FindName('btnAskSnooze').Add_Click({ $choice.Value = 'snooze'; $w.Close() }.GetNewClosure())
    [void]$w.ShowDialog()
    switch ($choice.Value) {
        'start'  { return (Start-AccountabilityCapture) }
        'ok'     {
            $script:PcapAnswered = $true
            Write-Log "No accountability capture for: $What (operator chose to continue without one; not asked again this session).`n" 'warn'
            return $true
        }
        'snooze' {
            $script:Settings.PcapSnoozeUntil = Get-PcapSnoozeDate
            try { Save-ToolSettings $script:Settings $script:SettingsPath } catch { }
            Write-Log "Accountability PCAP reminder off until $($script:Settings.PcapSnoozeUntil).`n" 'warn'
            return $true
        }
        default  { Write-Log "Cancelled before it started: $What.`n" 'warn'; return $false }
    }
}

# The Show command popup: what a tab would run, as text to copy and paste
# into PowerShell when the tool itself is the thing that broke.
function Show-CommandWindow([string]$Title, [string]$Intro, [string]$Text) {
    $cmdXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="980" Height="640" MinWidth="560" MinHeight="320"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
        UseLayoutRounding="True" TextOptions.TextFormattingMode="Display"
        FontFamily="Segoe UI" FontSize="13" Background="#1E2126">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <TextBlock x:Name="lblIntro" Style="{StaticResource Hint}" Margin="0,0,0,10"/>
    <TextBox x:Name="txtCmd" Grid.Row="1" IsReadOnly="True" FontFamily="Consolas" FontSize="12.5"
             TextWrapping="NoWrap" AcceptsReturn="True"
             HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto">
      <TextBox.Resources>
        <SolidColorBrush x:Key="{x:Static SystemColors.ControlBrushKey}" Color="#1A1D22"/>
      </TextBox.Resources>
    </TextBox>
    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
      <TextBlock x:Name="lblCopied" Style="{StaticResource Hint}" Margin="0,0,14,0" VerticalAlignment="Center"/>
      <Button x:Name="btnCopy" Content="COPY TO CLIPBOARD" Style="{StaticResource Primary}"/>
      <Button x:Name="btnClose" Content="Close" Margin="10,0,0,0" IsCancel="True"/>
    </StackPanel>
  </Grid>
</Window>
'@
    $w = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$cmdXaml)))
    $w.Title = $Title
    $w.Owner = $win
    $w.FindName('lblIntro').Text = $Intro
    $w.FindName('txtCmd').Text = $Text
    $copied = $w.FindName('lblCopied')
    $w.FindName('btnCopy').Add_Click({
        [System.Windows.Clipboard]::SetText($Text)
        $copied.Text = 'Copied.'
    }.GetNewClosure())
    $w.FindName('btnClose').Add_Click({ $w.Close() }.GetNewClosure())
    [void]$w.ShowDialog()
}

$btnCancel.Add_Click({
    # Not gated on $script:Busy: Busy is exactly when this button exists.
    $script:CancelRequested = $true
    $btnCancel.IsEnabled = $false
    Write-Log "Cancel requested.`n" 'warn'
})

$win.Add_Closing({
    param($sender, $e)
    # The rules folder is half moved during an update: closing then would
    # leave Hayabusa without rules until the next start repairs it.
    if ($script:RulesUpdating) {
        [void][System.Windows.MessageBox]::Show('The Hayabusa rules are being updated. Close EVTXER when it has finished.', 'Hayabusa rules')
        $e.Cancel = $true; return
    }
    # The queue asks first: a No must leave everything else running too.
    if ((Get-Command Confirm-QueueClose -ErrorAction SilentlyContinue) -and -not (Confirm-QueueClose)) { $e.Cancel = $true; return }
    # Closing mid-job must not leave a scan running with no window. A
    # collection is asked to stop instead of being killed, so it can still
    # clean up the target and restore TrustedHosts.
    $script:CancelRequested = $true
    try { if ($script:ActivePump) { $script:ActivePump.Kill() } } catch { }
    try {
        if ($script:ActiveConsole -and -not $script:ActiveConsole.HasExited) {
            & taskkill.exe /T /F /PID $script:ActiveConsole.Id 2>&1 | Out-Null
        }
    } catch { }
    try { [IO.File]::WriteAllText($script:LayoutFile, ([int]$colLog.ActualWidth).ToString()) } catch { }
})

# ---- tabs ----
# Each tab is its own file: one screen of UI per file, and the shell stays the
# only place that owns the window, the log and the dispatcher pump.
$script:Busy = $false
$missingTabs = @()
foreach ($tabFile in 'wpf-collect.ps1', 'wpf-convert.ps1', 'wpf-upload.ps1', 'wpf-takajo.ps1',
                     'wpf-kibana.ps1', 'wpf-soimport.ps1', 'wpf-settings.ps1', 'wpf-guide.ps1', 'wpf-queue.ps1') {
    $path = Join-Path $PSScriptRoot $tabFile
    # A missing tab used to be skipped in silence - and a code\ folder left
    # behind on a deployment copy is exactly how one goes missing.
    # One broken tab must not take the other four down with it: before this, a
    # tab that threw while loading stopped the whole tool at startup.
    if (Test-Path -LiteralPath $path) {
        try { . $path }
        catch { Write-Log "Tab $tabFile failed to load - its tab may be empty or partial: $($_.Exception.Message)`n" 'err' }
    }
    else { $missingTabs += $tabFile }
}

# Never open taller or wider than the screen: 1000px is most of a laptop at
# 150% scaling, and a window whose bottom is off-screen hides its own buttons.
$work = [System.Windows.SystemParameters]::WorkArea
$win.Height = [Math]::Min($win.Height, $work.Height)
$win.Width  = [Math]::Min($win.Width,  $work.Width)

# The log pane keeps the width it was dragged to last time - but never so wide
# that the tabs drop below their floor in this window.
$script:LayoutFile = Join-Path $script:AppRoot 'layout.conf'
$savedWidth = ''
try { $savedWidth = [IO.File]::ReadAllText($script:LayoutFile) } catch { }
$colLog.Width = New-Object System.Windows.GridLength (
    ConvertTo-LogPaneWidth $savedWidth -Max ([Math]::Max(280, $win.Width - 640)))
# ...and keeps fitting when the window is made narrower: the log gives way,
# the tabs keep their 560 (in a small window the log ran
# off the right edge and the tabs' text was cut off).
$win.Add_SizeChanged({
    $room = $win.ActualWidth - 640
    if ($colLog.ActualWidth -gt $room) { $colLog.Width = New-Object System.Windows.GridLength ([Math]::Max(280, $room)) }
})

# ---- last-chance error handler ----
# Without it, ONE error escaping ANY handler ends ShowDialog and the tool is
# gone - window, log pane, and whatever the operator was in the middle of.
# Measured 2026-10-06: an [int]::Parse('x') in a click handler closed the
# window; with this registered the window stayed up. Each handler's own
# try/finally still resets its buttons and $script:Busy - this only stops the
# crash and records where it came from.
$win.Dispatcher.Add_UnhandledException({
    param($s, $e)
    $e.Handled = $true
    try {
        $where = ''
        $rec = $e.Exception.ErrorRecord
        if ($rec -and $rec.InvocationInfo -and $rec.InvocationInfo.ScriptName) {
            $where = " (at $(Split-Path -Leaf $rec.InvocationInfo.ScriptName):$($rec.InvocationInfo.ScriptLineNumber))"
        }
        Write-Log "UNEXPECTED ERROR$where - the tool caught it and is still running: $($e.Exception.Message)`n" 'err'
    } catch { }
})

# The pills follow what they show: dumpcap even when it is started or
# stopped outside EVTXER (Wireshark, Task Manager, a full disk), the others
# the tabs as the operator fills them in.
Update-PcapPill
Update-ReadyPills
$script:PcapTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:PcapTimer.Interval = [timespan]::FromSeconds(3)
$script:PcapTimer.Add_Tick({ Update-PcapPill; Update-ReadyPills })
$script:PcapTimer.Start()

# ---- run it ----
# Without this the script builds the entire window and exits: no error, exit
# code 0, and nothing on screen. Every check during the WPF port rendered the
# window from a harness that supplied its own Show, so the one line the real
# launch depends on was the one line nothing exercised.
if ($missingTabs) { Write-Log "MISSING tab file(s) in code\: $($missingTabs -join ', ') - copy the whole code folder.`n" 'err' }
Write-Log "EVTXER v$script:ToolVersion ready. Log file: $script:LogFile`n" 'info'
# EVTXER is meant to run as administrator; the .cmd asks
# for it. Said once here, and again under WinRM when that is picked.
if (-not (Test-IsElevated)) {
    Write-Log "Not running as administrator: plain WinRM collection will not work. Start EVTXER with EVTXER.cmd, which asks Windows for administrator rights.`n" 'warn'
}
[void]$win.ShowDialog()
