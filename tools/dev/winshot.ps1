# Saves a picture of ONE EVTXER window (by process id) - drawn with
# PrintWindow, so it is that window only, even when something covers it.
# Never capture a region of the screen: that photographs whatever the user
# has open on top.
#   powershell -File tools\dev\winshot.ps1 -ProcId 1234 -Out C:\...\shot.png [-Tab 'Settings'] [-Width 1440 -Height 1100]
param([int]$ProcId, [string]$Out, [string]$Tab, [int]$Width, [int]$Height)
. "$PSScriptRoot\uia.ps1"
Add-Type -AssemblyName System.Drawing
if (-not ('WinShot' -as [type])) {
    Add-Type 'using System; using System.Runtime.InteropServices; public static class WinShot { [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags); }'
}
$w = Get-UiWindowByPid $ProcId
if ($Width -and $Height) {
    # Physical pixels: at 150% scaling 1440 is the window's 960 minimum.
    $w.GetCurrentPattern([System.Windows.Automation.TransformPattern]::Pattern).Resize($Width, $Height)
    Start-Sleep -Milliseconds 800
}
if ($Tab) { Select-UiTab $w $Tab; Start-Sleep -Milliseconds 700 }
$r = $w.Current.BoundingRectangle
$bmp = New-Object System.Drawing.Bitmap ([int]$r.Width), ([int]$r.Height)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$dc = $g.GetHdc(); [void][WinShot]::PrintWindow([IntPtr]$w.Current.NativeWindowHandle, $dc, 2); $g.ReleaseHdc($dc)
$bmp.Save($Out)
"saved $Out ($([int]$r.Width)x$([int]$r.Height))"
