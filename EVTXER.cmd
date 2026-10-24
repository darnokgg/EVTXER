@echo off
rem Double-click this to start the tool - no Set-ExecutionPolicy needed first.
rem -ExecutionPolicy Bypass applies to THIS PowerShell process only; the
rem machine's policy is not changed. -File runs STA, which WPF needs.
rem
rem EVTXER runs as administrator: plain WinRM writes this
rem PC's TrustedHosts and needs it. Not elevated yet, this file starts itself
rem again elevated - Windows asks once. Refused, it starts without, and the tool
rem says what that limits.
rem   - fltmc, not net session: net session also fails when the Server service
rem     is off, and the elevated copy would then relaunch itself for ever.
rem   - The relaunched copy gets "evtxer-elevated" and never relaunches again
rem     (an environment variable does not cross the UAC boundary).
rem   - The path goes through the environment, not a quoted string (a ' in it
rem     broke the command), and a mapped drive letter is turned into its
rem     \server\share path - the elevated copy cannot see the user's mappings.
if /i "%~1"=="evtxer-elevated" goto run
if "%EVTXER_NO_ELEVATE%"=="1" goto run
fltmc >nul 2>&1
if not errorlevel 1 goto run
set "EVTXER_SELF=%~f0"
powershell.exe -NoProfile -Command "$p = $env:EVTXER_SELF; if ((New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($p))).DriveType -eq 'Network' -and $p -match '^[A-Za-z]:') { $r = (Get-PSDrive $p.Substring(0,1) -ErrorAction SilentlyContinue).DisplayRoot; if (-not $r) { exit 2 }; $p = $r.TrimEnd('\') + $p.Substring(2) }; try { Start-Process -FilePath $p -ArgumentList 'evtxer-elevated' -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }"
if not errorlevel 1 exit /b 0
if errorlevel 2 (
  echo This copy runs from a mapped drive letter that cannot be found as a \server\share path,
  echo so it cannot be started as administrator. Starting without administrator rights.
) else (
  echo Administrator rights were not given - starting without them.
)
echo SMB and WinRM over HTTPS still work; plain WinRM needs administrator.
:run
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0code\HayabusaMissionTool.ps1"
rem A crash used to close this window before the error could be read, so on
rem a non-zero exit it stays open.
if errorlevel 1 (
  echo.
  echo The tool stopped with an error - the message is above. The full log is in the logs folder.
  pause
)
