# A scratch EVTXER for GUI tests: a copy of code\ in a SHORT path (the rules have
# 166-character paths), started with a known process id, and always closed.
#   powershell -NoProfile -File tools\dev\scratch-evtxer.ps1 -Action New     # (re)build %TEMP%\evx from code\
#   powershell -NoProfile -File tools\dev\scratch-evtxer.ps1 -Action Start   # prints the process id
#   powershell -NoProfile -File tools\dev\scratch-evtxer.ps1 -Action Stop    # closes the scratch EVTXER (never the developer's own)
#   powershell -NoProfile -File tools\dev\scratch-evtxer.ps1 -Action Status
# New never copies the operator's saved settings (importer.conf, soimport.conf,
# settings.conf, layout.conf) or rules\.git.
param([ValidateSet('New', 'Start', 'Stop', 'Status')][string]$Action, [string]$Dir = "$env:TEMP\evx")
# New deletes $Dir: only ever a folder under %TEMP% (never the repo or a deployment copy).
$full = [IO.Path]::GetFullPath($Dir).TrimEnd('\')
$temp = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
if (-not $full.StartsWith("$temp\", [StringComparison]::OrdinalIgnoreCase)) { throw "-Dir must be a folder under $temp" }
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. "$PSScriptRoot\uia.ps1"

function Get-EvtxerProcess {
    # Every EVTXER, wherever it runs from: powershell.exe hosting HayabusaMissionTool.ps1.
    @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" |
      Where-Object { $_.CommandLine -match 'HayabusaMissionTool\.ps1' })
}

switch ($Action) {
    'New' {
        if (@(Get-EvtxerProcess | Where-Object { $_.CommandLine -like "*$Dir*" }).Count) { throw "the scratch EVTXER is running - Stop it first" }
        if (Test-Path $Dir) { Remove-Item -Recurse -Force $Dir }
        New-Item -ItemType Directory -Force $Dir | Out-Null
        $null = robocopy "$repo\code" "$Dir\code" /E /XD .git /XF importer.conf soimport.conf settings.conf layout.conf evtxer.lock /NFL /NDL /NJH /NJS /NP
        if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }
        Copy-Item "$repo\EVTXER.cmd", "$repo\README.txt" $Dir
        "scratch copy ready: $Dir"
    }
    'Start' {
        $p = Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "$Dir\code\HayabusaMissionTool.ps1" -PassThru
        $null = Get-UiWindowByPid $p.Id 90
        "started: process $($p.Id)"
    }
    'Stop' {
        # Only the scratch copy: the developer's own EVTXER may be mid-job.
        foreach ($proc in @(Get-EvtxerProcess | Where-Object { $_.CommandLine -like "*$Dir*" })) {
            try { (Get-UiWindowByPid $proc.ProcessId 5).GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close() } catch { }
            # A "job is running - close anyway?" question would hold it open: wait, then make sure.
            $deadline = (Get-Date).AddSeconds(15)
            while ((Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
            if (Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue) {
                Stop-Process -Id $proc.ProcessId -Force
                "process $($proc.ProcessId) did not close - stopped"
            } else { "process $($proc.ProcessId) closed" }
        }
        $left = @(Get-EvtxerProcess | Where-Object { $_.CommandLine -like "*$Dir*" }).Count
        "EVTXER processes left: $left (all EVTXER running: $(@(Get-EvtxerProcess).Count))"
        if ($left) { exit 1 }
    }
    'Status' { Get-EvtxerProcess | ForEach-Object { "$($_.ProcessId)  $($_.CommandLine)" }; "EVTXER processes: $(@(Get-EvtxerProcess).Count)" }
}
