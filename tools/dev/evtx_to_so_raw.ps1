# Turns EVTX files into raw-event documents shaped the way Security Onion 2.4
# stores so-import-evtx imports (fields read from a real SO 2.4.211 import,
# 2026-10-16) - so the raw-event hunting dashboard can be tested on the local
# Docker lab without a Security Onion. Only the fields the dashboard reads are
# made; everything under winlog.* is a string, as SO maps it (keyword).
#   powershell -NoProfile -File tools\dev\evtx_to_so_raw.ps1 -In evtx-samples -Out output\rawlab\raw.ndjson
# Write the output into a folder Defender excludes: the events quote attack
# commands. Files are found by wildcard - never name an attack tool's sample
# on a command line.
param([string]$In, [string]$Out)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force (Split-Path -Parent $Out) | Out-Null
$w = New-Object IO.StreamWriter($Out, $false, (New-Object Text.UTF8Encoding($false)))
$n = 0; $files = 0
# Always a string: a function that outputs nothing becomes {} in ConvertTo-Json.
function Leaf([string]$p) { if ($p) { ($p -split '\\')[-1] } else { '' } }
foreach ($f in Get-ChildItem -LiteralPath $In -Recurse -Filter *.evtx) {
    $files++
    try { $events = @(Get-WinEvent -Path $f.FullName -Oldest -ErrorAction Stop) } catch { continue }
    foreach ($e in $events) {
        $x = [xml]$e.ToXml()
        $ed = [ordered]@{}; $unnamed = @()
        foreach ($d in @($x.Event.EventData.Data)) {
            if ($null -eq $d) { continue }
            $v = if ($d -is [string]) { $d } else { $d.'#text' }
            $name = if ($d -is [string]) { $null } else { $d.Name }
            if ($name) { if ($null -ne $v) { $ed[$name] = [string]$v } }
            elseif ($null -ne $v) { $unnamed += [string]$v }
        }
        if ($unnamed.Count) { $ed['Data'] = @{ '#text' = $unnamed } }
        $ud = $null
        $udNode = $x.Event.UserData
        if ($udNode -and $udNode.FirstChild) {
            $inner = [ordered]@{}
            foreach ($c in $udNode.FirstChild.ChildNodes) { if ($c.LocalName -and $c.InnerText) { $inner[$c.LocalName] = $c.InnerText } }
            $ud = @{ $udNode.FirstChild.LocalName = $inner }
        }
        $t = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        $win = [ordered]@{
            channel = $e.LogName; event_id = [string]$e.Id; computer_name = $e.MachineName
            record_id = [string]$e.RecordId; provider = @{ name = $e.ProviderName }
        }
        if ($ed.Count) { $win.event_data = $ed }
        $doc = [ordered]@{ '@timestamp' = $t; event = @{ created = $t; code = [string]$e.Id }; winlog = $win; tags = @('import') }
        if ($ud) { $doc.userdata = $ud }
        if ($e.Id -eq 4104 -and $ed.ScriptBlockText) { $doc.powershell = @{ file = @{ script_block_text = $ed.ScriptBlockText } } }
        if ($e.LogName -eq 'Microsoft-Windows-Sysmon/Operational') {
            if ($e.Id -eq 1) {
                $doc.process = @{ command_line = $ed.CommandLine; executable = $ed.Image; name = (Leaf $ed.Image)
                                  parent = @{ name = (Leaf $ed.ParentImage); command_line = $ed.ParentCommandLine } }
            } elseif ($e.Id -eq 10) {
                $doc.process = @{ executable = $ed.SourceImage; name = (Leaf $ed.SourceImage) }
            }
        }
        $w.WriteLine(($doc | ConvertTo-Json -Depth 8 -Compress)); $n++
    }
}
$w.Close()
"$files files, $n events -> $Out"
