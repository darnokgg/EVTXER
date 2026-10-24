# tests/ScanOutputPath.Tests.ps1
#
# The scan used to write its JSONL next to the Hayabusa executable
# (hayabusa-x64\hayabusa-results.jsonl), while the CSV went to output\ and the
# in-tool "Where the files go" panel and the Takajo tab's default both said
# output\results.jsonl. Three different answers, and the documented one was the
# only one that was wrong.
#
# Consequences seen on a real run: 24 MB of JSONL dumped into the binary folder
# of a deployment copy, and a Takajo default pointing at a file that did not
# exist.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$root = 'C:\case'

Assert-Equal (Get-ScanOutputPath $root) 'C:\case\output\hayabusa\results.jsonl' `
    "the scan writes results.jsonl into output\hayabusa\, beside the CSV"
Assert-Equal (Get-EcsOutputPath 'C:\case\output\hayabusa\results.jsonl') 'C:\case\output\hayabusa\results.ecs.jsonl' `
    "the ECS file sits beside its source"

# ---- one folder per job ----
# Hayabusa's JSONLs and CSV used to share output\ with Takajo's folders, so
# nothing said which file belonged to which tool.
$layout = Get-FolderLayout $root
Assert-Equal $layout.Targets  'C:\case\input\targets'   "target lists live under input\"
Assert-Equal $layout.Evtx     'C:\case\evtx'            "evtx\ stays top level - it is both an output and an input"
Assert-Equal $layout.Hayabusa 'C:\case\output\hayabusa' "Hayabusa results get their own folder"
Assert-Equal $layout.Takajo   'C:\case\output\takajo'   "Takajo results get their own folder"
Assert-Equal $layout.Logs     'C:\case\logs'            "run logs have their own folder"

# The thing that actually went wrong: never inside the binary folder.
Assert-True ((Get-ScanOutputPath $root) -notmatch 'hayabusa-x64') `
    "the scan output is not written into the Hayabusa binary folder"

# The panel, the Takajo default and the scan must agree, or one of them lies.
$guide = (Get-PathGuide) -join "`n"
Assert-True ($guide -match 'results\.jsonl')     "the panel names results.jsonl"
Assert-True ($guide -match 'results\.ecs\.jsonl') "the panel names the ECS file by its real name"

$tool = Get-ToolSource
Assert-True ($tool -match 'Get-ScanOutputPath')  "the tool uses the shared scan-output path"
Assert-True ($tool -notmatch "Join-Path \(Split-Path -Parent \`$exe\) 'hayabusa-results\.jsonl'") `
    "the tool no longer writes JSONL next to the executable"

# Every default folder in the launcher comes from Get-FolderLayout. A literal
# 'output\...' there is a second answer that drifts from this one.
Assert-True ($tool -notmatch "Join-Path \`$script:Root '(output|evtx|logs|input)") `
    "the tool builds no default folder paths by hand"
