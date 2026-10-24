# tests/ManualCommands.Tests.ps1
#
# The Show command buttons and README.txt give the operator commands to paste
# when the tool itself is broken. A fallback that has never been run is a
# fallback that does not work, so the Hayabusa and ECS commands are executed
# here for real, and the collection scripts (which need a target) are at least
# parsed.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$scratch = Join-Path ([IO.Path]::GetTempPath()) "manualcmd_$PID"
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
function Test-ParsesClean([string]$Text) {
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$null, [ref]$errs)
    return @($errs).Count -eq 0
}

# ---- the shared ECS conversion ----
$src = Join-Path $scratch 'results.jsonl'
$lines = @(
    '{"Timestamp":"2019-04-27T21:04:25.733401Z","Computer":"WS01","Channel":"Sec","EventID":4624,"Level":"info","RuleTitle":"Logon","Details":{"TgtUser":"bob"}}'
    '{"Timestamp":"2019-04-27T21:05:25.733401Z","Computer":"WS01","Channel":"Sysmon","EventID":13,"Level":"med","RuleTitle":"Reg Key Value Set","Details":{"":"evil.exe"}}'
    ''
    '{"Timestamp":"2019-04-27T21:06:25.733401Z","Computer":"WS02","Channel":"Sec","EventID":4625,"Level":"low","RuleTitle":"Logon Failure","Details":{}}'
)
[IO.File]::WriteAllLines($src, $lines)
$dst = Join-Path $scratch 'results.ecs.jsonl'
$r = Convert-HayabusaJsonlToEcs -Source $src -Destination $dst -ImportId 'test-id'
Assert-Equal $r.Converted 3 "every non-blank line is converted"
Assert-Equal $r.Recovered 1 "the empty-key Sysmon line is recovered, not dropped"
Assert-Equal $r.Bad 0 "nothing is dropped"
$first = Get-Content $dst -TotalCount 1 | ConvertFrom-Json
Assert-Equal $first.import.id 'test-id' "the import id is stamped on every document"
Assert-True ([IO.File]::ReadAllBytes($dst)[0] -ne 0xEF) "no byte-order mark (it would corrupt the first bulk line)"

# A cancel from the callback stops the run and removes the partial file.
$big = Join-Path $scratch 'big.jsonl'
[IO.File]::WriteAllLines($big, @(1..3000 | ForEach-Object { $lines[0] }))
$r = Convert-HayabusaJsonlToEcs -Source $big -Destination (Join-Path $scratch 'big.ecs.jsonl') -OnProgress { param($d, $t) $true }
Assert-True $r.Cancelled "returning true from the callback cancels"
Assert-True (-not (Test-Path (Join-Path $scratch 'big.ecs.jsonl'))) "a cancelled conversion leaves no partial file"

# ---- the manual ECS command, run as an operator would ----
$lib = (Resolve-Path "$PSScriptRoot\..\code\HayabusaLib.ps1").Path
Remove-Item $dst -ErrorAction SilentlyContinue
$cmd = Get-ManualEcsCommand -LibPath $lib -Source $src
Assert-True (Test-ParsesClean $cmd) "the manual ECS command parses"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
& powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc | Out-Null
Assert-True (Test-Path $dst) "running the manual ECS command writes results.ecs.jsonl beside the source"
Assert-Equal @(Get-Content $dst).Count 3 "and it holds the same documents the tab would write"

$blank = Get-ManualEcsCommand -LibPath $lib -Source ''
Assert-True ($blank -match "-Destination '<results\.ecs\.jsonl>'") "an empty source gives a placeholder, not an exception"
Assert-True ((Get-ManualEcsCommand -LibPath $lib -Source 'C:\x\r.jsonl') -match "-Destination 'C:\\x\\r\.ecs\.jsonl'") "the destination is named as the tab names it"

# ---- the manual Hayabusa command, run for real ----
$exe = @(Get-ChildItem "$PSScriptRoot\..\code\hayabusa-x64" -Filter 'hayabusa*.exe' -File -ErrorAction SilentlyContinue)[0].FullName
$evtx = @(Get-ChildItem "$PSScriptRoot\..\evtx-samples" -Recurse -Filter *.evtx -File -ErrorAction SilentlyContinue |
          Where-Object { $_.DirectoryName -match 'AutomatedTestingTools' })
$hOut = Join-Path $scratch 'hb\results.jsonl'
New-Item -ItemType Directory -Path (Split-Path $hOut) -Force | Out-Null
$cmd = Get-ManualHayabusaCommand -Exe $exe -EvtxDir 'C:\Some Folder\evtx' -OutFile $hOut -HtmlReport (Join-Path $scratch 'hb\s.html') -Csv
Assert-True (Test-ParsesClean $cmd) "the manual Hayabusa command parses"
Assert-True ($cmd -match "-d 'C:\\Some Folder\\evtx'") "a path with a space is quoted"
Assert-True ($cmd -match '(?m)^Set-Location ') "it runs from Hayabusa's own folder (rules are found from there)"
Assert-True ($cmd -match ' -O ' -and $cmd -match ' -w ') "it carries -O and -w like the tool does"
Assert-True ($cmd -match "(?m)^& '[^']+' dfir-timeline .* -t csv .* -q -N$") "the optional CSV pass is one complete line"
if (-not $exe -or $evtx.Count -eq 0) {
    Write-Host "  [SKIP] hayabusa binary or evtx-samples absent - manual scan not run" -ForegroundColor Yellow
} else {
    $cmd = Get-ManualHayabusaCommand -Exe $exe -EvtxDir $evtx[0].DirectoryName -OutFile $hOut
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc | Out-Null
    Assert-True (Test-Path $hOut) "running the manual Hayabusa command produces results.jsonl"
}

# ---- Takajo ----
$cmd = Get-ManualTakajoCommand -Exe 'C:\tool\code\takajo\takajo.exe' -Timeline 'C:\tool\output\hayabusa\results.jsonl' `
          -OutDir 'C:\tool\output\takajo\case-1' -Level 'low' -RulePath 'C:\tool\code\hayabusa-x64\rules' `
          -HtmlDir 'C:\tool\output\takajo\html' -Sqlite
Assert-True (Test-ParsesClean $cmd) "the manual Takajo commands parse"
Assert-True ($cmd -match "(?m)^Set-Location 'C:\\tool\\code\\takajo'") "Takajo runs from its own folder"
Assert-True ($cmd -match "automagic --timeline") "automagic is there"
Assert-True ($cmd -match "(?m)^& \.\\takajo\.exe html-report .*--output '\.\.\\\.\.\\output\\takajo\\html'") "html-report is one line with a RELATIVE output path"
Assert-True ($cmd -notmatch '--skipProgressBar') "by hand, in a console, the progress bar is wanted"

# ---- collection: no target here, so parse them and check what matters ----
foreach ($m in 'SMB', 'WinRM', 'WinRM-HTTPS') {
    foreach ($cat in 'DFIR', 'All') {
        $cmd = Get-ManualCollectCommand -Method $m -Targets @('WS01', "o'brien-pc") -Category $cat -Username 'analyst' `
                  -Domain '' -OutRoot 'C:\tool\evtx' -SkipCertificateCheck
        Assert-True (Test-ParsesClean $cmd) "the manual $m $cat collection parses"
        Assert-True ($cmd -match "Account = 'WS01\\analyst'") "$m $cat`: off-domain accounts are TARGET\user, as the tool resolves them"
        Assert-True ($cmd -notmatch 'ConvertTo-SecureString|-AsPlainText') "$m $cat`: no password is ever written into the script"
    }
}
$w = Get-ManualCollectCommand -Method 'WinRM' -Targets @('WS01') -Category 'DFIR' -Username 'analyst' -Domain 'CORP' -OutRoot 'C:\e'
Assert-True ($w -match "Account = 'CORP\\analyst'") "a domain account is DOMAIN\user"
Assert-True ($w -match 'TrustedHosts') "plain WinRM explains TrustedHosts"
Assert-True ($w -match "EVTX_Export_[0-9a-f]{8}") "it stages in a folder the tool's own sweep recognises"
Assert-True ($w -match 'Microsoft-Windows-Sysmon/Operational') "DFIR lists the preset's logs"
$h = Get-ManualCollectCommand -Method 'WinRM-HTTPS' -Targets @('WS01') -Category 'DFIR' -Username 'a' -SkipCertificateCheck
Assert-True ($h -match '-UseSSL -Port 5986') "HTTPS uses 5986 with SSL"
Assert-True ($h -match '-SkipCACheck -SkipCNCheck -SkipRevocationCheck') "and carries the skip when it was ticked"
Assert-True ($h -notmatch 'Set-Item WSMan') "HTTPS needs no TrustedHosts change"
$e = Get-ManualCollectCommand -Method '' -Targets @() -Category 'DFIR' -Username ''
Assert-True ($e -match '<TARGET>' -and $e -match '<USER>') "empty fields become placeholders, not blanks"

Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue

# ---- README.txt keeps up with the preset ----
# The manual WinRM block in README.txt was generated from the preset. If the
# preset changes and README.txt does not, the fallback quietly collects less.
$readme = Get-Content "$PSScriptRoot\..\README.txt" -Raw
Assert-True ($readme -match 'MANUAL PROCEDURES') "README.txt has the manual procedures"
foreach ($log in @(Resolve-LogPreset 'DFIR' @())) {
    Assert-True ($readme -match [regex]::Escape("'$log'")) "README.txt's manual collection lists $log"
}
