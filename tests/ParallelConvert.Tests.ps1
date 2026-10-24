# tests/ParallelConvert.Tests.ps1
#
# The ECS conversion ran on one thread: a 550k-detection batch kept a single
# core busy - 10-20% of the VM - for most of an hour. It now splits the file
# into contiguous slices, converts each in its own runspace and joins the parts
# in order. A parallel run must write the same file as a sequential one, and
# a cancelled one must leave nothing behind.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$dir = Join-Path ([IO.Path]::GetTempPath()) ("parconv-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $dir -Force | Out-Null
try {
    $src = Join-Path $dir 'results.jsonl'
    $tpl = '{{"Timestamp":"2026-10-01T10:00:{1:00}.000000Z","RuleTitle":"Rule {0}","Level":"high","Computer":"WS{2}","Channel":"Security","EventID":4624,"RecordID":{0},"RuleID":"r{2}","Details":{{"TgtUser":"u{0}"{3}}}}}'
    $lines = for ($i = 1; $i -le 2000; $i++) {
        # an unnamed Details key every 7th line (the recovered path), a blank
        # line every 250th, and one line that is not JSON at all
        $tpl -f $i, ($i % 60), ($i % 3), $(if ($i % 7 -eq 0) { ',"":"regval"' } else { '' })
        if ($i % 250 -eq 0) { '' }
        if ($i -eq 1234) { 'not json {' }
    }
    [IO.File]::WriteAllLines($src, [string[]]$lines)
    # "ingested" is the wall-clock time of conversion, the one field two runs
    # can never share.
    $strip = { param($p) @([IO.File]::ReadAllLines($p) | ForEach-Object { $_ -replace '"ingested":"[^"]*"', '' }) }

    $one  = Convert-HayabusaJsonlToEcs -Source $src -Destination (Join-Path $dir 'one.jsonl')  -ImportId 'x' -Workers 1
    $four = Convert-HayabusaJsonlToEcs -Source $src -Destination (Join-Path $dir 'four.jsonl') -ImportId 'x' -Workers 4

    Assert-Equal $four.Workers 4               "the conversion ran on 4 workers"
    Assert-Equal $one.Converted 2000           "every good line was converted"
    Assert-Equal $four.Converted $one.Converted "parallel converts as many as sequential"
    Assert-Equal $four.Bad 1                   "the non-JSON line is counted as bad, once"
    Assert-Equal $four.Recovered $one.Recovered "unnamed keys are recovered the same"
    Assert-Equal $four.Recovered 285           "every 7th line had an unnamed key"
    Assert-Equal $four.Total $one.Total        "the total line count matches"
    $a = & $strip (Join-Path $dir 'one.jsonl'); $b = & $strip (Join-Path $dir 'four.jsonl')
    Assert-Equal $b.Count $a.Count             "the same number of lines"
    $diff = 0; for ($i = 0; $i -lt $a.Count; $i++) { if ($a[$i] -cne $b[$i]) { $diff++ } }
    Assert-Equal $diff 0                       "the parallel file is the sequential file, line for line, in order"
    Assert-Equal @(Get-ChildItem $dir -Filter '*.part*').Count 0 "no part files are left behind"

    # ---- cancel ----
    $dst = Join-Path $dir 'cancel.jsonl'
    $c = Convert-HayabusaJsonlToEcs -Source $src -Destination $dst -ImportId 'x' -Workers 4 -OnProgress { param($d, $t) $true }
    Assert-True $c.Cancelled                   "a cancelled parallel conversion says so"
    Assert-True (-not (Test-Path $dst))        "and leaves no ECS file that could pass for a finished one"
    Assert-Equal @(Get-ChildItem $dir -Filter '*.part*').Count 0 "nor any part files"
    $c = Convert-HayabusaJsonlToEcs -Source $src -Destination $dst -ImportId 'x' -Workers 1 -OnProgress { param($d, $t) $true }
    Assert-True ($c.Cancelled -and -not (Test-Path $dst)) "a cancelled sequential conversion leaves nothing either"
} finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }

# ---- how many workers ----
Assert-Equal (Get-EcsWorkerCount 100 8)      1  "a small file stays on one worker - starting one costs more than it saves"
Assert-Equal (Get-EcsWorkerCount 12000 8)    3  "one worker per 5000 lines, up to the core count"
Assert-Equal (Get-EcsWorkerCount 550000 4)   3  "a big batch uses every core but one - the window stays responsive on a desktop"
Assert-Equal (Get-EcsWorkerCount 550000 12)  11 "a 12-core server gets 11"
Assert-Equal (Get-EcsWorkerCount 550000 1)   1  "a single core still converts"
Assert-Equal (Get-EcsWorkerCount 9000000 64) 16 "capped at 16 - each worker is a process of its own"
