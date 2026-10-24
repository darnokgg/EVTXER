# tests/EcsBatch.Tests.ps1
#
# The upload's first pass over ecs.jsonl. It used to read the whole file into
# memory twice - every line as text and as a parsed object - which on a
# 550k-detection batch took 10 GB of RAM and ten silent minutes before the
# first document was sent. Test-EcsFile streams and keeps only counts, and
# still names the lines that are not whole JSON objects (a file cut short) so
# the upload can refuse the batch before anything is sent.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$tmp = Join-Path $env:TEMP "ecsbatch_$PID.jsonl"
$id = 'f8429792ca631a08d51adfb3db062c03c7305db4'
$content = @(
    ('{"host":{"name":"dc01"},"event":{"id":"' + $id + '","code":"4624"}}')
    ''
    '{"host":{"name":"dc01"},"event":'
    '{"host":{"name":"ws01"}}'
    'not json at all'
) -join "`n"
[IO.File]::WriteAllText($tmp, $content, (New-Object Text.UTF8Encoding($false)))
try {
    $seen = @()
    $c = Test-EcsFile $tmp
    Assert-Equal (@($c.BadLines) -join ',') '3,5' "bad lines are named by their line number in the file, blank lines counted"
    Assert-Equal $c.Docs 2                        "only whole objects count as documents"
    Assert-Equal $c.MissingId 1                   "a document without event.id is counted (converted by an older version)"

    [IO.File]::WriteAllText($tmp, ('{"import":{"id":"aaa"}}' + "`n" + '{"import": {"id": "bbb"}}' + "`n" + '{"import":{"id":"aaa"}}' + "`n"), (New-Object Text.UTF8Encoding($false)))
    $c = Test-EcsFile $tmp
    Assert-Equal ((@($c.ImportIds) | Sort-Object) -join ',') 'aaa,bbb' "the file's own import.ids are collected (PowerShell and Python spacing)"

    [IO.File]::WriteAllText($tmp, ('{"a":1}' + "`n" + '{"a":2}' + "`n"), (New-Object Text.UTF8Encoding($false)))
    $c = Test-EcsFile $tmp
    Assert-Equal @($c.BadLines).Count 0           "a clean file has no bad lines"
    Assert-Equal $c.Docs 2                        "and counts every line"

    $lines = 1..12000 | ForEach-Object { '{"n":' + $_ + '}' }
    [IO.File]::WriteAllLines($tmp, [string[]]$lines)
    $c = Test-EcsFile $tmp -OnProgress { param($n) $script:seen += $n }
    Assert-Equal ($script:seen -join ',') '5000,10000' "progress is reported while it reads, so the window stays alive"
} finally { Remove-Item $tmp -ErrorAction SilentlyContinue }

# The upload checks with it, refuses a damaged file, and never holds the batch.
# Publish-EcsFile is the upload the Upload tab and the job queue share.
$upload = Get-Content "$PSScriptRoot\..\code\wpf-upload.ps1" -Raw
$publish = ${function:Publish-EcsFile}.ToString()
Assert-True ($publish -match 'Test-EcsFile')                     "the upload checks the batch with Test-EcsFile"
Assert-True ($publish -match '\.BadLines\.Count[\s\S]{0,600}Nothing was sent[\s\S]{0,400}return') "a damaged batch is refused before anything is sent"
Assert-True (($upload + $publish) -notmatch 'Read-EcsBatch|ReadAllLines|\$batch\.Docs|ConvertFrom-Json \$line|\$line \| ConvertFrom-Json') "the upload no longer loads or parses the whole batch"
Assert-True (${function:Send-EcsFile}.ToString() -match '\[IO\.File\]::OpenText\(\$Path\)[\s\S]{0,300}ReadLine\(\)') "the documents are streamed from the file"
