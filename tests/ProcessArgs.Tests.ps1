# tests/ProcessArgs.Tests.ps1
#
# Two helpers behind bugs a code review caught in the Takajo tab.
#
# ConvertTo-ProcessArgumentLine: Start-Process -ArgumentList joins a string[]
# with spaces and quotes nothing, so a path containing a space arrives at the
# child process as two arguments. Found on the Takajo html-server (since
# removed); the process pump, dumpcap and Wireshark still depend on it.
#
# Get-NextFreeFolder: takajo automagic refuses an --output folder that already
# exists ("The directory '...' exists. Please specify a new folder name.",
# exit 1). The default output folder was a fixed name, so the second run failed
# while the tool counted the FIRST run's files and reported success in green.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# ---------------------------------------------------- argument quoting -----
Assert-Equal (ConvertTo-ProcessArgumentLine @('automagic')) 'automagic' `
    "a single bare argument is unchanged"
Assert-Equal (ConvertTo-ProcessArgumentLine @('--level','high')) '--level high' `
    "arguments with no spaces are joined plainly"
Assert-Equal (ConvertTo-ProcessArgumentLine @('--timeline','C:\Case Files\results.jsonl')) `
    '--timeline "C:\Case Files\results.jsonl"' `
    "an argument containing a space is quoted"
Assert-Equal (ConvertTo-ProcessArgumentLine @('--out','C:\a b\c','--port','8823')) `
    '--out "C:\a b\c" --port 8823' `
    "only the arguments that need quoting get quoted"
Assert-Equal (ConvertTo-ProcessArgumentLine @()) '' "an empty argument list gives an empty line"

# A trailing backslash before the closing quote would escape it and swallow the
# rest of the command line, so it is doubled.
Assert-Equal (ConvertTo-ProcessArgumentLine @('--out','C:\a b\')) '--out "C:\a b\\"' `
    "a trailing backslash inside a quoted argument is escaped"

# ------------------------------------------------------- output folders ----
$tmp = Join-Path $env:TEMP ("nextfree-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $base = Join-Path $tmp 'case'
    Assert-Equal (Get-NextFreeFolder $base) $base "an unused name is returned unchanged"

    New-Item -ItemType Directory -Path $base -Force | Out-Null
    Assert-Equal (Get-NextFreeFolder $base) "$base-2" "an existing folder bumps to -2"

    New-Item -ItemType Directory -Path "$base-2" -Force | Out-Null
    Assert-Equal (Get-NextFreeFolder $base) "$base-3" "it keeps counting past the first collision"

    # The point of the helper: what it returns must not exist, so automagic
    # cannot refuse it.
    Assert-True (-not (Test-Path (Get-NextFreeFolder $base))) "the returned folder does not exist"
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
