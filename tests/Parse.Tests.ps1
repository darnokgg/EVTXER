# tests/Parse.Tests.ps1
#
# Every script in code\ must parse. Code review, 2026-10-16: a gate written as
# 'fetch Kibana's certificate' ended its string at the apostrophe, so all of
# wpf-kibana.ps1 failed to parse. The shell catches a tab that fails to load
# and logs it, so the window still opened, every other tab worked, the source
# checks matched their text - and nothing noticed the Kibana tab was gone.
$code = Join-Path (Split-Path -Parent $PSScriptRoot) 'code'
foreach ($f in Get-ChildItem -LiteralPath $code -Filter *.ps1 -File) {
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
    $first = if ($errors) { " - line $($errors[0].Extent.StartLineNumber): $($errors[0].Message)" } else { '' }
    Assert-Equal @($errors).Count 0 "$($f.Name) parses$first"
}
