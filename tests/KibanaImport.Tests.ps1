# tests/KibanaImport.Tests.ps1
#
# The Dashboards tab talks to a Kibana behind Security Onion's Kratos proxy,
# which cannot be exercised from a test: there is no server here, and pointing
# one at the live box is exactly what is not allowed. So everything that can be
# wrong WITHOUT a server lives in pure functions, and this file is the only
# thing that ever proves them.
#
# Three of them are the likely bugs:
#   * the multipart body. PowerShell 5.1 has no -Form, so it is hand-built, and
#     a missing CRLF or a boundary that does not match the Content-Type header
#     produces a 415 or "file is required" that says nothing about which. The
#     assertions below are on the actual BYTES, not on a rendered string.
#   * the version gate. Compared as text, '9.0.10' is older than '9.0.8' and
#     '10.0.0' is older than '9', so a string compare refuses good servers.
#   * the import summary. Kibana reports per-object errors in errors[], and a
#     tab that only prints success/failure throws away the one actionable part.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$enc = New-Object Text.UTF8Encoding($false)
function Bytes([string]$s) { $enc.GetBytes($s) }
function Text($b)          { $enc.GetString($b) }

# ====================================================== multipart body ======
$payload = "{`"id`":`"hayabusa-x`"}`n{`"id`":`"hayabusa-y`"}`n"
$m = New-MultipartFileBody -Content (Bytes $payload) -Boundary 'BOUNDARY123'

Assert-Equal $m.ContentType 'multipart/form-data; boundary=BOUNDARY123' `
    "the Content-Type header carries the same boundary the body uses"

$body = Text $m.Bytes
$expected = "--BOUNDARY123`r`n" +
            "Content-Disposition: form-data; name=`"file`"; filename=`"import.ndjson`"`r`n" +
            "Content-Type: application/ndjson`r`n`r`n" +
            $payload +
            "`r`n--BOUNDARY123--`r`n"
Assert-Equal $body $expected "the whole body is byte-for-byte what Kibana's parser expects"

# The individual rules, so a failure above says WHICH one broke.
Assert-True ($body.StartsWith("--BOUNDARY123`r`n"))  "the body opens with the delimiter and a CRLF"
Assert-True ($body.EndsWith("`r`n--BOUNDARY123--`r`n")) "it closes with CRLF, the delimiter, two dashes and a CRLF"
Assert-True ($body -match "filename=`"import\.ndjson`"") "the file part is named as a file, or Kibana ignores it"
Assert-True ($body -match 'name="file"')                 "the field is called 'file' - the name Kibana's API requires"
Assert-True ($body -match "Content-Type: application/ndjson`r`n`r`n") `
    "one blank line separates the part headers from the payload"

# A bare LF anywhere in the framing is the bug this exists to catch. The
# payload itself is LF-delimited ndjson and must be left exactly as it was, so
# the count is of LFs NOT preceded by a CR: two from the payload and no more.
$lfOnly = ([regex]::Matches($body, "(?<!`r)`n")).Count
Assert-Equal $lfOnly 2 "the framing uses CRLF throughout; only the ndjson's own newlines are bare LF"

# The payload must survive untouched, bytes and all.
Assert-True ($body.Contains($payload)) "the ndjson is embedded verbatim"

# Non-ASCII is the reason the payload is written as bytes and never through a
# string: PS 5.1 would send a string body as Latin-1 and corrupt it.
$u = New-MultipartFileBody -Content (Bytes "{`"host`":`"BuRO-PC`"}") -Boundary 'B'
Assert-True ((Text $u.Bytes).Contains('BuRO-PC')) "a non-ASCII payload round-trips as UTF-8"

# Byte-level: no UTF-8 BOM may be introduced ahead of the first delimiter. One
# would corrupt the first boundary and the part would never be found.
Assert-Equal $m.Bytes[0] ([byte]45) "the first byte is '-', not a byte-order mark"
Assert-Equal $m.Bytes[1] ([byte]45) "the second byte is the other dash of the delimiter"

# Length is the sum of the three pieces and nothing else - no stray padding.
$headLen = (Bytes ("--BOUNDARY123`r`nContent-Disposition: form-data; name=`"file`"; filename=`"import.ndjson`"`r`nContent-Type: application/ndjson`r`n`r`n")).Length
$tailLen = (Bytes "`r`n--BOUNDARY123--`r`n").Length
Assert-Equal $m.Bytes.Length ($headLen + (Bytes $payload).Length + $tailLen) `
    "the body is exactly head + payload + tail"

# An empty file still produces a well-formed body rather than a truncated one.
$e = New-MultipartFileBody -Content ([byte[]]@()) -Boundary 'B'
Assert-True ((Text $e.Bytes).EndsWith("`r`n--B--`r`n")) "an empty payload still closes the multipart properly"

# Two calls must not reuse a boundary, and the generated one must be safe to
# put in a header unquoted.
$b1 = (New-MultipartFileBody -Content (Bytes 'x')).Boundary
$b2 = (New-MultipartFileBody -Content (Bytes 'x')).Boundary
Assert-True ($b1 -ne $b2)            "each body gets its own boundary"
Assert-True ($b1 -match '^[0-9a-f]+$') "the generated boundary is hex, so it never needs quoting"

# A boundary that also occurs in the payload would end the part early. Nothing
# can stop a caller passing one, but the default must not collide by accident.
Assert-True (-not $payload.Contains($b1)) "the generated boundary does not occur in the payload"

# =================================================== version comparison =====
Assert-Equal (Compare-KibanaVersion '9.0.8' '9.0.8')  0  "equal versions compare equal"
Assert-Equal (Compare-KibanaVersion '9.0.9' '9.0.8')  1  "a newer patch is newer"
Assert-Equal (Compare-KibanaVersion '9.0.7' '9.0.8') -1  "an older patch is older"

# The two a string compare gets backwards, which is the whole reason this
# function exists rather than -lt on the text.
Assert-Equal (Compare-KibanaVersion '9.0.10' '9.0.8') 1 `
    "9.0.10 is NEWER than 9.0.8 - as text it would sort older"
Assert-Equal (Compare-KibanaVersion '10.0.0' '9.0.8') 1 `
    "10.0.0 is NEWER than 9.0.8 - as text it would sort older"
Assert-Equal (Compare-KibanaVersion '8.18.0' '9.0.8') -1 "8.18.0 is older, however big its minor"
Assert-Equal (Compare-KibanaVersion '9.1.0'  '9.0.8')  1 "a newer minor beats a bigger patch"

# Shapes a real /api/status returns.
Assert-Equal (Compare-KibanaVersion '9.0.8-SNAPSHOT' '9.0.8') 0 "a build suffix is ignored"
Assert-Equal (Compare-KibanaVersion '9.0' '9.0.0') 0 "a missing component counts as zero"
Assert-Equal (Compare-KibanaVersion '9' '9.0.8') -1 "9 alone is 9.0.0, which is older than 9.0.8"
Assert-Equal (Compare-KibanaVersion ' 9.0.8 ' '9.0.8') 0 "surrounding whitespace does not matter"

# Unparsable means "could not tell", never "older" - the tab asks rather than
# silently refusing a server it failed to read.
Assert-Equal (Compare-KibanaVersion '' '9.0.8')        $null "an empty version cannot be compared"
Assert-Equal (Compare-KibanaVersion $null '9.0.8')     $null "a null version cannot be compared"
Assert-Equal (Compare-KibanaVersion 'unknown' '9.0.8') $null "a non-numeric version cannot be compared"
Assert-Equal (Compare-KibanaVersion '9.0.8' 'x')       $null "an unparsable right side cannot be compared either"

# The gate the tab applies, spelled out: import only when target >= export.
foreach ($pair in @(@('9.0.8', $true), @('9.0.9', $true), @('9.1.0', $true),
                    @('10.0.0', $true), @('9.0.7', $false), @('8.18.0', $false))) {
    $cmp = Compare-KibanaVersion $pair[0] '9.0.8'
    Assert-Equal ($cmp -ge 0) $pair[1] "target $($pair[0]) against export 9.0.8: allowed = $($pair[1])"
}

# ====================================================== import summary ======
$resp = @'
{"success":false,"successCount":41,
 "successResults":[{"type":"dashboard","id":"hayabusa-overview-dashboard"}],
 "errors":[
   {"type":"lens","id":"hayabusa-panel-7","error":{"type":"conflict"}},
   {"type":"index-pattern","id":"hayabusa-evtx-dataview",
    "error":{"type":"unsupported_type","reason":"Unsupported saved object version"}}
 ]}
'@ | ConvertFrom-Json

$s = Get-KibanaImportSummary $resp
Assert-Equal $s.Success    $false "success is reported exactly as Kibana reported it"
Assert-Equal $s.Created    41     "successCount is the created count"
Assert-Equal $s.ErrorCount 2      "both per-object errors are kept"
Assert-Equal $s.Errors[0].Type      'lens'              "the failing object's type survives"
Assert-Equal $s.Errors[0].Id        'hayabusa-panel-7'  "the failing object's id survives"
Assert-Equal $s.Errors[0].ErrorType 'conflict'          "the error's own type survives"
Assert-Equal $s.Errors[1].ErrorType 'unsupported_type'  "so does the second one's"
Assert-Equal $s.Errors[1].Reason    'Unsupported saved object version' "the reason survives verbatim"
Assert-True  ($s.Errors[1].Text -match 'index-pattern/hayabusa-evtx-dataview') `
    "the log line names type and id, which is what the operator searches for"

# An error with no reason must still say something. Printing '' here is how a
# conflict turns into a blank log line nobody can act on.
Assert-True ($s.Errors[0].Reason -ne '') "an error carrying no reason falls back to the error object"

# The happy path.
$ok = Get-KibanaImportSummary (@'
{"success":true,"successCount":43,"errors":[]}
'@ | ConvertFrom-Json)
Assert-Equal $ok.Success    $true "a clean import reports success"
Assert-Equal $ok.Created    43    "all 43 objects counted"
Assert-Equal $ok.ErrorCount 0     "and no errors"

# Kibana omits errors[] entirely when there are none.
$noerr = Get-KibanaImportSummary (@'
{"success":true,"successCount":1}
'@ | ConvertFrom-Json)
Assert-Equal $noerr.ErrorCount 0 "a missing errors[] is not an error"

# Nothing at all - a torn response must not throw inside the handler.
$empty = Get-KibanaImportSummary $null
Assert-Equal $empty.Success    $false "a null response is not a success"
Assert-Equal $empty.Created    0      "and created nothing"
Assert-Equal $empty.ErrorCount 0      "and lists no errors"

# =========================================================== Kratos flow ====
$flow = @'
{"ui":{"action":"https://so/self-service/login?flow=abc",
 "nodes":[{"attributes":{"name":"identifier","value":""}},
          {"attributes":{"name":"csrf_token","value":"TOKEN-42"}},
          {"type":"text"}]}}
'@ | ConvertFrom-Json
Assert-Equal (Get-KratosCsrfToken $flow) 'TOKEN-42' "the csrf token is found among the flow's nodes"
Assert-Equal (Get-KratosCsrfToken $null) ''         "a missing flow yields an empty token, not a crash"
Assert-Equal (Get-KratosCsrfToken ('{"ui":{}}' | ConvertFrom-Json)) '' "a flow with no nodes yields nothing"

# ======================================= the delete guard (hayabusa- only) ==
$objs = @'
[{"type":"dashboard","id":"hayabusa-overview-dashboard"},
 {"type":"dashboard","id":"so-detections-overview"},
 {"type":"lens","id":"hayabusa-panel-1"},
 {"type":"index-pattern","id":"logs-import-so-dataview"},
 {"type":"search","id":"HAYABUSA-upper"},
 {"type":"lens","id":"xhayabusa-panel"},
 {"type":"lens","id":""}]
'@ | ConvertFrom-Json

$keep = Select-HayabusaSavedObjects $objs
Assert-Equal @($keep).Count 2 "only the two hayabusa- objects are selected for deletion"
Assert-True (@($keep | ForEach-Object { $_.id }) -contains 'hayabusa-overview-dashboard') "our dashboard is in"
Assert-True (@($keep | ForEach-Object { $_.id }) -contains 'hayabusa-panel-1')            "our lens is in"
Assert-True (@($keep | ForEach-Object { $_.id }) -notcontains 'so-detections-overview') `
    "Security Onion's own dashboard is never touched"
Assert-True (@($keep | ForEach-Object { $_.id }) -notcontains 'logs-import-so-dataview') `
    "its data view is never touched either"
Assert-True (@($keep | ForEach-Object { $_.id }) -notcontains 'HAYABUSA-upper') `
    "the prefix match is case-sensitive, as saved-object ids are"
Assert-True (@($keep | ForEach-Object { $_.id }) -notcontains 'xhayabusa-panel') `
    "the prefix must be at the START of the id"
$none = Select-HayabusaSavedObjects @()
$nul  = Select-HayabusaSavedObjects $null
Assert-Equal @($none).Count 0 "an empty list selects nothing"
Assert-Equal @($nul).Count  0 "a null list selects nothing"

# ================================================= counting what we import ==
# A Kibana export's last line is a summary, not an object, so a line count is
# always one too many - which is how the tab would promise 44 and deliver 43.
$tmp = Join-Path $env:TEMP ("kbimport_{0}.ndjson" -f [guid]::NewGuid().ToString('N'))
@'
{"type":"dashboard","id":"hayabusa-a","attributes":{}}
{"type":"lens","id":"hayabusa-b","attributes":{}}

{"excludedObjects":[],"excludedObjectsCount":0,"exportedCount":2,"missingRefCount":0}
'@ | Set-Content -LiteralPath $tmp -Encoding utf8
Assert-Equal (Get-NdjsonObjectCount $tmp) 2 "the trailing export summary is not counted as an object"
Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue

Assert-Equal (Get-NdjsonObjectCount 'C:\nope\missing.ndjson') 0 "a missing file counts zero rather than throwing"
Assert-Equal (Get-NdjsonObjectCount '') 0 "an empty path counts zero"

# The real file. 109 objects is what kibana\IMPORT.txt promises the operator.
$shipped = Join-Path (Split-Path -Parent $PSScriptRoot) 'kibana\hayabusa-kibana-objects.ndjson'
if (Test-Path -LiteralPath $shipped) {
    Assert-Equal (Get-NdjsonObjectCount $shipped) 171 "the shipped ndjson holds the 171 objects IMPORT.txt promises"
    $importTxt = Join-Path (Split-Path -Parent $PSScriptRoot) 'kibana\IMPORT.txt'
    Assert-True ((Get-Content -LiteralPath $importTxt -Raw) -match '\b171\b') "IMPORT.txt promises the same 171"
    # The raw-event hunting dashboard (2026-10-16) reads Security Onion's raw
    # imports: its own data view, timed by event.created (SO 2.4 files imports
    # under the import time), and every one of its panels on that data view.
    foreach ($f in $shipped, ($shipped -replace '\.ndjson$', '-8.7.ndjson')) {
        $all = @(Get-Content -LiteralPath $f -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json })
        $rawDv = @($all | Where-Object { $_.id -eq 'hayabusa-raw-dataview' })
        Assert-Equal $rawDv.Count 1 "$(Split-Path -Leaf $f): the raw-events data view is there"
        Assert-Equal $rawDv[0].attributes.timeFieldName 'event.created' "$(Split-Path -Leaf $f): timed by when the event happened"
        $dash = @($all | Where-Object { $_.id -eq 'hayabusa-raw-hunt-dashboard' })
        $lens = @($all | Where-Object { $_.type -eq 'lens' -and $_.id -like 'hayabusa-raw-*' -and $_.id -notlike 'hayabusa-raw-anomaly-*' })
        Assert-True ($dash.Count -eq 1 -and $lens.Count -eq 25) "$(Split-Path -Leaf $f): the raw hunt dashboard and its 25 panels"
        Assert-Equal @($lens | Where-Object { @($_.references | Where-Object { $_.id -ne 'hayabusa-raw-dataview' }).Count }).Count 0 `
            "$(Split-Path -Leaf $f): every raw panel reads the raw data view, none the detections"
    }
    # The Anomaly Hunt dashboards (2026-10-17): each on its own data view, and
    # that data view carrying every op.* field scripts\anomaly_runtime_fields.py
    # defines - they live ONLY in the export, like op.DetectionDay below.
    $py = Get-Command python -ErrorAction SilentlyContinue
    foreach ($f in $shipped, ($shipped -replace '\.ndjson$', '-8.7.ndjson')) {
        $all = @(Get-Content -LiteralPath $f -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json })
        foreach ($a in @(@('hayabusa-raw-anomaly-dashboard', 'hayabusa-raw-anomaly-', 'hayabusa-raw-dataview', 'raw'),
                         @('hayabusa-anomaly-dashboard', 'hayabusa-anomaly-', 'hayabusa-evtx-dataview', 'detections'))) {
            Assert-Equal @($all | Where-Object { $_.id -eq $a[0] }).Count 1 "$(Split-Path -Leaf $f): $($a[0]) is there"
            $al = @($all | Where-Object { $_.type -eq 'lens' -and $_.id.StartsWith($a[1]) })
            Assert-True ($al.Count -ge 28) "$(Split-Path -Leaf $f): with its panels ($($al.Count))"
            Assert-Equal @($al | Where-Object { @($_.references | Where-Object { $_.id -ne $a[2] }).Count }).Count 0 "$(Split-Path -Leaf $f): every $($a[1])* panel reads $($a[2]) only"
            if ($py) {
                $want = @(((& { $ErrorActionPreference = 'Continue'; & $py.Source -I (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\anomaly_runtime_fields.py') --view $a[3] 2>$null }) -join "`n" | ConvertFrom-Json).PSObject.Properties.Name)
                $dv = @($all | Where-Object { $_.id -eq $a[2] })[0]
                $have = @(($dv.attributes.runtimeFieldMap | ConvertFrom-Json).PSObject.Properties.Name)
                Assert-Equal (@($want | Where-Object { $_ -notin $have }) -join ',') '' "$(Split-Path -Leaf $f): $($a[2]) carries every anomaly runtime field"
            }
        }
    }
    # The Results Summary's busiest-day table groups by a runtime field that
    # lives ONLY in the exported data view - no generator recreates it - so a
    # re-export from a Kibana without it would silently empty that table.
    foreach ($f in $shipped, ($shipped -replace '\.ndjson$', '-8.7.ndjson')) {
        $dv = Get-Content -LiteralPath $f -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json } |
              Where-Object { $_.id -eq 'hayabusa-evtx-dataview' } | Select-Object -First 1
        Assert-True (($dv.attributes.runtimeFieldMap | ConvertFrom-Json).PSObject.Properties.Name -contains 'op.DetectionDay') `
            "$(Split-Path -Leaf $f): the data view carries op.DetectionDay (Results Summary)"
    }
    # Kibana 8.7's metric tile cannot show a date (First / Last detection drew
    # "Unsupported column format: date" on a live 8.7.0, 2026-10-20), so the
    # converter turns those into 8.7's legacy metric.
    $dateMetrics = @(Get-Content -LiteralPath ($shipped -replace '\.ndjson$', '-8.7.ndjson') -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json } |
        Where-Object { $_.type -eq 'lens' -and $_.attributes.visualizationType -eq 'lnsMetric' } | Where-Object {
            $v = $_.attributes.state.visualization
            $_.attributes.state.datasourceStates.formBased.layers.($v.layerId).columns.($v.metricAccessor).dataType -eq 'date' })
    Assert-Equal $dateMetrics.Count 0 "hayabusa-kibana-objects-8.7.ndjson: no metric tile shows a date (8.7 cannot draw one)"
    $legacy = @(Get-Content -LiteralPath ($shipped -replace '\.ndjson$', '-8.7.ndjson') -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json } |
        Where-Object { $_.id -in 'hayabusa-summary-first', 'hayabusa-summary-last' -and $_.attributes.visualizationType -eq 'lnsLegacyMetric' })
    Assert-Equal $legacy.Count 2 "hayabusa-kibana-objects-8.7.ndjson: First / Last detection are 8.7 legacy metrics"
}

# ==================================== and the tab must use all of the above ==
# Each of these was a separate way for the tab to silently half-work, so the
# checks have to be IN it, not just available to it.
$kb = Join-Path (Split-Path -Parent $PSScriptRoot) 'code\wpf-kibana.ps1'
Assert-True (Test-Path -LiteralPath $kb) "the Dashboards tab fragment exists"
$src = Get-Content -LiteralPath $kb -Raw

Assert-True ($src -match 'New-MultipartFileBody')    "the tab builds its multipart body with the tested builder"
Assert-True ($src -match 'Compare-KibanaVersion')    "the tab compares versions numerically"
Assert-True ($src -match 'Get-KibanaImportSummary')  "the tab reports the import per object"
Assert-True ($src -match 'Select-HayabusaSavedObjects') "the delete path goes through the prefix guard"
Assert-True ($src -match 'Get-KratosCsrfToken')      "the login reads the csrf token out of the flow"
Assert-True ($src -match 'kbn-xsrf')                 "every Kibana call carries kbn-xsrf"
Assert-True ($src -match 'Get-AuthHeader')           "basic auth rides on top of the session cookie"
Assert-True ($src -match 'self-service/login/browser') "the session comes from a Kratos browser login"
# Security Onion's web front end (443) presents a different certificate from
# Elasticsearch (9200), so the Upload tab's pin can never match it - that was
# the "SSL error" on import while Verify on the Upload tab was green.
Assert-True ($src -match 'Get-ServerCertThumbprint\s+\S+\s+443') "the tab fetches the web front end's own certificate, on 443"
Assert-True ($src -match 'Set-TlsTrust -Mode .Pin. -PinnedThumbprint') "and pins it, through the compiled callback"
Assert-True ($src -match 'rbTlsSkip')                 "Skip verification is still the Upload tab's one switch"
Assert-True ($src -notmatch 'Set-TlsTrustFromUi')     "the Upload tab's 9200-only pin is not what guards 443"
$up = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'code\wpf-upload.ps1') -Raw
Assert-True ($up -match 'web_pin')                    "the web front end's fingerprint is remembered in importer.conf"
Assert-True ($src -notmatch 'ServerCertificateValidationCallback\s*=\s*\{') `
    "no scriptblock certificate callback - it throws on the worker thread"
Assert-True ($src -match 'Get-UploadPassword')       "the password is read through the Upload tab's getter"
Assert-True ($src -match '(?s)MessageBoxButton.*YesNo') "REMOVE confirms before deleting"
Assert-True ($src -match '\$script:Busy')            "the tab sets the shared busy flag"
Assert-True ($src -match 'Invoke-UiPump')            "and pumps the dispatcher around the slow calls"
Assert-True ($src -match '(?i)hayabusa-\*')          "the tab says the dashboards need a hayabusa-* index"
Assert-True ($src -match '(?i)time picker')          "and that the time picker has to cover the data"

# The shell has to load it, and give it something to load into.
$shell = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'code\HayabusaMissionTool.ps1') -Raw
Assert-True ($shell -match "ScrollViewer x:Name=`"tabKibana`"") "the shell has a Dashboards tab to fill"
Assert-True ($shell -match "'wpf-kibana\.ps1'")                 "the shell dot-sources the fragment"
Assert-True ($shell -match "'tabKibana'")                       "and binds the ScrollViewer to a variable"
Assert-True ($src -match 'Anomaly Hunt') "the tab's hint names the Anomaly Hunt dashboards"
