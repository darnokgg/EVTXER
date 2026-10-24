# tests/ApiKey.Tests.ps1
#
# A scoped Elasticsearch API key for the upload (TODO item 1, built
# 2026-10-17). Leave Username empty and the password
# box holds an API key: sent as "Authorization: ApiKey ...". A key limited to
# hayabusa-* cannot install the index template (cluster-wide), so a NEW index
# is then created with the template's settings and mappings itself.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# ---- the header ----
Assert-Equal (Get-AuthHeader 'bob' 'pw').Authorization ('Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('bob:pw'))) "a username sends Basic auth, as before"
Assert-Equal (Get-AuthHeader '' 'kid:ksecret').Authorization ('ApiKey ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('kid:ksecret'))) "no username: an id:key pair is sent as an API key"
Assert-Equal (Get-AuthHeader '' 'a2lkOmtzZWNyZXQ=').Authorization 'ApiKey a2lkOmtzZWNyZXQ=' "the encoded form Kibana shows is sent as it is"
Assert-Equal (Get-AuthHeader '' ' a2lkOmtzZWNyZXQ= ').Authorization 'ApiKey a2lkOmtzZWNyZXQ=' "spaces pasted around a key are dropped (a key never holds one)"

# ---- the form ----
Assert-Equal ((Get-MissingConnectionFields 'es' '' 'key' -ApiKeyOk) -join ',') '' "the Upload tab accepts an empty username when a key is given"
Assert-Equal ((Get-MissingConnectionFields 'es' '' '' -ApiKeyOk) -join ',') 'password or API key' "and names both when neither is there"
Assert-Equal ((Get-MissingConnectionFields 'es' '' 'key') -join ',') 'username' "other forms still need a username"

# ---- what the activity log shows: nothing taken from the secret ----
# A password typed with the username forgotten looks like an id:key pair;
# reading an "id" out of it put half the password in the log (review).
Assert-Equal (Get-EsAccountLabel ' bob ') 'bob' "a username is the account"
Assert-Equal (Get-EsAccountLabel '') 'API key' "no username: just 'API key'"

# ---- creating an index without the template ----
$tpl = Get-Content "$PSScriptRoot\..\code\index-template.json" -Raw
$body = Get-IndexCreateBody $tpl | ConvertFrom-Json
Assert-Equal $body.mappings.properties.event.properties.id.type 'keyword' "the create body carries the template's mappings"
Assert-Equal "$($body.settings.'mapping.total_fields.limit')" '10000' "and its settings"
Assert-True (-not $body.index_patterns) "but not the template's own fields"

$src = Get-ToolSource
Assert-True ($src -match "Get-MissingConnectionFields \`$txtHost\.Text \`$txtUser\.Text \(Get-UploadPassword\) -ApiKeyOk") "the Upload tab lets the username stay empty for a key"
Assert-True (-not ($src -match "-Account \`$txtUser\.Text\.Trim\(\)")) "no activity-log row takes the account straight from the username box"
Assert-True ($src -match "A key cannot import dashboards") "the Kibana tab says a key cannot import dashboards"

# ---- live: a real hayabusa-* key against the lab Elasticsearch ----
$base = $env:TEST_ES_BASE
if (-not $base) { Write-Host "  [SKIP] TEST_ES_BASE not set - live API key test skipped" -ForegroundColor Yellow; return }
Set-TlsTrust -Mode 'Skip'
$admin = Get-AuthHeader $(if ($env:TEST_ES_USER) { $env:TEST_ES_USER } else { 'admin' }) $env:TEST_ES_PASSWORD
$stamp = Get-Date -Format 'yyyyMMddHHmmss'
$idx = "hayabusa-keytest-$stamp"
$role = '{"name":"evtxer-keytest-' + $stamp + '","expiration":"1h","role_descriptors":{"hayabusa":{"cluster":["monitor"],"index":[{"names":["hayabusa-*"],"privileges":["create_index","manage","read","write","view_index_metadata"]}]}}}'
$k = Invoke-EsJson -Uri "$base/_security/api_key" -Method Post -Headers $admin -ContentType 'application/json' -Body $role -TimeoutSec 30
$keyH = Get-AuthHeader '' $k.encoded
$dir = Join-Path ([IO.Path]::GetTempPath()) ("keytest-$stamp")
New-Item -ItemType Directory -Path $dir -Force | Out-Null
# The lab's template is put back at the end; without it this proves the
# fallback really creates the index with the right mappings.
$saved = $null
try { $saved = Invoke-EsJson -Uri "$base/_index_template/hayabusa-evtx" -Method Get -Headers $admin -TimeoutSec 30 } catch { }
try {
    if ($saved) { Invoke-EsJson -Uri "$base/_index_template/hayabusa-evtx" -Method Delete -Headers $admin -TimeoutSec 30 | Out-Null }
    $lines = foreach ($n in 1, 2) {
        $hit = @{ Computer = 'A'; Channel = 'Security'; RecordID = $n; EventID = 4624; Timestamp = '2026-10-01T10:00:00.000000Z'
                  RuleID = 'r1'; RuleTitle = 'Logon'; Level = 'low'; Details = @{ TgtUser = 'bob' } } | ConvertTo-Json -Depth 5 | ConvertFrom-Json
        ConvertTo-EcsDocument $hit 'keytest' | ConvertTo-Json -Depth 12 -Compress
    }
    $ecs = Join-Path $dir 'ecs.jsonl'
    [IO.File]::WriteAllLines($ecs, [string[]]$lines)
    $said = New-Object System.Collections.Generic.List[string]
    $r = Publish-EcsFile -Base $base -Headers $keyH -Index $idx -Path $ecs -Template $tpl -ImportId 'keytest' -Log { param($t, $kind) $said.Add($t) }
    Assert-Equal $r.Outcome 'Success' "an upload with a hayabusa-* key succeeds"
    Assert-Equal $r.Created 2 "and creates both detections"
    Assert-True (@($said | Where-Object { $_ -match 'may not change index templates' }).Count -eq 1) "it says why the template was not installed"
    $map = Invoke-EsJson -Uri "$base/$idx/_mapping" -Method Get -Headers $admin -TimeoutSec 30
    Assert-Equal $map.$idx.mappings.properties.event.properties.id.type 'keyword' "the new index still got the template's mappings"
    $refused = $false
    try { Invoke-EsJson -Uri "$base/other-keytest-$stamp" -Method Put -Headers $keyH -TimeoutSec 30 | Out-Null } catch { $refused = $_.Exception.Message -match '403' }
    Assert-True $refused "the key cannot create any index outside hayabusa-*"
}
finally {
    # Each step on its own, the key first: one failing must not leave a live key.
    try { Invoke-EsJson -Uri "$base/_security/api_key" -Method Delete -Headers $admin -ContentType 'application/json' -Body (@{ ids = @($k.id) } | ConvertTo-Json -Compress) -TimeoutSec 30 | Out-Null } catch { }
    if ($saved) {
        try { Invoke-EsJson -Uri "$base/_index_template/hayabusa-evtx" -Method Put -Headers $admin -ContentType 'application/json' -Body $tpl -TimeoutSec 30 | Out-Null } catch { }
    }
    try { Invoke-EsJson -Uri "$base/$idx" -Method Delete -Headers $admin -TimeoutSec 30 | Out-Null } catch { }
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}
