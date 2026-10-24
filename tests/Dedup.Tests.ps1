# tests/Dedup.Tests.ps1
#
# Duplicates are decided per DETECTION, by Elasticsearch, from a fixed id.
# The old rule was per host: a host already in the index was skipped (losing
# the new detections of a re-pull two weeks later) or replaced (losing the old
# ones that had since rolled out of the target's log). Now the same detection
# always gets the same _id, the upload sends "create", and Elasticsearch
# refuses (409) only the ones it already holds.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

function New-Hit([hashtable]$Over) {
    $h = @{
        Computer = 'WS01'; Channel = 'Security'; RecordID = 5809; EventID = 4624
        Timestamp = '2019-04-27T21:04:25.733401Z'; RuleID = '0b2a7f12-0000-4000-8000-000000000001'
        RuleTitle = 'Logon (Network)'; Level = 'low'; EvtxFile = 'C:\evtx\WS01_20261001\Security.evtx'
    }
    foreach ($k in $Over.Keys) { $h[$k] = $Over[$k] }
    $h | ConvertTo-Json | ConvertFrom-Json
}

# ---- the id ----
$id = Get-DetectionId (New-Hit @{})
Assert-Equal $id 'f8429792ca631a08d51adfb3db062c03c7305db4' "the id is SHA-1 of Computer|Channel|RecordID|EventID|Timestamp|RuleID|RuleTitle (pinned: Python builds the same string)"
Assert-Equal (Get-DetectionId (New-Hit @{ EvtxFile = 'D:\archive\WS01_20261015\Security.evtx' })) $id "a second copy of the same logs gives the same id - where the file landed is not part of it"
Assert-True ((Get-DetectionId (New-Hit @{ RuleID = 'other' })) -ne $id)  "the same record matched by another rule is another detection"
Assert-True ((Get-DetectionId (New-Hit @{ RecordID = 5810 })) -ne $id)   "another record is another detection"
Assert-True ((Get-DetectionId (New-Hit @{ Computer = 'WS02' })) -ne $id) "another host is another detection"
Assert-True ((Get-DetectionId (New-Hit @{ RecordID = $null })) -match '^[0-9a-f]{40}$') "a detection with no RecordID still gets an id"

# ---- written first in event, readable without parsing ----
$ecs  = ConvertTo-EcsDocument (New-Hit @{}) 'testid'
$line = $ecs | ConvertTo-Json -Depth 12 -Compress
Assert-Equal $ecs.event.id $id                     "the ECS document carries the id as event.id"
Assert-Equal (Get-EcsLineId $line) $id             "the upload reads it back from the converter's line without parsing"
Assert-Equal (Get-EcsLineId ('{"@timestamp":"x","event": {"id": "' + $id + '", "kind": "alert"}}')) $id "the Python converter's spaced JSON is read too"
Assert-Equal (Get-EcsLineId '{"event":{"kind":"alert"},"host":{"name":"a"}}') $null "a line from before event.id has none"
Assert-Equal (Get-EcsLineId ('{"message":"\"event\":{\"id\":\"' + $id + '\"}","event":{"kind":"alert"}}')) $null "the same text inside an escaped string value is not mistaken for the id"

# ---- the bulk action ----
Assert-Equal (New-BulkActionLine 'hayabusa-x' $id) ('{"create":{"_index":"hayabusa-x","_id":"' + $id + '"}}') "create with the detection id as _id"
Assert-Equal (New-BulkActionLine 'hayabusa-x' $null) '{"create":{"_index":"hayabusa-x"}}' "no id: Elasticsearch assigns one, as before"
$a = New-BulkActionLine 'hayabusa-x' $id | ConvertFrom-Json
Assert-Equal $a.create._id $id "the action line is valid JSON"

# ---- counting the answer ----
$resp = '{"items":[{"create":{"status":201}},{"create":{"status":409,"error":{"type":"version_conflict_engine_exception","reason":"already exists"}}},{"create":{"status":429,"error":{"type":"es_rejected_execution_exception","reason":"queue full"}}},{"create":{"status":201}}]}' | ConvertFrom-Json
$t = Get-BulkTally $resp
Assert-Equal $t.Created 2   "201 counts as created"
Assert-Equal $t.Duplicate 1 "409 counts as already in the index, not as a failure"
Assert-Equal $t.Failed 1    "anything else is a failure"
Assert-Equal $t.Errors[0].type 'es_rejected_execution_exception' "and its error is kept for the log"
Assert-Equal (Get-BulkTally ('{"items":[{"index":{"status":201}}]}' | ConvertFrom-Json)).Created 1 "an index action's answer is read too"
# Found driving the real Upload tab: @() around an empty List[object] throws
# "Argument types do not match" in PowerShell 5.1, after every document had
# gone in. The upload does exactly that with a clean batch's errors.
$clean = Get-BulkTally ('{"items":[{"create":{"status":201}}]}' | ConvertFrom-Json)
Assert-Equal @($clean.Errors).Count 0 "a clean batch's errors can be wrapped in @() - the upload does"
Assert-True (${function:Send-EcsFile}.ToString() -match 'Errors = @\(\)') "Send-EcsFile keeps its errors in a plain array too"

# ---- the upload uses all of it ----
$upload = Get-Content "$PSScriptRoot\..\code\wpf-upload.ps1" -Raw
$send   = ${function:Send-EcsFile}.ToString()
# The Upload tab and the job queue both upload through Publish-EcsFile.
$publish = ${function:Publish-EcsFile}.ToString()
Assert-True ($upload -match 'Publish-EcsFile -Base' -and $publish -match 'Send-EcsFile -Base') "the upload sends through Send-EcsFile"
Assert-True ($send -match 'New-BulkActionLine \$Index \(Get-EcsLineId \$line\)') "each line goes under its own detection id"
Assert-True ($send -match '_bulk\?\$\(\$script:BulkFilterPath\)')             "_bulk is asked for the trimmed answer"
Assert-True ($send -match 'Get-BulkTally')                                     "duplicates are counted apart from failures"
Assert-True ($upload -notmatch 'chkReplace|Get-DedupPlan|Group-DocsByHost')     "the per-host skip/replace is gone"

$tmpl = Get-Content "$PSScriptRoot\..\code\index-template.json" -Raw | ConvertFrom-Json
Assert-Equal $tmpl.template.mappings.properties.event.properties.id.type 'keyword' "event.id is mapped as a keyword"

# ---- refused for its fields: retried, not failed ----
$shapes = '{"items":[{"create":{"status":400,"error":{"type":"document_parsing_exception","reason":"failed to parse field [winlog.event_data.Foo]"}}},{"create":{"status":400,"error":{"type":"illegal_argument_exception","reason":"Limit of total fields [10000] has been exceeded"}}},{"create":{"status":400,"error":{"type":"illegal_argument_exception","reason":"something else"}}}]}' | ConvertFrom-Json
$t = Get-BulkTally $shapes
Assert-Equal (@($t.Refused) -join ',') '0,1' "a mapping clash and the field limit are refusals to retry without event fields"
Assert-Equal $t.Failed 1 "any other 400 is a plain failure"
$line = '{"event":{"id":"x"},"tags":["a"],"winlog":{"channel":"Security","event_data":{"Foo":{"n":1}}}}'
$o = Remove-EventDataFromLine $line | ConvertFrom-Json
Assert-True ($null -eq $o.winlog.event_data -and $o.winlog.channel -eq 'Security') "the retry drops only winlog.event_data"
Assert-Equal (@($o.tags) -join ',') 'a,evtxer-fields-refused' "and tags the detection"

# ---- review 2026-10-15 ----
# "Update detections already in the index": index instead of create - the same
# id replaced, never doubled; 200 = updated, 201 = new.
Assert-Equal (New-BulkActionLine 'hayabusa-x' $id -Overwrite) ('{"index":{"_index":"hayabusa-x","_id":"' + $id + '"}}') "Update: the action overwrites by detection id"
Assert-Equal (New-BulkActionLine 'hayabusa-x' $null -Overwrite) '{"create":{"_index":"hayabusa-x"}}' "without an id there is nothing to overwrite"
$t = Get-BulkTally ('{"items":[{"index":{"status":200}},{"index":{"status":201}}]}' | ConvertFrom-Json)
Assert-Equal "$($t.Created)/$($t.Updated)" '1/1' "200 is an updated detection, 201 a new one"
# A line whose braces balance but is not JSON: a counted failure, not an
# exception half way through the upload.
Assert-Equal (Remove-EventDataFromLine '{"broken": }') $null "the retry gives up on a line that is not JSON instead of throwing"
# An index from before v37 learns the new mappings when appended into.
$patch = Get-IndexMappingPatch (Get-Content "$PSScriptRoot\..\code\index-template.json" -Raw) | ConvertFrom-Json
Assert-Equal $patch.properties.event.properties.id.type 'keyword' "the patch maps event.id"
Assert-Equal $patch.properties.winlog.properties.event_data.dynamic $true "and winlog.event_data"
Assert-Equal @($patch.dynamic_templates).Count 5 "with the keyword dynamic templates"
$upload = Get-Content "$PSScriptRoot\..\code\wpf-upload.ps1" -Raw
Assert-True ($publish -match '_mapping" -Method Put' -and $publish -match 'Get-IndexMappingPatch') "the upload patches an existing index"
Assert-True ($publish -match '\$check\.ImportIds') "the count check asks about the file's own import.ids"
Assert-True ($upload -match 'chkRefresh' -and $upload -match '-Overwrite:\$refresh') "the Update checkbox reaches Send-EcsFile"
