# tests/IndexGuard.Tests.ps1
#
# The hayabusa- prefix guard is the only thing standing between this tool and
# Security Onion's own indices - in particular logs-import-so, which may hold
# evidence other people depend on.
#
# Until now it was three copy-pasted `if (-not $idx.StartsWith('hayabusa-'))`
# statements in the GUI with no test at all. Every other invariant in this
# project got one; the highest-stakes did not. Duplicated logic drifts - one
# copy gets fixed, the others do not, and nothing notices.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# ---- the names the tool is allowed to write ----
Assert-True (Test-HayabusaIndexName 'hayabusa-evtx-samples')     "the sample index is allowed"
Assert-True (Test-HayabusaIndexName 'hayabusa-dc01-20260908')    "a generated mission name is allowed"
Assert-True (Test-HayabusaIndexName 'hayabusa-a')                "the shortest valid name is allowed"

# ---- the ones that matter: Security Onion's own data ----
Assert-True (-not (Test-HayabusaIndexName 'logs-import-so'))     "logs-import-so is refused"
Assert-True (-not (Test-HayabusaIndexName '.kibana'))            "the Kibana saved-object index is refused"
Assert-True (-not (Test-HayabusaIndexName 'so-logs-zeek'))       "a Security Onion managed index is refused"
Assert-True (-not (Test-HayabusaIndexName '*'))                  "a bare wildcard is refused"
Assert-True (-not (Test-HayabusaIndexName '_all'))               "the _all alias is refused"

# ---- near misses, which is where a hand-rolled StartsWith gets it wrong ----
Assert-True (-not (Test-HayabusaIndexName 'hayabusa'))           "the prefix without its dash is refused"
Assert-True (-not (Test-HayabusaIndexName 'hayabusa-'))          "the prefix with nothing after it is refused"
Assert-True (-not (Test-HayabusaIndexName 'xhayabusa-evtx'))     "the prefix must be at the start"
Assert-True (-not (Test-HayabusaIndexName ' hayabusa-evtx'))     "a leading space does not sneak past"
Assert-True (-not (Test-HayabusaIndexName 'HAYABUSA-evtx')) `
    "an uppercase prefix is refused - Elasticsearch index names must be lowercase"

# ---- Elasticsearch's own naming rules ----
Assert-True (-not (Test-HayabusaIndexName 'hayabusa-Evtx')) "an uppercase letter anywhere is refused"
Assert-True (-not (Test-HayabusaIndexName 'hayabusa-a b'))  "a space in the name is refused"
Assert-True (-not (Test-HayabusaIndexName 'hayabusa-a/b'))  "a slash is refused"
Assert-True (-not (Test-HayabusaIndexName 'hayabusa-a*'))   "a wildcard inside the name is refused"
Assert-True (-not (Test-HayabusaIndexName 'hayabusa-a,b'))  "a comma is refused - it would address two indices"
Assert-True (Test-HayabusaIndexName 'hayabusa-a.b_c-d')     "dot, underscore and dash are allowed"

# ---- nothing at all ----
Assert-True (-not (Test-HayabusaIndexName ''))     "an empty name is refused"
Assert-True (-not (Test-HayabusaIndexName $null))  "a null name is refused"

# ---- and the GUI must actually use it, in every place it decides ----
# Three separate code paths each made this call: Check availability, the upload
# pre-flight, and the upload itself. All three have to go through one function
# or the drift starts again.
$tool = Get-ToolSource
Assert-True ($tool -notmatch "StartsWith\('hayabusa-'\)") `
    "no hand-rolled StartsWith guard remains in the tool"
$uses = ([regex]::Matches($tool, 'Test-HayabusaIndexName')).Count
Assert-True ($uses -ge 3) "all three decision points call the shared guard (found $uses)"
