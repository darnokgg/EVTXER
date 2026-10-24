# tests/DiskSpace.Tests.ps1
#
# ALL mode pulls every .evtx on the host - 2-20+ GB each, and the tab says so.
# A collection that fills the disk half way through is the worst outcome
# available: it costs the whole transfer window, leaves a folder that looks like
# evidence but is not, and the operator finds out from a copy error rather than
# from anything that mentions space. The estimate only has to be honest about
# its own precision - it is a pre-flight warning, not an accounting.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$GB = 1GB

# ---- DFIR: the preset is bounded, so the estimate is too ----
$dfir = Get-CollectSpaceEstimate -Category 'DFIR' -TargetCount 1
Assert-True ($dfir.Bytes -gt 0)          "DFIR estimates something per host"
Assert-True ($dfir.Bytes -lt 5 * $GB)    "the DFIR estimate stays in the hundreds of MB, not tens of GB"

# ---- it scales with the number of hosts ----
$one = Get-CollectSpaceEstimate -Category 'DFIR' -TargetCount 1
$ten = Get-CollectSpaceEstimate -Category 'DFIR' -TargetCount 10
Assert-Equal $ten.Bytes ($one.Bytes * 10) "ten hosts need ten times the room"

# ---- ALL is the case this exists for ----
$all = Get-CollectSpaceEstimate -Category 'All' -TargetCount 1
Assert-True ($all.Bytes -ge 8 * $GB)  "ALL budgets for the 2-20 GB the tab warns about"
Assert-True ($all.Bytes -gt $dfir.Bytes * 10) "ALL is budgeted far above DFIR"

# ---- Custom is priced per log, not per preset ----
$c1 = Get-CollectSpaceEstimate -Category 'Custom' -TargetCount 1 -LogCount 1
$c6 = Get-CollectSpaceEstimate -Category 'Custom' -TargetCount 1 -LogCount 6
Assert-True ($c6.Bytes -gt $c1.Bytes) "six custom logs need more room than one"

# ---- the verdict ----
# Free space is what the caller measured; the estimate is what we think it
# needs. Three outcomes, because "not enough" and "barely enough" call for
# different words.
$ok = Test-CollectSpace -FreeBytes (200 * $GB) -NeedBytes (10 * $GB)
Assert-Equal $ok.Level 'Ok'          "plenty of room is not worth mentioning"
Assert-True  $ok.CanProceed          "and it does not block"

$tight = Test-CollectSpace -FreeBytes (12 * $GB) -NeedBytes (10 * $GB)
Assert-Equal $tight.Level 'Tight'    "a 20% margin is tight, not fine"
Assert-True  $tight.CanProceed       "tight still proceeds - the estimate is not a measurement"
Assert-True  ($tight.Message -match '(?i)gb') "the message quantifies it in GB"

$short = Test-CollectSpace -FreeBytes (2 * $GB) -NeedBytes (10 * $GB)
Assert-Equal $short.Level 'Short'    "less room than the estimate is Short"
Assert-True  $short.CanProceed       "even Short only warns: the estimate can be wrong, the operator decides"
Assert-True  ($short.Message -match '(?i)free|space') "the message says what the problem is"

# ---- an unmeasurable drive must not invent a verdict ----
# Get-PSDrive returns nothing usable for some UNC and mapped paths. Guessing
# there would either block a fine collection or bless a doomed one.
$unknown = Test-CollectSpace -FreeBytes -1 -NeedBytes (10 * $GB)
Assert-Equal $unknown.Level 'Unknown' "an unmeasurable destination is Unknown, not Ok"
Assert-True  $unknown.CanProceed      "and it never blocks on a number it does not have"

# ---- the numbers in the message are the numbers it was given ----
$m = Test-CollectSpace -FreeBytes (3 * $GB) -NeedBytes (60 * $GB)
Assert-True ($m.Message -match '60')  "the estimate appears in the message"
Assert-True ($m.Message -match '3')   "so does the free space"
