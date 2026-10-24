# tests/LogCallback.Tests.ps1
#
# Regression for a bug that made remote collection fail on the first line it
# tried to log:
#
#   COLLECTION FAILED: The property 'SelectionStart' cannot be found on this
#   object. Verify that the property exists and can be set.
#
# Write-Log writes to $log, the RichTextBox at script scope.
# Invoke-EvtxCollection takes a [scriptblock]$Log callback. PowerShell variable
# names are CASE-INSENSITIVE and lookup is DYNAMICALLY SCOPED, so when the
# callback ran, Write-Log searched its caller chain for "$log", found the
# collector's $Log *parameter* - a scriptblock - and tried to set
# SelectionStart on it.
#
# Collector.Contract.Tests only asserted the parameter existed; it never
# invoked it, so nothing caught this and the collection path had never worked.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# A stand-in for the RichTextBox, at script scope exactly like the real one.
$script:log = [pscustomobject]@{
    TextLength     = 0
    SelectionStart = 0
    SelectionColor = $null
    Written        = New-Object System.Collections.ArrayList
}
Add-Member -InputObject $script:log -MemberType ScriptMethod -Name AppendText  -Value { param($t) [void]$this.Written.Add($t) }
Add-Member -InputObject $script:log -MemberType ScriptMethod -Name ScrollToCaret -Value { }

# The same shape as the real Write-Log, including the property it fell over on.
function Write-LogUnderTest([string]$Text) {
    $script:log.SelectionStart = $script:log.TextLength
    $script:log.SelectionColor = 'White'
    $script:log.AppendText($Text)
    $script:log.ScrollToCaret()
}

# A function with a scriptblock parameter named exactly as the collector's was.
# This is the trap: $Log here and $log above are the same name to PowerShell.
function Invoke-WithShadowingParam {
    param([scriptblock]$Log)
    & $Log 'first line'
}

# And with the parameter renamed, which is how the collector reads now.
function Invoke-WithSafeParam {
    param([scriptblock]$LogWriter)
    & $LogWriter 'first line'
}

$script:log.Written.Clear()
Invoke-WithSafeParam -LogWriter { param($m) Write-LogUnderTest $m }
Assert-Equal $script:log.Written.Count 1 "a callback with a non-colliding parameter name logs fine"

# The real assertion: the shipped code must not reintroduce the collision.
$collector = Get-Content (Join-Path $PSScriptRoot '..\code\EvtxCollector.ps1') -Raw
Assert-True ($collector -notmatch '\[scriptblock\]\$Log\b') `
    "the collector's callback parameter is not named -Log (it shadows the `$log RichTextBox)"
Assert-True ($collector -match '\[scriptblock\]\$LogWriter') `
    "the collector's callback parameter is -LogWriter"

# Write-Log must address the RichTextBox at script scope, so no caller's local
# variable can shadow it whatever it is called.
$tool = Get-ToolSource
# WPF writes into a FlowDocument rather than setting SelectionStart, but the
# scoping rule is the same one and was learned the same way.
Assert-True ($tool -match '\$script:log\.Document') `
    "Write-Log addresses `$script:log explicitly, not an inherited `$log"
Assert-True ($tool -notmatch '(?m)^\s+\$log\.Document') `
    "Write-Log no longer relies on dynamic scope to find the log box"
