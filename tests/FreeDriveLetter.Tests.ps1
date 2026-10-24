# tests/FreeDriveLetter.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# Collection hard-coded T: and Verify Access hard-coded V:, and both did
#
#     if (Get-PSDrive -Name $drv) { Remove-PSDrive -Name $drv -Force }
#
# on the ANALYST'S OWN workstation. If the examiner had T: mapped to a case
# share, running a collection silently tore it down and never put it back.
# Picking a letter nobody is using costs one call and removes the whole class
# of problem - no save/restore dance to get wrong.

# ---- skips what is in use, takes the first that is free ----
Assert-Equal (Get-FreeDriveLetter -Candidates @('T','U','V') -InUse @('T'))     'U' "the first free candidate is chosen"
Assert-Equal (Get-FreeDriveLetter -Candidates @('T','U','V') -InUse @('T','U')) 'V' "several taken letters are all skipped"
Assert-Equal (Get-FreeDriveLetter -Candidates @('T','U','V') -InUse @())        'T' "nothing in use means the first candidate"

# ---- drive letters are not case-sensitive, and neither is this ----
# Get-PSDrive reports 'C'; a candidate list written 'c' must still collide.
Assert-Equal (Get-FreeDriveLetter -Candidates @('T','U') -InUse @('t')) 'U' "a lowercase in-use letter still blocks its candidate"
Assert-Equal (Get-FreeDriveLetter -Candidates @('t','u') -InUse @('T')) 'u' "a lowercase candidate is still blocked by its uppercase twin"

# ---- no letter left ----
# Returning $null rather than throwing: the caller reports one clean failure
# for that host and moves to the next, which is how every other per-host
# problem in the collector behaves.
Assert-True ($null -eq (Get-FreeDriveLetter -Candidates @('T') -InUse @('T'))) "no free candidate returns null"

# ---- with no -InUse, it asks the live session ----
# C: exists on every Windows host, so it must never be handed out, and the
# free candidate beside it must be.
Assert-Equal (Get-FreeDriveLetter -Candidates @('C','T')) 'T' "a drive the session really has is never returned"

# ---- the default candidate set stays out of the way ----
# A: and B: are floppies, C: is the system drive, and D:-F: are where optical
# drives and USB sticks land. Nothing below T: is safe to assume free.
$default = Get-FreeDriveLetter -InUse @()
Assert-True ($default -ge 'T') "the default candidates start at T, above the letters real hardware uses"
