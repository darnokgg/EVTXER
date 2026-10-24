# tests/HayabusaLib.Load.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"
Assert-True $script:HayabusaLibLoaded "HayabusaLib dot-sources cleanly"
