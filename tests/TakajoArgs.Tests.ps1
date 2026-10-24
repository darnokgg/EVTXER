# tests/TakajoArgs.Tests.ps1
#
# Two gotchas found by running the real binary, both encoded here so they
# cannot regress:
#
#   1. html-report prepends "./" to --output, so an ABSOLUTE path
#      becomes "./C:\..." and the run dies with
#      "Failed to create directory ... Additional info: ./C:\".
#      automagic's --output accepts an absolute path fine. The subcommands
#      genuinely differ; verified both ways against takajo 2.16.1.
#
#   2. Short flags mean different things per subcommand: -s is
#      --skipProgressBar for automagic but --dboutput for html-report.
#      Only long flags are ever emitted.
#
# Takajo also resolves conf/ and templates/ relative to the CURRENT DIRECTORY,
# not the executable, so it must be run with the working directory set to the
# takajo folder. That is what makes the relative --output workable at all.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

$tj  = 'C:\tools\takajo'
$tl  = 'C:\case\output\results.jsonl'
$rul = 'C:\case\hayabusa-x64\rules'
$db  = 'C:\case\output\takajo\report.sqlite'

function Get-ArgValue($ArgList, $Name) {
    for ($i = 0; $i -lt $ArgList.Count; $i++) {
        if ($ArgList[$i] -ceq $Name) { return $ArgList[$i + 1] }
    }
    return $null
}

# ---------------------------------------------------------------- automagic --
$a = Get-TakajoArgs -Command 'automagic' -TakajoDir $tj -Timeline $tl -OutDir 'C:\case\output\takajo\case-1' -Level 'high'
Assert-Equal $a[0] 'automagic'                              "automagic is the first argument"
Assert-Equal (Get-ArgValue $a '--timeline') $tl             "the timeline is passed through absolute"
Assert-Equal (Get-ArgValue $a '--level') 'high'             "the minimum level is passed"
Assert-True ($a -contains '--skipProgressBar')              "the progress bar is suppressed"
Assert-True ($a -notcontains '--port')                      "automagic takes no port"
Assert-True ($a -notcontains '--sqlite')                    "automagic takes no sqlite flag"

# automagic accepts an absolute --output, and must keep it absolute: it is the
# one subcommand that does not prepend "./".
Assert-Equal (Get-ArgValue $a '--output') 'C:\case\output\takajo\case-1' `
    "automagic keeps an absolute output path"

# -------------------------------------------------------------- html-report --
$r = Get-TakajoArgs -Command 'html-report' -TakajoDir $tj -Timeline $tl `
        -OutDir 'C:\tools\output\takajo\html' -RulePath $rul -DbPath $db -Sqlite
Assert-Equal $r[0] 'html-report'                            "html-report is the first argument"
$ro = Get-ArgValue $r '--output'
Assert-True ($ro -notmatch '^[A-Za-z]:')                    "html-report output is NOT an absolute path"
Assert-True ($ro -match 'html')                             "html-report output still names the target folder"
Assert-Equal (Get-ArgValue $r '--rulepath') $rul            "the rules path is passed"
Assert-Equal (Get-ArgValue $r '--dboutput') $db             "the database path is passed absolute"
Assert-True ($r -contains '--sqlite')                       "sqlite is requested when asked for"
Assert-True ($r -contains '--clobber')                      "clobber is set so a rerun overwrites"

$r2 = Get-TakajoArgs -Command 'html-report' -TakajoDir $tj -Timeline $tl `
        -OutDir 'C:\tools\output\takajo\html' -RulePath $rul -DbPath $db
Assert-True ($r2 -notcontains '--sqlite')                   "sqlite is absent unless asked for (DuckDB is the default)"

# -------------------------------------------------------------- html-server --
# Gone on purpose: it listened on 0.0.0.0 with no authentication and Takajo has
# no bind-address flag, so the report was readable by anyone on the network.
Assert-Throws { Get-TakajoArgs -Command 'html-server' -TakajoDir $tj -Timeline $tl -RulePath $rul } `
    "html-server is refused - it would serve the report to the whole network"

# ------------------------------------------------- long flags only, always --
foreach ($set in @(,$a), @(,$r)) {
    foreach ($token in $set[0]) {
        if ($token -match '^-[^-]') {
            Assert-True $false "short flag '$token' emitted - -s means different things per subcommand"
        }
    }
}
Assert-True $true "no short flags are emitted for any subcommand"

# ------------------------------------------------------------------ guards --
Assert-Throws { Get-TakajoArgs -Command 'nonsense' -TakajoDir $tj -Timeline $tl } "an unknown Takajo command is rejected"
Assert-Throws { Get-TakajoArgs -Command 'html-report' -TakajoDir $tj -Timeline $tl -OutDir 'D:\elsewhere\html' -RulePath $rul } `
    "an output folder on another drive is refused, since it cannot be made relative"

# ------------------------------------------------------ relative path maths --
Assert-Equal (ConvertTo-TakajoRelativePath 'C:\tools\output\html' 'C:\tools\takajo') '..\output\html' `
    "a sibling folder becomes ..\ relative"
Assert-Equal (ConvertTo-TakajoRelativePath 'C:\tools\takajo\sub' 'C:\tools\takajo') 'sub' `
    "a child folder becomes a plain relative name"
Assert-Equal (ConvertTo-TakajoRelativePath '..\already\relative' 'C:\tools\takajo') '..\already\relative' `
    "an already-relative path is left alone"
