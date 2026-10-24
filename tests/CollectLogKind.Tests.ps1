# tests/CollectLogKind.Tests.ps1
#
# The collector reports through a -LogWriter callback that carries only text,
# so every line it wrote - [FAILED] and [ERROR] included - rendered in the
# plain colour. Get-CollectLogKind reads the marker the line already carries
# and picks the Write-Log colour from it, so a failure cannot read like a pass.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

Assert-Equal (Get-CollectLogKind '  [OK] Acquired: Security')              'ok'    "[OK] is ok"
Assert-Equal (Get-CollectLogKind '  [DONE] dc01 - 5 of 5 log(s) collected.') 'ok'    "[DONE] is ok"
Assert-Equal (Get-CollectLogKind '  [FAILED] Security - Access denied')     'err'   "[FAILED] is err"
Assert-Equal (Get-CollectLogKind '  [ERROR] dc01 - WinRM refused')         'err'   "[ERROR] is err"
Assert-Equal (Get-CollectLogKind '  [!!] TrustedHosts NOT reverted')       'err'   "[!!] is err"
Assert-Equal (Get-CollectLogKind '  [PARTIAL] dc01 - only 3 of 5')         'warn'  "[PARTIAL] is warn"
Assert-Equal (Get-CollectLogKind '  [SKIPPED] Export failed or log empty') 'warn'  "[SKIPPED] is warn"
Assert-Equal (Get-CollectLogKind '  [--] Not Found / Access Denied: X')    'warn'  "[--] is warn"
Assert-Equal (Get-CollectLogKind '==== Target: dc01 ====')                  'info'  "the target banner is info"
Assert-Equal (Get-CollectLogKind '  [..] Manifest written: x')             'plain' "[..] stays plain"
Assert-Equal (Get-CollectLogKind '  [WinRM] Establishing PSSession...')    'plain' "progress stays plain"
Assert-Equal (Get-CollectLogKind '')                                        'plain' "an empty line is plain"

# The port and access probes wrap their lines in newlines.
Assert-Equal (Get-CollectLogKind "  [OK] SMB (tcp/445): open`n")           'ok'    "a trailing newline does not hide the marker"
Assert-Equal (Get-CollectLogKind "`n  [--] WinRM (tcp/5985): closed`n")    'warn'  "a leading newline does not hide the marker"

# A marker mid-line is part of a message, not a status.
Assert-Equal (Get-CollectLogKind '  -> retry [FAILED] hosts later')         'plain' "a marker mid-line is not a status"

# Every Collect-tab callback goes through it. Passing ${function:Write-Log}
# straight through is what dropped the colour in the first place.
$src = Get-Content "$PSScriptRoot\..\code\wpf-collect.ps1" -Raw
Assert-True ($src -notmatch '-LogWriter\s+\$\{function:Write-Log\}') "no callback passes Write-Log straight through"
Assert-Equal ([regex]::Matches($src, '-LogWriter\s+\{\s*param\(\$m\)\s*Write-Log\b[^}]*Get-CollectLogKind').Count) 2 "Verify Access and Test Ports classify their lines"
# The collection runs in a background job now; its lines are drained from the
# job's queue on the UI thread, and classified there.
Assert-True ($src -match 'TryDequeue\(\[ref\]\$m\)\) \{ Write-Log "\$m`n" \(Get-CollectLogKind \$m\)') "the collection's drained lines are classified too"
