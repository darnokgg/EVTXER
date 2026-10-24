# tests/DiscoverLink.Tests.ps1
#
# After an upload the tool offers a link straight to the batch in Kibana. It
# has to carry three things the operator would otherwise have to know and type:
# which data view, which import.id, and what time range the batch covers.
# Discover defaults to the last 15 minutes, so a link without a time range
# lands on an empty screen and looks broken.
#
# The coverage check exists because of a real trap: the data view was
# `hayabusa-evtx-*` while the tool's guard only requires `hayabusa-`, so every
# index the name generator produced was invisible in Kibana. A link to a data
# view that does not match the index is worse than no link at all.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# ------------------------------------------------- index / pattern match ----
Assert-True  (Test-IndexCoveredByPattern 'hayabusa-laptop-20260908' 'hayabusa-*')      "a wildcard pattern matches a mission index"
Assert-True  (Test-IndexCoveredByPattern 'hayabusa-evtx-samples'    'hayabusa-evtx-*') "the old narrow pattern still matches its own index"
Assert-True  (-not (Test-IndexCoveredByPattern 'hayabusa-laptop-20260908' 'hayabusa-evtx-*')) `
    "the narrow pattern does NOT match a mission index - the bug this check exists for"
Assert-True  (-not (Test-IndexCoveredByPattern 'logs-import-so' 'hayabusa-*')) `
    "an unrelated index is not claimed by the pattern"
Assert-True  (Test-IndexCoveredByPattern 'hayabusa-evtx-samples' 'hayabusa-evtx-samples') `
    "an exact pattern with no wildcard matches"
Assert-True  (-not (Test-IndexCoveredByPattern 'hayabusa-evtx-samples2' 'hayabusa-evtx-samples')) `
    "an exact pattern does not match a longer name"
Assert-True  (Test-IndexCoveredByPattern 'hayabusa-a-2026' 'hayabusa-*-2026*') "several wildcards work"

# A dot is a regex metacharacter but a literal in an index pattern.
Assert-True  (-not (Test-IndexCoveredByPattern 'hayabusaXevtx' 'hayabusa.evtx')) `
    "a dot in the pattern is literal, not 'any character'"

# Kibana data views may hold several comma-separated patterns, and may exclude
# with a leading '-'. Both are on the live box:
#   'metrics-*,metricbeat-*,.monitoring-*'
#   '.alerts-security.alerts-default,...,logs-*,...,-*elastic-cloud-logs-*'
# Treating the whole string as one pattern makes every one of them fail to
# match; ignoring the exclusions makes some of them match things they should
# not.
Assert-True (Test-IndexCoveredByPattern 'metricbeat-2026' 'metrics-*,metricbeat-*,.monitoring-*') `
    "a comma-separated data view matches on any of its patterns"
Assert-True (Test-IndexCoveredByPattern 'metrics-abc' 'metrics-*,metricbeat-*') `
    "the first pattern of a list still matches"
Assert-True (-not (Test-IndexCoveredByPattern 'hayabusa-x' 'metrics-*,metricbeat-*')) `
    "a comma-separated list does not match something outside all of them"
Assert-True (-not (Test-IndexCoveredByPattern 'my-elastic-cloud-logs-1' 'logs-*,-*elastic-cloud-logs-*')) `
    "an excluded pattern is not counted as coverage"
Assert-True (Test-IndexCoveredByPattern 'logs-normal' 'logs-*,-*elastic-cloud-logs-*') `
    "the positive pattern still matches when an exclusion is present"
Assert-True (-not (Test-IndexCoveredByPattern 'anything' '-*')) `
    "a pattern that is only an exclusion covers nothing"

Assert-True  (-not (Test-IndexCoveredByPattern '' 'hayabusa-*'))  "an empty index name matches nothing"
Assert-True  (-not (Test-IndexCoveredByPattern 'hayabusa-x' '')) "an empty pattern matches nothing"

# ------------------------------------------------------------- the URL ------
$u = New-DiscoverUrl -HostName '192.0.2.20' -DataViewId 'hayabusa-evtx-dataview' `
        -ImportId '20260908085437fa4c6679' `
        -From '2026-06-15T11:31:37.640Z' -To '2026-09-08T12:53:34.127Z'

Assert-True ($u -match '^https://192\.0\.2\.20/kibana/app/discover')  "it points at Discover on the right host"
Assert-True ($u -match 'hayabusa-evtx-dataview')                          "it names the data view"
Assert-True ($u -match '20260908085437fa4c6679')                          "it carries the import id"
Assert-True ($u -match '2026-06-15T11:31:37\.640Z')                       "it carries the start of the batch"
Assert-True ($u -match '2026-09-08T12:53:34\.127Z')                       "it carries the end of the batch"
Assert-True ($u -match 'import\.id')                                      "it filters on import.id"

# A raw double quote or space in a URL breaks it in some clients, so the query
# is written without spaces and the quotes are escaped.
Assert-True ($u -notmatch '"')  "no raw double quote survives into the URL"
Assert-True ($u -notmatch ' ')  "no raw space survives into the URL"
Assert-True ($u -match '%22')   "the quotes around the import id are percent-encoded"

# Port only when it is not the default, so the common case stays clean.
$up = New-DiscoverUrl -HostName 'so.example' -DataViewId 'dv' -ImportId 'i' -From 'a' -To 'b' -Port 8443
Assert-True ($up -match '^https://so\.example:8443/kibana/') "a non-default port is included"
$ud = New-DiscoverUrl -HostName 'so.example' -DataViewId 'dv' -ImportId 'i' -From 'a' -To 'b' -Port 443
Assert-True ($ud -notmatch ':443')                           "port 443 is left out"
