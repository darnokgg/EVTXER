# tests/TargetsLabel.Tests.ps1
#
# The Upload tab's Case / label follows the targets that were just collected
# (operator request, 2026-10-14): one IP becomes the label, several become
# their range - so an index name says which boxes it holds without typing.
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

Assert-Equal (Get-TargetsLabel @('10.1.2.3')) '10.1.2.3' "one target is the label"
Assert-Equal (Get-TargetsLabel @('10.1.2.40','10.1.2.3','10.1.2.9')) '10.1.2.3-40-3hosts' "one /24 shortens to first-last octet, with a count"
Assert-Equal (Get-TargetsLabel @('10.1.2.3','10.1.9.200')) '10.1.2.3-10.1.9.200-2hosts' "across subnets the full ends are kept"
Assert-Equal (Get-TargetsLabel @('10.1.2.10','10.1.2.9')) '10.1.2.9-10-2hosts' "addresses sort as numbers, not text"
Assert-Equal (Get-TargetsLabel @('DC01','ws07','ws08')) 'dc01-and-2-more' "hostnames name the first and count the rest"
Assert-Equal (Get-TargetsLabel @('10.1.2.3','10.1.2.3')) '10.1.2.3' "duplicates are one target"
Assert-Equal (Get-TargetsLabel @()) '' "no targets, no label"
Assert-True (Test-HayabusaIndexName (New-IndexName (Get-TargetsLabel @('10.1.2.3','10.1.2.40')) @())) "the label always makes a legal index name"

# The hand-off must never overwrite a label the operator typed.
$up = Get-Content "$PSScriptRoot\..\code\wpf-upload.ps1" -Raw
$fn = [regex]::Match($up, '(?s)function Set-UploadLabelSuggestion.*?\n\}').Value
Assert-True ($fn.Length -gt 0) "the Upload tab takes a label suggestion"
Assert-True ($fn -match 'AutoLabel') "and only replaces a label that was itself filled in automatically"
Assert-Equal (Get-TargetsLabel @('fe80::1','fe80::2')) 'fe80-1-and-1-more' "IPv6 targets are named, not range-sorted (that threw)"
