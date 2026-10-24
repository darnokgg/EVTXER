# tests/WinRmHttps.Tests.ps1
. "$PSScriptRoot\..\code\EvtxCollector.ps1"

# WinRM used to mean HTTP on 5985 and nothing else. A target whose HTTP
# listener is removed by policy (STIG-hardened networks do this) failed the
# port check with "WinRM is not enabled - run Enable-PSRemoting", on a box
# where WinRM was running fine on 5986. WinRM-HTTPS is now a method of its own.

# ---- the port ----
Assert-Equal (Get-CollectPort 'WinRM-HTTPS') 5986 "WinRM-HTTPS uses 5986"
Assert-Equal (Get-CollectPort 'WinRM')       5985 "plain WinRM still uses 5985"

# ---- a closed 5986 says what HTTPS needs, not Enable-PSRemoting ----
# Enable-PSRemoting creates only the HTTP listener, so pointing at it here
# would send the operator to fix the wrong thing.
foreach ($status in 'Refused', 'Timeout') {
    $t = Get-PortCheckText 5986 $status
    Assert-True ($t -match 'HTTPS')                   "5986 $status names HTTPS"
    Assert-True ($t -match '(?i)certificate')         "5986 $status says the listener needs a certificate"
    Assert-True ($t -notmatch 'Enable-PSRemoting')    "5986 $status does not point at Enable-PSRemoting"
}

# ---- the wrong WinRM flavour chosen: say which one the target does offer ----
$toHttps = Get-WinRmSwitch 'WinRM'
Assert-Equal $toHttps.Method 'WinRM-HTTPS' "plain WinRM's alternative is WinRM-HTTPS"
Assert-True ($toHttps.Text -match '5986')  "the switch text names port 5986"
$toHttp = Get-WinRmSwitch 'WinRM-HTTPS'
Assert-Equal $toHttp.Method 'WinRM'        "WinRM-HTTPS's alternative is plain WinRM"
Assert-True ($toHttp.Text -match '5985')   "the switch text names port 5985"
Assert-True ($toHttp.Text -match '(?i)encrypt') "the switch to plain WinRM says the data is still encrypted"
Assert-Equal (Get-WinRmSwitch 'SMB') $null "SMB has no WinRM alternative"

# ---- the session ----
$plain = Get-CollectSessionArgs 'WinRM'
Assert-Equal $plain.Count 0 "plain WinRM opens the session exactly as before"

$https = Get-CollectSessionArgs 'WinRM-HTTPS'
Assert-True  ($https.UseSSL -eq $true)          "WinRM-HTTPS asks for SSL"
Assert-Equal $https.Port 5986                   "WinRM-HTTPS connects to 5986"
Assert-True  (-not $https.ContainsKey('SessionOption')) "the certificate is checked unless the operator says otherwise"

$skip = Get-CollectSessionArgs 'WinRM-HTTPS' -SkipCertificateCheck
Assert-True ($skip.SessionOption.SkipCACheck)         "skipping trusts an unknown issuer (self-signed)"
Assert-True ($skip.SessionOption.SkipCNCheck)         "skipping accepts a name mismatch (IP targets)"
Assert-True ($skip.SessionOption.SkipRevocationCheck) "skipping does not need the CRL, which an isolated network cannot reach"
Assert-Equal (Get-CollectSessionArgs 'WinRM' -SkipCertificateCheck).Count 0 "the skip means nothing to plain WinRM"
Assert-Throws { Get-CollectSessionArgs 'SMB' } "SMB has no session"

# ---- TrustedHosts is a plain-WinRM requirement only ----
# Over HTTPS the certificate is what identifies the target, so Windows does
# not demand TrustedHosts - and not touching it means no admin rights needed.
Assert-True  (Test-NeedsTrustedHosts 'WinRM')              "plain WinRM needs TrustedHosts"
Assert-True  (-not (Test-NeedsTrustedHosts 'WinRM-HTTPS')) "WinRM-HTTPS leaves TrustedHosts alone"
Assert-True  (-not (Test-NeedsTrustedHosts 'SMB'))         "SMB leaves TrustedHosts alone"

# ---- the method flows through every gate ----
$ready = Test-CollectReadiness -Targets @('dc01') -Method 'WinRM-HTTPS' -Username 'CORP\a' -Category 'DFIR' -CustomLogs @()
Assert-True $ready.Ready "a WinRM-HTTPS form is ready"
$plan = Get-ConnectivityPlan -PingSucceeded $false -Method 'WinRM-HTTPS'
Assert-True $plan.Proceed "a failed ping does not stop WinRM-HTTPS either"
$cap = Get-MethodCaption 'WinRM-HTTPS'
Assert-True ($cap.Caption -match '(?i)encrypts')    "the HTTPS caption says it encrypts"
Assert-True ($cap.Caption -match '(?i)certificate') "the HTTPS caption says it needs a certificate"
Assert-True ($cap.Caption -match '(?i)no TrustedHosts') "the HTTPS caption says it needs no TrustedHosts change"
foreach ($fn in 'Invoke-EvtxCollection', 'Test-CollectAccess') {
    $cmd = Get-Command $fn
    Assert-True (@($cmd.Parameters['Method'].Attributes.ValidValues) -contains 'WinRM-HTTPS') "$fn accepts WinRM-HTTPS"
    Assert-True $cmd.Parameters.ContainsKey('SkipCertificateCheck') "$fn takes -SkipCertificateCheck"
}

# ---- a refused certificate gets a hint that names the fix ----
$certErr = 'Connecting to remote server wks01 failed with the following error message : The server certificate on the destination computer (wks01:5986) has the following errors: The SSL certificate is signed by an unknown certificate authority.'
Assert-True ((Get-CollectErrorHint $certErr) -match 'Skip certificate check') "an untrusted certificate points at the skip option"
$cnErr = 'The SSL certificate contains a common name (CN) that does not match the hostname.'
Assert-True ((Get-CollectErrorHint $cnErr) -match '(?i)IP address') "a name mismatch explains that an IP never matches"
# An isolated network cannot reach the CRL. Importing the CA fixes nothing
# there, so the hint must not send the operator to do it.
$crlErr = 'The server certificate on the destination computer (wks01:5986) has the following errors: The SSL certificate could not be checked for revocation. The server used to check for revocation might be unreachable.'
$crlHint = Get-CollectErrorHint $crlErr
Assert-True ($crlHint -match '(?i)revocation')             "an unreachable CRL is named as such"
Assert-True ($crlHint -notmatch '(?i)Import the issuing CA') "an unreachable CRL is not told to import the CA"
# Expired is not something the skip promises to cover, so it is not offered as the fix.
$expErr = 'The server certificate on the destination computer (wks01:5986) has the following errors: The SSL certificate is expired.'
Assert-True ((Get-CollectErrorHint $expErr) -match '(?i)fixed on the target') "an expired certificate is sent to the target, not the skip box"

# ---- the evidence records an unverified target ----
$tmpM = Join-Path ([IO.Path]::GetTempPath()) ("winrmhttps-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmpM | Out-Null
try {
    $mj = Get-Content (Write-EvtxManifest -Entries @() -Folder $tmpM -HostName 'WKS01' -Method 'WinRM-HTTPS' -CertificateCheckSkipped) -Raw | ConvertFrom-Json
    Assert-True ($mj.CertificateCheckSkipped -eq $true) "the manifest says the certificate check was skipped"
    $mj = Get-Content (Write-EvtxManifest -Entries @() -Folder $tmpM -HostName 'WKS01' -Method 'WinRM-HTTPS') -Raw | ConvertFrom-Json
    Assert-True ($mj.CertificateCheckSkipped -eq $false) "and says so when it was not"
} finally { Remove-Item -LiteralPath $tmpM -Recurse -Force -ErrorAction SilentlyContinue }
Assert-True ((Get-Content "$PSScriptRoot\..\code\EvtxCollector.ps1" -Raw) -match 'CertificateCheckSkipped:') "the collector passes the skip into the manifest"

# ---- both buttons open the session the same way ----
$src = Get-Content "$PSScriptRoot\..\code\EvtxCollector.ps1" -Raw
$sessions = @([regex]::Matches($src, '(?m)^[^#\r\n]*New-PSSession [^\r\n]*') | ForEach-Object { $_.Value })
Assert-Equal $sessions.Count 3 "Collect, its size probe (Update-RemoteSize) and Verify Access each open one session"
foreach ($s in $sessions) { Assert-True ($s -match '@sessionArgs|@probeArgs') "every session is opened through Get-CollectSessionArgs: $($s.Trim())" }
Assert-True ($src -match '\$probeArgs = @\{\} \+ \$SessionArgs') "the size probe's settings are a copy of Get-CollectSessionArgs' (plus short timeouts)\"
$collect = [regex]::Match($src, '(?s)function Invoke-EvtxCollection.*?(?=\nfunction )').Value
$verify  = [regex]::Match($src, '(?s)function Test-CollectAccess.*?(?=\nfunction |\z)').Value
foreach ($pair in @(@('Collect', $collect), @('Verify Access', $verify))) {
    Assert-True ($pair[1] -match 'if \(Test-NeedsTrustedHosts \$Method\) \{ (\$savedTrustedHosts = )?Add-CollectTrustedHosts') "$($pair[0]) decides TrustedHosts by Test-NeedsTrustedHosts"
    Assert-True ($pair[1] -notmatch "\`$Method -eq 'WinRM'\)") "$($pair[0]) has no literal plain-WinRM test left"
}

# ---- the port probe covers all three ----
$rows = @(Test-CollectPorts -Targets @('192.0.2.1') -LogWriter { param($m) })
Assert-True ($rows[0].PSObject.Properties.Name -contains 'WinRM-HTTPS') "TEST PORTS reports WinRM-HTTPS too"
Assert-True (-not $rows[0].'WinRM-HTTPS') "an unreachable host's 5986 is not open"

# ---- the GUI ----
$gui = (Get-ToolSourceLines | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
Assert-True ($gui -match 'x:Name="rbWinRMHttps"')       "the Collect tab has a WinRM over HTTPS option"
Assert-True ($gui -match 'x:Name="chkSkipCertCheck"')   "the Collect tab has a skip-certificate-check box"
Assert-True ($gui -match "'WinRM-HTTPS'")               "the form reads the HTTPS option as WinRM-HTTPS"
Assert-True ($gui -match '-SkipCertificateCheck:\$state\.SkipCertCheck') "Verify Access passes the skip through"
# Collect hands its parameters to a background job as a table, not as switches.
Assert-True ($gui -match 'SkipCertificateCheck = \[bool\]\$state\.SkipCertCheck') "Collect passes the skip through to the job"
