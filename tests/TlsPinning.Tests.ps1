# tests/TlsPinning.Tests.ps1
. "$PSScriptRoot\..\code\HayabusaLib.ps1"

# ---- thumbprint normalization ----
Assert-Equal (ConvertTo-Thumbprint 'aa:bb:cc')     'AABBCC' "colons stripped and uppercased"
Assert-Equal (ConvertTo-Thumbprint '  aa bb cc  ') 'AABBCC' "spaces stripped"
Assert-Equal (ConvertTo-Thumbprint $null)          ''       "null normalizes to empty"

# ---- against real certificates from the local store (read-only) ----
$certs = @(Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | Select-Object -First 2)
if ($certs.Count -lt 2) {
    Write-Host "  [SKIP] fewer than 2 root certificates in the store" -ForegroundColor Yellow
} else {
    $t0 = Get-CertSha256Thumbprint $certs[0]
    $t1 = Get-CertSha256Thumbprint $certs[1]

    Assert-Equal $t0.Length 64                  "SHA-256 thumbprint is 64 hex chars"
    Assert-True  ($t0 -match '^[0-9A-F]{64}$')  "thumbprint is uppercase hex"
    Assert-True  ($t0 -ne $t1)                  "two different certificates give different thumbprints"

    # ---- the security decision ----
    Assert-True (Test-PinnedCertificate $certs[0] $t0)              "matching pin is accepted"
    Assert-True (-not (Test-PinnedCertificate $certs[0] $t1))       "a different certificate is rejected"
    Assert-True (-not (Test-PinnedCertificate $certs[0] ''))        "empty pin fails closed"
    Assert-True (-not (Test-PinnedCertificate $certs[0] $null))     "null pin fails closed"
    Assert-True (-not (Test-PinnedCertificate $null $t0))           "null certificate fails closed"

    # ---- operators paste fingerprints in whatever shape they copied them ----
    $colonised = (($t0 -replace '(..)', '$1:')).TrimEnd(':')
    Assert-True (Test-PinnedCertificate $certs[0] $colonised)       "colon-separated pin is accepted"
    Assert-True (Test-PinnedCertificate $certs[0] $t0.ToLower())    "lowercase pin is accepted"

    # ---- more than one pin: Security Onion serves Elasticsearch (9200) and
    # its web front end (443) with DIFFERENT certificates, and the Dashboards
    # tab talks to both in one session ----
    Assert-True (Test-PinnedCertificate $certs[0] @($t1, $t0))      "a certificate matching either pin is accepted"
    Assert-True (-not (Test-PinnedCertificate $certs[0] @($t1)))    "a certificate matching neither pin is rejected"
    Assert-True (-not (Test-PinnedCertificate $certs[0] @('', $null))) "a list of blank pins fails closed"

    Set-TlsTrust -Mode 'Pin' -PinnedThumbprint @($t0, '')
    Assert-Equal (@([HayabusaCertPin]::Expected) -join ',') $t0     "a blank pin in the list is dropped, the real one kept"
    Set-TlsTrust -Mode 'Pin' -PinnedThumbprint @($t0, $t1.ToLower())
    Assert-Equal @([HayabusaCertPin]::Expected).Count 2             "both pins are installed"
    Assert-Throws { Set-TlsTrust -Mode 'Pin' -PinnedThumbprint @($t0, 'ABC') } "a malformed pin in the list is refused, not dropped"
}
Assert-Throws { Set-TlsTrust -Mode 'Pin' -PinnedThumbprint @('', ' ') } "Pin mode with only blank thumbprints is refused"

# ---- Set-TlsTrust must never silently degrade to trust-all ----
Assert-Throws { Set-TlsTrust -Mode 'Bogus' }                  "an unknown TLS mode is rejected"
Assert-Throws { Set-TlsTrust -Mode 'Pin' -PinnedThumbprint '' } "Pin mode without a thumbprint is refused"

# ---- 'System' = ordinary OS chain validation ----
# This is what Set-TlsTrust $false used to mean. Security Onion's certificate
# can never pass it, so nothing selects this mode today; it is kept as the only
# way to express "verify normally", and these tests use it to leave the process
# in a safe state rather than with trust-all still installed.
Set-TlsTrust -Mode 'System'
Assert-True ($null -eq [System.Net.ServicePointManager]::ServerCertificateValidationCallback) `
    "System mode installs no validation callback"
Assert-True ($null -eq [System.Net.ServicePointManager]::CertificatePolicy) `
    "System mode clears the legacy certificate policy"
