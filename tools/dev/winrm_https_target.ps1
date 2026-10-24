# Turns a Windows machine into a TEMPORARY WinRM-over-HTTPS test target for
# EVTXER, and back. Run it ON THE TARGET, in PowerShell "Run as administrator":
#
#   powershell -ExecutionPolicy Bypass -File winrm_https_target.ps1 -Action Setup -AllowFrom 192.0.2.50
#   ... EVTXER collects with "WinRM over HTTPS" + "Skip certificate check" ...
#   powershell -ExecutionPolicy Bypass -File winrm_https_target.ps1 -Action Remove
#
# Setup records what it changes in %ProgramData%\evtxer-winrm-test.json, and
# Remove puts exactly that back: the HTTPS listener, its self-signed
# certificate, the firewall rule (port 5986, only from -AllowFrom), the WinRM
# service's start type and state, and LocalAccountTokenFilterPolicy (needed
# for a LOCAL admin account to log on remotely with full rights).
param([Parameter(Mandatory)][ValidateSet('Setup', 'Remove')][string]$Action, [string]$AllowFrom)
$ErrorActionPreference = 'Stop'
$state = Join-Path $env:ProgramData 'evtxer-winrm-test.json'
$rule = 'EVTXER test - WinRM HTTPS 5986'
$lsa = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

if ($Action -eq 'Setup') {
    if (-not $AllowFrom) { throw 'Give -AllowFrom <the EVTXER laptop IP>: the port opens to that address only.' }
    if (Test-Path $state) { throw "$state exists - run -Action Remove first." }
    $svc = Get-Service WinRM
    if ($svc.Status -eq 'Running' -and @(Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' }).Count) {
        throw 'This machine already has a WinRM HTTPS listener - test against it as it is; nothing was changed.'
    }
    $old = [ordered]@{
        WinRmStartType = "$($svc.StartType)"; WinRmRunning = ($svc.Status -eq 'Running')
        LatfpExisted   = $null -ne (Get-ItemProperty $lsa -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue)
        LatfpValue     = (Get-ItemProperty $lsa -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
        Thumbprint     = ''
    }
    # The address of the interface with the default route - not the first one
    # listed, which on a test machine was the Hyper-V/WSL switch.
    $ifx = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $ifx | Select-Object -First 1).IPAddress
    $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME, $ip -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddDays(2) -FriendlyName 'EVTXER WinRM HTTPS test'
    $old.Thumbprint = $cert.Thumbprint
    $old | ConvertTo-Json | Set-Content -Path $state -Encoding UTF8      # written before any change it describes
    Set-Service WinRM -StartupType Manual
    Start-Service WinRM
    New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null
    New-NetFirewallRule -DisplayName $rule -Direction Inbound -Protocol TCP -LocalPort 5986 -RemoteAddress $AllowFrom -Action Allow | Out-Null
    Set-ItemProperty $lsa -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord
    "Ready: WinRM over HTTPS on ${ip}:5986 (self-signed, valid 2 days), open to $AllowFrom only."
    "When the test is done: -Action Remove"
} else {
    if (-not (Test-Path $state)) { throw "$state not found - nothing to remove (or Setup never ran here)." }
    $old = Get-Content $state -Raw | ConvertFrom-Json
    Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' } | Remove-Item -Recurse -Force
    Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    if ($old.Thumbprint) { Remove-Item "Cert:\LocalMachine\My\$($old.Thumbprint)" -ErrorAction SilentlyContinue }
    if ($old.LatfpExisted) { Set-ItemProperty $lsa -Name LocalAccountTokenFilterPolicy -Value $old.LatfpValue -Type DWord }
    else { Remove-ItemProperty $lsa -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue }
    if (-not $old.WinRmRunning) { Stop-Service WinRM -Force }
    Set-Service WinRM -StartupType $old.WinRmStartType
    Remove-Item $state
    'Removed: listener, certificate, firewall rule; WinRM service and LocalAccountTokenFilterPolicy are back as they were.'
}
