# tests/PortCheck.Tests.ps1
. "$PSScriptRoot\..\code\EvtxCollector.ps1"

# An off-domain target had its firewall dropping 445, and the SMB mount froze
# the whole window while Windows waited it out. A TCP check with a hard timeout
# answers "is anything listening" in seconds, before any credential is sent.

# ---- a real open port ----
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
$open = Test-TcpPort '127.0.0.1' $port 5000
Assert-Equal $open.Status 'Open' "a listening port reports Open"

# ---- the same port once nothing listens ----
$listener.Stop()
$refused = Test-TcpPort '127.0.0.1' $port 5000
Assert-Equal $refused.Status 'Refused' "a port with no listener reports Refused"

# ---- a filtered / unroutable address never hangs ----
# 192.0.2.1 is TEST-NET-1, reserved and never routed. Whether this box says
# Timeout or Error depends on its routing table; what matters is that it is not
# Open and that the timeout is honoured.
$sw = [Diagnostics.Stopwatch]::StartNew()
$dead = Test-TcpPort '192.0.2.1' 445 1000
$sw.Stop()
Assert-True ($dead.Status -ne 'Open') "an unroutable address is not Open (got $($dead.Status))"
Assert-True ($sw.ElapsedMilliseconds -lt 3000) "the check returns within its timeout ($($sw.ElapsedMilliseconds) ms)"

# ---- the method-to-port map ----
Assert-Equal (Get-CollectPort 'SMB')   445  "SMB uses 445"
Assert-Equal (Get-CollectPort 'WinRM') 5985 "WinRM uses 5985"

# ---- the text says what to do, not just what happened ----
Assert-True ((Get-PortCheckText 445 'Open') -match '(?i)open')                     "Open says open"
Assert-True ((Get-PortCheckText 5985 'Refused') -match 'Enable-PSRemoting')        "WinRM refused points at Enable-PSRemoting"
Assert-True ((Get-PortCheckText 5985 'Timeout') -match 'Enable-PSRemoting')        "WinRM filtered points at Enable-PSRemoting too"
Assert-True ((Get-PortCheckText 445 'Timeout') -match 'File and Printer Sharing')  "SMB filtered points at File and Printer Sharing"
Assert-True ((Get-PortCheckText 445 'Refused') -match 'File and Printer Sharing')  "SMB refused points at File and Printer Sharing"

# ---- a closed port fails the host before any connection attempt ----
Assert-Throws { Assert-CollectPortOpen '192.0.2.1' 'WinRM' } "an unreachable WinRM port throws"

# ---- both buttons check the port BEFORE mounting or opening a session ----
$src = Get-Content "$PSScriptRoot\..\code\EvtxCollector.ps1" -Raw
$collect = [regex]::Match($src, '(?s)function Invoke-EvtxCollection.*?(?=\nfunction )').Value
$verify  = [regex]::Match($src, '(?s)function Test-CollectAccess.*?(?=\nfunction |\z)').Value
foreach ($pair in @(@('Collect', $collect), @('Verify Access', $verify))) {
    $check = $pair[1].IndexOf('Assert-CollectPortOpen')
    Assert-True ($check -ge 0) "$($pair[0]) checks the port"
    Assert-True ($check -lt $pair[1].IndexOf('New-PSDrive'))   "$($pair[0]) checks before the SMB mount"
    Assert-True ($check -lt $pair[1].IndexOf('New-PSSession')) "$($pair[0]) checks before the WinRM session"
}

# ---- the GUI has a credential-free port test ----
$toolLines = Get-ToolSourceLines | Where-Object { $_ -notmatch '^\s*#' }
Assert-True (@($toolLines | Where-Object { $_ -match 'Content="TEST PORTS"' }).Count -eq 1) "the Collect tab has a TEST PORTS button"
Assert-True (@($toolLines | Where-Object { $_ -match 'Test-CollectPorts' }).Count -ge 1)       "the button runs Test-CollectPorts"

# ---- a batch is checked concurrently, not one socket at a time ----
# Sequentially, 20 unreachable hosts cost 20 x 2 ports x the timeout: 100 s
# MEASURED, with the window unusable throughout. A sweep of a subnet is the
# normal case for this button, so the probes all go out together and the batch
# costs about one timeout instead of one per socket.
$deadHosts = 1..20 | ForEach-Object { "192.0.2.$_" }
$sw = [Diagnostics.Stopwatch]::StartNew()
$rows = @(Test-CollectPorts -Targets $deadHosts -LogWriter { param($m) })
$sw.Stop()
Assert-Equal $rows.Count 20 "every target gets a row"
Assert-True ($sw.Elapsed.TotalSeconds -lt 15) "20 unreachable targets finish well inside the sequential 100 s ($([int]$sw.Elapsed.TotalSeconds) s)"
Assert-True (@($rows | Where-Object { $_.SMB -or $_.WinRM }).Count -eq 0) "none of the unreachable targets is reported open"

# ---- and the verdicts are still right when they run together ----
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$openPort = $listener.LocalEndpoint.Port
$mixed = @(Test-TcpPortSet -Probes @(
    @{ Key = 'up';   HostName = '127.0.0.1'; Port = $openPort },
    @{ Key = 'down'; HostName = '127.0.0.1'; Port = 1 },
    @{ Key = 'gone'; HostName = '192.0.2.1'; Port = 445 }
) -TimeoutMs 5000)
$listener.Stop()
Assert-Equal ($mixed | Where-Object { $_.Key -eq 'up' }).Status   'Open'    "a live port in a batch is Open"
Assert-Equal ($mixed | Where-Object { $_.Key -eq 'down' }).Status 'Refused' "a closed port in a batch is Refused"
Assert-True  (($mixed | Where-Object { $_.Key -eq 'gone' }).Status -ne 'Open') "an unroutable port in a batch is not Open"
