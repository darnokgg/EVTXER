<#
.SYNOPSIS
    "Dashboards" tab (Kibana dashboards) - WPF fragment, dot-sourced by HayabusaMissionTool.ps1.

.DESCRIPTION
    Imports kibana\hayabusa-kibana-objects.ndjson (the dashboards, saved
    searches, Lens panels and data views - kibana\IMPORT.txt counts them) into
    the Kibana that Security Onion fronts with its Kratos auth proxy.

    The whole difficulty is the proxy. Plain basic auth against /kibana returns
    the LOGIN PAGE, not Kibana, and the reply still has status 200 - so a naive
    import "succeeds" and imports nothing. Both credentials are needed at once:
      * a Kratos browser session cookie, to get past the proxy, and
      * Elasticsearch basic auth, which Kibana itself checks.
    Proven in scripts/kibana_setup.py, which is what produced the ndjson; this
    is that flow in PowerShell 5.1.

    A fragment, not a script: it creates no window, loads no assemblies and
    dot-sources no library. The shell has already done all three and has given
    us $tabKibana, Write-Log, Invoke-UiPump, $bar, $lblStatus, $script:Busy,
    $script:Root. The Upload tab, loaded before this one, has given us
    $txtHost / $txtUser / Get-UploadPassword / $rbTlsSkip / $txtPin /
    $script:UpBrush - which is why this tab collects no credentials of its own.
    The one thing it does collect is the web front end's certificate pin:
    Security Onion serves 443 with a different certificate from 9200, so the
    Upload tab's pin cannot vouch for it.

    Everything pure lives in HayabusaLib.ps1 (New-MultipartFileBody,
    Compare-KibanaVersion, Get-KibanaImportSummary, Get-KratosCsrfToken,
    Select-HayabusaSavedObjects, Get-NdjsonObjectCount) and is unit-tested in
    tests/KibanaImport.Tests.ps1.
#>

# ------------------------------------------------------------ tab state -----
# The version the shipped ndjson was exported from. Kibana refuses saved
# objects exported by a NEWER Kibana than itself, and the error it gives is a
# migration failure that names no version, so the tab checks first.
$script:KbExportVersion = '9.0.8'
# The export ships in kibana\, but the installed copy on the operator's machine
# has that folder renamed 'kibana dashboards' - a rename nobody will remember
# having made when the tab says "file not found". Both names are checked, and
# the repo layout wins when both exist.
$script:KbDefaultFile = $null
foreach ($kbDir in 'kibana', 'kibana dashboards') {
    $candidate = Join-Path $script:Root (Join-Path $kbDir 'hayabusa-kibana-objects.ndjson')
    if (Test-Path -LiteralPath $candidate) { $script:KbDefaultFile = $candidate; break }
}
if (-not $script:KbDefaultFile) {
    $script:KbDefaultFile = Join-Path $script:Root 'kibana\hayabusa-kibana-objects.ndjson'
}

# ==================================================================== XAML ===
# DynamicResource, not StaticResource: this Grid is parsed detached from the
# window, so the shell's style keys do not exist yet at parse time and a
# StaticResource would throw during Load.
$kibanaXaml = @'
<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
      xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
      Margin="4,8,14,8">
  <StackPanel>

    <!-- ===== what gets imported ===== -->
    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <Grid>
          <TextBlock Text="Dashboards to import" Style="{DynamicResource SectionHead}"/>
          <TextBlock Text="* = required" HorizontalAlignment="Right" VerticalAlignment="Top"
                     Style="{DynamicResource Hint}"/>
        </Grid>

        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="128"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" Text="Objects file *" Margin="0,0,10,0"
                     ToolTip="The dashboards to import (an .ndjson export). The one for Security Onion is filled in by itself from the kibana dashboards folder."/>
          <TextBox   x:Name="txtKbFile" Grid.Column="1" Margin="0,0,8,0"/>
          <Button    x:Name="btnKbBrowse" Grid.Column="2" Content="Browse..." MinWidth="96"/>
        </Grid>
        <TextBlock x:Name="lblKbFile" Style="{DynamicResource Hint}" Margin="128,6,0,0"
                   Text="Nothing loaded."/>
      </StackPanel>
    </Border>

    <!-- ===== where it goes: the Upload tab's connection, deliberately not a
         second copy of the same three fields. Two sets of credentials on one
         screen is two things to keep in step, and the one that is wrong is
         always the one you did not look at. ===== -->
    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <TextBlock Text="Security Onion connection" Style="{DynamicResource SectionHead}"/>
        <TextBlock Style="{DynamicResource Hint}"
                   Text="This tab uses the host, username and password you typed on the Upload tab. Fill them in there; they are read when you press a button here, so a correction on that tab takes effect immediately. Pin or Skip verification is chosen on that tab too."/>
        <TextBlock x:Name="lblKbConn" Margin="0,8,0,0" Text="No host entered on the Upload tab yet."/>

        <!-- The Upload tab pins Elasticsearch on 9200. This tab talks to the
             web front end on 443, which presents a different certificate, so
             it needs a pin of its own. -->
        <Grid Margin="0,10,0,0">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="128"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" Text="Web UI fingerprint" Margin="0,0,10,0"
                     ToolTip="The SHA-256 of the certificate on the web page (port 443) - a different one from the Upload tab's Elasticsearch pin. Fetch, check once, and it is saved."/>
          <TextBox   x:Name="txtKbPin" Grid.Column="1" Margin="0,0,8,0"/>
          <Button    x:Name="btnKbFetch" Grid.Column="2" Content="Fetch" MinWidth="96"/>
        </Grid>
        <TextBlock Style="{DynamicResource Hint}" Margin="128,6,0,0"
                   Text="SHA-256 of the certificate on port 443. It is not the one the Upload tab pinned (that is Elasticsearch on 9200), so it needs its own. Confirm it once; it is saved. Not needed when the Upload tab is set to Skip verification."/>
        <TextBlock Style="{DynamicResource Hint}" Margin="0,8,0,0"
                   Text="Security Onion puts a login page in front of Kibana, so the tool signs in the same way a browser does before it imports anything. The account must be allowed to manage saved objects; on Security Onion that means an administrator. This tab works with Security Onion only: for a plain Elastic stack import the dashboards by hand - see kibana dashboards\IMPORT.txt."/>
      </StackPanel>
    </Border>

    <!-- ===== the two actions ===== -->
    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <TextBlock Text="Import" Style="{DynamicResource SectionHead}"/>
        <StackPanel Orientation="Horizontal">
          <Button x:Name="btnKbImport" Content="IMPORT DASHBOARDS" Style="{DynamicResource Primary}"/>
          <Button x:Name="btnKbRemove" Content="REMOVE HAYABUSA DASHBOARDS" Margin="14,0,0,0"/>
        </StackPanel>
        <TextBlock Style="{DynamicResource Hint}" Margin="0,8,0,0"
                   Text="Import overwrites objects with the same id, so running it twice leaves one copy of everything, not two. Remove deletes only saved objects whose id starts with hayabusa-, and asks first; Security Onion's own dashboards are never touched."/>
        <TextBlock x:Name="lblKbResult" Margin="0,10,0,0" Text="" TextWrapping="Wrap"/>
      </StackPanel>
    </Border>

    <!-- ===== the two reasons a perfect import still shows nothing ===== -->
    <Border Style="{DynamicResource CardPanel}">
      <StackPanel>
        <TextBlock Text="After importing" Style="{DynamicResource SectionHead}"/>
        <TextBlock Style="{DynamicResource Hint}"
                   Text="1. The dashboards stay EMPTY until an index whose name matches hayabusa-* exists and holds documents. That is what the Upload tab creates; nothing on this tab uploads any data."/>
        <TextBlock Style="{DynamicResource Hint}" Margin="0,6,0,0"
                   Text="2. Set the time picker (top right in Kibana) to a range that covers the events, for example 'Last 5 years'. EVTX records carry the time they happened on the host, not the time they were uploaded, so the default 'Last 15 minutes' shows nothing on a correct import."/>
        <TextBlock Style="{DynamicResource Hint}" Margin="0,6,0,0"
                   Text="3. The 'Raw Events' dashboards (PEAK Hunt, Anomaly Hunt, Lateral Movement, Active Directory, Persistence &amp; Evasion) read EVERY raw event EVTXER sent to hayabusa-raw-*, not only the detections, and open on all time."/>
        <TextBlock Style="{DynamicResource Hint}" Margin="0,6,0,0"
                   Text="4. The two 'Anomaly Hunt' dashboards look for what 'rarest first' misses: only on one machine, new lately, odd hours (UTC), wrong place, bursts, fan-out, longest command lines. On real machines start with their sections 4, 6 and 7."/>
        <TextBlock Style="{DynamicResource Hint}" Margin="0,6,0,0"
                   Text="Then: Menu, Dashboards, search 'Hayabusa' or 'Raw Events'. Saved searches are under Menu, Discover, Open."/>
      </StackPanel>
    </Border>

  </StackPanel>
</Grid>
'@

$kibanaRoot = [Windows.Markup.XamlReader]::Load(
    (New-Object System.Xml.XmlNodeReader ([xml]$kibanaXaml)))
$tabKibana.Content = $kibanaRoot

foreach ($name in @('txtKbFile','btnKbBrowse','lblKbFile','lblKbConn',
                    'txtKbPin','btnKbFetch',
                    'btnKbImport','btnKbRemove','lblKbResult')) {
    Set-Variable -Name $name -Scope Script -Value $kibanaRoot.FindName($name)
}

# ----------------------------------------------------------- the file -------
function Update-KibanaFileNote {
    $path = $txtKbFile.Text.Trim()
    if (-not $path) {
        # Which of the two shipped files is which was nowhere on screen
        # (usability walk, 2026-10-21).
        $lblKbFile.Text = "Nothing loaded. Browse to 'kibana dashboards\hayabusa-kibana-objects.ndjson' (Kibana 9 / Security Onion - this tab). The -8.7 file beside it is for Kibana 8.7, imported by hand (IMPORT.txt)."
        $lblKbFile.Foreground = $script:UpBrush.muted
        return 0
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $lblKbFile.Text = "Not found: $path"
        $lblKbFile.Foreground = $script:UpBrush.err
        return 0
    }
    # A Kibana export ends with a summary line that is not an object, so this
    # is not a line count - it is what will actually be imported.
    $n = Get-NdjsonObjectCount $path
    if ($n -le 0) {
        $lblKbFile.Text = "$([IO.Path]::GetFileName($path)) holds no saved objects. Is this a Kibana export?"
        $lblKbFile.Foreground = $script:UpBrush.err
        return 0
    }
    $lblKbFile.Text = "Ready: $([IO.Path]::GetFileName($path)) - $n saved object(s), exported from Kibana $script:KbExportVersion."
    $lblKbFile.Foreground = $script:UpBrush.ok
    return $n
}

$btnKbBrowse.Add_Click({
    $d = New-Object Microsoft.Win32.OpenFileDialog
    $d.Filter = 'Kibana saved objects (*.ndjson)|*.ndjson|All files (*.*)|*.*'
    $start = Join-Path $script:Root 'kibana'
    if (Test-Path -LiteralPath $start) { $d.InitialDirectory = $start }
    if ($d.ShowDialog() -ne $true) { return }
    $txtKbFile.Text = $d.FileName
    [void](Update-KibanaFileNote)
})
$txtKbFile.Add_LostFocus({ [void](Update-KibanaFileNote) })

# ------------------------------------------------------- the connection -----
# Read at click time, never cached: the operator may fix a typo on the Upload
# tab between two presses here, and a cached copy would keep failing.
function Get-KibanaConnection {
    $hostName = ''; $user = ''; $secret = ''
    try { $hostName = $txtHost.Text.Trim() } catch { }
    try { $user     = $txtUser.Text.Trim() } catch { }
    try { $secret   = Get-UploadPassword }   catch { }

    $missing = Get-MissingConnectionFields $hostName $user $secret

    [pscustomobject]@{
        Ok       = ($missing.Count -eq 0)
        Missing  = $missing
        HostName = $hostName
        User     = $user
        Secret   = $secret
        Reason   = if (-not $user -and $secret.Trim()) {
                       "The Upload tab holds an API key (no username). A key cannot import dashboards - enter a username and password there for this tab."
                   } elseif ($missing.Count) {
                       "Fill in the $($missing -join ', ') on the Upload tab first. This tab has no fields of its own on purpose - it uses that one connection."
                   } else { '' }
    }
}

function Update-KibanaConnNote {
    $c = Get-KibanaConnection
    if (-not $c.HostName) {
        $lblKbConn.Text = 'No host entered on the Upload tab yet.'
        $lblKbConn.Foreground = $script:UpBrush.muted
        return
    }
    $who = if ($c.User) { $c.User } elseif ("$($c.Secret)".Trim()) { '(an API key - needs a username and password here)' } else { '(no username yet)' }
    $pw  = if ('password' -notin $c.Missing) { 'password entered' } else { 'NO PASSWORD ENTERED' }
    $lblKbConn.Text = "Will sign in to https://$($c.HostName)/kibana as $who ($pw)."
    # Neutral, not green: nothing has been checked yet (usability walk).
    $lblKbConn.Foreground = if ($c.Ok) { $script:UpBrush.muted } else { $script:UpBrush.warn }
}
# Refreshed whenever the operator arrives on this tab, so the line is never a
# stale copy of what the Upload tab held a minute ago.
try { $tabs.Add_SelectionChanged({ Update-KibanaConnNote }) } catch { }

# ------------------------------------------------------------ the pin -------
# Security Onion serves Elasticsearch (9200) and its web front end (443) with
# different certificates. Pinning only the Upload tab's 9200 certificate made
# every import fail the TLS handshake while Verify on the Upload tab was green.
$btnKbFetch.Add_Click({
    $hostName = ''
    try { $hostName = $txtHost.Text.Trim() } catch { }
    if (-not $hostName) {
        [void][System.Windows.MessageBox]::Show("Enter the host on the Upload tab first.", 'Missing host')
        return
    }
    if (-not (Confirm-PcapBeforeNetwork 'fetch the Kibana certificate')) { return }
    $fetchResult = 'Failed'; $fetchDetail = ''
    try {
        $tp = Get-ServerCertThumbprint $hostName 443
        $txtKbPin.Text = $tp
        Write-Log ("Web UI certificate fingerprint at {0}:443" -f $hostName) 'info'
        Write-Log ("  " + $tp + [Environment]::NewLine)
        Write-Log ("Confirm this against the certificate a browser shows for https://$hostName (the padlock). It is saved, and every later import must see the same certificate or it stops." + [Environment]::NewLine)
        $fetchResult = 'Success'; $fetchDetail = "SHA-256 $tp"
    } catch {
        $fetchDetail = Get-ConnectionHint $_.Exception.Message $hostName 443
        Write-Log "Could not read the certificate: $fetchDetail`n" 'err'
        [void][System.Windows.MessageBox]::Show($fetchDetail, 'Could not read certificate')
    } finally {
        Write-Ledger @(New-LedgerRow -Action 'Certificate fetch' -Target $hostName -Port 443 -Protocol 'HTTPS (Kibana)' `
                          -Result $fetchResult -Details $fetchDetail)
    }
})

function Set-KibanaTlsTrust {
    # Returns $false and says why, like the Upload tab does. Both pins are
    # installed because the callback is process-wide: the Upload tab's index
    # name check talks to 9200 afterwards without setting trust again.
    # Set-TlsTrust installs the COMPILED HayabusaCertPin callback. A
    # scriptblock callback throws "There is no Runspace available" on .NET's
    # worker thread and every HTTPS request here would fail.
    if ($rbTlsSkip.IsChecked -eq $true) { Set-TlsTrust -Mode 'Skip'; return $true }
    if (-not (ConvertTo-Thumbprint $txtKbPin.Text)) {
        [void][System.Windows.MessageBox]::Show(
            "Press Fetch next to 'Web UI fingerprint' on this tab and confirm it first. Security Onion's web interface (port 443) uses a different certificate from Elasticsearch (port 9200), so the Upload tab's fingerprint does not cover it.`n`nOr choose 'Skip verification' on the Upload tab.",
            'Web UI fingerprint missing')
        return $false
    }
    try { Set-TlsTrust -Mode 'Pin' -PinnedThumbprint @($txtKbPin.Text, $txtPin.Text); return $true }
    catch {
        [void][System.Windows.MessageBox]::Show($_.Exception.Message, 'Certificate pin missing')
        return $false
    }
}

# The raw .NET messages name neither the cause nor the fix.
function Get-KibanaErrorText([string]$Message) {
    if ($Message -match '401') { return 'HTTP 401 - the username or password on the Upload tab is wrong.' }
    if ($Message -match '403') { return 'HTTP 403 - this account is not allowed to manage saved objects. Use an administrator account.' }
    if ($Message -match 'trust relationship') {
        return 'the certificate on port 443 does not match the Web UI fingerprint on this tab. Press Fetch, confirm the new fingerprint, and try again.'
    }
    return $Message
}

# ------------------------------------------------------------- transport ----
# Kratos self-service browser login. Exactly kibana_setup.py::_login:
# GET the flow, pull csrf_token out of it, POST identifier + password as JSON,
# and confirm a session cookie came back. Invoke-WebRequest -SessionVariable /
# -WebSession is what carries the cookie across the calls that follow.
function Connect-KibanaSession {
    param([string]$HostName, [string]$User, [string]$Secret, [int]$TimeoutSec = 30)

    $sess = $null
    $flowResp = Invoke-WebRequest -Uri "https://$HostName/auth/self-service/login/browser" `
        -Headers @{ Accept = 'application/json' } -SessionVariable sess `
        -UseBasicParsing -TimeoutSec $TimeoutSec
    # Decoded from the raw bytes for the Invoke-EsJson reason: PowerShell 5.1
    # reads a charset-less JSON response as Latin-1.
    $flow = [Text.Encoding]::UTF8.GetString($flowResp.RawContentStream.ToArray()) | ConvertFrom-Json

    $action = [string]$flow.ui.action
    if (-not $action) {
        throw "The login endpoint did not return a Kratos flow. Is https://$HostName Security Onion?"
    }
    $csrf = Get-KratosCsrfToken $flow
    if (-not $csrf) {
        throw 'The Kratos login flow carried no csrf_token, so the sign-in would be rejected.'
    }

    $payload = @{ method = 'password'; identifier = $User; password = $Secret; csrf_token = $csrf } |
               ConvertTo-Json -Compress
    $null = Invoke-WebRequest -Uri $action -Method Post -WebSession $sess `
        -Headers @{ Accept = 'application/json' } -ContentType 'application/json' `
        -Body (ConvertTo-BulkBody $payload) -UseBasicParsing -TimeoutSec $TimeoutSec

    # The cookie is the only proof the login worked: Kratos answers 200 with a
    # fresh flow when the password is wrong, so a status check alone would let
    # a bad password through to an import that silently does nothing.
    $cookies = $sess.Cookies.GetCookies((New-Object System.Uri("https://$HostName/")))
    $names = @($cookies | ForEach-Object { $_.Name })
    if ($names -notcontains 'ory_kratos_session') {
        throw "Sign-in did not return a Kratos session cookie. The username or password is probably wrong (cookies seen: $($names -join ', '))."
    }
    return $sess
}

# One call into Kibana's API: session cookie for the proxy, basic auth for
# Kibana, kbn-xsrf on everything (Kibana refuses a write without it).
function Invoke-KibanaApi {
    param(
        [string]$HostName,
        $Session,
        $Auth,
        [string]$Path,
        [string]$Method = 'Get',
        $Body,
        [string]$ContentType,
        [int]$TimeoutSec = 120
    )
    $headers = @{ 'kbn-xsrf' = 'true'; Accept = 'application/json' }
    foreach ($k in @($Auth.Keys)) { $headers[$k] = $Auth[$k] }

    $p = @{ Uri = "https://$HostName/kibana$Path"; Method = $Method; Headers = $headers
            WebSession = $Session; UseBasicParsing = $true; TimeoutSec = $TimeoutSec }
    if ($ContentType)    { $p.ContentType = $ContentType }
    if ($null -ne $Body) { $p.Body = $Body }

    $resp  = Invoke-WebRequest @p
    $bytes = $resp.RawContentStream.ToArray()
    if ($bytes.Length -eq 0) { return $null }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    try { return ($text | ConvertFrom-Json) }
    catch {
        # The proxy answers an unauthenticated request with the login PAGE and
        # status 200. Saying "not JSON" would send the operator hunting for a
        # Kibana fault that is really a sign-in fault.
        throw "Kibana returned HTML rather than JSON for $Path - the request did not get past the login proxy. Check the username and password on the Upload tab."
    }
}

# ---------------------------------------------------------- the version -----
# Kibana refuses saved objects exported by a newer Kibana than itself, and says
# so only as a migration error naming no version. Compared numerically:
# '9.0.10' sorts before '9.0.8' as text, which would refuse a server that is
# actually newer.
function Test-KibanaVersionAccepts {
    param([string]$HostName, $Session, $Auth)

    $status = $null
    try { $status = Invoke-KibanaApi -HostName $HostName -Session $Session -Auth $Auth -Path '/api/status' -TimeoutSec 60 }
    catch { $status = $null }

    $ver = ''
    if ($status -and $status.version) { $ver = [string]$status.version.number }

    $cmp = Compare-KibanaVersion $ver $script:KbExportVersion
    if ($null -eq $cmp) {
        Write-Log "Could not read the Kibana version from /api/status.`n" 'warn'
        $answer = [System.Windows.MessageBox]::Show(
            "The tool could not read this Kibana's version.`n`nThe dashboards were exported from Kibana $script:KbExportVersion, and an older Kibana refuses them with an unhelpful migration error. Import anyway?",
            'Kibana version unknown',
            [System.Windows.MessageBoxButton]::YesNo,
            [System.Windows.MessageBoxImage]::Warning)
        return ($answer -eq [System.Windows.MessageBoxResult]::Yes)
    }

    if ($cmp -lt 0) {
        $msg = "This Kibana is version $ver. The dashboards were exported from Kibana $script:KbExportVersion, and Kibana refuses saved objects from a NEWER version than itself, so the import would fail part-way and leave half the objects behind.`n`nUpgrade Kibana to $script:KbExportVersion or later, or re-export the dashboards from a Kibana $ver."
        Write-Log "Refusing to import: target Kibana $ver is older than the export's $script:KbExportVersion.`n" 'err'
        [void][System.Windows.MessageBox]::Show($msg, 'Kibana is too old')
        $lblKbResult.Text = "Refused: target Kibana $ver is older than the export ($script:KbExportVersion)."
        $lblKbResult.Foreground = $script:UpBrush.err
        return $false
    }

    Write-Log "Target Kibana $ver accepts objects exported from $script:KbExportVersion.`n" 'ok'
    return $true
}

# -------------------------------------------------------------- import ------
$btnKbImport.Add_Click({
    if ($script:Busy) { return }

    $count = Update-KibanaFileNote
    if ($count -le 0) {
        [void][System.Windows.MessageBox]::Show($lblKbFile.Text, 'Nothing to import')
        return
    }
    $conn = Get-KibanaConnection
    if (-not $conn.Ok) {
        [void][System.Windows.MessageBox]::Show($conn.Reason, 'Missing Security Onion credentials')
        return
    }
    # Ahead of the busy flag: a refused pin must leave the buttons usable.
    if (-not (Set-KibanaTlsTrust)) { return }

    $file = $txtKbFile.Text.Trim()
    if (-not (Confirm-PcapBeforeNetwork 'import dashboards into Kibana')) { return }
    Set-AppBusy $true 'importing dashboards'
    $btnKbImport.IsEnabled = $false; $btnKbRemove.IsEnabled = $false
    $bar.Maximum = 3; $bar.Value = 0
    try {
        $auth = Get-AuthHeader $conn.User $conn.Secret

        $lblStatus.Text = 'Signing in to Security Onion...'
        Write-Log "`nSigning in to https://$($conn.HostName) as $($conn.User)...`n" 'info'
        Invoke-UiPump
        $sess = Connect-KibanaSession -HostName $conn.HostName -User $conn.User -Secret $conn.Secret
        Write-Log "Kratos session established.`n" 'ok'
        $bar.Value = 1; Invoke-UiPump

        $lblStatus.Text = 'Checking the Kibana version...'
        if (-not (Test-KibanaVersionAccepts -HostName $conn.HostName -Session $sess -Auth $auth)) { return }
        $bar.Value = 2; Invoke-UiPump

        $lblStatus.Text = "Importing $count saved object(s)..."
        Write-Log "Importing $count object(s) from $([IO.Path]::GetFileName($file))...`n" 'info'
        Invoke-UiPump

        # Read as bytes and posted as bytes: a string body would be sent as
        # Latin-1 on 5.1 and mangle every non-ASCII character in the panels.
        $content = [IO.File]::ReadAllBytes($file)
        $mp = New-MultipartFileBody -Content $content -FileName ([IO.Path]::GetFileName($file))
        $resp = Invoke-KibanaApi -HostName $conn.HostName -Session $sess -Auth $auth `
            -Path '/api/saved_objects/_import?overwrite=true' -Method Post `
            -Body $mp.Bytes -ContentType $mp.ContentType -TimeoutSec 300
        $bar.Value = 3; Invoke-UiPump

        # Per object, not just success/failure: the errors[] entries name the
        # object that failed, which is the only actionable part of the reply.
        $summary = Get-KibanaImportSummary $resp
        Write-Log "created : $($summary.Created)`nerrors  : $($summary.ErrorCount)`n"
        foreach ($e in @($summary.Errors)) {
            Write-Log "  $($e.Text)`n" 'err'
        }

        if ($summary.Success -and $summary.ErrorCount -eq 0) {
            $lblKbResult.Text = "Imported $($summary.Created) saved object(s). Open Kibana, then Menu, Dashboards, search 'Hayabusa'. Remember the time picker."
            $lblKbResult.Foreground = $script:UpBrush.ok
            Write-Log "Import OK: $($summary.Created) object(s) at https://$($conn.HostName)/kibana/app/dashboards`n" 'ok'
        } else {
            $lblKbResult.Text = "Imported $($summary.Created) object(s) with $($summary.ErrorCount) error(s). See the log - each failing object is named there."
            $lblKbResult.Foreground = $script:UpBrush.err
            Write-Log "Import finished with errors.`n" 'err'
        }
    } catch {
        $msg = Get-KibanaErrorText $_.Exception.Message
        Write-Log "`nIMPORT FAILED: $msg`n" 'err'
        $lblKbResult.Text = "Import failed: $msg"
        $lblKbResult.Foreground = $script:UpBrush.err
    } finally {
        # Handed back to Set-AppBusy, which ends it on "Done" or "Failed - see
        # the log" by the errors logged; a fixed 'Finished' said done either way.
        $lblStatus.Text = $script:ActionWhat
        $btnKbImport.IsEnabled = $true; $btnKbRemove.IsEnabled = $true
        Set-AppBusy $false
    }
})

# -------------------------------------------------------------- remove ------
# The back-out path, kibana_setup.py --delete: find the saved objects, keep
# only the ones whose id carries our prefix, confirm the count, delete those.
$btnKbRemove.Add_Click({
    if ($script:Busy) { return }

    $conn = Get-KibanaConnection
    if (-not $conn.Ok) {
        [void][System.Windows.MessageBox]::Show($conn.Reason, 'Missing Security Onion credentials')
        return
    }
    if (-not (Set-KibanaTlsTrust)) { return }

    if (-not (Confirm-PcapBeforeNetwork 'remove dashboards from Kibana')) { return }
    Set-AppBusy $true 'removing dashboards'
    $btnKbImport.IsEnabled = $false; $btnKbRemove.IsEnabled = $false
    try {
        $auth = Get-AuthHeader $conn.User $conn.Secret

        $lblStatus.Text = 'Signing in to Security Onion...'
        Invoke-UiPump
        $sess = Connect-KibanaSession -HostName $conn.HostName -User $conn.User -Secret $conn.Secret
        Write-Log "`nKratos session established.`n" 'ok'

        $lblStatus.Text = 'Listing saved objects...'
        Invoke-UiPump
        $found = Invoke-KibanaApi -HostName $conn.HostName -Session $sess -Auth $auth `
            -Path '/api/saved_objects/_find?type=dashboard&type=lens&type=index-pattern&type=search&per_page=500' `
            -TimeoutSec 120

        # The guard. Security Onion's own dashboards, lenses and data views sit
        # in the same saved-object space, so only our prefix is ever deleted.
        $targets = @(Select-HayabusaSavedObjects $found.saved_objects)
        if ($targets.Count -eq 0) {
            Write-Log "Nothing to remove - no saved object on this Kibana carries the hayabusa- prefix.`n"
            $lblKbResult.Text = 'Nothing to remove: this Kibana holds no Hayabusa saved objects.'
            $lblKbResult.Foreground = $script:UpBrush.muted
            return
        }

        $byType = ($targets | Group-Object type | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '
        $answer = [System.Windows.MessageBox]::Show(
            "Delete $($targets.Count) saved object(s) from https://$($conn.HostName)/kibana ?`n`n$byType`n`nOnly objects whose id starts with 'hayabusa-' are deleted, so Security Onion's own dashboards are untouched. Data you uploaded is NOT affected - that lives in the hayabusa-* index.",
            'Remove Hayabusa dashboards',
            [System.Windows.MessageBoxButton]::YesNo,
            [System.Windows.MessageBoxImage]::Warning)
        if ($answer -ne [System.Windows.MessageBoxResult]::Yes) {
            Write-Log "Removal cancelled - nothing was deleted.`n"
            return
        }

        $bar.Maximum = $targets.Count; $bar.Value = 0
        $gone = 0; $failed = 0
        foreach ($o in $targets) {
            $id = [string]$o.id
            try {
                $null = Invoke-KibanaApi -HostName $conn.HostName -Session $sess -Auth $auth `
                    -Path ("/api/saved_objects/{0}/{1}" -f $o.type, [uri]::EscapeDataString($id)) `
                    -Method Delete -TimeoutSec 60
                $gone++
                Write-Log "  deleted $($o.type)/$id`n"
            } catch {
                $failed++
                Write-Log "  FAILED $($o.type)/${id}: $($_.Exception.Message)`n" 'err'
            }
            $bar.Value = $gone + $failed
            $lblStatus.Text = "removed $gone, failed $failed"
            Invoke-UiPump
        }

        if ($failed -eq 0) {
            $lblKbResult.Text = "Removed $gone Hayabusa saved object(s). Uploaded data is untouched."
            $lblKbResult.Foreground = $script:UpBrush.ok
        } else {
            $lblKbResult.Text = "Removed $gone object(s), $failed failed. See the log."
            $lblKbResult.Foreground = $script:UpBrush.err
        }
    } catch {
        $msg = Get-KibanaErrorText $_.Exception.Message
        Write-Log "`nREMOVE FAILED: $msg`n" 'err'
        $lblKbResult.Text = "Remove failed: $msg"
        $lblKbResult.Foreground = $script:UpBrush.err
    } finally {
        # Handed back to Set-AppBusy, which ends it on "Done" or "Failed - see
        # the log" by the errors logged; a fixed 'Finished' said done either way.
        $lblStatus.Text = $script:ActionWhat
        $btnKbImport.IsEnabled = $true; $btnKbRemove.IsEnabled = $true
        Set-AppBusy $false
    }
})

# ------------------------------------------------------------- defaults -----
if (Test-Path -LiteralPath $script:KbDefaultFile) { $txtKbFile.Text = $script:KbDefaultFile }
# Read from importer.conf by the Upload tab, which loads first and saves it.
if ($script:SavedWebPin) { $txtKbPin.Text = $script:SavedWebPin }
[void](Update-KibanaFileNote)
Update-KibanaConnNote
