# Pure engine functions for the EVTXER. Dot-source this file.
# MUST have no side effects on load: no UI, no network, no file writes.
$script:HayabusaLibLoaded = $true

# ---------------------------------------------------------------- TLS ------
# Security Onion presents a certificate no public CA has signed, so ordinary
# chain validation always fails and the tool historically answered "trust
# everything". That encrypts the traffic but authenticates nobody: an attacker
# on the path can terminate TLS, read the password and the uploaded detections,
# and forward on. Pinning fixes the authentication half without any PKI - it
# ignores who signed the certificate and asks only whether it is the same one
# the operator enrolled.

function ConvertTo-Thumbprint([string]$Text) {
    # Operators paste fingerprints in whatever shape they copied them:
    # "AA:BB:CC", "aa bb cc", lowercase. Only separators are stripped - any
    # other stray character survives and makes the comparison fail, which is
    # the safe direction.
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    return ($Text -replace '[\s:\-]', '').ToUpperInvariant()
}

function Initialize-CertPin {
    # Compiled on purpose, not a PowerShell scriptblock. .NET invokes the
    # certificate validation callback on a worker thread that has no
    # PowerShell runspace, so ANY scriptblock callback - even { $true } -
    # throws "There is no Runspace available to run scripts in this thread"
    # and the request fails before the callback's verdict matters. This is
    # also why the original trust-all used Add-Type rather than a scriptblock.
    #
    # Compiled lazily: dot-sourcing this file must stay side-effect-free.
    if (-not ('HayabusaCertPin' -as [type])) {
        Add-Type -ErrorAction Stop @"
using System;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public static class HayabusaCertPin
{
    // Set by Set-TlsTrust. Each entry is a 64-character uppercase hex SHA-256.
    // More than one because Security Onion serves Elasticsearch (9200) and its
    // web front end (443) with different certificates.
    public static string[] Expected = new string[0];

    public static string Fingerprint(X509Certificate cert)
    {
        if (cert == null) return "";
        byte[] raw = cert.GetRawCertData();
        if (raw == null || raw.Length == 0) return "";
        using (SHA256 sha = SHA256.Create())
        {
            byte[] h = sha.ComputeHash(raw);
            StringBuilder sb = new StringBuilder(h.Length * 2);
            foreach (byte b in h) sb.Append(b.ToString("X2"));
            return sb.ToString();
        }
    }

    // Fails closed: a missing certificate, a missing pin, or a pin that is
    // not a full SHA-256 all mean "do not trust" - never "allow".
    public static bool Matches(X509Certificate cert, string expected)
    {
        if (expected == null || expected.Length != 64) return false;
        string have = Fingerprint(cert);
        if (have.Length != 64) return false;
        return string.Equals(have, expected, StringComparison.Ordinal);
    }

    public static bool MatchesAny(X509Certificate cert, string[] expected)
    {
        if (expected == null) return false;
        foreach (string e in expected) if (Matches(cert, e)) return true;
        return false;
    }

    private static bool ValidatePin(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
    {
        return MatchesAny(cert, Expected);
    }

    private static bool AcceptAny(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
    {
        return true;
    }

    public static readonly RemoteCertificateValidationCallback Pinned =
        new RemoteCertificateValidationCallback(ValidatePin);
    public static readonly RemoteCertificateValidationCallback TrustAll =
        new RemoteCertificateValidationCallback(AcceptAny);
}
"@
    }
}

function Get-CertSha256Thumbprint($Certificate) {
    # X509Certificate2.Thumbprint is SHA-1. This is SHA-256 over the DER
    # bytes, which is what openssl and browsers show.
    if ($null -eq $Certificate) { return '' }
    Initialize-CertPin
    return [HayabusaCertPin]::Fingerprint($Certificate)
}

function Test-PinnedCertificate($Certificate, [string[]]$ExpectedThumbprint) {
    # Same comparison the TLS callback runs, so the unit tests exercise the
    # code that actually guards the connection rather than a copy of it.
    Initialize-CertPin
    [string[]]$want = @($ExpectedThumbprint | ForEach-Object { ConvertTo-Thumbprint $_ })
    return [HayabusaCertPin]::MatchesAny($Certificate, $want)
}

function Set-TlsTrust {
    param(
        [ValidateSet('Pin','Skip','System')]
        [string]$Mode = 'Pin',
        [string[]]$PinnedThumbprint
    )
    Initialize-CertPin
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    # The legacy ICertificatePolicy hook takes precedence over the callback
    # below, so clear it in every mode or a stale trust-all policy from an
    # earlier call would keep winning.
    [System.Net.ServicePointManager]::CertificatePolicy = $null

    if ($Mode -eq 'Skip') {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [HayabusaCertPin]::TrustAll
        return
    }

    # Ordinary OS chain validation. Security Onion's own certificate cannot
    # pass it, so nothing in the tool selects this today - it is kept because
    # it is the only way to express "verify normally", and because tests reset
    # the process to it rather than leaving trust-all installed.
    if ($Mode -eq 'System') {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
        return
    }

    # Blank entries are dropped - a caller may pass a pin the operator has not
    # fetched yet alongside one they have. A malformed entry is refused, never
    # dropped: it is a typo in a pin the operator thinks is guarding them.
    [string[]]$want = @($PinnedThumbprint | ForEach-Object { ConvertTo-Thumbprint $_ } | Where-Object { $_ })
    foreach ($w in $want) {
        if ($w.Length -ne 64) {
            throw "Certificate pinning needs a 64-character SHA-256 fingerprint, but got '$w'. Press Fetch beside Fingerprint and confirm the value with whoever runs the stack. Skip verification is for a lab only."
        }
    }
    if ($want.Count -eq 0) {
        throw "Certificate pinning needs a 64-character SHA-256 fingerprint, but none was entered. Press Fetch beside Fingerprint and confirm the value with whoever runs the stack. Skip verification is for a lab only."
    }
    [HayabusaCertPin]::Expected = $want
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [HayabusaCertPin]::Pinned
}

function Get-ServerCertThumbprint([string]$HostName, [int]$Port = 9200, [int]$TimeoutMs = 10000) {
    # Reads the certificate the server presents, on its own socket, so that
    # identifying it never disturbs ServicePointManager for the rest of the
    # session. Accepting any certificate here is deliberate and safe: this call
    # establishes WHICH certificate is on the far end so the operator can
    # confirm it. Nothing is uploaded over this connection.
    Initialize-CertPin
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            throw "Timed out connecting to ${HostName}:${Port}"
        }
        $client.EndConnect($iar)
        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, [HayabusaCertPin]::TrustAll)
        try {
            $ssl.AuthenticateAsClient($HostName)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            return Get-CertSha256Thumbprint $cert
        } finally { $ssl.Dispose() }
    } finally { $client.Close() }
}

function Get-AuthHeader([string]$User, [string]$Pass) {
    # No username: the secret is an Elasticsearch API key - the one Kibana
    # shows as "encoded", or its id:key pair. A key limited to hayabusa-*
    # keeps the tool out of every other index.
    if ([string]::IsNullOrWhiteSpace($User)) {
        $k = "$Pass".Trim()
        if ($k.Contains(':')) { $k = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($k)) }
        return @{ Authorization = "ApiKey $k" }
    }
    $b = [Text.Encoding]::ASCII.GetBytes("${User}:${Pass}")
    return @{ Authorization = "Basic " + [Convert]::ToBase64String($b) }
}

function Get-EsAccountLabel([string]$User) {
    # The activity log's Account for an Elasticsearch login. Nothing is taken
    # from the secret: a password typed with the username forgotten looks
    # like an id:key pair, and half of it would land in the log (review,
    # 2026-10-17).
    if ([string]::IsNullOrWhiteSpace($User)) { return 'API key' }
    return $User.Trim()
}

function Get-MissingConnectionFields([string]$HostName, [string]$User, [string]$Secret, [switch]$ApiKeyOk) {
    # Whitespace-only counts as missing: it passed `-not $secret`, went out as
    # Basic auth, and the 401 was then reported as a wrong password the
    # operator never typed. The secret is tested, never trimmed - spaces
    # around a real password are part of it. -ApiKeyOk: an empty username
    # means the secret is an API key (the Upload tab).
    $missing = @()
    if ([string]::IsNullOrWhiteSpace($HostName)) { $missing += 'host / IP' }
    $key = $ApiKeyOk -and [string]::IsNullOrWhiteSpace($User)
    if (-not $key -and [string]::IsNullOrWhiteSpace($User)) { $missing += 'username' }
    if ([string]::IsNullOrWhiteSpace($Secret))   { $missing += $(if ($key) { 'password or API key' } else { 'password' }) }
    return ,$missing
}

function Get-ConnectionFingerprint([string]$Base, [string]$User, [string]$Secret) {
    # What VERIFY checked, so UPLOAD can refuse a form edited since. Hashed so
    # the password is not held in a second plaintext copy.
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$Base`0$User`0$Secret"))) }
    finally { $sha.Dispose() }
}

function Find-Hayabusa {
    # Names vary by release and platform, so match on the prefix.
    # The binaries ship inside code\ (AppRoot), not beside the operator's data.
    if (-not $script:AppRoot) { return '' }
    foreach ($d in @((Join-Path $script:AppRoot 'hayabusa-x64'),
                     (Join-Path $script:AppRoot 'hayabusa'),
                     $script:AppRoot)) {
        if (-not $d -or -not (Test-Path $d)) { continue }
        $hit = Get-ChildItem -Path $d -Filter 'hayabusa*.exe' -File -ErrorAction SilentlyContinue |
               Sort-Object Name | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    $c = Get-Command hayabusa -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    return ''
}

# ---------------------------------------------------------------- naming ---
function ConvertTo-IndexLabel([string]$Text) {
    $s = ($Text).Trim().ToLower() -replace '[^a-z0-9._-]+', '-'
    $s = $s.Trim('-', '.', '_')
    if ($s.Length -gt 40) { $s = $s.Substring(0, 40) }
    return $s
}

function Get-MissionIndexName([string]$Mission) {
    # One index per mission, deleted when the mission ends.
    # No date in it: a mission over several days, and the job
    # queue's host after host, all append to the same index - duplicates are
    # impossible anyway, every detection has a fixed _id (Get-DetectionId).
    $lab = ConvertTo-IndexLabel $Mission
    if (-not $lab) { return '' }
    return "hayabusa-mission-$lab"
}

function Test-DeletableIndexName([string]$Name) {
    # What "Delete mission index" may remove: one hayabusa- index by exact
    # name. A wildcard, a list or a data stream pattern could take more.
    return ((Test-HayabusaIndexName $Name) -and $Name -notmatch '[*,?\s]' -and $Name -notmatch '^\.')
}

function New-IndexName([string]$Label, [string[]]$Taken) {
    # Reusing an index name mixes unrelated cases and makes counts meaningless,
    # so the date plus a collision check keeps every import distinct.
    $lab  = ConvertTo-IndexLabel $Label
    $stem = if ($lab) { "hayabusa-$lab-" } else { "hayabusa-" }
    $base = "$stem$(Get-Date -Format 'yyyyMMdd')"
    if ($Taken -notcontains $base) { return $base }
    foreach ($i in 2..999) {
        $c = "{0}-{1:D3}" -f $base, $i
        if ($Taken -notcontains $c) { return $c }
    }
    return "$base-$([guid]::NewGuid().ToString('N').Substring(0,6))"
}


# ----------------------------------------------------- ECS transform -------
$script:SeverityMap = @{
    'emergency' = 100; 'critical' = 99; 'high' = 75
    'medium'    = 50;  'low'      = 25; 'informational' = 1
}
$script:TacticMap = @{
    'Recon'      = @('Reconnaissance','TA0043');  'ResDev'     = @('Resource Development','TA0042')
    'InitAccess' = @('Initial Access','TA0001');  'Exec'       = @('Execution','TA0002')
    'Persis'     = @('Persistence','TA0003');     'PrivEsc'    = @('Privilege Escalation','TA0004')
    'Stealth'    = @('Defense Evasion','TA0005'); 'DefImpair'  = @('Defense Impairment',$null)
    'CredAccess' = @('Credential Access','TA0006');'Disc'      = @('Discovery','TA0007')
    'LatMov'     = @('Lateral Movement','TA0008');'Collect'    = @('Collection','TA0009')
    'C2'         = @('Command and Control','TA0011'); 'Exfil'  = @('Exfiltration','TA0010')
    'Impact'     = @('Impact','TA0040')
}
$script:Placeholders = @('', '-', 'n/a', 'N/A')

function Get-Scalar($Value) {
    # Hayabusa emits a LIST when a field occurs twice in the source event
    # (commonly @('n/a','n/a')). ECS fields are single-valued.
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $keep = @()
        foreach ($i in $Value) {
            if ($null -eq $i) { continue }
            if ($i -is [string] -and $Placeholders -contains $i.Trim()) { continue }
            if ($keep -notcontains $i) { $keep += $i }
        }
        if ($keep.Count -eq 0) { return $null }
        if ($keep.Count -eq 1) { return $keep[0] }
        return ($keep -join ' | ')
    }
    if ($Value -is [string] -and $Placeholders -contains $Value.Trim()) { return $null }
    return $Value
}

function Get-Field($Obj, [string[]]$Names) {
    foreach ($n in $Names) {
        if ($Obj.PSObject.Properties.Name -contains $n) {
            $v = Get-Scalar $Obj.$n
            if ($null -ne $v -and "$v" -ne '') { return $v }
        }
    }
    return $null
}

function ConvertTo-Int($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [int] -or $Value -is [long]) { return [long]$Value }
    $s = "$Value".Trim()
    try {
        if ($s -match '^0[xX]') { return [Convert]::ToInt64($s.Substring(2), 16) }  # Windows logs PIDs as hex
        return [long]$s
    } catch { return $null }
}

function Get-DedupedCI($Values) {
    # De-duplicate case-insensitively, keep first-seen casing, sort
    # case-insensitively. Must stay byte-identical to dedupe_ci() in
    # scripts/hayabusa_to_ecs.py -- PowerShell's Sort-Object -Unique and
    # Python's sorted(set()) disagree on case, which silently diverges the
    # two implementations.
    $seen = [ordered]@{}
    foreach ($v in $Values) {
        $k = "$v".ToLower()
        if (-not $seen.Contains($k)) { $seen[$k] = $v }
    }
    return @($seen.Keys | Sort-Object | ForEach-Object { $seen[$_] })
}

function Test-Ip([string]$Value) {
    if (-not $Value) { return $false }
    $v = $Value.Trim()
    if ($v -in @('', '-', '::')) { return $false }
    $out = [ref]([System.Net.IPAddress]::Loopback)
    return [System.Net.IPAddress]::TryParse($v, $out)
}

function ConvertTo-LongPath([string]$Path) {
    # The \\?\ form of a path: no 260-character limit, for reading AND for
    # walking a folder - a directory past the limit is otherwise never entered.
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\?\')) { return $full }
    if ($full.StartsWith('\\')) { return '\\?\UNC\' + $full.Substring(2) }
    return '\\?\' + $full
}

function Get-DetailsAliasMap([string]$HayabusaDir) {
    # Hayabusa's Details shortens field names (TargetUserName -> TgtUser,
    # IpAddress -> SrcIP), using its own tables: rules/config/default_details.txt
    # per provider and event ID, or the rule's own "details:" line, which wins.
    # Both are "Short: %RealName% ¦ ...". This reads them back so every field
    # can be written under its real Windows name (winlog.event_data.*, the
    # names Winlogbeat and Security Onion use). Returns
    # @{ 'rule:<rule id>' = @{ Short = 'RealName' }; '<Provider>|<EventID>' = @{...} }.
    # An empty map when the Hayabusa folder is not there: Details keys then keep
    # Hayabusa's names, which is what they were before.
    $map = @{}
    if (-not $HayabusaDir) { return $map }
    $sep  = [string][char]0xA6   # the broken bar between pairs; kept out of this file's bytes
    $pair = [regex]"([^:$sep]+?):\s*%([^%]+)%"
    $toTable = {
        param($text)
        $t = @{}
        foreach ($m in $pair.Matches($text)) { $t[$m.Groups[1].Value.Trim()] = $m.Groups[2].Value.Trim() }
        $t
    }
    $defaults = Join-Path $HayabusaDir 'rules\config\default_details.txt'
    if (Test-Path -LiteralPath $defaults) {
        foreach ($line in [IO.File]::ReadAllLines($defaults, [Text.Encoding]::UTF8)) {
            $parts = $line.Split([char[]]',', 3)
            if ($parts.Count -lt 3 -or $parts[1].Trim() -eq 'EID') { continue }
            $map["$($parts[0].Trim())|$($parts[1].Trim())"] = & $toTable $parts[2]
        }
    }
    $rules = Join-Path $HayabusaDir 'rules'
    if (Test-Path -LiteralPath $rules) {
        $id = [regex]'(?m)^id:\s*(\S+)'
        $details = [regex]'(?m)^details:\s*[''"]?(.*?)[''"]?\s*$'
        foreach ($f in [IO.Directory]::EnumerateFiles((ConvertTo-LongPath $rules), '*.yml', [IO.SearchOption]::AllDirectories)) {
            # Walked through the \\?\ form, so even a rule path past 260
            # characters reads (a deployment copy had one at 264, which once failed
            # every conversion). A rule that still cannot be read costs only
            # its own short names, never the conversion.
            try { $text = [IO.File]::ReadAllText($f, [Text.Encoding]::UTF8) } catch { continue }
            if ($text.IndexOf("`ndetails:") -lt 0 -and -not $text.StartsWith('details:')) { continue }
            $d = $details.Match($text); $i = $id.Match($text)
            if ($d.Success -and $i.Success) { $map["rule:$($i.Groups[1].Value)"] = & $toTable $d.Groups[1].Value }
        }
    }
    return $map
}

function Get-EventData($Doc, [hashtable]$Aliases) {
    # Every field of the event under its real name: ExtraFieldInfo already uses
    # real names, Details is translated back through Get-DetailsAliasMap. A key
    # the map does not know is already a real name - when no summary is defined
    # for an event, Hayabusa puts the event's own fields in Details.
    $data = [ordered]@{}
    if ($Doc.ExtraFieldInfo -is [pscustomobject]) {
        foreach ($p in $Doc.ExtraFieldInfo.PSObject.Properties) { $data[$p.Name] = $p.Value }
    }
    if ($Doc.Details -is [pscustomobject]) {
        $map = $null
        if ($Aliases) {
            $map = $Aliases["rule:$($Doc.RuleID)"]
            if (-not $map) { $map = $Aliases["$($Doc.Provider)|$($Doc.EventID)"] }
        }
        foreach ($p in $Doc.Details.PSObject.Properties) {
            $name = if ($map -and $map.ContainsKey($p.Name)) { $map[$p.Name] } else { $p.Name }
            $data[$name] = $p.Value
        }
    }
    return $data
}

function Get-DetectionId($Doc) {
    # The same detection gets the same id however often it is scanned: from a
    # re-pull two weeks later (whatever has not rolled out of the log comes back
    # again), or from a forgotten second copy of the same logs. The upload sends
    # it as _id, so Elasticsearch stores the detection once. EvtxFile is left
    # out on purpose - it is where a copy landed, not what happened. One record
    # can match several rules, hence the rule. detection_id() in
    # scripts/hayabusa_to_ecs.py builds the same string.
    $key = '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $Doc.Computer, $Doc.Channel, $Doc.RecordID, $Doc.EventID,
                                            $Doc.Timestamp, $Doc.RuleID, $Doc.RuleTitle
    if (-not $script:IdHasher) { $script:IdHasher = [Security.Cryptography.SHA1]::Create() }
    $hash = $script:IdHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($key))
    return [BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant()
}

function ConvertTo-EcsDocument($Doc, [string]$ImportId, [hashtable]$Aliases) {
    $details = if ($Doc.PSObject.Properties.Name -contains 'Details' -and $Doc.Details) { $Doc.Details } else { [pscustomobject]@{} }
    $extra   = if ($Doc.PSObject.Properties.Name -contains 'ExtraFieldInfo' -and $Doc.ExtraFieldInfo) { $Doc.ExtraFieldInfo } else { [pscustomobject]@{} }
    $level   = "$($Doc.Level)".ToLower()
    $sev     = if ($SeverityMap.ContainsKey($level)) { $SeverityMap[$level] } else { 0 }

    $out = [ordered]@{
        '@timestamp' = $Doc.Timestamp
        ecs     = @{ version = '8.11.0' }
        message = $Doc.RuleTitle
        event   = [ordered]@{
            # First, so the upload can read it without parsing - see Get-EcsLineId.
            id   = (Get-DetectionId $Doc)
            kind = 'alert'; module = 'hayabusa'; dataset = 'hayabusa.alert'
            severity = $sev; risk_score = $sev
            ingested = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        }
        import   = [ordered]@{ id = $ImportId }
        # Which EVTXER made it (owner, 2026-10-26: tell an index's old
        # documents from new ones); event.ingested above says when. Not part
        # of the detection id, so a new version never duplicates a detection.
        agent    = [ordered]@{ name = 'EVTXER'; type = 'evtxer' }
        # Hayabusa's own one-line summary stays as it was. ExtraFieldInfo is no
        # longer written separately: every one of its fields is in
        # winlog.event_data below, under the same name.
        hayabusa = [ordered]@{ details = $details; level = $Doc.Level }
    }
    if ($null -ne $Doc.EventID) { $out.event.code = "$($Doc.EventID)" }
    # Hayabusa writes "-" when a record has no provider. Python's EMPTY
    # tuple treats "-" as absent; a bare truthiness test here does not,
    # which silently diverged the two importers.
    if ($Doc.Provider -and $Doc.Provider -ne '-') { $out.event.provider = $Doc.Provider }
    if ($Doc.EvtxFile)          { $out.import.file = $Doc.EvtxFile }
    if ($script:ToolVersion)    { $out.agent.version = "$script:ToolVersion" }

    $rule = [ordered]@{}
    if ($Doc.RuleTitle)  { $rule.name = $Doc.RuleTitle }
    if ($Doc.RuleID)     { $rule.id = $Doc.RuleID }
    if ($Doc.RuleFile)   { $rule.ruleset = $Doc.RuleFile }
    if ($Doc.RuleAuthor) { $rule.author = @($Doc.RuleAuthor -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    if ($rule.Count)     { $out.rule = $rule }

    if ($Doc.Computer) { $out.host = @{ name = $Doc.Computer; hostname = $Doc.Computer } }

    $win = [ordered]@{}
    if ($Doc.Channel)        { $win.channel = $Doc.Channel }
    if ($Doc.Provider -and $Doc.Provider -ne '-') { $win.provider_name = $Doc.Provider }
    if ($null -ne $Doc.EventID)  { $win.event_id = "$($Doc.EventID)" }
    if ($null -ne $Doc.RecordID) { $win.record_id = $Doc.RecordID }
    # Every field of the event as a field of its own, under its real name -
    # searchable, filterable and chartable in Kibana instead of a JSON blob.
    $eventData = Get-EventData $Doc $Aliases
    if ($eventData.Count) { $win.event_data = $eventData }
    if ($win.Count) { $out.winlog = $win }
    if ($Doc.EvtxFile) { $out.log = @{ file = @{ path = $Doc.EvtxFile } } }

    foreach ($pair in @(@('Status','rule_status'), @('RuleCreationDate','rule_creation_date'),
                        @('RuleModifiedDate','rule_modified_date'), @('RuleFile','rule_file'),
                        @('EvtxFile','evtx_file'))) {
        $v = $Doc.($pair[0]); if ($v) { $out.hayabusa[$pair[1]] = $v }
    }

    # --- MITRE ---
    # NOTE the outer @( ): a PowerShell pipeline unwraps a single-element result
    # to a scalar, which would emit "Stealth" instead of ["Stealth"] and diverge
    # from the Python implementation. Keep every one of these wrapped.
    $tactics = @(@($Doc.MitreTactics) | Where-Object { $_ })
    $tags    = @(@($Doc.MitreTags)    | Where-Object { $_ })
    $techs   = @($tags | Where-Object { $_ -match '^T\d{4}(\.\d{3})?$' })
    $others  = @($tags | Where-Object { $_ -notmatch '^T\d{4}(\.\d{3})?$' })
    if ($tactics.Count -or $techs.Count) {
        $threat = [ordered]@{ framework = 'MITRE ATT&CK' }
        if ($tactics.Count) {
            $names = @(); $ids = @()
            foreach ($t in $tactics) {
                if ($TacticMap.ContainsKey("$t")) { $m = $TacticMap["$t"] } else { $m = @("$t", $null) }
                if ($names -notcontains $m[0]) { $names += $m[0] }
                if ($m[1] -and $ids -notcontains $m[1]) { $ids += $m[1] }
            }
            $threat.tactic = [ordered]@{ name = @($names) }
            if ($ids.Count) { $threat.tactic.id = @($ids) }
        }
        if ($techs.Count) { $threat.technique = @{ id = @($techs) } }
        $out.threat = $threat
    }
    if ($tactics.Count) { $out.hayabusa.mitre_tactics = @($tactics) }
    if ($others.Count)  { $out.hayabusa.mitre_tags = @($others) }
    if ($Doc.OtherTags) { $out.tags = @(@($Doc.OtherTags) | Where-Object { $_ }) }

    # --- promoted ECS fields ---
    $users = @(); $ips = @(); $hosts = @()
    $user = [ordered]@{}
    # Hayabusa's short TgtUser/SrcUser come last: only a rule that wrote no
    # full name falls back to them ("Logon Failure (Unknown Reason)"). On
    # Sysmon 10 SrcUser is the account doing the access, TgtUser the owner of
    # the process accessed (often SYSTEM) - the actor is the one to hunt.
    $short = if ("$($Doc.EventID)" -eq '10' -and "$($Doc.Channel)" -like '*Sysmon*') { @('SrcUser','TgtUser') } else { @('TgtUser','SrcUser') }
    $userKeys = @('TargetUserName','SubjectUserName','User','AccountName') + $short
    $un = Get-Field $details $userKeys
    if ($un) { $user.name = $un }
    $ud = Get-Field $details @('TargetDomainName','SubjectDomainName'); if ($ud) { $user.domain = $ud }
    $ui = Get-Field $details @('TargetUserSid','SubjectUserSid');       if ($ui) { $user.id = $ui }
    if ($user.Count) { $out.user = $user }
    foreach ($n in $userKeys) {
        $v = Get-Scalar $details.$n
        if ($v -is [string] -and $v -and $users -notcontains $v) { $users += $v }
    }

    $sip = Get-Field $details @('IpAddress','SourceIp','SrcIP','ClientAddress')
    if ((Test-Ip "$sip")) {
        $src = [ordered]@{ ip = "$sip" }
        $p = ConvertTo-Int (Get-Field $details @('IpPort','SourcePort','SrcPort'))
        if ($null -ne $p) { $src.port = $p }
        $out.source = $src; $ips += "$sip"
    }
    $dip = Get-Field $details @('DestinationIp','TgtIP','DestAddress')
    if ((Test-Ip "$dip")) {
        $dst = [ordered]@{ ip = "$dip" }
        $p = ConvertTo-Int (Get-Field $details @('DestinationPort','TgtPort'))
        if ($null -ne $p) { $dst.port = $p }
        $out.destination = $dst; $ips += "$dip"
    }

    $proc = [ordered]@{}
    $exe = Get-Field $details @('NewProcessName','Image','ProcessName','Proc')
    if ($exe) { $proc.executable = $exe; $proc.name = ("$exe" -replace '/', '\').Split('\')[-1] }
    $cl = Get-Field $details @('CommandLine','Cmdline'); if ($cl) { $proc.command_line = $cl }
    $pid_ = ConvertTo-Int (Get-Field $details @('NewProcessId','ProcessId','PID'))
    if ($null -ne $pid_) { $proc.pid = $pid_ }
    $pexe = Get-Field $details @('ParentProcessName','ParentImage','ParentProc')
    if ($pexe) {
        $parent = [ordered]@{ executable = $pexe; name = ("$pexe" -replace '/', '\').Split('\')[-1] }
        $ppid = ConvertTo-Int (Get-Field $details @('ParentProcessId','ParentPID'))
        if ($null -ne $ppid) { $parent.pid = $ppid }
        $proc.parent = $parent
    }
    if ($proc.Count) { $out.process = $proc }

    $hashes = Get-Field $details @('Hashes','Hash')
    if ($hashes -is [string] -and $hashes -match '=') {
        $h = [ordered]@{}
        foreach ($m in [regex]::Matches($hashes, '(\w+)=([0-9a-fA-F]+)')) {
            $h[$m.Groups[1].Value.ToLower()] = $m.Groups[2].Value
        }
        if ($h.Count) { $out.file = [ordered]@{ hash = $h } }
    }

    # --- hunt fields (2026-10-14) ---
    # What the hunt dashboard pivots on, under their ECS names. They were in
    # the index already, but only as Windows' own names in hayabusa.details /
    # .extra - or Hayabusa's short alias when a rule renames one (7045: Svc,
    # Path) - so every panel had to know every spelling. Details first, then
    # ExtraFieldInfo, where the raw name lands when the rule did not pick it.
    $any = { param([string[]]$n) $v = Get-Field $details $n; if ($null -eq $v) { $v = Get-Field $extra $n }; $v }
    # Hayabusa's short aliases are only safe on the events whose default
    # details define them (rules/config/default_details.txt): "Type" is the
    # logon type on 4624/4625/4634 but a WMI or firewall type elsewhere, and
    # "Query" is a DNS name only on Sysmon 22 - Sysmon 19 and WMI 5859 use it
    # for WMI queries.
    $eid = "$($Doc.EventID)"

    $lt = & $any @(@('LogonType') + $(if ($eid -in '4624', '4625', '4634') { 'Type' }))
    if ($null -ne $lt) {
        if (-not $out.Contains('winlog')) { $out.winlog = [ordered]@{} }
        $out.winlog.logon = [ordered]@{ type = ConvertTo-LogonTypeName $lt }
    }
    $pcl = & $any @('ParentCommandLine','ParentCmdline')
    if ($pcl) {
        if (-not $out.Contains('process')) { $out.process = [ordered]@{} }
        if (-not $out.process.Contains('parent')) { $out.process.parent = [ordered]@{} }
        $out.process.parent.command_line = $pcl
    }
    $svc = & $any @('ServiceName','Svc')
    if ($svc) { $out.service = [ordered]@{ name = $svc } }
    $fp = ConvertTo-BinaryPath (& $any @('TargetFilename','ImagePath','ServiceFileName','Path'))
    if ($fp) {
        if (-not $out.Contains('file')) { $out.file = [ordered]@{} }
        $out.file.path = $fp
        $out.file.name = ("$fp" -replace '/', '\').Split('\')[-1]
    }
    $sb = & $any @('ScriptBlockText','ScriptBlock')
    if ($sb) { $out.powershell = [ordered]@{ file = [ordered]@{ script_block_text = "$sb" } } }
    $reg = & $any @(@('TargetObject','TgtObj','RegKey') + $(if ($eid -eq '14') { 'OldName' }))
    if ($reg) { $out.registry = [ordered]@{ path = $reg } }
    $q = & $any @(@('QueryName') + $(if ($eid -eq '22') { 'Query' }))
    if ($q) { $out.dns = [ordered]@{ question = [ordered]@{ name = $q } } }

    $wks = Get-Field $details @('WorkstationName','SrcComp')
    if ($wks -is [string] -and $wks) { $hosts += $wks }
    if ($Doc.Computer) { $hosts += $Doc.Computer }

    $rel = [ordered]@{}
    if ($users.Count) { $rel.user  = @(Get-DedupedCI $users) }
    if ($ips.Count)   { $rel.ip    = @(Get-DedupedCI $ips) }
    if ($hosts.Count) { $rel.hosts = @(Get-DedupedCI $hosts) }
    if ($rel.Count)   { $out.related = $rel }

    return $out
}

# Winlogbeat's names for the logon types, so a filter reads
# winlog.logon.type:RemoteInteractive rather than a bare number. Hayabusa's
# field mapping writes "10 - REMOTE_INTERACTIVE"; only the number is used.
$script:LogonTypeNames = @{
    0 = 'System'; 2 = 'Interactive'; 3 = 'Network'; 4 = 'Batch'; 5 = 'Service'; 7 = 'Unlock'
    8 = 'NetworkCleartext'; 9 = 'NewCredentials'; 10 = 'RemoteInteractive'; 11 = 'CachedInteractive'
    12 = 'CachedRemoteInteractive'; 13 = 'CachedUnlock'
}
function ConvertTo-BinaryPath($Value) {
    # A service's ImagePath is a command line, not a path:
    # '"C:\Program Files\Agent\svc.exe" -k netsvcs' or
    # '%SystemRoot%\system32\svchost.exe -k LocalService'. The arguments are
    # cut so one binary is one file.path. A path with no recognisable
    # executable followed by a space or the end is kept whole.
    if (-not ($Value -is [string]) -or -not $Value.Trim()) { return $null }
    $v = $Value.Trim()
    $m = [regex]::Match($v, '^"([^"]+)"')
    if ($m.Success) { return $m.Groups[1].Value }
    $m = [regex]::Match($v, '^(.+?\.(exe|dll|sys|com|scr|bat|cmd|ps1))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return $v
}

function ConvertTo-LogonTypeName($Value) {
    $m = [regex]::Match("$Value", '^\s*(\d+)')
    if ($m.Success -and $script:LogonTypeNames.ContainsKey([int]$m.Groups[1].Value)) {
        return $script:LogonTypeNames[[int]$m.Groups[1].Value]
    }
    return "$Value".Trim()
}

# -------------------------------------------------------- Task 3: ConvertTo-HostList ---
function Format-TargetList([string]$Text) {
    # The Targets window's Tidy: one target per line,
    # each once (any case), IPv4 addresses in number order - 10.0.0.2 before
    # 10.0.0.10 - then names A-Z.
    $ips = @(); $names = @()
    foreach ($h in @(ConvertTo-HostList $Text)) {
        if ($h -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$' -and -not (@($Matches[1..4]) | Where-Object { [int]$_ -gt 255 })) { $ips += $h }
        else { $names += $h }
    }
    $ips = @($ips | Sort-Object { ($_ -split '\.' | ForEach-Object { '{0:000}' -f [int]$_ }) -join '.' })
    $names = @($names | Sort-Object)
    return ((@($ips) + @($names)) -join "`r`n")
}

function ConvertTo-HostList([string]$Text, [string]$FilePath) {
    $raw = @()
    if ($Text)     { $raw += ($Text -split '[,\r\n]+') }
    if ($FilePath -and (Test-Path $FilePath)) { $raw += (Get-Content -LiteralPath $FilePath) }
    $seen = [ordered]@{}
    foreach ($h in $raw) {
        $t = "$h".Trim()
        if ($t -and -not $seen.Contains($t.ToLowerInvariant())) { $seen[$t.ToLowerInvariant()] = $t }
    }
    @($seen.Values)
}

function ConvertTo-ExportFileName([string]$LogName) {
    # The file wevtutil writes a log to on the target. The log name comes from
    # the target (ALL mode reads `wevtutil el`), so every character Windows
    # forbids in a file name becomes '_' - a ':' would otherwise write an
    # alternate data stream, a '\' or '/' a subfolder.
    return (($LogName -replace '[\\/:*?"<>|\x00-\x1f]', '_') + '.evtx')
}

function Get-StagingListing {
    # Runs ON THE TARGET (Invoke-Command -ScriptBlock this function): what lies
    # in the staging area, one flat row per entry - the top-level candidates
    # (this run's folder and archive, and every EVTX_Export*/LOOT_Export) and
    # the direct children of each candidate folder. Nothing is deleted here;
    # Get-StagingDeletePlan decides, on this machine, where it is tested.
    # Cmdlets and string operations only: a target whose PowerShell runs in
    # ConstrainedLanguage (AppLocker, WDAC) refuses .NET method calls, and a
    # cleanup that throws leaves copies of the Security log behind. Owners are
    # SIDs read from the SDDL, because account NAMES are translated
    # ("VORDEFINIERT\Administratoren"). Flat rows, because remoting flattens
    # nested objects to strings.
    param([string]$Parent, [string[]]$Filters, [string[]]$Current)
    $me = ''
    # By full path: never a whoami that happens to come first on PATH.
    foreach ($w in @(& "$env:SystemRoot\System32\whoami.exe" /user /fo csv /nh 2>$null)) { if ("$w" -match '"(S-1-[0-9-]+)"\s*$') { $me = $Matches[1] } }
    $row = {
        param($i, [string]$Top)
        $sddl = try { "$((Get-Acl -LiteralPath $i.FullName -ErrorAction Stop).Sddl)" } catch { '' }
        # A hashtable, not [pscustomobject]: ConstrainedLanguage refuses that cast.
        @{
            Path = $i.FullName; Name = $i.Name; Top = $Top; Me = $me
            IsDir = [bool]$i.PSIsContainer; IsLink = ("$($i.Attributes)" -match 'ReparsePoint')
            Owner = $(if ($sddl -match '^O:(\S+?)G:') { $Matches[1] } else { '' })
            LastWrite = $i.LastWriteTime
        }
    }
    $tops = @()
    foreach ($p in $Current) { $tops += @(Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue) }
    foreach ($f in $Filters) { $tops += @(Get-ChildItem -LiteralPath $Parent -Filter $f -Force -ErrorAction SilentlyContinue) }
    $done = @()
    foreach ($t in $tops) {
        if (-not $t -or $done -contains $t.FullName) { continue }
        $done += $t.FullName
        & $row $t ''
        if ($t.PSIsContainer -and -not ("$($t.Attributes)" -match 'ReparsePoint')) {
            foreach ($c in @(Get-ChildItem -LiteralPath $t.FullName -Force -ErrorAction SilentlyContinue)) { & $row $c $t.FullName }
        }
    }
}

function Test-StagingOwner([string]$Owner, [string]$Me) {
    # SYSTEM, the Administrators group, the built-in Administrator (SDDL
    # writes its SID as LA, whoami as S-1-5-21-...-500) or the account doing
    # the collection - as SIDs or their SDDL aliases. An ordinary user cannot
    # create an entry any of these owns, nor replace one.
    if (-not "$Owner") { return $false }
    if (@('SY', 'BA', 'LA', 'S-1-5-18', 'S-1-5-32-544') -contains $Owner) { return $true }
    return ("$Me" -and ($Owner -eq $Me -or ($Owner -eq 'LA' -and "$Me" -match '-500$')))
}

function Get-StagingDeletePlan {
    # What may go, from Get-StagingListing's rows. The staging area is in
    # C:\Windows\Temp, where ordinary users can create entries, and this runs
    # as administrator, so it deletes only what a user can neither create nor
    # swap: files directly in an administrator's staging folder (or this
    # run's), never a link, never a subfolder (the collector only ever writes
    # flat *.evtx files). A folder
    # is then removed only if that left it empty. A walk down a tree could be
    # turned by swapping a subfolder for a junction mid-delete; this has no
    # tree to walk. Everything not taken is reported, not touched.
    # $Current: this run's own folder and archive, taken whatever their age;
    # anything else only once Test-StaleStagingItem calls it abandoned.
    param($Listing, [string[]]$Current, [datetime]$Now = (Get-Date))
    $files = @(); $dirs = @(); $left = @()
    foreach ($t in @($Listing | Where-Object { -not $_.Top })) {
        $ours = @($Current) -contains $t.Path
        if (-not $ours -and -not (Test-StaleStagingItem -Name $t.Name -LastWrite $t.LastWrite -Now $Now)) { continue }
        # This run's own items need no owner test: New-Item without -Force
        # proved the folder new, and a user cannot rename or replace an
        # administrator's entry in C:\Windows\Temp. Anything else must be an
        # administrator's to be swept.
        if ($t.IsLink -or (-not $ours -and -not (Test-StagingOwner $t.Owner $t.Me))) { $left += $t.Path; continue }
        if (-not $t.IsDir) { $files += $t.Path; continue }
        foreach ($c in @($Listing | Where-Object { $_.Top -eq $t.Path })) {
            # Inside an administrator's folder a user cannot swap a name, so
            # deleting a plain file only removes that file - whoever made it.
            if ($c.IsLink -or $c.IsDir) { $left += $c.Path }
            else { $files += $c.Path }
        }
        $dirs += $t.Path
    }
    return [pscustomobject]@{ Files = $files; Dirs = $dirs; Left = $left }
}

function Remove-StagingPlan {
    # Runs ON THE TARGET: deletes exactly Get-StagingDeletePlan's files, then
    # each folder if it is now empty (never -Recurse), and returns which of
    # $Check is still there. Cmdlets only - see Get-StagingListing.
    param([string[]]$Files, [string[]]$Dirs, [string[]]$Check)
    foreach ($f in $Files) { if ($f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue } }
    foreach ($d in $Dirs) {
        if ($d -and -not @(Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue).Count) {
            try { Remove-Item -LiteralPath $d -Force -ErrorAction Stop } catch { }
        }
    }
    @($Check | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
}

function Test-TargetName([string]$Name) {
    # A host name, FQDN, IPv4 or IPv6 address - nothing else. A target list
    # can come from someone else's file, and the name goes into TrustedHosts
    # ('*' would trust every host for the run), into the evidence folder's
    # path ('..\x' would climb out of it) and onto plink's command line ('-x'
    # would be read as an option). Must start with a letter or digit.
    return ("$Name" -match '^[A-Za-z0-9][A-Za-z0-9._:-]*$')
}

# ------------------------------------------------------- Task 4: ConvertTo-EvtxFileName ---
function ConvertTo-EvtxFileName([string]$LogName) {
    ($LogName -replace '/', '%4') + '.evtx'
}

# --------------------------------------------------------- Task 5: Log catalog & presets ---
function Get-LogCatalog {
    @(
        [pscustomobject]@{ LogName='Security';   Notes='Authentication, privilege, account management' }
        [pscustomobject]@{ LogName='System';     Notes='OS-level events, services, drivers' }
        [pscustomobject]@{ LogName='Application'; Notes='App-level errors and warnings' }
        [pscustomobject]@{ LogName='Windows PowerShell'; Notes='Classic PS engine logging' }
        [pscustomobject]@{ LogName='Microsoft-Windows-PowerShell/Operational'; Notes='Script blocks, remoting, module loads' }
        [pscustomobject]@{ LogName='Microsoft-Windows-Sysmon/Operational'; Notes='Requires Sysmon. Process, network, file events' }
        [pscustomobject]@{ LogName='Microsoft-Windows-TaskScheduler/Operational'; Notes='Scheduled task creation and execution' }
        [pscustomobject]@{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Notes='WMI queries and remote execution activity' }
        [pscustomobject]@{ LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Notes='RDP session logon/logoff events' }
        [pscustomobject]@{ LogName='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; Notes='RDP connection attempts and failures' }
        [pscustomobject]@{ LogName='Microsoft-Windows-DNS-Client/Operational'; Notes='DNS lookups - useful for C2 beacon detection' }
        [pscustomobject]@{ LogName='Microsoft-Windows-NTLM/Operational'; Notes='NTLM authentication events' }
        [pscustomobject]@{ LogName='Microsoft-Windows-Bits-Client/Operational'; Notes='BITS transfers - common malware download method' }
        [pscustomobject]@{ LogName='Microsoft-Windows-AppLocker/EXE and DLL'; Notes='AppLocker execution allow/block events' }
        [pscustomobject]@{ LogName='Microsoft-Windows-Windows Defender/Operational'; Notes='Defender detections, exclusions, scan results' }
        [pscustomobject]@{ LogName='Microsoft-Windows-AppLocker/MSI and Script'; Notes='Every script and installer run, where an AppLocker policy exists' }
        [pscustomobject]@{ LogName='Microsoft-Windows-CodeIntegrity/Operational'; Notes='Unsigned or blocked drivers and binaries' }
        [pscustomobject]@{ LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; Notes='Firewall rules added, changed or deleted' }
        [pscustomobject]@{ LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Notes='Inbound RDP connections and their source address' }
    )
}
# Chosen by how many Hayabusa rules read each channel, and on by default
# (2026-10-12): Defender (31 rules), CodeIntegrity (10), Firewall (9),
# WMI-Activity (8), BITS (8), the two RDP logs (8). AppLocker records every
# executable and script launched, but only where a policy exists.
# TaskScheduler/Operational records task registration (106) and runs (200/201)
# with no audit policy - but it is DISABLED by default on Windows 10/11, so on a
# workstation it is often "not on this host".
# Sysmon stays LAST: each WinRM export is a wevtutil run Sysmon logs, so
# exporting it last keeps the collection's own noise out of the others.
$script:DfirPreset = @(
    'Security','System','Application','Windows PowerShell',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-CodeIntegrity/Operational',
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
    'Microsoft-Windows-WMI-Activity/Operational',
    'Microsoft-Windows-Bits-Client/Operational',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
    'Microsoft-Windows-AppLocker/EXE and DLL',
    'Microsoft-Windows-AppLocker/MSI and Script',
    'Microsoft-Windows-Sysmon/Operational'
)

# Every Windows install has these. "Not on this host" is only ever believed
# for the optional channels: the answer comes from the target, and a
# compromised target that claims to have no Security log must read PARTIAL,
# not as a clean collection.
$script:CoreLogs = @('Security', 'System', 'Application', 'Windows PowerShell',
                     'Microsoft-Windows-PowerShell/Operational')

function Test-LogCanBeAbsent([string]$Name) {
    # Takes a channel name or its .evtx file name (/ written as %4).
    $channel = ($Name -replace '\.evtx$', '') -replace '%4', '/'
    return -not ($script:CoreLogs -contains $channel)
}

function Get-ExportVerdict([int]$ExitCode, [bool]$FileExists, [string]$LogName) {
    # A requested log that does not exist on the host - Sysmon not installed,
    # AppLocker on a Home edition - is not a failed collection. Counting it as
    # one marked nearly every workstation Partial, and a word that is always on
    # stops being read. wevtutil says "channel not found" with 15007
    # (ERROR_EVT_CHANNEL_NOT_FOUND), measured 2026-10-12; a disabled-but-present
    # channel exports fine as an empty file. Never for a core log - see
    # $script:CoreLogs.
    if ($FileExists) { return 'Exported' }
    if ($ExitCode -eq 15007 -and (Test-LogCanBeAbsent $LogName)) { return 'Absent' }
    return 'Failed'
}
function Resolve-LogPreset([string]$Category, [string[]]$Custom) {
    switch ($Category) {
        'DFIR'   { return $script:DfirPreset }
        'All'    { return 'ALL' }
        'Custom' { return @($Custom) }
        default  { throw "unknown category: $Category" }
    }
}

# --------------------------------------------- WinRM transfer mode choice ---
# Pulling each .evtx back individually with Copy-Item -FromSession sends every
# file base64-encoded over WS-Man (~+33% on the wire) in its own round-trip.
# EVTX compresses very well, so zipping the export folder once and pulling a
# single archive is far cheaper. Two things stop us doing it unconditionally,
# and both fall back to the per-file loop rather than failing the collection.
function Get-WinRmZipCeilingBytes {
    # Compress-Archive in PS 5.1 is built on System.IO.Compression and falls
    # over near 2 GB. Stop well short of that: the number below is the total
    # UNcompressed size of the export folder, and the archive is what has to
    # stay under the real limit.
    return 1536MB
}

function Test-TargetStagingSpace {
    # WinRM copies the logs into C:\Windows\Temp ON THE TARGET before pulling
    # them, and nothing checked that the target could spare the room - a nearly
    # full C: on a production PC could run out mid-collection, and everything on
    # that machine with it (targets that must not be disrupted). The
    # copies, and the zip beside them when the logs are small enough to be
    # zipped, must leave at least 5 GB or 10% of the disk, whichever is more.
    param(
        [long]$FreeBytes,      # C: free on the target; -1 = could not be read
        [long]$DiskBytes,      # C: size on the target
        [long]$LogBytes        # the logs about to be copied, as the target sizes them
    )
    if ($FreeBytes -lt 0 -or $DiskBytes -le 0) {
        return [pscustomobject]@{ Ok = $true; Known = $false; NeedBytes = 0; FloorBytes = 0
                                  Message = 'free space on the target could not be read - collecting without the check' }
    }
    $need  = if ($LogBytes -gt 0 -and $LogBytes -le (Get-WinRmZipCeilingBytes)) { $LogBytes * 2 } else { [Math]::Max([long]0, $LogBytes) }
    $floor = [long][Math]::Max(5GB, $DiskBytes * 0.10)
    $ok    = ($FreeBytes - $need) -ge $floor
    $gb    = { param($b) '{0:N1} GB' -f ($b / 1GB) }
    $msg = if ($ok) { "target C: has $(& $gb $FreeBytes) free; the copies need about $(& $gb $need)" }
           else { "NOT COLLECTED to protect the target's disk: its C: has $(& $gb $FreeBytes) free, and copying these logs there needs about $(& $gb $need), which would leave less than $(& $gb $floor). Free space on the target, or collect fewer logs (DFIR instead of All), or use SMB, which copies nothing onto the target." }
    return [pscustomobject]@{ Ok = $ok; Known = $true; NeedBytes = $need; FloorBytes = $floor; Message = $msg }
}

function Select-WinRmTransferMode {
    param(
        [long]$ExportedBytes,
        [int]$RemotePsMajor
    )
    # Compress-Archive ships with PowerShell 5.0. Older targets, and targets
    # whose version we could not read, get the per-file path.
    if ($RemotePsMajor -lt 5) { return 'PerFile' }

    # A size of zero or less means the measurement failed, not that the folder
    # is empty - an empty folder never reaches this decision. Do not gamble a
    # whole host's collection on an unknown.
    if ($ExportedBytes -le 0) { return 'PerFile' }

    if ($ExportedBytes -gt (Get-WinRmZipCeilingBytes)) { return 'PerFile' }
    return 'Zip'
}

# ------------------------------------------------------------ bulk body ---
# PowerShell 5.1's Invoke-RestMethod encodes a *string* body as Latin-1 when
# the Content-Type carries no charset, so any non-ASCII character arrives at
# Elasticsearch as an invalid UTF-8 byte and the document is rejected with
# "Invalid UTF-8 start byte". Handing it a byte[] bypasses that encoding step
# entirely, which is the only reliable fix on 5.1 - setting charset on the
# Content-Type is not enough.
#
# Found in use, not in review: two Service Control Manager records
# naming "Intel(R) Graphics Software" (U+00AE) were rejected out of a
# 936-document upload. The 599-file sample corpus contains no non-ASCII in
# Details, which is why every earlier upload looked clean.
function ConvertTo-BulkBody([string]$Text) {
    # UTF8Encoding($false): no byte-order mark. A BOM would corrupt the first
    # action line of the ndjson payload.
    #
    # The leading comma is load-bearing. Without it PowerShell unrolls the
    # array on return and the caller receives Object[] rather than byte[];
    # Invoke-RestMethod then does not treat it as a raw body and the request
    # fails with 400 Bad Request.
    return ,((New-Object Text.UTF8Encoding($false)).GetBytes($Text))
}

function Invoke-EsJson {
    # The read-side counterpart to ConvertTo-BulkBody. Elasticsearch answers
    # with "content-type: application/json" and no charset, and PowerShell 5.1
    # then decodes the body as Latin-1: a host named "BuRO-PC" with a U+00FC
    # comes back as mojibake (42 C3BC becomes 42 C383C2BC). Measured against
    # the live box, not assumed.
    #
    # That matters for anything read back and then matched: an ES keyword is
    # matched exactly and case-sensitively, so a mangled host name matches
    # nothing.
    #
    # Invoke-WebRequest -UseBasicParsing exposes the raw bytes, so the decoding
    # is ours to get right.
    param(
        [string]$Uri,
        [string]$Method = 'Get',
        $Headers,
        [string]$ContentType,
        $Body,
        [int]$TimeoutSec = 60
    )
    $p = @{ Uri = $Uri; Method = $Method; TimeoutSec = $TimeoutSec; UseBasicParsing = $true }
    if ($Headers)     { $p.Headers = $Headers }
    if ($ContentType) { $p.ContentType = $ContentType }
    if ($null -ne $Body -and $Body -ne '') {
        # Requests go out as UTF-8 bytes for the same reason: a string body
        # would be encoded Latin-1 on the way out.
        $p.Body = if ($Body -is [byte[]]) { $Body } else { ConvertTo-BulkBody ([string]$Body) }
    }
    $resp  = Invoke-WebRequest @p
    $bytes = $resp.RawContentStream.ToArray()
    if ($bytes.Length -eq 0) { return $null }
    return ([Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json)
}

function Get-FolderLayout([string]$Root, [string]$Evtx, [string]$Archive) {
    # The one place the tool's folders are named. What the operator supplies
    # goes under input\, each tool's processed results under output\<tool>\,
    # so the folder name says what goes where. evtx\ stays top level: it is the
    # Collect tab's output AND the Convert tab's input. The Settings tab can
    # move the EVTX drop folder and the archive (local or \\server\share).
    [pscustomobject]@{
        Targets  = Join-Path $Root 'input\targets'
        Evtx     = $(if ($Evtx) { $Evtx } else { Join-Path $Root 'evtx' })
        Hayabusa = Join-Path $Root 'output\hayabusa'
        Takajo   = Join-Path $Root 'output\takajo'
        Logs     = Join-Path $Root 'logs'
        Archive  = $(if ($Archive) { $Archive } else { Join-Path $Root 'archive' })
        Pcap     = Join-Path $Root 'pcap'
    }
}

function Read-ToolSettings([string]$Path) {
    # code\settings.conf - the Settings tab's choices. A missing or unreadable
    # file is the defaults, never an error: the tool must still start.
    # PcapReminder is 'on'/'off', not a boolean: a JSON false is falsy and
    # would read back as the default.
    $s = [pscustomobject]@{ EvtxFolder = ''; ArchiveFolder = ''
                            WiresharkFolder = ''; PcapInterface = ''; PcapFolder = ''
                            PcapReminder = 'on'; PcapSnoozeUntil = ''; MissionName = ''
                            PcapViewer = 'on'
                            # Notepad with the run log when a job ends (Stop-UiJob).
                            OpenRunLog = 'on'
                            # The job queue's switches. Archive deletes
                            # the original EVTX (after a verified zip) and raw import sends
                            # them to another server, so those two are the operator's choice.
                            AutoConvert = 'on'; AutoUpload = 'on'; AutoRaw = 'off'; AutoArchive = 'off' }
    try {
        $c = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
        foreach ($p in $s.PSObject.Properties) { if ($c.($p.Name)) { $p.Value = [string]$c.($p.Name) } }
    } catch { }
    return $s
}

function Resolve-TypedPath([string]$Text, [string]$NetworkKey = 'HKCU:\Network') {
    # A path as the operator pasted it, made usable. Explorer's "Copy as path"
    # wraps it in quotes. And a drive letter mapped to a share (Z:\...) does not
    # exist for EVTXER run as administrator - Windows keeps mapped drives per
    # elevation - so it becomes the \\server\share it points at, read from the
    # account's saved mapping (field, 2026-10-27: the share could not be picked
    # or pasted). A mapping made without "Reconnect at sign-in" is not saved
    # there; that one has to be typed as \\server\share.
    $t = "$Text".Trim().Trim('"').Trim()
    if ($t -match '^([A-Za-z]):(\\.*)?$' -and -not (Test-Path -LiteralPath "$($Matches[1]):\")) {
        $rest = "$($Matches[2])"
        try {
            $unc = (Get-ItemProperty -LiteralPath (Join-Path $NetworkKey $Matches[1]) -ErrorAction Stop).RemotePath
            if ($unc) { $t = $unc.TrimEnd('\') + $(if ($rest) { $rest } else { '\' }) }
        } catch { }
    }
    return $t
}

function Select-FolderPath([string]$Title, [string]$Current, [switch]$Multiple) {
    # The Explorer-style folder picker (address bar, Network, every drive), not
    # WinForms' FolderBrowserDialog: that old tree has no address bar, so a
    # share could be neither typed nor found in it (field, 2026-10-27). .NET
    # Framework has no wrapper for this dialog, hence the COM interfaces.
    # $null when cancelled; with -Multiple, every folder picked (Ctrl-click).
    if (-not ('EvtxerFolderPicker' -as [type])) {
        Add-Type -ErrorAction Stop @"
using System;
using System.Runtime.InteropServices;

public static class EvtxerFolderPicker {
    [ComImport, Guid("DC1C5A9C-E88A-4dde-A5A1-60F82A20AEF7")]
    class FileOpenDialog { }

    [ComImport, Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IShellItem {
        void BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);
        void GetParent(out IShellItem ppsi);
        void GetDisplayName(uint sigdnName, [MarshalAs(UnmanagedType.LPWStr)] out string ppszName);
        void GetAttributes(uint sfgaoMask, out uint psfgaoAttribs);
        void Compare(IShellItem psi, uint hint, out int piOrder);
    }

    [ComImport, Guid("b63ea76d-1f85-456f-a19c-48159efa858b"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IShellItemArray {
        void BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppvOut);
        void GetPropertyStore(int flags, ref Guid riid, out IntPtr ppv);
        void GetPropertyDescriptionList(IntPtr keyType, ref Guid riid, out IntPtr ppv);
        void GetAttributes(int attribFlags, uint sfgaoMask, out uint psfgaoAttribs);
        void GetCount(out uint pdwNumItems);
        void GetItemAt(uint dwIndex, out IShellItem ppsi);
        void EnumItems(out IntPtr ppenumShellItems);
    }

    // IModalWindow::Show first, then IFileDialog and IFileOpenDialog in
    // vtable order - every method, since GetResults comes last.
    [ComImport, Guid("d57c7288-d4ad-4768-be02-9d969532d960"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IFileOpenDialog {
        [PreserveSig] int Show(IntPtr parent);
        void SetFileTypes(uint cFileTypes, IntPtr rgFilterSpec);
        void SetFileTypeIndex(uint iFileType);
        void GetFileTypeIndex(out uint piFileType);
        void Advise(IntPtr pfde, out uint pdwCookie);
        void Unadvise(uint dwCookie);
        void SetOptions(uint fos);
        void GetOptions(out uint pfos);
        void SetDefaultFolder(IShellItem psi);
        void SetFolder(IShellItem psi);
        void GetFolder(out IShellItem ppsi);
        void GetCurrentSelection(out IShellItem ppsi);
        void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string pszName);
        void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string pszTitle);
        void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string pszText);
        void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string pszLabel);
        void GetResult(out IShellItem ppsi);
        void AddPlace(IShellItem psi, int fdap);
        void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string pszDefaultExtension);
        void Close(int hr);
        void SetClientGuid(ref Guid guid);
        void ClearClientData();
        void SetFilter(IntPtr pFilter);
        void GetResults(out IShellItemArray ppenum);
        void GetSelectedItems(out IShellItemArray ppsai);
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    static extern void SHCreateItemFromParsingName(string pszPath, IntPtr pbc, ref Guid riid, out IShellItem ppv);

    [DllImport("user32.dll")]
    static extern IntPtr GetActiveWindow();

    const uint FOS_PICKFOLDERS = 0x20, FOS_FORCEFILESYSTEM = 0x40, FOS_ALLOWMULTISELECT = 0x200;
    const uint SIGDN_FILESYSPATH = 0x80058000;

    public static string[] Show(string title, string start, bool multiple) {
        IFileOpenDialog d = (IFileOpenDialog)new FileOpenDialog();
        try {
            d.SetOptions(FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | (multiple ? FOS_ALLOWMULTISELECT : 0));
            if (!String.IsNullOrEmpty(title)) { d.SetTitle(title); }
            if (!String.IsNullOrEmpty(start)) {
                try {
                    Guid iid = typeof(IShellItem).GUID;
                    IShellItem item;
                    SHCreateItemFromParsingName(start, IntPtr.Zero, ref iid, out item);
                    d.SetFolder(item);
                } catch (Exception) { }
            }
            if (d.Show(GetActiveWindow()) != 0) { return null; }
            IShellItemArray results;
            d.GetResults(out results);
            uint n;
            results.GetCount(out n);
            string[] paths = new string[n];
            for (uint i = 0; i < n; i++) {
                IShellItem item;
                results.GetItemAt(i, out item);
                item.GetDisplayName(SIGDN_FILESYSPATH, out paths[i]);
            }
            return paths;
        } finally { Marshal.ReleaseComObject(d); }
    }
}
"@
    }
    # Never opened at a share: asking a server that is down holds the window
    # up. The picker's address bar takes one.
    $start = Resolve-TypedPath $Current
    if (-not $start -or $start -like '\\*' -or -not (Test-Path -LiteralPath $start)) { $start = '' }
    $picked = [EvtxerFolderPicker]::Show($Title, $start, [bool]$Multiple)
    if (-not $picked) { return $null }
    if ($Multiple) { return , [string[]]$picked }
    return $picked[0]
}

function ConvertTo-FolderSetting([string]$Text) {
    # A folder the Settings tab may use - D:\... or \\server\share\... - fully
    # resolved, or '' for anything else. IsPathRooted also passes "D:" and
    # "\x", which Windows resolves against the CURRENT folder: a drop folder of
    # D:\ trimmed to D: would quietly have become code\.
    $t = Resolve-TypedPath $Text
    if ($t -notmatch '^([A-Za-z]:\\|\\\\[^\\]+\\[^\\]+)') { return '' }
    try { $full = [IO.Path]::GetFullPath($t) } catch { return '' }
    if ($full -ne [IO.Path]::GetPathRoot($full)) { $full = $full.TrimEnd('\') }
    return $full
}

function Save-ToolSettings($Settings, [string]$Path) {
    $Settings | ConvertTo-Json | Set-Content -LiteralPath $Path -Encoding utf8
}

function Get-ScanOutputPath([string]$Root) {
    # output\hayabusa\, not beside the executable. The scan used to write
    # hayabusa-x64\hayabusa-results.jsonl while the CSV went to output\ and
    # both the in-tool path panel and the Takajo tab's default said
    # output\results.jsonl - so the documented answer was the wrong one, the
    # Takajo default pointed at nothing, and a deployment copy accumulated tens
    # of megabytes of results inside the binary folder.
    return (Join-Path (Get-FolderLayout $Root).Hayabusa 'results.jsonl')
}

function Get-EcsOutputPath([string]$SourceJsonl) {
    # Sits beside whatever it was converted from, so a browsed file's ECS copy
    # does not land somewhere unrelated.
    return ([IO.Path]::ChangeExtension($SourceJsonl, $null) + 'ecs.jsonl')
}

function Get-JsonlImportId([string]$Path, [int]$SampleLines = 5) {
    # An ecs.jsonl already carries the import.id it was converted with. The
    # tool used to mint a fresh one at upload time, which appears nowhere in
    # the documents - so the "filter this batch with import.id: X" advice named
    # an id that matched nothing, and the Kibana link found no documents to
    # take a time range from.
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    try {
        foreach ($line in (Get-Content -LiteralPath $Path -TotalCount ($SampleLines * 4) -ErrorAction Stop)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $doc = $null
            try { $doc = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
            if ($doc -and $doc.import -and $doc.import.id) { return [string]$doc.import.id }
        }
    } catch { }
    return ''
}

# ------------------------------------------------------------ index guard ---
function Test-HayabusaIndexName([string]$Name) {
    # The only thing keeping this tool out of Security Onion's own indices,
    # logs-import-so above all, which may hold evidence other people depend
    # on. It lived as three copy-pasted StartsWith checks
    # in the GUI with no test; one function, tested, so the copies cannot drift
    # apart.
    #
    # Deliberately stricter than "starts with hayabusa-":
    #   - something must follow the prefix, so 'hayabusa-' alone is refused
    #   - lowercase only, which Elasticsearch requires anyway
    #   - no comma (would address several indices), no wildcard, no slash,
    #     no whitespace
    # Anything not matched here is refused, which is the safe direction.
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    return [regex]::IsMatch($Name, '^hayabusa-[a-z0-9._-]+$')
}

# --------------------------------------------------- Kibana Discover link ---
function Test-IndexCoveredByPattern([string]$IndexName, [string]$Pattern) {
    # Elasticsearch index patterns use * and nothing else, so everything but
    # the star is a literal - including the dots that are all over these names.
    if ([string]::IsNullOrWhiteSpace($IndexName)) { return $false }
    if ([string]::IsNullOrWhiteSpace($Pattern))   { return $false }

    # A Kibana data view's title can be several comma-separated patterns, and a
    # leading '-' excludes. Both are on the live box, e.g.
    # 'metrics-*,metricbeat-*,.monitoring-*' and one ending '-*elastic-cloud-logs-*'.
    # Reading the whole title as one pattern makes every such view fail to
    # match; ignoring the exclusions makes some match what they deliberately
    # leave out.
    $covered = $false
    foreach ($part in ($Pattern -split ',')) {
        $p = $part.Trim()
        if (-not $p) { continue }
        $exclude = $p.StartsWith('-')
        if ($exclude) { $p = $p.Substring(1) }
        if (-not $p) { continue }

        $rx = '^' + (($p -split '\*' | ForEach-Object { [regex]::Escape($_) }) -join '.*') + '$'
        if ([regex]::IsMatch($IndexName, $rx, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            # An exclusion wins outright, however many positives matched.
            if ($exclude) { return $false }
            $covered = $true
        }
    }
    return $covered
}

function New-DiscoverUrl {
    # Carries the three things the operator would otherwise have to know and
    # type by hand: which data view, which import.id, and the time span of the
    # batch. Discover opens on the last 15 minutes by default, so a link with
    # no time range lands on an empty screen and looks broken.
    param(
        [string]$HostName,
        [string]$DataViewId,
        [string]$ImportId,
        [string]$From,
        [string]$To,
        [int]$Port = 443
    )
    $authority = if ($Port -and $Port -ne 443) { "${HostName}:$Port" } else { $HostName }

    # Rison, which Kibana reads for _g and _a. Its own punctuation - ( ) : ' , -
    # has to survive intact, so nothing generic is applied here; only the two
    # characters that would actually break a URL are escaped. The KQL is
    # written without a space after the colon so there is no space to encode.
    $g = "(time:(from:'$From',to:'$To'))"
    $a = "(index:'$DataViewId',query:(language:kuery,query:'import.id:`"$ImportId`"'))"
    $esc = {
        param($t)
        $t.Replace('%', '%25').Replace('"', '%22').Replace(' ', '%20')
    }
    return "https://$authority/kibana/app/discover#/?_g=$(& $esc $g)&_a=$(& $esc $a)"
}

# ------------------------------------------------------------- host links ---
# After an upload or a raw import, EVTXER itself shows each
# host's links - its Hayabusa detections in Kibana and its raw events in
# Security Onion - "as far back as possible", so every collection of that host
# is on one timeline. Keyed on the machine's own name from the events, not the
# collect folder (that holds whatever was typed, often an IP).

function Get-HostKey([string]$Name) {
    # One machine reports itself both as WIN2022-SRV-X64 and as
    # WIN2022-SRV-X64.corp.local (seen 2026-09-09: both forms are kept in
    # the data). The upper-case short form groups them; it is never queried.
    $n = "$Name".Trim()
    if (-not $n -or (Test-IsIpLiteral $n)) { return $n }
    return ($n -split '\.')[0].ToUpperInvariant()
}

function Get-HostLinkSet([string[]]$Names) {
    # The names seen, one row per machine: Key for display and grouping,
    # Names = every form it was seen under, exactly as written.
    $rows = [ordered]@{}
    foreach ($n in @($Names | ForEach-Object { "$_".Trim() } | Where-Object { $_ })) {
        $k = Get-HostKey $n
        if (-not $rows.Contains($k)) { $rows[$k] = New-Object 'System.Collections.Generic.List[string]' }
        if (-not $rows[$k].Contains($n)) { $rows[$k].Add($n) }
    }
    @(foreach ($k in $rows.Keys) { [pscustomobject]@{ Key = $k; Names = @($rows[$k]) } })
}

function Get-HostLinkQuery([string[]]$Names, [string]$Field = 'host.name') {
    # host.name is a keyword: matched exactly, case and all. So every form
    # seen is asked for as written, its short name likewise, and any FQDN of
    # it - the other system may have stored a form this one never saw.
    $exact = New-Object 'System.Collections.Generic.List[string]'
    $wild  = New-Object 'System.Collections.Generic.List[string]'
    foreach ($n in @($Names | Where-Object { $_ })) {
        if (-not $exact.Contains($n)) { $exact.Add($n) }
        if (Test-IsIpLiteral $n) { continue }
        $short = ($n -split '\.')[0]
        foreach ($f in $short, $short.ToUpperInvariant(), $short.ToLowerInvariant()) {
            if (-not $exact.Contains($f)) { $exact.Add($f) }
            if (-not $wild.Contains("$f.*")) { $wild.Add("$f.*") }
        }
    }
    $terms = @($exact | ForEach-Object { "`"$_`"" }) + @($wild)
    # OR, not or: KQL takes either, Security Onion's Lucene-style query only
    # the upper case - a lower-case "or" there is a search word.
    return "${Field}:($($terms -join ' OR '))"
}

function New-HostDetectionsUrl {
    # Kibana Discover on the detections data view: this host, all time.
    param([string]$KibanaHost, [string]$DataViewId, [string[]]$Names, [int]$Port = 443)
    $authority = if ($Port -and $Port -ne 443) { "${KibanaHost}:$Port" } else { $KibanaHost }
    # Rison: ' inside a value is written !'; only what breaks a URL is escaped.
    # From 1970: nothing in an EVTX predates it, and Discover draws the range.
    $q = (Get-HostLinkQuery $Names).Replace('!', '!!').Replace("'", "!'")
    $g = "(time:(from:'1970-01-01T00:00:00.000Z',to:now+1d))"
    $a = "(index:'$DataViewId',query:(language:kuery,query:'$q'))"
    $esc = { param($t) $t.Replace('%', '%25').Replace('"', '%22').Replace(' ', '%20').Replace('+', '%2B').Replace('&', '%26').Replace('#', '%23') }
    return "https://$authority/kibana/app/discover#/?_g=$(& $esc $g)&_a=$(& $esc $a)"
}

function New-HostRawUrl {
    # Security Onion's dashboards on this host's raw events, all time - the
    # same page so-import-evtx links to, with the same &t= form
    # (Get-SoWideLink), so it opens the way the importer's own link does.
    param([string]$SoHost, [string[]]$Names, [datetime]$NowUtc = [datetime]::UtcNow)
    # winlog.computer_name, NOT host.name: in Security Onion's imported raw
    # events host.name is the Security Onion box that ingested them
    # ("manager"), and the Windows machine is only in winlog.computer_name.
    # Seen on a real SO 2.4.211 import, 2026-10-16. (Our detections carry
    # the event's Computer in host.name, so their link keeps that.)
    $q = [uri]::EscapeDataString((Get-HostLinkQuery $Names 'winlog.computer_name') + ' | groupby event.dataset')
    $to = $NowUtc.Date.AddDays(1)
    # Built by hand: in a .NET date format the F of %2F is itself a code.
    $t = '1970%2F01%2F01%2000%3A00%3A00%20AM%20-%20' + ('{0:yyyy}%2F{0:MM}%2F{0:dd}' -f $to) + '%2000%3A00%3A00%20AM'
    return "https://$SoHost/#/dashboards?q=$q&t=$t&z=UTC"
}

function Get-EvtxHostNames([string]$Folder) {
    # The machines whose logs sit in $Folder, as they name themselves: the
    # Computer of the first event in one .evtx per folder (Get-WinEvent reads
    # one record in milliseconds). For the Raw Events tab, which has no index
    # to ask.
    $names = @()
    if (-not $Folder -or -not (Test-Path -LiteralPath $Folder)) { return $names }
    # The folder and its host folders - the collect layout. Not recursive: a
    # deep tree or a share would hold the window up (this runs on its thread).
    $dirs = @(Get-Item -LiteralPath $Folder) + @(Get-ChildItem -LiteralPath $Folder -Directory -ErrorAction SilentlyContinue | Select-Object -First 200)
    foreach ($d in $dirs) {
        # Biggest first: an empty log (69,632 bytes, header only) has no
        # event to ask, and a big one surely has.
        $files = Get-ChildItem -LiteralPath $d.FullName -Filter *.evtx -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.Extension -eq '.evtx' } | Sort-Object Length -Descending | Select-Object -First 5
        foreach ($f in $files) {
            try {
                $e = Get-WinEvent -Path ([WildcardPattern]::Escape($f.FullName)) -MaxEvents 1 -ErrorAction Stop
                if ($e.MachineName) { $names += $e.MachineName; break }
            } catch { }
        }
    }
    return @($names | Select-Object -Unique)
}

# ----------------------------------------------------------------- Takajo ---
# Takajo analyses Hayabusa's RAW JSONL timeline - the results.jsonl this tool
# also produces - not the ECS file the Security Onion upload uses. It reads
# Hayabusa's abbreviated Details keys (TgtUser, SrcIP, Cmdline, Proc), which
# are present in our -b output alongside the full Windows names because
# different Sigma rules emit different keys. Verified against all 32,386
# sample detections.
function Get-PathGuide {
    # Drawn on the Convert tab, which is where the confusion is created: this
    # one step writes two files whose names differ by a few characters and
    # which feed opposite tabs. Aligned for a monospaced font.
    return @(
        'input\targets\             target host lists (one per line) for the Collect tab',
        'evtx\<host>_<timestamp>\   EVTX from the Collect tab. Drop your own EVTX here too.',
        '                           Any folder works, including a UNC share the partner staged.',
        'output\hayabusa\',
        '  results.jsonl            raw Hayabusa timeline  ->  Takajo tab',
        '  results.ecs.jsonl        ECS transform          ->  Upload tab',
        '  results.csv              optional analyst copy, local only - never uploaded',
        '  jobs\<host>_<timestamp>\  the QUEUE''s results for each collected host (same files)',
        'output\takajo\             automagic results, HTML report and database',
        'logs\                      one log file per run, for troubleshooting'
    )
}

function ConvertTo-ProcessArgumentLine([string[]]$Arguments) {
    # Start-Process -ArgumentList joins a string[] with spaces and quotes
    # nothing, so "C:\Case Files\x.jsonl" arrives as two arguments. Anything
    # invoked through Start-Process has to be quoted here first. The "& $exe
    # @args" call style does not need this - PowerShell quotes for it.
    if (-not $Arguments -or $Arguments.Count -eq 0) { return '' }
    # The rules CommandLineToArgvW (and every C runtime) parses by: inside
    # quotes, N backslashes before a '"' are written as 2N+1 and the quote as
    # \", N before the closing quote as 2N, any other backslash as itself. An
    # embedded quote used to end the argument early - a username or path
    # with a '"' split into two arguments - and an empty argument vanished.
    $parts = foreach ($a in $Arguments) {
        if ($null -eq $a) { continue }
        if ($a -ne '' -and $a -notmatch '[\s"]') { $a; continue }
        $sb = New-Object System.Text.StringBuilder('"')
        $slashes = 0
        foreach ($c in $a.ToCharArray()) {
            if ($c -eq '\') { $slashes++; continue }
            if ($c -eq '"') { [void]$sb.Append('\', 2 * $slashes + 1).Append('"') }
            else            { [void]$sb.Append('\', $slashes).Append($c) }
            $slashes = 0
        }
        [void]$sb.Append('\', 2 * $slashes).Append('"')
        $sb.ToString()
    }
    return ($parts -join ' ')
}

function Get-NextFreeFolder([string]$Path) {
    # takajo automagic refuses an --output folder that already exists, so a
    # fixed default name works exactly once. Returning the next free name keeps
    # repeat runs working and keeps each run's results separate, which matches
    # New-IndexName's behaviour for index names.
    if (-not (Test-Path -LiteralPath $Path)) { return $Path }
    foreach ($i in 2..999) {
        $candidate = "$Path-$i"
        if (-not (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    return "$Path-$([guid]::NewGuid().ToString('N').Substring(0,6))"
}

function Find-Takajo {
    if (-not $script:AppRoot) { return '' }
    foreach ($d in @((Join-Path $script:AppRoot 'takajo'),
                     (Join-Path $script:AppRoot 'takajo-x64'),
                     $script:AppRoot)) {
        if (-not $d -or -not (Test-Path $d)) { continue }
        $hit = Get-ChildItem -Path $d -Filter 'takajo*.exe' -File -ErrorAction SilentlyContinue |
               Sort-Object Name | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    $c = Get-Command takajo -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    return ''
}

function ConvertTo-TakajoRelativePath([string]$Target, [string]$TakajoDir) {
    # html-report prepends "./" to whatever --output is given,
    # so an absolute path becomes "./C:\..." and the run dies. The output has
    # to be expressed relative to the working directory, which is always the
    # takajo folder (see Get-TakajoArgs).
    if ([string]::IsNullOrWhiteSpace($Target)) { return '' }
    if (-not [IO.Path]::IsPathRooted($Target)) { return $Target }

    # [IO.Path]::GetRelativePath is .NET Core only; PS 5.1 is on .NET Framework,
    # so this goes through Uri instead.
    $fromUri = New-Object System.Uri (($TakajoDir.TrimEnd('\', '/') + '\'))
    $toUri   = New-Object System.Uri $Target
    $rel     = [System.Uri]::UnescapeDataString($fromUri.MakeRelativeUri($toUri).ToString()) -replace '/', '\'

    # Different volumes cannot be expressed relatively; MakeRelativeUri hands
    # back something still absolute. Fail loudly rather than let Takajo die
    # with its own confusing "./C:\" message.
    if ($rel -match '^[A-Za-z]:' -or $rel -match '^\\\\') {
        throw "Takajo's output folder must be on the same drive as the takajo binary ($TakajoDir), because html-report only accepts a relative path. Got: $Target"
    }
    return $rel
}

function Get-TakajoArgs {
    # Only long flags are emitted. Short flags are not interchangeable between
    # subcommands: -s is --skipProgressBar for automagic but --dboutput for
    # html-report, which would silently write a database file where a
    # progress-bar switch was meant.
    # html-server is deliberately absent: it listens on 0.0.0.0 with no
    # authentication and Takajo has no bind-address flag, so anyone on the
    # network could read the report. html-report writes the same report as
    # self-contained files, opened straight from disk.
    param(
        [ValidateSet('automagic','html-report')]
        [string]$Command,
        [string]$TakajoDir,
        [string]$Timeline,
        [string]$OutDir,
        [string]$RulePath,
        [string]$DbPath,
        [switch]$Sqlite,
        [string]$Level = '',
        # Run in a real console window, where Takajo's own progress bar is
        # worth seeing. Captured runs still suppress it: piped, it is noise.
        [switch]$ShowProgress
    )

    $a = @($Command, '--timeline', $Timeline)

    switch ($Command) {
        'automagic' {
            # The one subcommand that takes an absolute --output happily.
            if ($OutDir) { $a += @('--output', $OutDir) }
            if ($Level)  { $a += @('--level', $Level) }
        }
        'html-report' {
            if ($OutDir)   { $a += @('--output', (ConvertTo-TakajoRelativePath $OutDir $TakajoDir)) }
            if ($RulePath) { $a += @('--rulepath', $RulePath) }
            if ($DbPath)   { $a += @('--dboutput', $DbPath) }
            if ($Sqlite)   { $a += '--sqlite' }
            $a += '--clobber'
        }
    }

    $a += '--quiet'
    if (-not $ShowProgress) { $a += '--skipProgressBar' }
    return ,$a
}

# ------------------------------------------------- upload source vetting ---
# The pipeline writes two .jsonl files side by side in output/:
#   results.jsonl  raw Hayabusa output
#   ecs.jsonl      the ECS transform, and the only correct upload source
# Uploading the raw one indexes Timestamp instead of @timestamp with no
# hayabusa.details object, disagreeing with the index template. Same folder,
# same extension, similar names - so the tool checks the shape rather than
# trusting the operator to pick right.
function Get-JsonlKind([string]$Path, [int]$SampleLines = 5) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return @{ Kind = 'Missing'; Reason = 'No file selected.' }
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        # A path that was typed or remembered but is not there is a different
        # problem from an empty box, and saying "no file selected" about it
        # sends the operator looking in the wrong place.
        return @{ Kind = 'Missing'; Reason = "File not found: $Path" }
    }

    # Read only the head. On an 80 MB export this has to stay instant, and a
    # file whose first lines are ECS but whose later lines are not did not come
    # out of this pipeline.
    $sampled = @()
    try {
        foreach ($line in (Get-Content -LiteralPath $Path -TotalCount ($SampleLines * 4) -ErrorAction Stop)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $sampled += $line
            if ($sampled.Count -ge $SampleLines) { break }
        }
    } catch {
        return @{ Kind = 'Unknown'; Reason = "Could not read the file: $($_.Exception.Message)" }
    }

    if ($sampled.Count -eq 0) {
        return @{ Kind = 'Empty'; Reason = 'The file is empty.' }
    }

    # Classify on the first line that parses. PS 5.1 ConvertFrom-Json rejects a
    # line containing a "" key outright - the bug that once dropped 107
    # documents - so a single unparseable line must not decide the verdict.
    $parsedAny = $false
    foreach ($line in $sampled) {
        $doc = $null
        try { $doc = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        if ($null -eq $doc) { continue }
        $parsedAny = $true

        $names = @($doc.PSObject.Properties.Name)
        $hasEcs = ($names -contains '@timestamp') -and ($names -contains 'ecs') -and ($names -contains 'hayabusa')
        if ($hasEcs) {
            return @{ Kind = 'Ecs'; Reason = 'Hayabusa ECS JSONL - ready to upload.' }
        }

        $hasRaw = ($names -contains 'Timestamp') -and
                  (($names -contains 'RuleTitle') -or ($names -contains 'Level')) -and
                  ($names -notcontains '@timestamp')
        if ($hasRaw) {
            return @{ Kind = 'RawHayabusa'
                      Reason = 'This is raw Hayabusa output, not the converted ECS file. Convert it on the Convert tab first.' }
        }
    }

    if (-not $parsedAny) {
        return @{ Kind = 'Unknown'; Reason = 'The file is not JSON Lines - no sampled line could be parsed.' }
    }
    return @{ Kind = 'Unknown'; Reason = 'Not a Hayabusa ECS JSONL.' }
}

# ------------------------------------------------- collection method text ---
# Kept here rather than inline in the GUI so the wording is testable. Two
# constraints the tests enforce:
#   1. The SMB caution is about the collected log DATA, never the password.
#      Both methods authenticate by challenge-response, so neither puts the
#      password on the wire in cleartext; claiming otherwise would teach the
#      operator the wrong threat model. What SMB leaves readable on the network
#      is the EVTX contents themselves.
#   2. ASCII only. PS 5.1 + WinForms render non-ASCII unreliably.
function Get-MethodCaption([string]$Method) {
    switch ($Method) {
        'SMB' {
            return @{
                Caption = 'Best for Domain Admins. Direct C$ share file copy. Fast for large files. Sequential per host.'
                # "by default" is load-bearing: SMB 3.x can encrypt, but only
                # when it has been switched on server-side, which is rare.
                Caution = 'CAUTION: SMB does not encrypt collected log data in transit (by default).'
            }
        }
        'WinRM' {
            return @{
                Caption = 'Scales across multiple hosts. Uses wevtutil on the target to export locked logs cleanly. Requires local TrustedHosts change. Encrypts the collected data in transit.'
                Caution = ''
            }
        }
        'WinRM-HTTPS' {
            return @{
                Caption = 'For targets that only accept WinRM over HTTPS. Same export as WinRM, wrapped in TLS. Needs a certificate on the target; no TrustedHosts change. Encrypts the collected data in transit.'
                Caution = ''
            }
        }
        default { throw "unknown collection method: $Method" }
    }
}

# ------------------------------------------------------- collection guards ---
function Get-EvtxStagingPaths {
    # Folders this tool creates on the TARGET. [0] is the one collection writes
    # to now; the rest are names older builds used, kept so a host visited
    # before a rename still gets its leftover folder purged instead of carrying
    # it forever. A stray staging folder on a client's domain controller is
    # exactly the artifact an investigation is supposed to notice.
    return @(
        'C:\Windows\Temp\EVTX_Export',
        'C:\Windows\Temp\LOOT_Export'
    )
}

function New-EvtxStagingPath {
    # A FRESH folder per run, because the fixed one was reused by every
    # collection and only cleaned on the success path. A host that threw kept
    # its exports, and the next run's Test-Path then found the PREVIOUS run's
    # file and copied it back as current evidence. Two examiners hitting the
    # same host at once deleted each other's exports the same way.
    #
    # The base literal stays in Get-EvtxStagingPaths so the folder we write to
    # and the folders we purge cannot drift apart.
    $base = (Get-EvtxStagingPaths)[0]
    return "{0}_{1}" -f $base, [guid]::NewGuid().ToString('N').Substring(0, 8)
}

function Test-StaleStagingItem {
    # The price of a per-run folder: a hard kill orphans one that the
    # fixed-name purge list will never match, and a stray artifact in
    # C:\Windows\Temp on a client's domain controller is exactly what an
    # investigation is supposed to notice.
    #
    # Three kinds of thing can be left behind, and one rule governs all of them:
    #
    #   EVTX_Export_<token>       a per-run staging folder
    #   EVTX_Export_<token>.zip   its archive, written BESIDE the folder, so a
    #                             directory-only sweep never saw it - and it is
    #                             the largest thing this tool ever puts on a
    #                             target
    #   EVTX_Export / LOOT_Export the fixed names older builds used
    #
    # AGE is the rule, because knowing something is ours does not tell us
    # nobody is using it. The fixed names used to be deleted on sight, which
    # would pull the exports out from under an older build of this collector
    # running against the same host at the same time. Anything written recently
    # belongs to a collection that is still going, and is left alone.
    #
    # Every match is anchored. This runs against a directory on a machine we do
    # not own, and deleting anything we did not create there is unacceptable.
    param(
        [string]$Name,
        [datetime]$LastWrite,
        [datetime]$Now,
        [int]$MaxAgeHours = 24
    )
    $known = @(Get-EvtxStagingPaths | ForEach-Object { Split-Path -Leaf $_ })
    $base  = $known[0]

    $ours = $false
    if ($Name -match ('^' + [regex]::Escape($base) + '_[0-9a-fA-F]{8}(\.zip)?$')) { $ours = $true }
    elseif ($known -contains $Name) { $ours = $true }
    if (-not $ours) { return $false }

    $ageHours = ($Now - $LastWrite).TotalHours
    # A target clock skewed into the future must not read as ancient, and must
    # not be "corrected" into looking fresh either - it is simply not stale.
    if ($ageHours -lt 0) { return $false }
    return ($ageHours -ge $MaxAgeHours)
}

function Test-CopiedFile([string]$Path) {
    # Copy-Item errors are NON-TERMINATING by default, so a refused copy let
    # execution fall straight through to "$files += $dst" and "[OK] Acquired".
    # -ErrorAction Stop fixes the refusal; it says nothing about a copy that
    # returned cleanly and left a 0-byte file, which is what an interrupted
    # transfer produces. A real .evtx is never empty, so nothing counts as
    # collected until the destination has been looked at.
    $result = [pscustomobject]@{ Ok = $false; Bytes = [long]0; Reason = '' }
    if ([string]::IsNullOrWhiteSpace($Path)) { $result.Reason = 'no destination path'; return $result }
    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item)          { $result.Reason = 'file did not arrive'; return $result }
    if ($item.PSIsContainer) { $result.Reason = 'destination is a directory, not a file'; return $result }
    $result.Bytes = [long]$item.Length
    if ($result.Bytes -le 0) { $result.Reason = 'arrived empty (0 bytes)'; return $result }
    $result.Ok = $true
    return $result
}

# Where a WinRM archive is unpacked before its files are moved into place.
# Expand-Archive writes each file under its real name as it goes, so a failed
# unpack straight into the evidence folder left half-written .evtx files there.
$script:UnzipStagingName = '_unpacking'

function Invoke-StagedCopy {
    # Every transfer lands as "<name>.partial" and gets its real name only once
    # the copy returned and the file is not empty. A link that drops half way
    # used to leave a truncated .evtx under its real name: nothing counted it,
    # but Hayabusa scans the evidence folder recursively and analysed it anyway.
    # The copy's own exception still reaches the caller, after the partial is
    # gone. $Copy is called with the path to write to.
    param([scriptblock]$Copy, [string]$Destination)
    $part = "$Destination.partial"
    Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
    try { & $Copy $part }
    catch {
        Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
        throw
    }
    $v = Test-CopiedFile $part
    if (-not $v.Ok) {
        Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
        return $v
    }
    Move-Item -LiteralPath $part -Destination $Destination -Force -ErrorAction Stop
    return $v
}

function Remove-PartialTransfers([string]$Folder) {
    # What a hard kill (window closed, laptop slept) can leave mid-transfer,
    # before Invoke-StagedCopy's own cleanup ran. Returns what was removed.
    if (-not $Folder -or -not (Test-Path -LiteralPath $Folder)) { return @() }
    # An empty -Filter matches every folder, and this deletes recursively.
    if (-not $script:UnzipStagingName) { return @() }
    $gone = @()
    $items = @(Get-ChildItem -LiteralPath $Folder -Filter '*.partial' -File -Force -ErrorAction SilentlyContinue) +
             @(Get-ChildItem -LiteralPath $Folder -Filter $script:UnzipStagingName -Directory -Force -ErrorAction SilentlyContinue)
    foreach ($i in $items) {
        Remove-Item -LiteralPath $i.FullName -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $i.FullName)) { $gone += $i.Name }
    }
    return $gone
}

function Get-FreeDriveLetter {
    # Collection hard-coded T: and Verify Access hard-coded V:, and both
    # force-removed the letter first. That is the ANALYST'S workstation: an
    # examiner with T: mapped to a case share lost it to a collection and
    # never got it back. Picking an unused letter costs one call and beats
    # any save-and-restore dance, which only has to be got wrong once.
    #
    # Nothing below T: is safe to assume free - A:/B: are floppies, C: is the
    # system drive, and D:-F: is where optical drives and USB sticks land.
    param(
        [string[]]$Candidates = @('T', 'U', 'V', 'W', 'X', 'Y', 'Z'),
        [string[]]$InUse
    )
    if ($null -eq $InUse) {
        $InUse = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    }
    # -notcontains is already case-insensitive, so a 'T' in use blocks a 't'
    # candidate with no manual case fold.
    #
    # Null rather than a throw: the caller reports one clean failure for this
    # host and moves to the next, like every other per-host problem here - and
    # an empty match set indexes to $null, which is exactly that.
    return @($Candidates | Where-Object { $InUse -notcontains $_ })[0]
}

function Get-ConnectivityPlan {
    # Collection used to [SKIPPED] any host that did not answer a ping. ICMP is
    # not a precondition for SMB or WinRM - inbound echo is off by default on
    # the Windows Firewall's Public profile and is routinely dropped in
    # hardened environments - so hosts that would have collected fine were
    # dropped without ever being tried. Worse, Test-CollectAccess never pings,
    # so a host could pass Verify Access clean and then be skipped by the very
    # collection it had just verified.
    #
    # The ping is advisory now: it flavours the log line and decides nothing.
    # The protocol attempt is the authoritative answer, and it fails with a
    # real error message instead of an unexplained skip.
    param(
        [bool]$PingSucceeded,
        [ValidateSet('SMB', 'WinRM', 'WinRM-HTTPS')]
        [string]$Method
    )
    if ($PingSucceeded) {
        return [pscustomobject]@{ Proceed = $true; Note = '' }
    }
    return [pscustomobject]@{
        Proceed = $true
        Note    = "no ICMP reply - firewalls routinely drop echo, so trying $Method anyway"
    }
}

function Get-HostOutcome {
    # $succeeded++ used to sit at the bottom of the per-host try, so it fired
    # whenever no exception escaped: a host where every requested log came back
    # "Not Found / Access Denied" counted as a success. The catch incremented
    # nothing at all, so Attempted never equalled Succeeded + Skipped and the
    # missing hosts were invisible.
    #
    # Three outcomes, because two cannot tell the truth: a run that got some of
    # what was asked for is neither, and the examiner has to know which one
    # they are holding before they start analysing it.
    param(
        [int]$Requested,
        [int]$Collected,
        [bool]$Errored,
        # Exact: DFIR/Custom named specific logs, so all of them must arrive.
        # BestEffort: ALL enumerates every channel on the box and most are
        # empty or disabled, so demanding all of them would mark every ALL
        # collection partial and train the operator to ignore the word.
        [ValidateSet('Exact', 'BestEffort')]
        [string]$Mode,
        # A SHA-256 mismatch, or fewer files/bytes than the target sent. It
        # used to be logged and then ignored, so a set that did not verify
        # read Success and stayed off the retry list.
        [bool]$IntegrityFailed = $false
    )
    # An exception outranks any file count: the host has an unknown amount of
    # an unknown thing on disk, and files already landed do not redeem it.
    if ($Errored)         { return 'Failed' }
    if ($Collected -le 0) { return 'Failed' }
    if ($IntegrityFailed) { return 'Partial' }
    if ($Mode -eq 'Exact' -and $Collected -lt $Requested) { return 'Partial' }
    return 'Success'
}

function Test-IsIpLiteral([string]$Value) {
    $v = "$Value".Trim()
    if (-not $v) { return $false }
    # A strict dotted quad, deliberately NOT [IPAddress]::TryParse: TryParse
    # accepts bare integers and other shorthand ("2019" parses as 0.0.7.227),
    # which would flag a hostname like srv2019 as an IP address.
    if ($v -match '^\d{1,3}(\.\d{1,3}){3}$') {
        foreach ($octet in $v.Split('.')) { if ([int]$octet -gt 255) { return $false } }
        return $true
    }
    if ($v.Contains(':')) {
        $parsed = [System.Net.IPAddress]::Any
        return [System.Net.IPAddress]::TryParse($v, [ref]$parsed)
    }
    return $false
}

function Get-TargetAuthNote([string[]]$Targets) {
    # Kerberos authenticates against an SPN (cifs/HOST.domain.local) and an SPN
    # requires a NAME, so a target given as a bare IP falls back to NTLM.
    #
    # What that costs is the target's IDENTITY, not the password. Both Kerberos
    # and NTLM are challenge-response and neither puts the password on the wire
    # in cleartext - saying otherwise would teach the operator the wrong threat
    # model, and TargetAuthNote.Tests.ps1 fails if this text ever claims it.
    # The real loss is mutual authentication, which is precisely what the WinRM
    # TrustedHosts change is Windows making you consent to out loud.
    if (-not $Targets) { return '' }
    $all = @($Targets | Where-Object { "$_".Trim() })
    if ($all.Count -eq 0) { return '' }
    $ips = @($all | Where-Object { Test-IsIpLiteral $_ })
    if ($ips.Count -eq 0) { return '' }
    $noun = if ($ips.Count -eq 1) { 'target is an IP address' } else { 'targets are IP addresses' }
    return ("NOTE: {0} of {1} {2}. Kerberos needs a hostname, so authentication falls back to NTLM and the target's identity is not verified. Use hostnames where you can." `
        -f $ips.Count, $all.Count, $noun)
}

function Merge-TrustedHosts([string]$Current, [string[]]$Targets) {
    # Exact, case-insensitive entry comparison. The collector used to test
    # `-notmatch [regex]::Escape($t)`, a substring match, so an existing
    # 192.0.2.234 made 192.0.2.23 look trusted and it was never added.
    $entries = [System.Collections.Generic.List[string]]::new()
    foreach ($e in "$Current".Split(',')) { if ($e.Trim()) { $entries.Add($e.Trim()) } }
    if ($entries -contains '*') { return ($entries -join ',') }
    foreach ($t in $Targets) {
        $name = "$t".Trim()
        if ($name -and $entries -notcontains $name) { $entries.Add($name) }
    }
    return ($entries -join ',')
}

function Test-TcpPort([string]$HostName, [int]$Port, [int]$TimeoutMs = 2500) {
    # Not Test-NetConnection: it pings first and waits out the OS connect
    # timeout, which on a firewall that drops packets freezes the window for
    # ~20 s per port. A TcpClient with a hard deadline answers in seconds.
    #   Open     - something accepted the connection
    #   Refused  - the host answered, nothing listens there
    #   Timeout  - no answer at all: firewall drop, host off, or unroutable
    #   Error    - anything else (name does not resolve, network unreachable)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync($HostName, $Port)
        if (-not $task.Wait($TimeoutMs)) { return [pscustomobject]@{ Port = $Port; Status = 'Timeout'; Detail = "no answer in $($TimeoutMs / 1000) s" } }
        return [pscustomobject]@{ Port = $Port; Status = 'Open'; Detail = '' }
    }
    catch {
        $base = $_.Exception.GetBaseException()
        $status = if ($base -is [System.Net.Sockets.SocketException] -and
                      $base.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused) { 'Refused' } else { 'Error' }
        return [pscustomobject]@{ Port = $Port; Status = $status; Detail = $base.Message }
    }
    finally { $client.Close() }
}

function Test-TcpPortSet([object[]]$Probes, [int]$TimeoutMs = 2500) {
    # Every probe is started before any of them is waited on, so a batch costs
    # about ONE timeout rather than one per socket. Checking a 20-host subnet
    # one socket at a time took 100 s measured, with the window unusable for
    # all of it - and a subnet sweep is the normal case for this.
    #
    # Each probe is a hashtable with Key/HostName/Port; Key is handed back
    # untouched so the caller can match results to whatever it asked about.
    $started = foreach ($p in $Probes) {
        $client = New-Object System.Net.Sockets.TcpClient
        # ConnectAsync resolves names on a worker thread too, so a target whose
        # name does not resolve cannot stall the batch either.
        $task = try { $client.ConnectAsync($p.HostName, $p.Port) } catch { $null }
        [pscustomobject]@{ Probe = $p; Client = $client; Task = $task; Error = if ($task) { '' } else { "$($_.Exception.Message)" } }
    }

    $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
    while ((Get-Date) -lt $deadline -and @($started | Where-Object { $_.Task -and -not $_.Task.IsCompleted }).Count -gt 0) {
        Start-Sleep -Milliseconds 40
    }

    $results = foreach ($s in $started) {
        $status, $detail = if (-not $s.Task)            { 'Error', $s.Error }
                           elseif (-not $s.Task.IsCompleted) { 'Timeout', "no answer in $($TimeoutMs / 1000) s" }
                           elseif ($s.Task.IsFaulted) {
                               $base = $s.Task.Exception.GetBaseException()
                               $refused = ($base -is [System.Net.Sockets.SocketException] -and
                                           $base.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused)
                               $(if ($refused) { 'Refused' } else { 'Error' }), $base.Message
                           }
                           else { 'Open', '' }
        # Closing a client whose connect never completed is what cancels it;
        # skipping this leaks a socket per unreachable host, every sweep.
        $s.Client.Close()
        [pscustomobject]@{ Key = $s.Probe.Key; Port = $s.Probe.Port; Status = $status; Detail = $detail }
    }
    return @($results)
}

function Get-CollectErrorHint([string]$Message) {
    # Windows names the symptom and never the fix, and two of these actively
    # mislead: "The network name cannot be found" sounds like a DNS or hostname
    # problem when the name resolved fine and the SHARE is what is missing, and
    # "Access is denied" on a local admin account is usually remote UAC
    # filtering rather than a wrong password.
    #
    # Returns '' for anything unrecognised: a wrong hint costs more than none.
    switch -Regex ("$Message") {
        # WinRM-HTTPS only. Ahead of the logon patterns because the TLS
        # handshake fails before any credential is looked at.
        # Most specific first: one refusal can list several certificate errors.
        'common name \(CN\) that does not match' {
            return "the name on the target's certificate is not what you typed. An IP address never matches a certificate issued to a hostname: type the name on the certificate (if it is also self-signed, its issuer must be trusted here too), or tick 'Skip certificate check' - which also skips proving the target is the machine you meant."
        }
        'unknown certificate authority' {
            return "the target's HTTPS certificate was refused - this machine does not trust its issuer (self-signed is the usual case). Import the issuing CA here, or tick 'Skip certificate check' - which also skips proving the target is the machine you meant."
        }
        # Importing the CA does not help here: the issuer is trusted, its CRL
        # is unreachable - the normal state of an isolated network.
        'checked for revocation' {
            return "the target's certificate could not be checked for revocation - this machine cannot reach the revocation list its issuer names (normal on an isolated network). Importing the CA does not fix this; tick 'Skip certificate check' - which also skips proving the target is the machine you meant."
        }
        # Any other refusal (expired, not issued for server authentication):
        # the skip does not promise to cover these, so the hint does not either.
        'server certificate on the destination computer|SSL certificate' {
            return "the target's HTTPS certificate was refused for the reason above. 'Skip certificate check' covers an untrusted issuer, a name mismatch and an unreachable revocation list; anything else, such as an expired certificate, has to be fixed on the target."
        }
        # A link that dropped mid-collection. Ahead of the share pattern, which
        # a dead SMB session can also trip.
        'session state is Broken|session is not available|network connection was lost|connection was (forcibly )?closed|specified network name is no longer available|semaphore timeout' {
            # The same errors also come from a connection that never got going
            # (a firewalled host, a reset TLS handshake), so this says both.
            return "the connection to the target dropped or timed out. If it happened while connecting, check the target is reachable (TEST PORTS). If it happened during the transfer, files that fully arrived are kept and nothing half-copied was kept - press RETRY to collect this host again into a fresh folder."
        }
        'network name cannot be found|network path was not found' {
            return "the target has no C`$ admin share. Windows Home editions never have one; otherwise it is disabled (AutoShareWks) or the Server service is not sharing. Check Get-SmbShare on the target. Not a name or password problem - the IP is fine. With no C`$ there is nothing to mount: use WinRM, or export at the target's console with wevtutil epl."
        }
        'account restriction|blank password' {
            return 'Windows refuses network logons for accounts with a blank password. Set a password on the account, or collect at the console instead.'
        }
        'Access is denied|user name or password is incorrect|logon failure|1326' {
            return "check the account. A domain account: put the domain in the Domain field (CORP or corp.local), or type user@corp.local as the username - that form always works for a real AD domain. A local account: leave Domain empty so the tool logs in as HOST\user, and a local admin that is not the built-in Administrator also needs LocalAccountTokenFilterPolicy=1 on the target."
        }
    }
    return ''
}

function Get-CollectPort([string]$Method) {
    switch ($Method) { 'SMB' { 445 } 'WinRM' { 5985 } 'WinRM-HTTPS' { 5986 } default { throw "unknown collection method: $Method" } }
}

function Get-WinRmSwitch([string]$Method) {
    # The other WinRM flavour, for when the chosen one is closed. A target with
    # only the HTTPS listener used to be told "WinRM is not enabled", so the
    # operator went and ran Enable-PSRemoting on a box where WinRM was fine.
    switch ($Method) {
        'WinRM' {
            return [pscustomobject]@{ Method = 'WinRM-HTTPS'
                Text = "but WinRM over HTTPS (tcp/5986) is open - this target only accepts HTTPS. Choose 'WinRM over HTTPS (port 5986)'." }
        }
        'WinRM-HTTPS' {
            return [pscustomobject]@{ Method = 'WinRM'
                Text = "but plain WinRM (tcp/5985) is open - this target has no HTTPS listener. Choose 'WinRM (port 5985)'; it still encrypts the collected data." }
        }
    }
    return $null
}

function Test-NeedsTrustedHosts([string]$Method) {
    # Off-domain NTLM over HTTP is what Windows wants TrustedHosts consent for.
    # Over HTTPS the certificate identifies the target instead, so the list -
    # and the admin rights needed to write it - stay out of it.
    return ($Method -eq 'WinRM')
}

function Test-IsElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-LocalWinRmProblems([string]$Method, [bool]$Elevated = (Test-IsElevated),
                                [string]$ServiceStatus = "$((Get-Service WinRM -ErrorAction SilentlyContinue).Status)") {
    # What THIS PC lacks for plain WinRM, which writes the targets into this
    # PC's TrustedHosts: administrator rights, and its own WinRM service. Both
    # used to surface only as "Cannot find path 'WSMan:\localhost\Client\
    # TrustedHosts'" after VERIFY or COLLECT was pressed (usability walk,
    # 2026-10-21). Said when WinRM is picked instead. HTTPS needs neither.
    if (-not (Test-NeedsTrustedHosts $Method)) { return @() }
    $p = @()
    if (-not $Elevated) {
        $p += 'EVTXER is not running as administrator. Close it and start it with EVTXER.cmd, which asks Windows for administrator rights.'
    }
    if ($ServiceStatus -ne 'Running') {
        $p += "the WinRM service is not running. As administrator: Start-Service WinRM (or pick WinRM over HTTPS, which does not need it)."
    }
    return $p
}

function ConvertFrom-WrappedErrorText([string]$Message) {
    # PowerShell wraps a .NET call's failure as 'Exception calling "X" with
    # "N" argument(s): "<the cause>"' - sometimes twice. The cause is what an
    # operator can act on.
    $m = "$Message"
    while ($m -match '^Exception calling "[^"]+" with "\d+" argument\(s\): "(.*)"$') { $m = $Matches[1] }
    return $m.Trim()
}

function Get-CollectFailureText([Exception]$Exception) {
    # A failure inside a background job arrives wrapped by PowerShell:
    # 'Exception calling "EndInvoke" with "1" argument(s): "<the cause>"'.
    # The operator gets the cause, not the plumbing.
    $e = $Exception
    while ($e -is [System.Management.Automation.MethodInvocationException] -and $e.InnerException) { $e = $e.InnerException }
    return (ConvertFrom-WrappedErrorText "$($e.Message)")
}

function Get-LocalAddressFor([string]$HostName, [int]$Port) {
    # This PC's address on the way to HostName - what Security Onion's firewall
    # has to let in. A UDP "connect" only picks the route; nothing is sent.
    try {
        $u = New-Object Net.Sockets.UdpClient
        try { $u.Connect($HostName, $Port); return $u.Client.LocalEndPoint.Address.ToString() } finally { $u.Close() }
    } catch { return '' }
}

function Get-ConnectionHint([string]$Message, [string]$HostName, [int]$Port, $LocalIp = $null) {
    # $LocalIp untyped on purpose: [string] turns 'not given' into '', and
    # then the address was never looked up. Tests pass it; callers do not.
    # "Unable to connect to the remote server" or a .NET 'Exception calling
    # "EndConnect"...' said nothing about the usual first-day cause - Security
    # Onion's firewall - while the Collect tab names a fix for every port
    # (usability walk, 2026-10-21). Nothing answering gets that hint, with
    # what the Security Onion administrator needs - this PC's address and the
    # exact command (owner, 2026-10-26); any other error is passed on, unwrapped.
    $m = ConvertFrom-WrappedErrorText $Message
    if ($m -match '(?i)could not be resolved|no such host') {
        return "$HostName could not be found - check the name, or use the manager's IP address. (Windows said: $m)"
    }
    if ($m -match '(?i)actively refused|unable to connect|timed out|unreachable|did not properly respond|connection attempt failed') {
        $group = @{ 9200 = 'elasticsearch_rest'; 443 = 'analyst' }[$Port]
        $hint = "Nothing answered at ${HostName}:$Port. Check the host and port."
        if ($group) {
            # Security Onion's command, offered as such: 9200 is also a plain
            # Elastic stack's port, where so-firewall does not exist (review).
            if ($null -eq $LocalIp) { $LocalIp = Get-LocalAddressFor $HostName $Port }
            $ip = if ($LocalIp) { $LocalIp } else { "<this PC's IP address - ipconfig shows it>" }
            $hint += " If they are right and this is Security Onion, its firewall is not letting this PC in" +
                     $(if ($LocalIp) { " - this PC's address is $LocalIp" }) +
                     ". Ask its administrator to run on the manager:`n    sudo so-firewall --apply includehost $group $ip`n"
            if ($Port -eq 9200) { $hint += "On a plain Elastic stack: check that Elasticsearch is running and the server's firewall allows port 9200.`n" }
        } else { $hint += ' On Security Onion this PC must first be let through its firewall. ' }
        return "${hint}README.txt, SECURITY ONION: LETTING EVTXER IN. (Windows said: $m)"
    }
    return $m
}

function Get-CollectSessionArgs([string]$Method, [switch]$SkipCertificateCheck) {
    # Splatted into New-PSSession by Collect and Verify Access alike, so the two
    # cannot reach a target by different routes.
    switch ($Method) {
        'WinRM' { return @{} }
        'WinRM-HTTPS' {
            $a = @{ UseSSL = $true; Port = (Get-CollectPort $Method) }
            # All three: a self-signed certificate fails the CA check, an IP
            # target fails the name check, and an isolated network cannot
            # reach the CRL, which fails the revocation check.
            if ($SkipCertificateCheck) {
                $a.SessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
            }
            return $a
        }
        default { throw "no WinRM session for collection method: $Method" }
    }
}

function Get-PortCheckText([int]$Port, [string]$Status) {
    # Says what to change on the target, not just what happened. Both default
    # blocks are on the Windows Firewall's Public profile, which is where an
    # off-domain machine usually sits.
    $fix = switch ($Port) {
        445  { "File and Printer Sharing is off or blocked by the target's firewall (blocked by default on the Public profile)" }
        5985 { "WinRM is not enabled on the target - as admin there: Enable-PSRemoting -Force -SkipNetworkProfileCheck" }
        # Not Enable-PSRemoting: that creates only the HTTP listener.
        5986 { "the target has no WinRM HTTPS listener - that needs a server certificate on the target and an HTTPS listener bound to it (winrm quickconfig -transport:https), plus a firewall rule for 5986" }
        default { '' }
    }
    switch ($Status) {
        'Open'    { "open" }
        'Refused' { "closed - the host answered but nothing listens. $fix" }
        'Timeout' { "no answer - dropped by a firewall, or the host is off. $fix" }
        default   { "unreachable. $fix" }
    }
}

function Test-CollectReadiness {
    # Returns EVERY gap in one pass. The form paints from this and nothing
    # else, so validation cannot drift from what the operator is shown.
    #
    # Method is allowed to be empty and that is the point: the Collect tab
    # starts with neither radio selected, and the old
    # `if ($rbWinRM.Checked) { 'WinRM' } else { 'SMB' }` silently read "nothing
    # chosen" as SMB - which was how an unchosen method became an unencrypted
    # collection.
    # No password check, on purpose: a standalone workstation account with no
    # password set is a legitimate target, and demanding one made it unusable.
    param(
        [string[]]$Targets,
        [string]$Method,
        [string]$Username,
        [string]$Category,
        [string[]]$CustomLogs
    )
    if ("$Method".Trim() -and @('SMB', 'WinRM', 'WinRM-HTTPS') -notcontains $Method) {
        throw "unknown collection method: $Method"
    }
    $missing = @()
    $invalid = @($Targets | Where-Object { "$_".Trim() -and -not (Test-TargetName "$_".Trim()) } | ForEach-Object { "$_".Trim() })
    if (@($Targets | Where-Object { "$_".Trim() }).Count -eq 0 -or $invalid.Count) { $missing += 'Targets' }
    if (-not "$Method".Trim())   { $missing += 'Method' }
    if (-not "$Username".Trim()) { $missing += 'Username' }
    if ($Category -eq 'Custom' -and @($CustomLogs | Where-Object { "$_".Trim() }).Count -eq 0) {
        $missing += 'CustomLogs'
    }
    return [pscustomobject]@{
        Ready   = ($missing.Count -eq 0)
        Missing = $missing
        # Targets that are not a host name or address (Test-TargetName).
        Invalid = $invalid
    }
}

function New-CollectCredential([string]$Username, [string]$Password) {
    # `'' | ConvertTo-SecureString -AsPlainText -Force` throws on an empty
    # string, so a blank password gets an empty SecureString instead.
    $secure = if ($Password) { ConvertTo-SecureString $Password -AsPlainText -Force }
              else           { New-Object System.Security.SecureString }
    New-Object System.Management.Automation.PSCredential($Username, $secure)
}

function Resolve-CollectUsername([string]$Username, [string]$Domain, [string]$Target) {
    # The username format was the most common collection failure: `.\user` and
    # a bare `user` both fail remotely, because "." and "no domain" mean the
    # EXAMINER's machine, not the target's. So the prefix is chosen here:
    #   - an explicit DOMAIN\user or user@upn is the operator's call - verbatim;
    #   - otherwise the Domain field if filled (domain account),
    #   - otherwise the target itself, as typed (local account on that box -
    #     TARGET\user, IP or name, is the form that works for a local admin).
    #
    # A Domain with a dot in it is a DNS name, and builds user@domain instead.
    # "corp.local\admin" was refused in use where
    # "admin@corp.local" typed by hand worked: every AD account has the
    # implicit UPN sAMAccountName@dns-domain, while DOMAIN\user wants the
    # NetBIOS name, which is often not the DNS name with the dots removed.
    $u = "$Username".Trim()
    if (-not $u) { return '' }
    if ($u.StartsWith('.\')) { $u = $u.Substring(2) }
    elseif ($u.Contains('\') -or $u.Contains('@')) { return $u }
    $d = "$Domain".Trim().TrimEnd('\').TrimStart('@')
    # An IP address has dots too, and in Domain it means "this host's local
    # account" (IP\user), the form the old hint taught.
    if ($d.Contains('.') -and -not (Test-IsIpLiteral $d)) { return "$u@$d" }
    $prefix = if ($d) { $d } else { "$Target".Trim() }
    return "$prefix\$u"
}

function New-CollectHostResult {
    param([string]$Target, [string]$Account, [string]$Outcome,
          [int]$Collected, [int]$Requested, [string]$Folder, [string]$Detail,
          # For the activity ledger. -1 bytes/seconds = not measured.
          [long]$Bytes = -1, [double]$Seconds = -1, [string]$Integrity = '', [string]$LeftOnTarget = '')
    # One line per target, and one line only: an exception message can span
    # several, which would break both the results block and the CSV row.
    [pscustomobject]@{
        Target       = $Target
        Account      = $Account
        Outcome      = $Outcome
        Collected    = $Collected
        Requested    = $Requested
        Folder       = $Folder
        Detail       = ("$Detail" -replace '\s*\r?\n\s*', ' ').Trim()
        Bytes        = $Bytes
        Seconds      = $Seconds
        Integrity    = $Integrity
        LeftOnTarget = $LeftOnTarget
    }
}

function Format-CollectResults($Hosts) {
    # The "which IPs actually came back" answer, as aligned lines for the log
    # pane. Kind is the Write-Log colour, so a failure cannot read like a pass.
    $rows = @($Hosts)
    if ($rows.Count -eq 0) { return @() }
    $w = ($rows | ForEach-Object { "$($_.Target)".Length } | Measure-Object -Maximum).Maximum
    $a = ($rows | ForEach-Object { "$($_.Account)".Length } | Measure-Object -Maximum).Maximum
    foreach ($r in $rows) {
        $label = switch ($r.Outcome) { 'Success' { 'OK' } default { "$($r.Outcome)".ToUpper() } }
        $kind  = switch ($r.Outcome) { 'Success' { 'ok' } 'Partial' { 'warn' } default { 'err' } }
        # The folder's leaf only - the full path is in the CSV.
        $where = if ($r.Outcome -eq 'Success' -and $r.Folder) { Split-Path -Leaf $r.Folder } else { $r.Detail }
        [pscustomobject]@{
            Kind = $kind
            Text = ('  {0,-8} {1} {2} {3,5}  {4}' -f $label, "$($r.Target)".PadRight($w),
                    "$($r.Account)".PadRight($a), "$($r.Collected)/$($r.Requested)", $where)
        }
    }
}

function Get-CollectLogKind([string]$Line) {
    # The collector's -LogWriter carries text only, so the Write-Log colour is
    # read off the status marker the line already opens with. A marker later
    # in the line is part of a message, not a status.
    $l = "$Line".Trim()
    if ($l -match '^\[(OK|DONE)\]')              { return 'ok' }
    if ($l -match '^\[(FAILED|ERROR|!!)\]')      { return 'err' }
    if ($l -match '^\[(PARTIAL|SKIPPED|--)\]')   { return 'warn' }
    if ($l -match '^==== Target:')               { return 'info' }
    return 'plain'
}

function Export-CollectResults($Hosts, [string]$Path) {
    # Beside the evidence folders, so the record of what came back travels
    # with what came back. Opens straight into Excel.
    # The text columns carry target names, error text from the target and log
    # names, and the file opens in Excel: no cell may start a formula - the
    # same rule as the activity log (ConvertTo-LedgerCell).
    @($Hosts) | Select-Object @{ n = 'Target';  e = { ConvertTo-LedgerCell $_.Target } },
                              @{ n = 'Account'; e = { ConvertTo-LedgerCell $_.Account } },
                              @{ n = 'Outcome'; e = { ConvertTo-LedgerCell $_.Outcome } },
                              Collected, Requested,
                              @{ n = 'Folder';  e = { ConvertTo-LedgerCell $_.Folder } },
                              @{ n = 'Detail';  e = { ConvertTo-LedgerCell $_.Detail } } |
        Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    return $Path
}

function Get-TargetCredential([pscredential]$Credential, [string]$Domain, [string]$Target) {
    # Same SecureString, per-target name - the password is never unwrapped.
    # No credential in, none out: the collector must fail on the target, not here.
    if (-not $Credential -or -not $Credential.UserName) { return $Credential }
    $name = Resolve-CollectUsername $Credential.UserName $Domain $Target
    New-Object System.Management.Automation.PSCredential($name, $Credential.Password)
}

function Test-EvtxReadable([string]$Path) {
    # MEASURED on Windows 11, elevated, 2026-09-09. The Event Log service holds
    # winevt\Logs\*.evtx with a share mode that grants ReadWrite and REFUSES
    # FileShare::Read:
    #
    #     FileShare::Read       REFUSED  "used by another process"
    #     FileShare::ReadWrite  OPENED   20,975,616 bytes readable
    #     FileShare::None       REFUSED  "used by another process"
    #
    # So asking for FileShare::Read - the intuitive choice when you only intend
    # to read - reports a perfectly copyable Security.evtx as locked. That
    # false negative is the origin of the folklore that live event logs cannot
    # be copied. Copy-Item asks correctly; so must this.
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
                                     [System.IO.FileAccess]::Read,
                                     [System.IO.FileShare]::ReadWrite)
        try   { $bytes = $fs.Length }
        finally { $fs.Close() }
        return [pscustomobject]@{ Readable = $true; Bytes = $bytes; Reason = '' }
    } catch {
        return [pscustomobject]@{ Readable = $false; Bytes = 0; Reason = $_.Exception.Message }
    }
}

function Get-TransferReconciliation {
    # The WinRM zip path gets integrity free: zip entries carry a CRC32, so
    # Expand-Archive fails on a damaged archive. The per-file fallback and the
    # SMB path have nothing checking what arrived.
    #
    # Hashing would not help on the main path anyway - a live .evtx is written
    # to while it is read, so a source hash never matches by design. Counting
    # files and bytes catches the failure that actually happens: a log that did
    # not arrive, or one that arrived short.
    #
    # ExpectedBytes of -1 means "not measured", which is not a failure: the SMB
    # path cannot total the remote side without an extra round trip.
    param(
        [int]$ExpectedFiles,
        [int]$ActualFiles,
        [long]$ExpectedBytes,
        [long]$ActualBytes
    )
    $problems = @()
    if ($ActualFiles -ne $ExpectedFiles) {
        $problems += ("missing files - {0} of {1} arrived" -f $ActualFiles, $ExpectedFiles)
    }
    $bytesKnown = ($ExpectedBytes -ge 0)
    if ($bytesKnown -and $ActualBytes -ne $ExpectedBytes) {
        # Deliberately not "short by": a live log can GROW between the size
        # probe and the copy, so an overshoot is a mismatch to report, not an
        # error to swallow and not a shortfall to mislabel.
        $problems += ("byte total mismatch - expected {0:N0}, received {1:N0}" -f $ExpectedBytes, $ActualBytes)
    }
    $counts = "Collected {0} of {1} logs" -f $ActualFiles, $ExpectedFiles
    $bytesPart = if ($bytesKnown) { "{0:N0} bytes received" -f $ActualBytes } else { "byte total not measured" }
    $summary = if ($problems.Count) {
        "$counts, $bytesPart. MISMATCH: " + ($problems -join '; ')
    } else {
        "$counts, $bytesPart. OK"
    }
    return [pscustomobject]@{
        Ok       = ($problems.Count -eq 0)
        Problems = $problems
        Summary  = $summary
    }
}

function Get-EcsLineId([string]$Line) {
    # The detection id Convert-HayabusaJsonlToEcs wrote as event.id, read without
    # parsing the line - parsing is what made a big upload slow. It is the first
    # key of "event", which comes before "hayabusa", so the first match is ours;
    # the same text inside a string value is escaped (\"event\") and cannot match.
    # \s* lets the Python converter's spaced JSON match too.
    $m = $script:EcsLineIdPattern.Match($Line)
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}
$script:EcsImportIdPattern = [regex]'"import":\s*\{\s*"id":\s*"([^"]+)"'
$script:EcsLineIdPattern = [regex]'"event":\s*\{\s*"id":\s*"([0-9a-f]{40})"'

function Test-EcsFile([string]$Path, [scriptblock]$OnProgress) {
    # The upload's first pass over ecs.jsonl: counts, never the documents. The
    # upload used to hold every line twice - as text and as a parsed object -
    # which on a 550k-detection batch took 10 GB of RAM and froze the VM for ten
    # minutes before the first document went out. The second pass streams.
    # A line that is not a whole JSON object (a file cut short) is named by its
    # line number so the batch can be refused before anything is sent. Shape
    # only: a full parse per line is the slow part, and Elasticsearch still
    # rejects anything malformed that gets past. OpenText reads UTF-8.
    $bad = New-Object System.Collections.Generic.List[int]
    $ids = New-Object 'System.Collections.Generic.HashSet[string]'
    $n = 0; $docs = 0; $noId = 0
    $reader = [IO.File]::OpenText($Path)
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            $n++
            if ($OnProgress -and ($n % 5000) -eq 0) { & $OnProgress $n }
            $t = $line.Trim()
            if (-not $t) { continue }
            if (-not ($t.StartsWith('{') -and $t.EndsWith('}'))) { $bad.Add($n); continue }
            $docs++
            if (-not (Get-EcsLineId $t)) { $noId++ }
            $m = $script:EcsImportIdPattern.Match($t)
            if ($m.Success) { [void]$ids.Add($m.Groups[1].Value) }
        }
    } finally { $reader.Close() }
    # ImportIds: what the upload's count check asks Elasticsearch about - the
    # file's own, not whatever this session last converted.
    [pscustomobject]@{ Docs = $docs; BadLines = $bad; MissingId = $noId; ImportIds = @($ids) }
}

function New-BulkActionLine([string]$Index, [string]$Id, [switch]$Overwrite) {
    # "create", not "index": a detection whose id is already in the index is
    # refused (409) instead of overwritten, so a re-pull, a forgotten second
    # copy of the same logs, or the same file uploaded twice stores each
    # detection once, and it keeps the import.id of the upload that first
    # brought it. A line with no id (an ecs.jsonl from before event.id) gets one
    # from Elasticsearch, as every upload used to. Built as text, not with
    # ConvertTo-Json, because it runs once per document: the index name has
    # passed Test-HayabusaIndexName and the id is hex, so neither needs escaping.
    # -Overwrite ("Update detections already in the index"): "index" replaces
    # a stored detection with the same id - a re-upload after a newer
    # conversion refreshes it, still without doubling.
    $op = if ($Overwrite -and $Id) { 'index' } else { 'create' }
    if ($Id) { return '{"' + $op + '":{"_index":"' + $Index + '","_id":"' + $Id + '"}}' }
    return '{"create":{"_index":"' + $Index + '"}}'
}

# Asked of _bulk with every upload: only what Get-BulkTally reads. A full
# response repeats the index, id and shard detail for all 2000 documents, and
# PowerShell 5.1 parses all of it.
$script:BulkFilterPath = 'filter_path=items.*.status,items.*.error.type,items.*.error.reason'

function Test-FieldRejection($Result) {
    # Refused for its FIELDS, not for being a bad document: a mapping conflict
    # (a field that was text in one event arrives as an object in another), or
    # an index past its field limit. winlog.event_data is the dynamic part of a
    # detection and the only part whose shape the evidence decides, so this is
    # where such a refusal comes from - see Remove-EventDataFromLine.
    if ([int]$Result.status -ne 400 -or -not $Result.error) { return $false }
    $type = [string]$Result.error.type
    return ($type -in 'mapper_parsing_exception', 'document_parsing_exception') -or
           ($type -eq 'illegal_argument_exception' -and [string]$Result.error.reason -match 'total fields')
}

function Get-IndexCreateBody([string]$TemplateJson) {
    # The template's settings and mappings as a create-index body - for a
    # login that may create hayabusa-* indices but not install templates.
    ($TemplateJson | ConvertFrom-Json).template | ConvertTo-Json -Depth 50 -Compress
}

function Get-IndexMappingPatch([string]$TemplateJson) {
    # What an index created before v37 is missing from the current template:
    # event.id and the winlog.event_data dynamic mapping - and, from before
    # v72, the agent.* version stamp. The template only
    # applies when an index is CREATED, so appending into an older one left
    # the new fields stored but unsearchable, silently. Sent as PUT _mapping.
    $m = ($TemplateJson | ConvertFrom-Json).template.mappings
    @{
        dynamic_templates = @($m.dynamic_templates)
        properties = @{
            event  = @{ properties = @{ id = $m.properties.event.properties.id } }
            winlog = @{ properties = @{ event_data = $m.properties.winlog.properties.event_data } }
            agent  = $m.properties.agent
        }
    } | ConvertTo-Json -Depth 12 -Compress
}

function Get-BulkTally($Response) {
    # One _bulk response, counted. 409 is "that id is already in the index" -
    # the duplicate the fixed ids exist to catch, so it is not a failure.
    # Refused is the item positions Test-FieldRejection names: they are sent
    # again without their event fields, so they are not failures either - yet.
    # A plain array, not a List[object]: PowerShell 5.1 throws "Argument types
    # do not match" on @() around an empty generic list - found driving the real
    # Upload tab, after every document had gone in.
    $created = 0; $updated = 0; $dup = 0; $failed = 0
    $errors = @(); $refused = @()
    $i = -1
    foreach ($item in @($Response.items)) {
        $i++
        $r = if ($item.create) { $item.create } else { $item.index }
        $status = [int]$r.status
        if ($status -eq 200) { $updated++ }   # "index" over a stored id: refreshed
        elseif ($status -ge 200 -and $status -lt 300) { $created++ }
        elseif ($status -eq 409) { $dup++ }
        elseif (Test-FieldRejection $r) { $refused += $i }
        else {
            $failed++
            if ($errors.Count -lt 5) { $errors += $r.error }
        }
    }
    [pscustomobject]@{ Created = $created; Updated = $updated; Duplicate = $dup; Failed = $failed; Errors = @($errors); Refused = @($refused) }
}

# Tag on a detection that was stored without its event fields.
$script:FieldsRefusedTag = 'evtxer-fields-refused'

function Remove-EventDataFromLine([string]$Line) {
    # The detection without winlog.event_data, tagged so an analyst can find
    # the ones this happened to (tags: evtxer-fields-refused) and read their
    # fields in hayabusa.details or the local results file. Whatever the event
    # data holds, the detection itself still lands: one odd field must not
    # take the alert with it. Parsed here only - this is the rare path.
    # $null for a line that is not JSON after all (a damaged file whose braces
    # still balance): the caller counts it as a failure instead of aborting
    # the upload half way.
    try { $o = $Line | ConvertFrom-Json } catch { return $null }
    if ($o.winlog -and $o.winlog.PSObject.Properties['event_data']) { $o.winlog.PSObject.Properties.Remove('event_data') }
    $tags = @(@($o.tags) | Where-Object { $_ }) + $script:FieldsRefusedTag
    if ($o.PSObject.Properties['tags']) { $o.tags = $tags } else { $o | Add-Member -NotePropertyName tags -NotePropertyValue $tags }
    return ($o | ConvertTo-Json -Depth 20 -Compress)
}

function Send-EcsFile {
    # The upload's second pass: ecs.jsonl streamed to _bulk, BatchSize documents
    # per request, each under its own detection id. Only one batch is ever held.
    # $OnBatch runs after every request with the running tally, so the window
    # can show it and keep pumping. A detection refused for its event fields is
    # sent once more without them (Remove-EventDataFromLine) and counted in
    # Created and in FieldsRefused.
    param(
        [string]$Base,
        $Headers,
        [string]$Index,
        [string]$Path,
        [int]$BatchSize = 2000,
        [scriptblock]$OnBatch,
        # Replace detections already stored under the same id (New-BulkActionLine).
        [switch]$Overwrite
    )
    $tally = [pscustomobject]@{ Created = 0; Updated = 0; Duplicate = 0; Failed = 0; FieldsRefused = 0; Errors = @() }
    $sb = New-Object Text.StringBuilder
    $lines = New-Object System.Collections.Generic.List[string]
    $post = {
        param($body)
        $resp = Invoke-RestMethod -Uri "$Base/_bulk?$($script:BulkFilterPath)" -Method Post -Headers $Headers `
                    -ContentType 'application/x-ndjson' -Body (ConvertTo-BulkBody $body) -TimeoutSec 300
        Get-BulkTally $resp
    }
    $add = {
        param($t)
        $tally.Created += $t.Created; $tally.Updated += $t.Updated; $tally.Duplicate += $t.Duplicate; $tally.Failed += $t.Failed
        foreach ($e in $t.Errors) { if ($tally.Errors.Count -lt 5) { $tally.Errors += $e } }
    }
    $send = {
        $t = & $post $sb.ToString()
        & $add $t
        if ($t.Refused.Count) {
            $again = New-Object Text.StringBuilder
            foreach ($i in $t.Refused) {
                $stripped = Remove-EventDataFromLine $lines[$i]
                if (-not $stripped) {
                    $tally.Failed++
                    if ($tally.Errors.Count -lt 5) { $tally.Errors += [pscustomobject]@{ type = 'not_json'; reason = 'a line Elasticsearch could not parse and neither could the retry' } }
                    continue
                }
                [void]$again.AppendLine((New-BulkActionLine $Index (Get-EcsLineId $lines[$i]) -Overwrite:$Overwrite))
                [void]$again.AppendLine($stripped)
            }
            $t2 = if ($again.Length) { & $post $again.ToString() } else { [pscustomobject]@{ Created = 0; Updated = 0; Duplicate = 0; Failed = 0; Errors = @(); Refused = @() } }
            & $add $t2
            $tally.FieldsRefused += $t2.Created + $t2.Updated
            # Refused a second time even without its event fields: that one is
            # a real failure, named as one.
            $tally.Failed += $t2.Refused.Count
        }
        [void]$sb.Clear(); $lines.Clear()
        if ($OnBatch) { & $OnBatch $tally }
    }
    $reader = [IO.File]::OpenText($Path)
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            $line = $line.Trim()
            if (-not $line) { continue }
            [void]$sb.AppendLine((New-BulkActionLine $Index (Get-EcsLineId $line) -Overwrite:$Overwrite)); [void]$sb.AppendLine($line)
            $lines.Add($line)
            if ($lines.Count -ge $BatchSize) { . $send }
        }
        if ($lines.Count) { . $send }
    } finally { $reader.Close() }
    return $tally
}

# --------------------------------------------------------- disk space ------
# A pre-flight warning, not an accounting. Collections are refused by nothing
# here: the estimate is a rule of thumb, and an operator who knows the target is
# a fresh VM should not be argued with. What it prevents is finding out from a
# copy error, half way through a transfer window, that the destination was never
# going to hold the evidence.
#
# The per-log figure is deliberately generous. MEASURED on the sample corpus and
# on the collections run from this tool: a DFIR-preset host lands between 20 MB
# and 300 MB in total, dominated by Security.evtx, so 150 MB per big log and
# 25 MB per small one (about 1.1 GB for the DFIR preset) is already several
# times what a workstation produces and covers a busy server. ALL is budgeted at 12 GB per host, inside
# the 2-20 GB the Collect tab already warns about.
function Get-CollectSpaceEstimate {
    param(
        [ValidateSet('DFIR','All','Custom')]
        [string]$Category,
        [int]$TargetCount,
        [int]$LogCount = 0
    )
    $perLog  = 150MB
    $perHost = switch ($Category) {
        'All'    { 12GB }
        'Custom' { $perLog * [Math]::Max($LogCount, 1) }
        default  {
            # Only the big channels get the generous figure. The operational
            # logs DFIR added on 2026-10-12 (Defender, Firewall, RDP...) cap at
            # 1-16 MB by default; pricing them at 150 MB each would claim 2.4 GB
            # for a preset that lands in the low hundreds.
            $big = @('Security', 'System', 'Application', 'Windows PowerShell',
                     'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational')
            $nBig = @($script:DfirPreset | Where-Object { $big -contains $_ }).Count
            $perLog * $nBig + 25MB * ($script:DfirPreset.Count - $nBig)
        }
    }
    [pscustomobject]@{
        Bytes   = [long]($perHost * [Math]::Max($TargetCount, 1))
        PerHost = [long]$perHost
    }
}

function Test-CollectSpace {
    param(
        # -1 when the destination's free space could not be read at all: some
        # UNC and mapped paths report nothing. Guessing there would either block
        # a collection that was fine or bless one that was doomed.
        [long]$FreeBytes,
        [long]$NeedBytes
    )
    $freeGb = [Math]::Round($FreeBytes / 1GB, 1)
    $needGb = [Math]::Round($NeedBytes / 1GB, 1)

    if ($FreeBytes -lt 0) {
        return [pscustomobject]@{
            Level = 'Unknown'; CanProceed = $true
            Message = "Free space on the destination could not be read. This collection is estimated at about $needGb GB."
        }
    }
    if ($FreeBytes -lt $NeedBytes) {
        return [pscustomobject]@{
            Level = 'Short'; CanProceed = $true
            Message = "Only $freeGb GB free where this collection is estimated to need about $needGb GB. Free some space or collect fewer hosts."
        }
    }
    # Within a quarter of the estimate is close enough to be worth saying out
    # loud: the estimate has no idea how busy the target's Security log is.
    if (($FreeBytes - $NeedBytes) -lt ($NeedBytes * 0.25)) {
        return [pscustomobject]@{
            Level = 'Tight'; CanProceed = $true
            Message = "$freeGb GB free against an estimated $needGb GB. That is tight - the estimate is a rule of thumb, not a measurement."
        }
    }
    [pscustomobject]@{
        Level = 'Ok'; CanProceed = $true
        Message = "$freeGb GB free, about $needGb GB estimated."
    }
}

# Free bytes on whatever holds $Path, or -1 when that cannot be determined.
# Walks up to the first parent that exists, because the destination folder is
# usually created by the collection itself.
function Get-FreeSpaceBytes([string]$Path) {
    try {
        $probe = $Path
        while ($probe -and -not (Test-Path -LiteralPath $probe)) { $probe = Split-Path -Parent $probe }
        if (-not $probe) { return [long](-1) }
        $full = (Resolve-Path -LiteralPath $probe -ErrorAction Stop).ProviderPath
        if ($full -like '\\*') { return [long](-1) }   # UNC: no drive to ask
        $drive = Get-PSDrive -Name ($full.Substring(0,1)) -ErrorAction Stop
        if ($null -eq $drive.Free) { return [long](-1) }
        return [long]$drive.Free
    } catch { return [long](-1) }
}

# ------------------------------------------- Kibana saved-object import ----
# Everything below is pure: no window, no socket, no file write. The Dashboards
# tab (wpf-kibana.ps1) is the only caller, and these live here so they can be
# unit-tested without building a window - see tests/KibanaImport.Tests.ps1.

function New-MultipartFileBody {
    # PowerShell 5.1 has no Invoke-WebRequest -Form, so the multipart body is
    # hand-built. Same shape as scripts/so_http.py::_encode_multipart, and the
    # byte-level detail is the whole point:
    #   * every header line and the closing delimiter end with CRLF, never LF.
    #     A part whose headers end with a bare LF is dropped by Kibana's parser
    #     and the answer is an unhelpful 415 or "file is required".
    #   * exactly one blank line (CRLF CRLF) between the part headers and the
    #     payload, and a CRLF after the payload BEFORE the closing delimiter.
    #   * the payload is written as raw bytes, never through a string, for the
    #     ConvertTo-BulkBody reason: a string body is sent as Latin-1 on 5.1 and
    #     every non-ASCII byte in the ndjson would be corrupted on the way out.
    param(
        [string]$FieldName = 'file',
        [string]$FileName  = 'import.ndjson',
        [byte[]]$Content,
        [string]$FileContentType = 'application/ndjson',
        [string]$Boundary
    )
    # uuid4().hex in the Python original: hex only, so nothing in the boundary
    # ever needs quoting inside the Content-Type header.
    if ([string]::IsNullOrWhiteSpace($Boundary)) { $Boundary = [guid]::NewGuid().ToString('N') }

    $enc  = New-Object Text.UTF8Encoding($false)
    $head = "--$Boundary`r`n" +
            "Content-Disposition: form-data; name=`"$FieldName`"; filename=`"$FileName`"`r`n" +
            "Content-Type: $FileContentType`r`n`r`n"
    $tail = "`r`n--$Boundary--`r`n"

    $ms = New-Object System.IO.MemoryStream
    try {
        $hb = $enc.GetBytes($head); $ms.Write($hb, 0, $hb.Length)
        if ($Content -and $Content.Length -gt 0) { $ms.Write($Content, 0, $Content.Length) }
        $tb = $enc.GetBytes($tail); $ms.Write($tb, 0, $tb.Length)
        $bytes = $ms.ToArray()
    } finally { $ms.Dispose() }

    [pscustomobject]@{
        Boundary    = $Boundary
        ContentType = "multipart/form-data; boundary=$Boundary"
        Bytes       = $bytes
    }
}

function ConvertTo-VersionNumbers([string]$Text) {
    # '9.0.8', '9.0.8-SNAPSHOT', '10.1' -> @(9,0,8) / @(9,0,8) / @(10,1).
    # $null when there is no version in the text at all, so a caller can tell
    # "older" apart from "could not tell".
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $core = ($Text.Trim() -split '[-+ ]')[0]
    if ($core -notmatch '^\d+(\.\d+)*$') { return $null }
    return ,@($core -split '\.' | ForEach-Object { [int]$_ })
}

function Compare-KibanaVersion([string]$Left, [string]$Right) {
    # -1 / 0 / 1, or $null when either side cannot be parsed.
    #
    # Numeric per component, never a string compare: as text '9.0.10' sorts
    # BEFORE '9.0.8' and '10.0.0' before '9.0.8'. Both are exactly the
    # comparison the import gate makes, and either mistake refuses a perfectly
    # good Kibana or lets an old one fail with Kibana's own migration error.
    $a = ConvertTo-VersionNumbers $Left
    $b = ConvertTo-VersionNumbers $Right
    if ($null -eq $a -or $null -eq $b) { return $null }
    $a = @($a); $b = @($b)
    $n = [Math]::Max($a.Count, $b.Count)
    for ($i = 0; $i -lt $n; $i++) {
        # A missing component is zero, so 9.0 and 9.0.0 are the same version.
        $x = if ($i -lt $a.Count) { [int]$a[$i] } else { 0 }
        $y = if ($i -lt $b.Count) { [int]$b[$i] } else { 0 }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    return 0
}

function Get-KibanaImportSummary($Response) {
    # Kibana answers _import with success / successCount / errors[], where each
    # error names the object it belongs to (type, id) and carries its own
    # nested error object (type, reason). Reporting only success/failure loses
    # the one thing an operator can act on, so this flattens it per object.
    $created = 0
    if ($null -ne $Response -and $null -ne $Response.successCount) {
        try { $created = [int]$Response.successCount } catch { $created = 0 }
    }

    $errs = @()
    if ($null -ne $Response -and $Response.errors) {
        foreach ($e in @($Response.errors)) {
            if ($null -eq $e) { continue }
            $etype = ''; $reason = ''
            if ($null -ne $e.error) {
                if ($e.error.type)   { $etype  = [string]$e.error.type }
                if ($e.error.reason) { $reason = [string]$e.error.reason }
                # Some errors (conflict, unsupported_type) carry no reason at
                # all. An empty string there would say nothing, so the error
                # object itself is the fallback.
                if (-not $reason) {
                    try { $reason = ($e.error | ConvertTo-Json -Compress -Depth 5) } catch { $reason = '' }
                }
            }
            $text = ("{0}/{1}: {2} {3}" -f [string]$e.type, [string]$e.id, $etype, $reason).Trim()
            $errs += [pscustomobject]@{
                Type      = [string]$e.type
                Id        = [string]$e.id
                ErrorType = $etype
                Reason    = $reason
                Text      = $text
            }
        }
    }

    [pscustomobject]@{
        Success    = ($null -ne $Response -and $Response.success -eq $true)
        Created    = $created
        ErrorCount = @($errs).Count
        Errors     = @($errs)
    }
}

function Get-KratosCsrfToken($Flow) {
    # The csrf_token is a hidden input buried in the login flow's node list.
    # Kratos rejects the password POST without it, with a 400 that does not say
    # which field was missing.
    if ($null -eq $Flow -or $null -eq $Flow.ui -or $null -eq $Flow.ui.nodes) { return '' }
    foreach ($node in @($Flow.ui.nodes)) {
        if ($null -eq $node -or $null -eq $node.attributes) { continue }
        if ([string]$node.attributes.name -eq 'csrf_token') { return [string]$node.attributes.value }
    }
    return ''
}

function Select-HayabusaSavedObjects($SavedObjects, [string]$Prefix = 'hayabusa-') {
    # The delete path's only guard. Security Onion ships its own dashboards,
    # lenses and data views in the same saved-object space, so anything whose
    # id does not carry our prefix is left alone - case-sensitively, because
    # saved-object ids are.
    $out = @()
    foreach ($o in @($SavedObjects)) {
        if ($null -eq $o) { continue }
        $id = [string]$o.id
        if (-not $id) { continue }
        if ($id.StartsWith($Prefix, [System.StringComparison]::Ordinal)) { $out += $o }
    }
    return ,@($out)
}

function Get-NdjsonObjectCount([string]$Path) {
    # How many saved objects the file will actually import. A Kibana export
    # ends with a summary line ({"exportedCount":43,...}) that is NOT an
    # object, so a plain line count is always one too many.
    if ([string]::IsNullOrWhiteSpace($Path)) { return 0 }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 0 }
    $n = 0
    try {
        foreach ($line in [IO.File]::ReadLines($Path)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $doc = $null
            try { $doc = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
            if ($doc -and $doc.id -and $doc.type) { $n++ }
        }
    } catch { return 0 }
    return $n
}

# ------------------------------------------------------------ manifest ------
# Test-CopiedFile answers "did a file arrive". The manifest answers "is the file
# that arrived the file that was on the target", which is the only one of the
# two worth anything if the evidence is ever challenged.
#
# Where the source can be hashed, it is, and the two are compared per file.
# WinRM can: wevtutil exports a static copy into staging, so hashing it on the
# target is a fair comparison. SMB cannot: it reads the live log while Windows
# is still writing to it, so a source hash would differ from the copy for
# entirely innocent reasons. That case records NotCompared rather than inventing
# either a match or a mismatch.
function New-ManifestEntry {
    param(
        [string]$Path,
        [string]$LogName,
        [string]$SourceSha256 = ''
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{
            File = [IO.Path]::GetFileName($Path); LogName = $LogName
            Bytes = 0; Sha256 = ''; SourceSha256 = $SourceSha256; Verdict = 'Missing'
        }
    }
    $item = Get-Item -LiteralPath $Path
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    $verdict =
        if (-not $SourceSha256) { 'NotCompared' }
        # Case-insensitive on purpose: Get-FileHash upper-cases, and the
        # helpers that produce a hash on the far end do not always agree.
        elseif ($hash -eq $SourceSha256.ToUpperInvariant()) { 'Match' }
        else { 'MISMATCH' }
    [pscustomobject]@{
        File = $item.Name; LogName = $LogName
        Bytes = [long]$item.Length; Sha256 = $hash
        SourceSha256 = $SourceSha256; Verdict = $verdict
    }
}

function Get-ManifestSummary($Entries) {
    $all      = @($Entries)
    $verified = @($all | Where-Object { $_.Verdict -eq 'Match' }).Count
    $bad      = @($all | Where-Object { $_.Verdict -eq 'MISMATCH' }).Count
    $missing  = @($all | Where-Object { $_.Verdict -eq 'Missing' }).Count
    $notCmp   = @($all | Where-Object { $_.Verdict -eq 'NotCompared' }).Count

    $text =
        if ($bad -or $missing) {
            "Manifest: $bad MISMATCH, $missing missing, $verified verified of $($all.Count) file(s) - DO NOT treat this set as intact."
        } elseif ($verified) {
            "Manifest: $verified of $($all.Count) file(s) verified by SHA-256 against the source."
        } else {
            "Manifest: $($all.Count) file(s) hashed; source not compared (live logs cannot be hashed at rest)."
        }
    [pscustomobject]@{
        Ok = (($bad + $missing) -eq 0)
        Verified = $verified; Mismatched = $bad; Missing = $missing; NotCompared = $notCmp
        Text = $text
    }
}

# Written into the evidence folder itself, so the hashes travel with the files
# rather than living only in a log on the examiner's laptop.
function Write-EvtxManifest {
    param($Entries, [string]$Folder, [string]$HostName, [string]$Method,
          # WinRM-HTTPS with the certificate check skipped: nothing proved the
          # host that answered was $HostName, and the evidence has to say so.
          [switch]$CertificateCheckSkipped,
          # What this visit itself did to the host - see New-CollectionFootprint.
          $Footprint)
    $doc = [ordered]@{
        Host         = $HostName
        Method       = $Method
        CertificateCheckSkipped = [bool]$CertificateCheckSkipped
        CollectedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        Tool         = 'EVTXER'
        Algorithm    = 'SHA-256'
        Files        = @($Entries)
    }
    if ($Footprint) { $doc.Footprint = $Footprint }
    $path = Join-Path $Folder 'manifest.json'
    $doc | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}

# ------------------------------------------------------------- long jobs ---
# Hayabusa, Takajo and the collection used to run on the window's own thread.
# Hayabusa prints nothing between "Scanning in progress" and its summary when
# its output is piped - it hides its progress bar without a console - so
# nothing pumped the dispatcher and the window froze for the whole scan. The
# shell now waits on these in a loop that keeps the window alive; the pieces
# that decide what it says live here, where they can be tested.

function Format-JobDuration([timespan]$Span) {
    if ($Span.TotalHours -ge 1) { return ('{0}:{1:mm\:ss}' -f [int][Math]::Floor($Span.TotalHours), $Span) }
    return ('{0:mm\:ss}' -f $Span)
}

function Get-JobStatusText {
    # CPU time is the honest "not frozen" signal: a program that is working
    # keeps adding it, a hung one does not. Elapsed time alone grows either way.
    param([string]$Label, [timespan]$Elapsed, $Cpu, [string]$Detail)
    $parts = @($Label, "$(Format-JobDuration $Elapsed) elapsed")
    if ($Cpu -is [timespan]) { $parts += "CPU $(Format-JobDuration $Cpu)" }
    if ($Detail) { $parts += $Detail }
    return ($parts -join ' - ')
}

function Get-RunLogPath([string]$LogsDir, [string]$Job, [datetime]$Now) {
    # One file per run holding everything the tool printed - the summary tables
    # included - so a finished job can be read again without scrolling the pane.
    $slug = (($Job.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-'))
    return (Join-Path $LogsDir ("run_{0}_{1}.txt" -f $slug, $Now.ToString('yyyyMMdd_HHmmss')))
}

function Get-HayabusaScanArgs {
    # The flags live in exactly one place, so no caller can drop -O (local-time
    # timestamps Elasticsearch will not parse) or -w (an interactive prompt that
    # blocks forever). The Show Command popup and the README use this too.
    param(
        [string]$EvtxDir,
        [string]$OutFile,
        [ValidateSet('JSONL', 'csv')]
        [string]$Format = 'JSONL',
        # Hayabusa's own Results Summary as an HTML page beside the results.
        [string]$HtmlReport,
        # -q -N: no banner, no Results Summary. For a second pass whose banner
        # and summary were just printed by the first.
        [switch]$Quiet
    )
    $a = @('dfir-timeline', '-d', $EvtxDir, '-o', $OutFile, '-t', $Format,
           '-p', 'super-verbose', '-w', '-O', '-b', '-C')
    if ($HtmlReport) { $a += @('-H', $HtmlReport) }
    if ($Quiet)      { $a += @('-q', '-N') }
    return ,$a
}

function Initialize-ProcessPump {
    # Compiled for the same reason as HayabusaCertPin: .NET raises
    # OutputDataReceived on a worker thread with no PowerShell runspace, so a
    # scriptblock handler there throws and the output is lost. The compiled
    # handlers only queue lines; the UI thread drains them.
    #
    # stdin is redirected and closed at once: a program that stops to ask a
    # question gets end-of-file instead of waiting forever on a prompt nobody
    # can see. The one exception is text the caller hands over to be written
    # there first - sudo's password for the Raw Events tab, which must not
    # appear on a command line.
    if (-not ('EvtxerProcessPump' -as [type])) {
        Add-Type -ErrorAction Stop @"
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

public sealed class EvtxerProcessPump : IDisposable
{
    private readonly Process _p;
    private readonly ConcurrentQueue<string> _lines = new ConcurrentQueue<string>();
    private volatile bool _outDone;
    private volatile bool _errDone;

    public EvtxerProcessPump(string file, string arguments, string workingDirectory)
        : this(file, arguments, workingDirectory, null) { }

    public EvtxerProcessPump(string file, string arguments, string workingDirectory, string standardInput)
    {
        ProcessStartInfo si = new ProcessStartInfo(file, arguments);
        si.UseShellExecute = false;
        si.CreateNoWindow = true;
        si.RedirectStandardOutput = true;
        si.RedirectStandardError = true;
        si.RedirectStandardInput = true;
        si.StandardOutputEncoding = Encoding.UTF8;
        si.StandardErrorEncoding = Encoding.UTF8;
        if (!String.IsNullOrEmpty(workingDirectory)) si.WorkingDirectory = workingDirectory;
        _p = new Process();
        _p.StartInfo = si;
        _p.OutputDataReceived += (s, e) => { if (e.Data == null) _outDone = true; else _lines.Enqueue(e.Data); };
        _p.ErrorDataReceived  += (s, e) => { if (e.Data == null) _errDone = true; else _lines.Enqueue(e.Data); };
        // Process.Start builds the stdin writer from Console.InputEncoding and
        // flushes it at once, so with a UTF-8 console it sends a byte-order
        // mark before anything else - and sudo then reads "<BOM>password" and
        // refuses it. Found against a real Security Onion (bytes EF BB BF on
        // the far side); a console without UTF-8 hid it. So for the length of
        // Start the console's input encoding is UTF-8 WITHOUT the mark, then
        // put back. No console: the setter throws, and there is no mark anyway.
        Encoding saved = null;
        if (!String.IsNullOrEmpty(standardInput))
        {
            try
            {
                Encoding current = Console.InputEncoding;
                if (current.GetPreamble().Length > 0) { Console.InputEncoding = new UTF8Encoding(false); saved = current; }
            }
            catch { saved = null; }
        }
        try { _p.Start(); }
        finally { if (saved != null) { try { Console.InputEncoding = saved; } catch { } } }
        if (!String.IsNullOrEmpty(standardInput)) _p.StandardInput.Write(standardInput);
        _p.StandardInput.Close();
        _p.BeginOutputReadLine();
        _p.BeginErrorReadLine();
    }

    public string[] Drain()
    {
        List<string> list = new List<string>();
        string line;
        while (_lines.TryDequeue(out line)) list.Add(line);
        return list.ToArray();
    }

    // Exited AND both streams at end-of-file: the last lines arrive after
    // the process itself has gone.
    public bool IsDone { get { return _p.HasExited && _outDone && _errDone; } }
    public int ExitCode { get { return _p.ExitCode; } }
    public int Id { get { return _p.Id; } }
    public TimeSpan CpuTime { get { try { return _p.TotalProcessorTime; } catch { return TimeSpan.Zero; } } }

    // The whole tree: a child that inherited the output pipe would otherwise
    // keep it open, and the job would never see end-of-file.
    public void Kill()
    {
        try
        {
            if (_p.HasExited) return;
            ProcessStartInfo k = new ProcessStartInfo("taskkill.exe", "/T /F /PID " + _p.Id);
            k.UseShellExecute = false;
            k.CreateNoWindow = true;
            using (Process t = Process.Start(k)) { t.WaitForExit(5000); }
        }
        catch { }
        try { if (!_p.HasExited) _p.Kill(); } catch { }
    }
    public void Dispose() { _p.Dispose(); }
}
"@
    }
}

function New-ConsoleRunScript {
    # For "Open in console window": the program runs in a real console, so
    # Hayabusa draws its own progress bar and ETA. The script writes the exit
    # code to a file the moment the program ends - the tool carries on from
    # there - and then holds the window open so the summary can be read.
    # Every literal is single-quoted; the caller hands this over as
    # -EncodedCommand, so nothing passes through another layer of quoting.
    param([string]$Exe, [string[]]$Arguments, [string]$ExitCodeFile, [string]$Title, [switch]$NoPause)
    $q = { param($s) ConvertTo-PsLiteral $s }
    $argText = (@($Arguments) | ForEach-Object { ConvertTo-PsLiteral (Protect-NativeArgument $_) }) -join ' '
    $lines = @(
        'try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }'
        "`$Host.UI.RawUI.WindowTitle = $(& $q $Title)"
        "& $(& $q $Exe) $argText"
        # A program that never started leaves $LASTEXITCODE empty: say -1, not 0.
        '$rc = if ($null -eq $LASTEXITCODE) { -1 } else { $LASTEXITCODE }'
        # Written whole, then renamed into place: the tool polls for this file,
        # and Set-Content creates it empty before writing, which read as 0.
        "Set-Content -LiteralPath $(& $q "$ExitCodeFile.tmp") -Value `$rc -Encoding Ascii"
        "Move-Item -LiteralPath $(& $q "$ExitCodeFile.tmp") -Destination $(& $q $ExitCodeFile) -Force"
        "Write-Host ''"
        'Write-Host ("Finished - exit code {0}. The tool has carried on; this window is yours to read." -f $rc)'
    )
    if (-not $NoPause) { $lines += "[void](Read-Host 'Press Enter to close')" }
    $lines += 'exit $rc'
    return ($lines -join "`r`n")
}

function ConvertTo-PsLiteral([string]$Text) {
    # PowerShell also ends a single-quoted string at the typographic quotes
    # U+2018-U+201B, so a folder named O'Brien with a curly apostrophe broke
    # out of the literal. Each is doubled, like ', which PowerShell accepts.
    return ("'" + [regex]::Replace($Text, "['\u2018\u2019\u201A\u201B]", '$0$0') + "'")
}

function Protect-NativeArgument([string]$Arg) {
    # PowerShell 5.1 wraps an argument containing a space in double quotes for
    # the native program and does NOT escape a trailing backslash, so
    # "C:\My Cases\" reaches it as an escaped quote and swallows the rest of
    # the line. Doubling the trailing backslashes is what the program's own
    # parser expects - the same rule ConvertTo-ProcessArgumentLine applies.
    if ($Arg -notmatch '\s' -or $Arg -notmatch '\\$') { return $Arg }
    return ($Arg + [regex]::Match($Arg, '\\+$').Value)
}

function Read-ExitCodeFile([string]$Path) {
    # The console wrapper's exit code: an [int], or $null while it is not there
    # yet. Anything unreadable counts as a failure (-1), never as success.
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { $t = ([IO.File]::ReadAllText($Path)).Trim() } catch { return $null }
    $n = 0
    if ([int]::TryParse($t, [ref]$n)) { return $n }
    return -1
}

function Get-CollectProgressView {
    # What the status line and bar say during a collection. $Progress is the
    # synchronized table the collector updates from its runspace; $CurrentBytes
    # is how much of the file in flight has landed locally so far.
    param([hashtable]$Progress, [long]$CurrentBytes, [datetime]$Now = [datetime]::UtcNow)
    $hostCount = [int]$Progress.HostCount
    if ($hostCount -le 0) { return [pscustomobject]@{ Text = ''; Fraction = -1 } }
    $hostIndex = [Math]::Max(1, [int]$Progress.HostIndex)
    $head      = "Host $hostIndex/$hostCount $($Progress.Host)"
    $logIndex  = [int]$Progress.LogIndex
    $logCount  = [Math]::Max(1, [int]$Progress.LogCount)
    $done      = [long]$Progress.DownloadDone + $CurrentBytes
    $total     = [long]$Progress.DownloadTotal
    $mb        = { param($b) [Math]::Round($b / 1MB) }
    $byteShare = if ($total -gt 0) { [Math]::Min(1.0, $done / $total) } else { 0.0 }

    # How far through THIS host, 0..1. A WinRM host spends roughly the first
    # half exporting and the second half pulling the result back.
    switch ($Progress.Step) {
        'exporting'   { $inner = 0.45 * ($logIndex - 1) / $logCount
                        $text  = "$head - exporting log $logIndex/$($Progress.LogCount): $($Progress.LogName)" }
        'compressing' { $inner = 0.45; $text = "$head - compressing the exports on the target" }
        'downloading' { $inner = 0.5 + 0.5 * $byteShare
                        $text  = "$head - downloading $(& $mb $done) / $(& $mb $total) MB" }
        'copying'     { $inner = (($logIndex - 1) + $byteShare) / $logCount
                        $text  = "$head - copying $logIndex/$($Progress.LogCount): $($Progress.LogName) ($(& $mb $done) / $(& $mb $total) MB)" }
        'cleaning up' { $inner = 1.0; $text = "$head - cleaning up the target" }
        default       { $inner = 0.0; $text = "$head - $(if ($Progress.Step) { $Progress.Step } else { 'connecting' })" }
    }
    # Exporting and compressing happen on the target and used to show nothing
    # at all for minutes - it looked frozen. What the target has written so
    # far (read over a second session, see Update-RemoteSize) and how long the
    # step has been going say it is not.
    if ($Progress.Step -in 'exporting', 'compressing' -and $null -ne $Progress.RemoteBytes -and [long]$Progress.RemoteBytes -ge 0) {
        $text += " - $(& $mb ([long]$Progress.RemoteBytes)) MB written"
    }
    if ($Progress.StepStarted -is [datetime] -and $Progress.Step -ne 'cleaning up') {
        $text += " ($(Format-JobDuration ($Now - $Progress.StepStarted)))"
    }
    return [pscustomobject]@{ Text = $text; Fraction = (($hostIndex - 1) + $inner) / $hostCount }
}

function ConvertTo-LogPaneWidth([string]$Text, [double]$Default = 460, [double]$Min = 280, [double]$Max = 1200) {
    # The log pane's width is remembered in code\layout.conf between runs. A
    # missing, garbled or absurd value must never open a window whose log is
    # gone or whose tabs are crushed, so whatever is read is clamped.
    $w = 0.0
    $styles = [Globalization.NumberStyles]::Float
    $inv    = [Globalization.CultureInfo]::InvariantCulture
    if (-not [double]::TryParse("$Text".Trim(), $styles, $inv, [ref]$w)) { return $Default }
    return [Math]::Min($Max, [Math]::Max($Min, $w))
}

# ------------------------------------------------------- ECS conversion ---
function Convert-EcsRange {
    # The per-line work of Convert-HayabusaJsonlToEcs, over the lines
    # [Skip, Skip + Take) of Source - every line counted, blank ones too. One
    # worker of a parallel conversion runs exactly this, so a parallel and a
    # sequential conversion write the same documents.
    param(
        [string]$Source,
        [string]$Destination,
        [string]$ImportId,
        $Footprints,
        # Get-DetailsAliasMap: Details names back to real field names.
        [hashtable]$Aliases,
        # Byte position to start reading at (a line start, from
        # Get-JsonlLineIndex); then Skip lines more.
        [long]$Offset = 0,
        [long]$Skip = 0,
        [long]$Take = [long]::MaxValue,
        # Called about every 100 ms with the number of documents written so
        # far. Returning $true stops the range.
        [scriptblock]$OnTick
    )
    $n = 0; $bad = 0; $recovered = 0; $tagged = 0; $cancelled = $false
    $clock  = [Diagnostics.Stopwatch]::StartNew()
    $fs = [IO.File]::OpenRead($Source)
    if ($Offset -gt 0) { [void]$fs.Seek($Offset, [IO.SeekOrigin]::Begin) }
    $reader = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
    $writer = New-Object IO.StreamWriter($Destination, $false, (New-Object Text.UTF8Encoding($false)))
    try {
        for ($i = 0; $i -lt $Skip; $i++) { if ($null -eq $reader.ReadLine()) { break } }
        $read = 0
        while ($read -lt $Take -and $null -ne ($line = $reader.ReadLine())) {
            $read++
            if (-not $line.Trim()) { continue }
            try {
                try {
                    $doc = $line | ConvertFrom-Json
                } catch {
                    # PowerShell 5.1's ConvertFrom-Json cannot create a property
                    # with an empty name, so it rejects the whole line. Hayabusa's
                    # "Reg Key Value Set (Sysmon Alert)" rule emits Details with a
                    # "" key holding the registry value data -- a persistence IOC
                    # we must not drop. Rename the key in key position only (after
                    # { or ,) and re-parse. Python's json accepts these lines as-is,
                    # which is why the two GUIs disagreed on the document count.
                    $patched = [regex]::Replace($line, '(?<=[{,]\s*)""(?=\s*:)', '"(unnamed)"')
                    $doc = $patched | ConvertFrom-Json
                    $recovered++
                }
                $ecs = ConvertTo-EcsDocument $doc $ImportId $Aliases
                if ($Footprints.Count -and (Test-CollectionNoise $doc $Footprints)) {
                    $ecs.tags = @(@($ecs.tags) | Where-Object { $_ }) + $script:CollectionTag
                    $tagged++
                }
                $writer.WriteLine(($ecs | ConvertTo-Json -Depth 12 -Compress))
                $n++
            } catch { $bad++ }
            if ($OnTick -and $clock.ElapsedMilliseconds -ge 100) {
                $clock.Restart()
                if (@(& $OnTick $n) -contains $true) { $cancelled = $true; break }
            }
        }
    } finally { $reader.Close(); $writer.Close() }
    [pscustomobject]@{ Converted = $n; Bad = $bad; Recovered = $recovered; Tagged = $tagged; Cancelled = $cancelled }
}

function Get-JsonlLineIndex([string]$Path, [int]$Every = 1000) {
    # One pass over the bytes: how many lines (as ReadLine counts them - a last
    # line without a newline counts), and where every Every-th line starts.
    # Marks[k] is the byte offset of line k*Every, so a worker can seek close
    # to its slice instead of reading through all the slices before it - on a
    # multi-GB timeline with 8 workers that was several times the file's I/O.
    $marks = New-Object System.Collections.Generic.List[long]
    $marks.Add(0)
    $lines = [long]0; $pos = [long]0; $last = -1
    $buf = New-Object byte[] (4MB)
    $fs = [IO.File]::OpenRead($Path)
    try {
        while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
            $i = [Array]::IndexOf($buf, [byte]10, 0, $n)
            while ($i -ge 0) {
                $lines++
                if ($lines % $Every -eq 0) { $marks.Add($pos + $i + 1) }
                $i = if ($i + 1 -lt $n) { [Array]::IndexOf($buf, [byte]10, $i + 1, $n - $i - 1) } else { -1 }
            }
            $last = $buf[$n - 1]; $pos += $n
        }
    } finally { $fs.Close() }
    if ($pos -gt 0 -and $last -ne 10) { $lines++ }
    [pscustomobject]@{ Lines = $lines; Every = $Every; Marks = $marks }
}

function Get-EcsWorkerCount([long]$Lines, [int]$Cores = [Environment]::ProcessorCount) {
    # Every core but one: the conversion is CPU-bound PowerShell, and on one
    # thread a 550k-detection batch kept a single core busy - 10-20% of the VM -
    # for most of an hour. The spare core keeps the window and a running
    # collection responsive on a 4-core desktop; a 12-core server gets 11.
    # Capped at 16 - separate processes still scaled there when measured (10x
    # one), and each is about 100 MB. Small files stay on one: starting a
    # worker and loading this library into it costs a second or two.
    $byLines = [Math]::Ceiling($Lines / $script:EcsLinesPerWorker)
    return [int][Math]::Max(1, [Math]::Min([Math]::Min($Cores - 1, $script:EcsMaxWorkers), $byLines))
}
$script:EcsLinesPerWorker = 5000
$script:EcsMaxWorkers     = 16
$script:HayabusaLibPath   = $PSCommandPath

function Start-EcsWorker {
    # One slice of a parallel conversion, in a hidden powershell.exe of its own.
    # Runspaces in this process were tried first and stopped scaling at about
    # three cores - MEASURED: 4, 8 and 16 runspaces all ran near 1,000 lines/s,
    # because they share one garbage-collected heap - while separate processes
    # ran 4, 7.3 and 10 times faster than one. Below-normal priority keeps the
    # window and anything else on the VM responsive while it works.
    # The worker reports through files beside its part: <part>.n (lines done,
    # rewritten about every 100 ms), <part>.done (its counts, as JSON) or
    # <part>.err (why it failed). It rebuilds the footprints and the Details
    # name map itself rather than receiving them - both take well under a second.
    param([string]$Source, [string]$PartPath, [string]$ImportId, [string]$EvtxDir, [string]$HayabusaDir,
          [long]$Offset, [long]$Skip, [long]$Take)
    $lit = { param($v) ConvertTo-PsLiteral ([string]$v) }
    $script = @(
        "try {"
        "    . $(& $lit $script:HayabusaLibPath)"
        # The version stamp (agent.version): only the launcher defines it.
        "    `$script:ToolVersion = $(& $lit $script:ToolVersion)"
        "    `$fp = @(Get-CollectionFootprints $(& $lit $EvtxDir))"
        "    `$al = Get-DetailsAliasMap $(& $lit $HayabusaDir)"
        "    `$r = Convert-EcsRange -Source $(& $lit $Source) -Destination $(& $lit $PartPath) -ImportId $(& $lit $ImportId) ``"
        "            -Footprints `$fp -Aliases `$al -Offset $Offset -Skip $Skip -Take $Take -OnTick {"
        "        param(`$n) try { [IO.File]::WriteAllText($(& $lit "$PartPath.n"), [string]`$n) } catch { }"
        "    }"
        "    `$r | ConvertTo-Json -Compress | Set-Content -LiteralPath $(& $lit "$PartPath.done") -Encoding ASCII"
        "} catch {"
        "    `"`$_`" | Set-Content -LiteralPath $(& $lit "$PartPath.err") -Encoding UTF8"
        "    exit 1"
        "}"
    ) -join "`n"
    $psi = New-Object Diagnostics.ProcessStartInfo (Join-Path $PSHOME 'powershell.exe')
    $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' +
                     [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true
    $proc = [Diagnostics.Process]::Start($psi)
    try { $proc.PriorityClass = [Diagnostics.ProcessPriorityClass]::BelowNormal } catch { }
    return $proc
}

function Convert-HayabusaJsonlToEcs {
    # The one conversion. The Convert tab runs it with a progress callback;
    # an operator runs it by hand from PowerShell when the GUI cannot be used
    # (see the Show command button and README.txt). One function, so the two
    # can never produce different documents.
    param(
        [string]$Source,
        [string]$Destination,
        [string]$ImportId,
        # Called about every 100 ms with ($done, $total). Returning $true
        # cancels, and the partial file is removed.
        [scriptblock]$OnProgress,
        # Where the scanned EVTX came from. Its manifests' footprints decide
        # which detections are our own collection - see Test-CollectionNoise.
        [string]$EvtxDir,
        # 0 = Get-EcsWorkerCount decides.
        [int]$Workers = 0,
        # Whose rules/ and rules\config\default_details.txt name the Details
        # fields - see Get-DetailsAliasMap. The tool's own copy by default.
        [string]$HayabusaDir = (Join-Path (Split-Path -Parent $script:HayabusaLibPath) 'hayabusa-x64')
    )
    $footprints = @(Get-CollectionFootprints $EvtxDir)
    if (-not $ImportId) {
        $ImportId = (Get-Date -Format 'yyyyMMddHHmmss') + [guid]::NewGuid().ToString('N').Substring(0, 8)
    }
    $index = Get-JsonlLineIndex $Source
    $total = $index.Lines
    if ($Workers -le 0) { $Workers = Get-EcsWorkerCount $total }
    $Workers = [int][Math]::Max(1, [Math]::Min($Workers, [Math]::Max(1, $total)))

    $cancelled = $false
    if ($Workers -eq 1) {
        $tick = if ($OnProgress) { { param($n) & $OnProgress $n $total } }
        # Built here, not before the branch: the workers build their own.
        $parts = @(Convert-EcsRange -Source $Source -Destination $Destination -ImportId $ImportId `
                       -Footprints $footprints -Aliases (Get-DetailsAliasMap $HayabusaDir) -OnTick $tick)
    } else {
        # Each worker converts one contiguous slice into its own part file, and
        # the parts are joined in order - the same file, line for line, as a
        # sequential run. Cancel kills the workers: all they write is their own
        # part, which goes either way.
        $slice = [long][Math]::Ceiling($total / $Workers)
        $jobs  = @()
        $parts = @()
        try {
            for ($w = 0; $w -lt $Workers; $w++) {
                $partPath = "$Destination.part$w"
                # Seek to the checkpoint at or before the slice, skip the rest:
                # never reading through every earlier slice to get there.
                $first = $w * $slice
                $mark  = [Math]::Min([long][Math]::Floor($first / $index.Every), $index.Marks.Count - 1)
                $jobs += [pscustomobject]@{
                    Part    = $partPath
                    Done    = [long]0
                    Process = (Start-EcsWorker -Source $Source -PartPath $partPath -ImportId $ImportId `
                                   -EvtxDir $EvtxDir -HayabusaDir $HayabusaDir -Offset $index.Marks[$mark] `
                                   -Skip ($first - $mark * $index.Every) -Take $slice)
                }
            }
            while (@($jobs | Where-Object { -not $_.Process.HasExited }).Count) {
                Start-Sleep -Milliseconds 50
                if ($OnProgress -and -not $cancelled) {
                    # A read that lands while the worker rewrites its .n file
                    # gets "" (0) or a sharing error: keep the last good count,
                    # or the bar and the number jump backwards (field, 1.1M).
                    $done = 0
                    foreach ($j in $jobs) {
                        try { $j.Done = [Math]::Max($j.Done, [long][IO.File]::ReadAllText("$($j.Part).n")) } catch { }
                        $done += $j.Done
                    }
                    if (@(& $OnProgress $done $total) -contains $true) {
                        $cancelled = $true
                        foreach ($j in $jobs) { try { if (-not $j.Process.HasExited) { $j.Process.Kill() } } catch { } }
                    }
                }
            }
            if (-not $cancelled) {
                foreach ($j in $jobs) {
                    if (-not (Test-Path -LiteralPath "$($j.Part).done")) {
                        $why = try { (Get-Content -LiteralPath "$($j.Part).err" -Raw -ErrorAction Stop).Trim() } catch { "exit code $($j.Process.ExitCode)" }
                        throw "ECS conversion worker $([array]::IndexOf($jobs, $j) + 1) of $Workers failed: $why"
                    }
                    $parts += Get-Content -LiteralPath "$($j.Part).done" -Raw | ConvertFrom-Json
                }
                $out = [IO.File]::Create($Destination)
                try {
                    foreach ($j in $jobs) {
                        $in = [IO.File]::OpenRead($j.Part)
                        try { $in.CopyTo($out) } finally { $in.Close() }
                    }
                } finally { $out.Close() }
            }
        } finally {
            foreach ($j in $jobs) {
                try { if (-not $j.Process.HasExited) { $j.Process.Kill(); $j.Process.WaitForExit(5000) | Out-Null } } catch { }
                $j.Process.Dispose()
                foreach ($f in $j.Part, "$($j.Part).n", "$($j.Part).done", "$($j.Part).err") {
                    Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    $sum = { param($name) [long](@($parts | ForEach-Object { $_.$name }) | Measure-Object -Sum).Sum }
    $cancelled = [bool]@($parts | Where-Object { $_.Cancelled }) -or [bool]$cancelled
    # A part-written ECS file must not look like a finished one.
    if ($cancelled) { Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue }
    [pscustomobject]@{
        Source = $Source; Destination = $Destination; ImportId = $ImportId
        Total = $total; Converted = (& $sum 'Converted'); Bad = (& $sum 'Bad'); Recovered = (& $sum 'Recovered')
        Cancelled = $cancelled; Tagged = (& $sum 'Tagged'); Footprints = $footprints.Count; Workers = $Workers
    }
}

# ----------------------------------------------------- raw events (SO) ---
# The Raw Events tab sends the collected EVTX themselves to a Security Onion
# manager and runs its own importer there, so EVERY event becomes searchable,
# not only the ones a Hayabusa rule matched. so-import-evtx (read from the
# Security Onion 2.4 source, not guessed):
#   - must run on a manager-type node (standalone, eval, import, manager);
#   - names each import after the MD5 of the FILE, and skips a file it has
#     imported before - so sending the same logs twice adds nothing;
#   - prints a link whose time range runs from the oldest to the newest
#     event - BUT, MEASURED on a real 2.4.211 Import node, files every event
#     under the time of the IMPORT: its agent input decodes the converted
#     JSON without overwrite_keys, so @timestamp stays the read time and the
#     event's own time lands in event.created. Its link therefore opens on an
#     empty window; Get-SoWideLink stretches it to cover both;
#   - writes into Security Onion's own logs-import-so data stream, not ours.
# Transport is PuTTY's plink/pscp (code\putty): they take a password and a
# pinned host key without a prompt, which Windows' own ssh/scp cannot.

function Find-PuttyTool([ValidateSet('plink', 'pscp')][string]$Name) {
    # Shipped in code\putty beside this library. '' when missing.
    $p = Join-Path (Split-Path -Parent $script:HayabusaLibPath) "putty\$Name.exe"
    if (Test-Path -LiteralPath $p) { return $p }
    return ''
}

function Get-SshHostKeyFingerprint([string]$Text) {
    # The SHA-256 host key fingerprint in plink's output. With -batch and no
    # -hostkey, an unknown server makes plink stop and print it - which is
    # how the Fetch button reads it without trusting anything.
    $m = [regex]::Match("$Text", 'SHA256:[A-Za-z0-9+/]{43}=?')
    if ($m.Success) { return $m.Value }
    return ''
}

function New-PasswordFile([string]$Password) {
    # plink/pscp -pwfile: the password in a file only this Windows account
    # can read, instead of on a command line every process can see. The
    # caller deletes it in a finally.
    # A process killed mid-step (Task Manager, power loss) never reaches the
    # caller's finally, so an earlier file can be left behind (found when a
    # test harness was cut short). Each file is named after the EVTXER that
    # made it, and is swept only once that process is gone: sweeping by age
    # deleted a raw import's file in use - 15 minutes in, at copy 570 of 598,
    # when a second SSH step started (v50, found driving the job queue).
    foreach ($old in Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Filter 'evtxer-pw-*.txt' -File -ErrorAction SilentlyContinue) {
        $owner = [regex]::Match($old.Name, '^evtxer-pw-(\d+)-')
        $gone = if ($owner.Success) { -not (Get-Process -Id ([int]$owner.Groups[1].Value) -ErrorAction SilentlyContinue) }
                else { $old.LastWriteTime -lt (Get-Date).AddHours(-1) }   # named before v50: no owner in it
        if ($gone) { Remove-Item -LiteralPath $old.FullName -Force -ErrorAction SilentlyContinue }
    }
    $f = Join-Path ([IO.Path]::GetTempPath()) ("evtxer-pw-{0}-{1}.txt" -f $PID, [guid]::NewGuid().ToString('N'))
    [IO.File]::WriteAllText($f, $Password, (New-Object Text.UTF8Encoding($false)))
    try {
        $acl = New-Object Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')))
        Set-Acl -LiteralPath $f -AclObject $acl
    } catch { }
    return $f
}

function Get-PlinkArgs {
    # Every plink call the tab makes: -batch (never wait for a prompt), the
    # pinned host key, the password from a file. An empty -HostKey is the
    # Fetch probe: plink then refuses the unknown server and names its key.
    param([string]$HostName, [int]$Port = 22, [string]$User, [string]$HostKey,
          [string]$PasswordFile, [string]$Command)
    # The host is positional: one starting with '-' would be read as an
    # option (-proxycmd runs a local command).
    if (-not (Test-TargetName $HostName)) { throw "not a host name or address: '$HostName'" }
    $a = @('-ssh', '-batch', '-P', "$Port")
    if ($User)         { $a += @('-l', $User) }
    if ($HostKey)      { $a += @('-hostkey', $HostKey) }
    if ($PasswordFile) { $a += @('-pwfile', $PasswordFile) }
    $a += $HostName
    if ($Command)      { $a += $Command }
    return ,$a
}

function Get-PscpArgs {
    # One file to one remote path. -scp: Security Onion's sshd may run without
    # the SFTP subsystem, and plain scp needs nothing on the far side.
    param([string]$HostName, [int]$Port = 22, [string]$User, [string]$HostKey,
          [string]$PasswordFile, [string]$LocalFile, [string]$RemotePath)
    if (-not (Test-TargetName $HostName)) { throw "not a host name or address: '$HostName'" }
    return ,@('-batch', '-scp', '-P', "$Port", '-l', $User, '-hostkey', $HostKey, '-pwfile', $PasswordFile,
              $LocalFile, ("{0}:{1}" -f $HostName, $RemotePath))
}

function New-SoImportStagingDir([datetime]$Now = (Get-Date)) {
    # The manager's temporary folder for one import. Only [a-z0-9-], so it is
    # safe unquoted in a remote shell command.
    return '/tmp/evtxer-import-{0}-{1}' -f $Now.ToString('yyyyMMddHHmmss'), [guid]::NewGuid().ToString('N').Substring(0, 8)
}

function Get-SoImportRemoteName([int]$Index, [string]$Path) {
    # Every host folder has its own Security.evtx, so the files are renamed
    # on the way: a number, the host folder, the file - and only characters a
    # remote shell takes as they are. so-import-evtx names imports by content,
    # not by file name, so the name changes nothing about the import.
    $folder = Split-Path -Leaf (Split-Path -Parent $Path)
    $name = '{0:000}_{1}__{2}' -f $Index, $folder, (Split-Path -Leaf $Path)
    return ($name -replace '[^A-Za-z0-9._-]', '_')
}

function Get-SoImportFiles([string]$Folder) {
    # The .evtx files to send: the whole tree (one subfolder per collected
    # host), never a transfer still landing as .partial.
    if (-not $Folder -or -not (Test-Path -LiteralPath $Folder)) { return @() }
    return @(Get-ChildItem -LiteralPath $Folder -Recurse -File -Filter '*.evtx' -ErrorAction SilentlyContinue |
             Sort-Object FullName)
}

function Get-SoRemoteCommand {
    # The shell commands run on the manager. sudo -S -p '' reads the password
    # from standard input (written there by the process pump) and prints no
    # prompt; the staging folder is New-SoImportStagingDir's, safe unquoted.
    param([ValidateSet('Test', 'Stage', 'Import', 'Clean')][string]$Step, [string]$RemoteDir)
    switch ($Step) {
        'Test'   { return "echo EVTXER-SSH-OK; sudo -S -p '' true && echo EVTXER-SUDO-OK; " +
                          "command -v so-import-evtx >/dev/null 2>&1 || test -x /usr/sbin/so-import-evtx && echo EVTXER-IMPORTER-OK" }
        # The free space rides on this call (ConvertFrom-DfOutput); '; true'
        # because df fails where /nsm does not exist - EVTXER-STAGED still
        # says whether the folder was made.
        'Stage'  { return "mkdir -p $RemoteDir && chmod 700 $RemoteDir && echo EVTXER-STAGED; df -Pk /tmp /nsm 2>/dev/null; true" }
        'Import' { return "sudo -S -p '' so-import-evtx $RemoteDir/*.evtx" }
        'Clean'  { return "rm -rf $RemoteDir && echo EVTXER-CLEANED" }
    }
}

function ConvertFrom-DfOutput([string[]]$Lines) {
    # 'df -Pk': "Filesystem 1024-blocks Used Available Capacity Mounted on",
    # one row per path asked, in that order. Anything else is skipped.
    @(foreach ($l in $Lines) {
        if ("$l" -match '^\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%\s+(/\S*)\s*$') {
            [pscustomobject]@{ Mount = $Matches[5]; SizeKB = [long]$Matches[1]; AvailKB = [long]$Matches[3]; UsedPct = [int]$Matches[4] }
        }
    })
}

function Get-SoDiskWarning([object[]]$Disks, [long]$SendBytes) {
    # A warning, never a stop (owner, 2026-10-26: "more of a warning than
    # anything", and not polled). $Disks = ConvertFrom-DfOutput of
    # 'df -Pk /tmp /nsm': [0] where the files are staged, [1] /nsm, where
    # so-import-evtx keeps its copy and Elasticsearch indexes every event -
    # about 3x the EVTX, a rough rule. Elasticsearch stops placing data at
    # 90% full and refuses writes at 95%, so this speaks up past 85%.
    $gb = { param($b) '{0:N1} GB' -f ($b / 1GB) }
    @(
        if (@($Disks).Count -ge 1 -and $Disks[0].AvailKB * 1KB -lt $SendBytes * 1.1) {
            "The manager's /tmp has $(& $gb ($Disks[0].AvailKB * 1KB)) free and this import stages $(& $gb $SendBytes) there - the copy may fail."
        }
        if (@($Disks).Count -ge 2 -and $Disks[1].SizeKB -gt 0) {
            $n = $Disks[1]; $need = $SendBytes * 3
            if ((($n.SizeKB - $n.AvailKB) * 1KB + $need) / ($n.SizeKB * 1KB) -gt 0.85) {
                "/nsm on the manager has $(& $gb ($n.AvailKB * 1KB)) free ($($n.UsedPct)% used) and this import may need about $(& $gb $need) there (a copy of the files plus the indexed events). Elasticsearch refuses new data at 95% full - free space there, or import fewer hosts."
            }
        }
    )
}

function Get-SoTestVerdict([string[]]$Lines) {
    # What the Test button learned, from the markers Get-SoRemoteCommand
    # 'Test' prints.
    $t = $Lines -join "`n"
    [pscustomobject]@{
        Ssh      = $t -match 'EVTXER-SSH-OK'
        Sudo     = $t -match 'EVTXER-SUDO-OK'
        Importer = $t -match 'EVTXER-IMPORTER-OK'
    }
}

function Get-SoWideLink([string]$Url, [datetime]$NowUtc = [datetime]::UtcNow) {
    # so-import-evtx's link with its time range (&t=<from> - <to>) stretched
    # to end tomorrow: from the oldest EVENT (where a fixed Security Onion
    # would file them) to now (where 2.4.211 does). Unchanged if the link has
    # no range in the expected form.
    $day = '{0}%2000%3A00%3A00%20AM'
    $m = [regex]::Match($Url, '&t=(\d{4}%2F\d{2}%2F\d{2})%2000%3A00%3A00%20AM%20-%20\d{4}%2F\d{2}%2F\d{2}%2000%3A00%3A00%20AM')
    if (-not $m.Success) { return $Url }
    # Built by hand: in a .NET date format the F of %2F is itself a code
    # (fractions of a second), escaped % or not.
    $t = $NowUtc.Date.AddDays(1)
    $to = ($day -f ('{0:yyyy}%2F{0:MM}%2F{0:dd}' -f $t))
    return $Url.Substring(0, $m.Index) + '&t=' + ($day -f $m.Groups[1].Value) + '%20-%20' + $to + $Url.Substring($m.Index + $m.Length)
}

function Get-SoImportResult([string[]]$Lines) {
    # so-import-evtx's own report, read from its printed lines (2.4 wording):
    # "- importing logs to Elasticsearch..." per new file, "- this EVTX has
    # already been imported; skipping", "- WARNING: This evtx file may not
    # have fully imported successfully", "Import complete!", the
    # "From: ... To: ..." line and the https://.../#/dashboards link.
    $imported = @($Lines | Where-Object { $_ -match 'importing logs to Elasticsearch' }).Count
    $skipped  = @($Lines | Where-Object { $_ -match 'already been imported' }).Count
    $warned   = @($Lines | Where-Object { $_ -match 'may not have fully imported' }).Count
    $url  = @($Lines | Where-Object { $_ -match '^\s*https://\S+/#/dashboards' } | ForEach-Object { $_.Trim() }) | Select-Object -Last 1
    $span = @($Lines | Where-Object { $_ -match '^\s*From:\s*\S+\s+To:\s*\S+' } | ForEach-Object { $_.Trim() }) | Select-Object -Last 1
    [pscustomobject]@{
        Complete = [bool](@($Lines | Where-Object { $_ -match 'Import complete!' }).Count)
        Imported = $imported; Skipped = $skipped; Warnings = $warned
        Url = "$url"; WideUrl = $(if ($url) { Get-SoWideLink "$url" } else { '' }); TimeRange = "$span"
    }
}

# ------------------------------------------------------ manual commands ---
# What each tab does, as commands an operator can paste into PowerShell when
# the tool itself is broken. Built from the same functions the tool uses
# (Get-HayabusaScanArgs, Get-TakajoArgs, Resolve-CollectUsername,
# Convert-HayabusaJsonlToEcs), so the manual route cannot drift from the real
# one. Never contains a password: the scripts prompt for it.


function Format-PsArgument([string]$Arg) {
    # Flags and plain words stay bare so the line reads like the docs; anything
    # with a path separator, space or quote is single-quoted.
    if ($Arg -match '^[A-Za-z0-9_.-]+$') { return $Arg }
    return (ConvertTo-PsLiteral (Protect-NativeArgument $Arg))
}

function Get-ManualCollectCommand {
    param(
        [string]$Method,
        [string[]]$Targets,
        [string]$Category,
        [string[]]$CustomLogs,
        [string]$Username,
        [string]$Domain,
        [string]$OutRoot,
        [switch]$SkipCertificateCheck
    )
    if (-not $Method) { $Method = 'WinRM' }
    $hostList = @($Targets | Where-Object { "$_".Trim() })
    if ($hostList.Count -eq 0) { $hostList = @('<TARGET>') }
    $user = if ("$Username".Trim()) { $Username } else { '<USER>' }
    $hostLines = foreach ($h in $hostList) {
        "    @{ Name = $(ConvertTo-PsLiteral $h); Account = $(ConvertTo-PsLiteral (Resolve-CollectUsername $user $Domain $h)) }"
    }
    $all  = ($Category -eq 'All')
    $logs = if ($all) { "'ALL'   # every channel the target has" }
            else { "@(`r`n" + ((@(Resolve-LogPreset $Category $CustomLogs) | ForEach-Object { '    ' + (ConvertTo-PsLiteral $_) }) -join "`r`n") + "`r`n)" }
    $out  = if ($OutRoot) { $OutRoot } else { '<OUTPUT FOLDER>' }

    $head = @(
        "# Manual EVTX collection over $Method - what COLLECT does, step by step."
        '# Paste into an ELEVATED PowerShell on this workstation. Nothing is installed'
        '# on the target. It asks for the password; nothing here stores it.'
        '$hosts = @('
        ($hostLines -join "`r`n")
        ')'
        "`$logs  = $logs"
        "`$out   = $(ConvertTo-PsLiteral $out)"
        '$pw    = Read-Host -AsSecureString ''Password'''
    )

    if ($Method -eq 'SMB') {
        $copy = if ($all) {
            "    Copy-Item -Path 'EVTXSRC:\Windows\System32\winevt\Logs\*.evtx' -Destination `$dest"
        } else {
@'
    foreach ($l in $logs) {
        # Channel names map to file names with / written as %4.
        $file = ($l -replace '/', '%4') + '.evtx'
        Copy-Item -LiteralPath "EVTXSRC:\Windows\System32\winevt\Logs\$file" -Destination $dest
    }
'@.TrimEnd()
        }
        $body = @(
            ''
            '# SMB: mount C$ and copy the log files. Nothing runs on the target. Logs'
            '# Windows holds open (often Security.evtx) can refuse - use WinRM then.'
            'foreach ($h in $hosts) {'
            '    $cred = New-Object System.Management.Automation.PSCredential($h.Account, $pw)'
            '    New-PSDrive -Name EVTXSRC -PSProvider FileSystem -Root "\\$($h.Name)\C$" -Credential $cred | Out-Null'
            '    $dest = Join-Path $out (''{0}_{1}'' -f $h.Name, (Get-Date -Format ''yyyyMMdd_HHmm''))'
            '    New-Item -ItemType Directory -Path $dest -Force | Out-Null'
            $copy
            '    Remove-PSDrive EVTXSRC'
            '    Get-ChildItem $dest -Filter *.evtx | Get-FileHash -Algorithm SHA256 |'
            '        Export-Csv (Join-Path $dest ''hashes.csv'') -NoTypeInformation'
            '}'
        )
        return (($head + $body) -join "`r`n")
    }

    # The run token is drawn when the script RUNS, per host: a fixed one
    # would, on a second paste after a failed run, find the first run's
    # folder and copy its exports back as if they were new.
    $stageBase = (Get-EvtxStagingPaths)[0]
    $session = '    $s = New-PSSession -ComputerName $h.Name -Credential $cred'
    if ($Method -eq 'WinRM-HTTPS') {
        $session += ' -UseSSL -Port 5986'
        if ($SkipCertificateCheck) {
            $session += ' -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck)'
        }
    }
    $trusted = @()
    if (Test-NeedsTrustedHosts $Method) {
        $trusted = @(
            ''
            '# Workgroup or IP targets: WinRM needs them in TrustedHosts. Note the value'
            '# printed here so you can put it back afterwards (last line).'
            'Start-Service WinRM'
            '(Get-Item WSMan:\localhost\Client\TrustedHosts).Value'
            'Set-Item WSMan:\localhost\Client\TrustedHosts -Value (($hosts | ForEach-Object { $_.Name }) -join '','') -Concatenate -Force'
        )
    }
    $enum = if ($all) { "        if (`$logs -eq 'ALL') { `$logs = @(wevtutil el) }" } else { $null }
    $body = @(
        "`$stageBase = $(ConvertTo-PsLiteral $stageBase)  # + _<8 hex> per host: EVTX_Export_0a1b2c3d"
    ) + $trusted + @(
        ''
        '# WinRM: export each log ON the target with wevtutil (it reads logs Windows'
        '# holds open), pull the files back, then delete the staging folder.'
        'foreach ($h in $hosts) {'
        '    $cred = New-Object System.Management.Automation.PSCredential($h.Account, $pw)'
        '    $stage = $stageBase + ''_'' + [guid]::NewGuid().ToString(''N'').Substring(0, 8)'
        $session
        '    $dest = Join-Path $out (''{0}_{1}'' -f $h.Name, (Get-Date -Format ''yyyyMMdd_HHmm''))'
        '    New-Item -ItemType Directory -Path $dest -Force | Out-Null'
        '    # A failed export skips the host - nothing is copied that this run did not write.'
        '    try { Invoke-Command -Session $s -ErrorAction Stop -ArgumentList $stage, $logs -ScriptBlock {'
        '        param($stage, $logs)'
        $enum
        '        New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null'
        '        icacls $stage /inheritance:r /grant:r ''*S-1-5-18:(OI)(CI)F'' ''*S-1-5-32-544:(OI)(CI)F'' | Out-Null'
        '        foreach ($l in $logs) {'
        '            wevtutil epl $l (Join-Path $stage (($l -replace ''[/\\:*?"<>|]'', ''_'') + ''.evtx'')) /overwrite:true'
        '        }'
        '    } } catch { Write-Warning "$($h.Name): export failed, nothing copied - $_"; Remove-PSSession $s; continue }'
        '    Copy-Item -FromSession $s -Path "$stage\*.evtx" -Destination $dest'
        '    Invoke-Command -Session $s -ArgumentList $stage -ScriptBlock { param($stage) Get-ChildItem -LiteralPath $stage -File -Force | Remove-Item -Force; Remove-Item -LiteralPath $stage -Force }'
        '    Remove-PSSession $s'
        '    Get-ChildItem $dest -Filter *.evtx | Get-FileHash -Algorithm SHA256 |'
        '        Export-Csv (Join-Path $dest ''hashes.csv'') -NoTypeInformation'
        '}'
    )
    if ($trusted) {
        $body += @('', '# Afterwards, put TrustedHosts back to the value printed above:',
                   "# Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<old value>' -Force")
    }
    return ((($head + $body) | Where-Object { $null -ne $_ }) -join "`r`n")
}

function Get-ManualHayabusaCommand {
    param([string]$Exe, [string]$EvtxDir, [string]$OutFile, [string]$HtmlReport, [switch]$Csv)
    $exePath = if ($Exe) { $Exe } else { '<HAYABUSA EXE>' }
    $dir     = Split-Path -Parent $exePath
    $a = Get-HayabusaScanArgs -EvtxDir $(if ($EvtxDir) { $EvtxDir } else { '<EVTX FOLDER>' }) -OutFile $OutFile -HtmlReport $HtmlReport
    $lines = @(
        '# Manual Hayabusa scan - exactly what SCAN + CONVERT runs first.'
        '# Hayabusa finds its rules folder from the current folder, so run it from its own.'
        "Set-Location $(ConvertTo-PsLiteral $dir)"
        "& $(ConvertTo-PsLiteral $exePath) " + ((@($a) | ForEach-Object { Format-PsArgument $_ }) -join ' ')
    )
    if ($Csv) {
        $csvOut = Join-Path (Split-Path -Parent $OutFile) 'results.csv'
        $c = Get-HayabusaScanArgs -EvtxDir $(if ($EvtxDir) { $EvtxDir } else { '<EVTX FOLDER>' }) -OutFile $csvOut -Format csv -Quiet
        $lines += @('', '# Optional CSV copy for reading in Excel (not used for the upload).',
                    ("& $(ConvertTo-PsLiteral $exePath) " + ((@($c) | ForEach-Object { Format-PsArgument $_ }) -join ' ')))
    }
    return ($lines -join "`r`n")
}

function Get-ManualEcsCommand {
    param([string]$LibPath, [string]$Source, [string]$EvtxDir)
    $src = if ($Source) { $Source } else { '<results.jsonl>' }
    # Same naming as Get-EcsOutputPath, done as text: that one goes through
    # [IO.Path], which rejects the <placeholder> an empty field turns into.
    $dst = if (-not $Source) { '<results.ecs.jsonl>' }
           elseif ($src -match '\.jsonl?$') { $src -replace '\.jsonl?$', '.ecs.jsonl' }
           else { "$src.ecs.jsonl" }
    return (@(
        '# Manual ECS conversion - the same function the Convert tab runs.'
        '# Start PowerShell with:   powershell -ExecutionPolicy Bypass'
        ". $(ConvertTo-PsLiteral $LibPath)"
        # The version stamp (agent.version) - a fresh console has none.
        "`$script:ToolVersion = $(ConvertTo-PsLiteral "$script:ToolVersion")"
        ("Convert-HayabusaJsonlToEcs -Source $(ConvertTo-PsLiteral $src) -Destination $(ConvertTo-PsLiteral $dst)" +
            $(if ($EvtxDir) { " -EvtxDir $(ConvertTo-PsLiteral $EvtxDir)" } else { '' }))
    ) -join "`r`n")
}

function Get-ManualTakajoCommand {
    param([string]$Exe, [string]$Timeline, [string]$OutDir, [string]$Level, [string]$RulePath,
          [string]$HtmlDir, [switch]$Sqlite)
    $exePath = if ($Exe) { $Exe } else { '<TAKAJO EXE>' }
    $dir  = Split-Path -Parent $exePath
    $leaf = '.\' + (Split-Path -Leaf $exePath)
    $tl   = if ($Timeline) { $Timeline } else { '<results.jsonl>' }
    $auto = Get-TakajoArgs -Command automagic -TakajoDir $dir -Timeline $tl -OutDir $OutDir -Level $Level -ShowProgress
    $lines = @(
        '# Manual Takajo - what RUN AUTOMAGIC and BUILD OFFLINE HTML run.'
        '# Takajo reads conf\ and templates\ from the CURRENT folder, so run it from its own.'
        "Set-Location $(ConvertTo-PsLiteral $dir)"
        ''
        '# automagic: every CSV analysis into a NEW folder (it refuses one that exists).'
        "& $leaf " + ((@($auto) | ForEach-Object { Format-PsArgument $_ }) -join ' ')
    )
    if ($HtmlDir) {
        $db = Join-Path (Split-Path -Parent $HtmlDir) 'takajo-report.sqlite'
        try {
            $html = Get-TakajoArgs -Command html-report -TakajoDir $dir -Timeline $tl -OutDir $HtmlDir `
                        -RulePath $RulePath -DbPath $db -Sqlite:$Sqlite -ShowProgress
            $lines += @('', '# html-report: --output must be RELATIVE to the takajo folder (it prepends ./).',
                        ("& $leaf " + ((@($html) | ForEach-Object { Format-PsArgument $_ }) -join ' ')))
        } catch {
            $lines += @('', "# html-report: $($_.Exception.Message)")
        }
    }
    return ($lines -join "`r`n")
}

# ---------------------------------------------- our own collection, tagged ---
# A collection is a remote admin logon, and the logs it pulls are snapshots
# taken DURING it: the logon is in Security, the WinRM host process in
# PowerShell, the wevtutil runs in Sysmon. Hayabusa flags some of that. Rather
# than delete anything, each host's manifest records a footprint of the visit,
# and the ECS conversion tags matching detections "evtxer-collection" so the
# analyst can filter them out (NOT tags:evtxer-collection) - or look at them.
$script:CollectionTag = 'evtxer-collection'
$script:MaxTrustedSkewSeconds = 300

function Get-OperatorAddresses {
    # This workstation's IPv4 addresses: the source address our logons carry.
    try {
        return @([System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
                 Where-Object { $_.AddressFamily -eq 'InterNetwork' -and -not $_.ToString().StartsWith('127.') } |
                 ForEach-Object { $_.ToString() } | Select-Object -Unique)
    } catch { return @() }
}

function New-CollectionFootprint {
    param(
        [string]$Account,
        [datetime]$StartUtc,
        [datetime]$EndUtc,
        [string]$StagingFolder,
        # Target clock minus ours, where it could be read (WinRM). Event
        # timestamps are the target's clock; the window is in ours.
        $TargetClockSkewSeconds,
        [string[]]$OperatorAddresses
    )
    $user = ("$Account" -split '[\\@]')
    $user = if ("$Account".Contains('@')) { $user[0] } else { $user[-1] }
    [ordered]@{
        OperatorHost       = $env:COMPUTERNAME
        OperatorAddresses  = @($OperatorAddresses)
        Account            = $Account
        AccountName        = $user
        StartUtc           = $StartUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        EndUtc             = $EndUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        StagingFolder      = $StagingFolder
        TargetClockSkewSeconds = $TargetClockSkewSeconds
    }
}

function ConvertTo-UtcDate($Value) {
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture,
                             [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
}

function Get-CollectionFootprints([string]$EvtxDir) {
    # Every manifest.json under the scanned folder that carries a footprint.
    # The folder it sits in is the collection folder: a detection belongs to
    # it when Hayabusa's EvtxFile is inside that folder.
    if (-not $EvtxDir -or -not (Test-Path -LiteralPath $EvtxDir)) { return @() }
    $found = foreach ($m in Get-ChildItem -LiteralPath $EvtxDir -Recurse -Filter 'manifest.json' -File -ErrorAction SilentlyContinue) {
        try {
            $j = Get-Content -LiteralPath $m.FullName -Raw | ConvertFrom-Json
            if (-not $j.Footprint) { continue }
            $f = $j.Footprint
            # The skew is the TARGET's word. Believed only when small: a
            # compromised host reporting a wild clock would otherwise slide the
            # window onto its own activity and get it tagged as ours. Ignoring
            # it can only leave some of our noise untagged.
            $measured = $null -ne $f.TargetClockSkewSeconds
            $skew = if ($measured -and [Math]::Abs([double]$f.TargetClockSkewSeconds) -le $script:MaxTrustedSkewSeconds) {
                        [double]$f.TargetClockSkewSeconds } else { 0.0 }
            # Five minutes either side when the target's clock is unknown (SMB),
            # one when it was measured.
            $slack = if ($measured) { 60 } else { 300 }
            # wsmprovhost only for a WinRM visit (the only kind with a staging
            # folder): over SMB nothing of ours ran there, and tagging someone
            # else's remote PowerShell would hide it behind our tag.
            $words = @(@($f.AccountName) + @($f.OperatorAddresses) + @($f.StagingFolder))
            if ("$($f.StagingFolder)".Trim()) { $words += 'wsmprovhost' }
            # Whole tokens only: 10.0.0.5 must not match 10.0.0.50 or 110.0.0.5,
            # nor admin match sysadmin. A dot may FOLLOW (wsmprovhost.exe).
            $needles = @($words | Where-Object { "$_".Trim() } | ForEach-Object {
                '(?<![\w.])' + [regex]::Escape("$_".ToLowerInvariant()) + '(?!\w)'
            })
            [pscustomobject]@{
                Folder  = $m.DirectoryName.TrimEnd('\') + '\'
                From    = (ConvertTo-UtcDate $f.StartUtc).AddSeconds($skew - $slack)
                To      = (ConvertTo-UtcDate $f.EndUtc).AddSeconds($skew + $slack)
                Needles = @($needles)
            }
        } catch { }
    }
    if ($found) { return @($found) } else { return @() }
}

function Test-CollectionNoise($Doc, $Footprints) {
    # Cheap tests first - the file and the time - so the text search only runs
    # on the handful of detections inside a collection window.
    if (-not $Footprints -or -not $Doc.EvtxFile -or -not $Doc.Timestamp) { return $false }
    $file = "$($Doc.EvtxFile)"
    $when = $null
    foreach ($f in $Footprints) {
        if (-not $file.StartsWith($f.Folder, [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($null -eq $when) { try { $when = ConvertTo-UtcDate $Doc.Timestamp } catch { return $false } }
        if ($when -lt $f.From -or $when -gt $f.To) { continue }
        $text = (@($Doc.Details, $Doc.ExtraFieldInfo) | ConvertTo-Json -Compress -Depth 6).ToLowerInvariant()
        foreach ($n in $f.Needles) { if ($text -match $n) { return $true } }
    }
    return $false
}

# ------------------------------------------------------- activity ledger ---
# The accountability record (operator request, 2026-10-14): one CSV under
# logs\ that keeps growing across every session - a row per thing the tool did
# to a target, with when, who, from where, to which IP and port, over what,
# with which account, and whether it worked. The mission log is per launch,
# untimestamped prose; this is the table handed to whoever asks "what touched
# that box, and when". Never holds a password.
$script:LedgerColumns = @('Date','Time','UTC','Operator','Workstation','WorkstationIP','Action','Target','Port',
                          'Protocol','Account','Result','Files','Size','Duration','Integrity','LeftOnTarget',
                          'Output','Details','ToolVersion')

function Format-ByteSize([long]$Bytes) {
    if ($Bytes -lt 0)   { return '' }
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N0} KB' -f ($Bytes / 1KB)) }
    return "$Bytes B"
}

function ConvertTo-LedgerCell($t) {
    # One line per cell, and never a formula: hostnames, accounts and error
    # text come from the target, and Excel runs a cell that starts with
    # = + - @ (or a tab/CR) as a formula when it opens the CSV. A leading
    # apostrophe keeps it text.
    # Checked past any leading whitespace, then trimmed: trimming after a
    # plain ^[=...] check turned " =cmd" back into a formula.
    $v = ("$t" -replace '\s*\r?\n\s*', ' ').Trim()
    if ("$t" -match '^\s*[=+\-@]') { "'$v" } else { $v }
}

function New-LedgerRow {
    param(
        [string]$Action, [string]$Target, $Port = '', [string]$Protocol, [string]$Account,
        [string]$Result, [string]$Files, [long]$Bytes = -1, [double]$Seconds = -1,
        [string]$Integrity, [string]$LeftOnTarget, [string]$Output, [string]$Details,
        [datetime]$When = (Get-Date)
    )
    # Computed once per session: a DNS lookup per row would stall the UI.
    if ($null -eq $script:LedgerWorkstationIp) { $script:LedgerWorkstationIp = (@(Get-OperatorAddresses) -join ' ') }
    # One spelling in the record: callers wrote 'FAILED' and 'Failed' for the
    # same outcome (usability walk, 2026-10-21) - a filter on one missed the other.
    if ($Result -eq 'failed') { $Result = 'Failed' }
    $cell = ${function:ConvertTo-LedgerCell}
    $row = [ordered]@{
        Date          = $When.ToString('yyyy-MM-dd')
        Time          = $When.ToString('HH:mm:ss')
        UTC           = $When.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        Operator      = "$env:USERDOMAIN\$env:USERNAME"
        Workstation   = $env:COMPUTERNAME
        WorkstationIP = $script:LedgerWorkstationIp
        Action        = & $cell $Action
        Target        = & $cell $Target
        Port          = "$Port"
        Protocol      = & $cell $Protocol
        Account       = & $cell $Account
        Result        = & $cell $Result
        Files         = & $cell $Files
        Size          = Format-ByteSize $Bytes
        Duration      = $(if ($Seconds -ge 0) { Format-JobDuration ([timespan]::FromSeconds([Math]::Round($Seconds))) } else { '' })
        Integrity     = & $cell $Integrity
        LeftOnTarget  = & $cell $LeftOnTarget
        Output        = & $cell $Output
        Details       = & $cell $Details
        ToolVersion   = "$script:ToolVersion"
    }
    [pscustomobject]$row
}

function Get-LedgerPendingPath([string]$Path) {
    # Where rows wait while Excel holds the activity log open.
    return ([IO.Path]::ChangeExtension($Path, $null).TrimEnd('.') + '-pending.csv')
}

function Get-LedgerRows([string]$Path) {
    # Every row in order, those still waiting in the pending file included.
    $rows = @()
    foreach ($f in $Path, (Get-LedgerPendingPath $Path)) {
        if (Test-Path -LiteralPath $f) { $rows += @(Import-Csv -LiteralPath $f -Encoding UTF8) }
    }
    return $rows
}

function Format-LedgerText($Rows) {
    # The activity log as a report a person reads top to bottom: one block per
    # action, the empty fields left out.
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        $where = (@($r.Target, $(if ($r.Port) { "port $($r.Port)" }), $r.Protocol) | Where-Object { $_ }) -join ', '
        $out.Add("$($r.Date) $($r.Time) ($($r.UTC))  $($r.Action)  $where  -  $($r.Result)")
        foreach ($k in 'Operator', 'Workstation', 'WorkstationIP', 'Account', 'Files', 'Size', 'Duration',
                       'Integrity', 'LeftOnTarget', 'Output', 'Details', 'ToolVersion') {
            if ($r.$k) { $out.Add(('    {0,-14} {1}' -f "${k}:", $r.$k)) }
        }
        $out.Add('')
    }
    return , $out.ToArray()
}

function Get-LedgerExportRows([string]$Ledger, [string]$Destination) {
    # The live file is never moved or rewritten - it stays append-only. Saving
    # an export over it (the dialog would allow it) is refused, and over the
    # pending file too: the next write would fold those rows in twice.
    $dest = [IO.Path]::GetFullPath($Destination)
    foreach ($p in $Ledger, (Get-LedgerPendingPath $Ledger)) {
        if ($dest -ieq [IO.Path]::GetFullPath($p)) { throw "$(Split-Path -Leaf $p) is the live activity log - export to another file." }
    }
    return @(Get-LedgerRows $Ledger)
}

function Write-LedgerCsv($Rows, [string[]]$Columns, [string]$Destination) {
    if (@($Rows).Count) {
        $Rows | Select-Object $Columns | Export-Csv -LiteralPath $Destination -NoTypeInformation -Encoding UTF8
    } else {
        # Export-Csv of nothing writes a 0-byte file with no header.
        [IO.File]::WriteAllText($Destination, '"' + ($Columns -join '","') + '"' + "`r`n", (New-Object Text.UTF8Encoding($true)))
    }
}

function Export-ActivityLog([string]$Ledger, [string]$Destination) {
    # A copy to hand over: .csv for Excel (every column), .txt to read.
    $rows = @(Get-LedgerExportRows $Ledger $Destination)
    if ($Destination -match '\.txt$') {
        $head = @('EVTXER - activity log',
                  "Exported $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') on $env:COMPUTERNAME by $env:USERDOMAIN\$env:USERNAME - $($rows.Count) action(s)",
                  '')
        [IO.File]::WriteAllLines($Destination, [string[]]($head + (Format-LedgerText $rows)), (New-Object Text.UTF8Encoding($true)))
    } else {
        Write-LedgerCsv $rows $script:LedgerColumns $Destination
    }
    return $rows.Count
}

# The network log: the activity log re-shaped, one row per
# action that went over the network - a scan, a conversion or a local archive
# touched no target and stays in the full log only.
$script:NetworkLogColumns = @('Date / time', 'Target IP', 'Command run', 'Success', 'Pulled / sent', 'Duration', 'Notes')

function ConvertTo-NetworkLogRow($r) {
    # $null for a row that never left this machine. Each command says what the
    # code really runs for that action - this is an accountability record.
    $t = $r.Target; $p = $r.Port; $as = $(if ($r.Account) { ", as $($r.Account)" } else { '' })
    if ($r.Action -eq 'EVTX archive') {
        if ($r.Protocol -ne 'SMB') { return $null }
        # Output is the zip, or the share when no zip was made (a failure).
        $share = if ($r.Output -match '\.zip$') { Split-Path $r.Output } else { $r.Output }
        $t = ConvertTo-LedgerCell $(if ($r.Output -match '^\\\\([^\\]+)') { $Matches[1] } else { '' })
        $cmd = "zip the host folder onto $share as .partial, read it back to check SHA-256, rename it (SMB 445)"
    } elseif ($r.Action -eq 'Rules update') {
        if ($r.Protocol -notlike 'HTTPS*') { return $null }
        $t = 'github.com'; $cmd = 'hayabusa update-rules (git clone of Yamato-Security/hayabusa-rules, HTTPS 443)'
    } elseif (-not $p) {
        return $null
    } else {
        $cmd = switch ($r.Action) {
            'Port test'         { "TCP connect to ${t}:$p ($($r.Protocol))" }
            'Verify access'     { if ($r.Protocol -eq 'SMB') { "list and read \\$t\C$\Windows\System32\winevt\Logs (SMB $p$as)" }
                                  else { "WinRM session to ${t}: wevtutil gli Security, copy a test file back ($($r.Protocol) $p$as)" } }
            'Collect'           { if ($r.Protocol -eq 'SMB') { "copy the selected .evtx from \\$t\C$\Windows\System32\winevt\Logs (SMB $p$as)" }
                                  else { "WinRM session to ${t}: wevtutil epl the selected logs, pull them back (one zip when small enough, else file by file), delete the copies ($($r.Protocol) $p$as)" } }
            'Verify connection' { "GET https://${t}:$p/ and /_cluster/health (Elasticsearch$as)" }
            'Upload'            { "PUT https://${t}:$p/_index_template/hayabusa-evtx, then POST /_bulk (create) into index $($r.Output) (Elasticsearch$as)" }
            'Delete index'      { "DELETE https://${t}:$p/$($r.Output) (Elasticsearch$as)" }
            'SO host key read'  { "plink ${t}:$p - read the SSH host key only" }
            'Certificate fetch' { "TLS handshake to ${t}:$p - read the certificate's SHA-256 fingerprint only ($($r.Protocol))" }
            'SO import test'    { "plink ${t}:$p - log in, sudo, look for so-import-evtx$as" }
            'SO import'         { "pscp EVTX to ${t}:$p, sudo so-import-evtx, delete the copies$as" }
            default             { "$($r.Action) ${t}:$p ($($r.Protocol))" }
        }
    }
    $ok = $r.Result -in 'Success', 'OK', 'Open'
    $left = if ($r.LeftOnTarget) { "left on target: $($r.LeftOnTarget)" }
    # The ledger writes mm:ss under an hour, which Excel reads as h:mm.
    $took = if ($r.Duration -match '^\d+:\d\d$') { "0:$($r.Duration)" } else { $r.Duration }
    [pscustomobject][ordered]@{
        'Date / time'   = "$($r.Date) $($r.Time)"
        'Target IP'     = $t
        'Command run'   = $cmd
        'Success'       = $(if ($ok) { 'Yes' } elseif ($r.Result -eq 'Partial') { 'Partial' } else { 'No' })
        'Pulled / sent' = (@($r.Files, $r.Size) | Where-Object { $_ }) -join ', '
        'Duration'      = $took
        'Notes'         = (@($(if (-not $ok) { $r.Result }), $r.Integrity, $left, $r.Details) | Where-Object { $_ }) -join ' - '
    }
}

function Export-NetworkLog([string]$Ledger, [string]$Destination) {
    $rows = @(Get-LedgerExportRows $Ledger $Destination | ForEach-Object { ConvertTo-NetworkLogRow $_ } | Where-Object { $_ })
    Write-LedgerCsv $rows $script:NetworkLogColumns $Destination
    return $rows.Count
}

function Add-LedgerRows([object[]]$Rows, [string]$Path) {
    # Appends, never rewrites: a ledger that is regenerated can lose history.
    # Excel locks an open CSV against writers, and an operator WILL have it
    # open - so a refused write goes to a pending file beside it, and the next
    # write that gets through folds those rows back in, in order.
    $lines = @(@($Rows) | Select-Object $script:LedgerColumns | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1)
    $pending = Get-LedgerPendingPath $Path
    $carried = @()
    if (Test-Path -LiteralPath $pending) {
        try { $carried = @(Get-Content -LiteralPath $pending -Encoding UTF8 | Select-Object -Skip 1 | Where-Object { $_ }) } catch { }
    }
    $header = '"' + ($script:LedgerColumns -join '","') + '"'
    $write = {
        param($File, [string[]]$Body)
        $isNew = -not (Test-Path -LiteralPath $File) -or (Get-Item -LiteralPath $File).Length -eq 0
        # FileShare.Read: anyone may look while we write; nobody may write too.
        $fs = [IO.File]::Open($File, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        try {
            # BOM on a new file only - Excel needs it to read UTF-8 names, and
            # one in the middle of the file would land in a cell.
            $sw = New-Object IO.StreamWriter($fs, (New-Object Text.UTF8Encoding($isNew)))
            if ($isNew) { $sw.WriteLine($header) }
            foreach ($l in $Body) { $sw.WriteLine($l) }
            $sw.Flush()
        } finally { $fs.Dispose() }
    }
    New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($Path)) -Force -ErrorAction SilentlyContinue | Out-Null
    try {
        & $write $Path (@($carried) + @($lines))
        if ($carried.Count) { Remove-Item -LiteralPath $pending -Force -ErrorAction SilentlyContinue }
        return [pscustomobject]@{ Path = $Path; Pending = $false }
    } catch [IO.IOException] {
        & $write $pending $lines
        return [pscustomobject]@{ Path = $pending; Pending = $true }
    }
}

function Get-TargetsLabel([string[]]$Targets) {
    # The Upload tab's case label from what was collected: one target is the
    # label, several IPs are their range plus a count (a bare range would claim
    # the hosts in between), several names are the first plus a count.
    $t = @($Targets | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Sort-Object -Unique)
    if ($t.Count -eq 0) { return '' }
    if ($t.Count -eq 1) { return (ConvertTo-IndexLabel $t[0]) }
    # Dotted quads only: Test-IsIpLiteral also takes IPv6, which neither sorts
    # as a [version] nor has a last octet.
    $ips = @($t | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
    if ($ips.Count -eq $t.Count) {
        $sorted = @($ips | Sort-Object { [version]$_ })
        $lo = $sorted[0]; $hi = $sorted[-1]
        $loNet = $lo.Substring(0, $lo.LastIndexOf('.')); $hiNet = $hi.Substring(0, $hi.LastIndexOf('.'))
        $range = if ($loNet -eq $hiNet) { "$lo-$($hi.Substring($hi.LastIndexOf('.') + 1))" } else { "$lo-$hi" }
        return (ConvertTo-IndexLabel "$range-$($t.Count)hosts")
    }
    $first = @($t | Sort-Object)[0]
    return (ConvertTo-IndexLabel "$first-and-$($t.Count - 1)-more")
}

function Get-HayabusaCoverage([string]$Text) {
    # Hayabusa's own summary line, e.g.
    #   Events with hits / Total events: 3,140 / 7,053 (Data reduction: 3,913 events (55.48%))
    # Only events that matched a rule are output. Stated after every scan, so
    # nobody takes the upload for every record in the logs.
    $m = [regex]::Match("$Text", 'Events with hits / Total events:\s*([\d,]+)\s*/\s*([\d,]+)')
    if (-not $m.Success) { return $null }
    $hits  = [long]($m.Groups[1].Value -replace ',', '')
    $total = [long]($m.Groups[2].Value -replace ',', '')
    $pct   = if ($total -gt 0) { [Math]::Round(100.0 * $hits / $total, 1) } else { 0 }
    [pscustomobject]@{
        Hits = $hits; Total = $total; Percent = $pct
        Text = ('{0:N0} of {1:N0} event records matched a rule ({2}%)' -f $hits, $total, $pct)
    }
}

# ---------------------------------------------------------------- archive ---
# The Settings tab's Archive: each collected host folder becomes ONE zip in the
# archive folder (local, or \\server\share - whatever this Windows login can
# reach in Explorer; no credentials are stored). It holds the raw .evtx and the
# folder's manifest.json, their SHA-256 record from the collection - nothing
# else lives in a host folder. Hayabusa/ECS output is never archived.
#
# Written as <zip>.partial, every file hashed on the way in, then re-read and
# every entry re-hashed; only a zip that matches gets its real name, and only
# then is the source deleted. A failure or Cancel at any point deletes the
# .partial and leaves the source untouched.
#
# .NET's ZipArchive, not Compress-Archive: the latter stops at 2 GB in
# PowerShell 5.1 and cannot be cancelled or report progress.

function Get-ArchiveFiles([string]$Folder) {
    # What goes into a host folder's zip. *.evtx by extension, not -Filter: a
    # half-copied "x.evtx.partial" must never be archived and then deleted.
    @(Get-ChildItem -LiteralPath (ConvertTo-LongPath $Folder) -Recurse -File -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Extension -eq '.evtx' -or $_.Name -eq 'manifest.json' } | Sort-Object FullName)
}

function Get-ArchiveCandidates([string]$EvtxRoot) {
    # The host folders under the drop folder that hold .evtx - one per
    # collected host (HOST_yyyyMMdd_HHmmss). Loose .evtx at the top level
    # belong to no host and are not offered.
    if (-not $EvtxRoot -or -not (Test-Path -LiteralPath $EvtxRoot)) { return @() }
    @(foreach ($d in Get-ChildItem -LiteralPath $EvtxRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name) {
        if ($d.Name -eq $script:UnzipStagingName) { continue }
        $evtx = @(Get-ArchiveFiles $d.FullName | Where-Object { $_.Extension -eq '.evtx' })
        if (-not $evtx.Count) { continue }
        $bytes = [long]($evtx | Measure-Object Length -Sum).Sum
        [pscustomobject]@{
            Name = $d.Name; Path = $d.FullName; Files = $evtx.Count; Bytes = $bytes
            Label = "$($d.Name)   -   $($evtx.Count) .evtx, $(Format-ByteSize $bytes)"
        }
    })
}

function Get-QueueFolderChoices([string]$Path) {
    # A folder picked with the queue's "From another folder..." (owner,
    # 2026-10-27: EVTX in more than one place, without moving the drop
    # folder). A folder holding .evtx itself is one machine and is offered as
    # it is; otherwise its machine subfolders, as the drop folder offers them.
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }
    if (@(Get-ChildItem -LiteralPath $Path -Filter *.evtx -File -ErrorAction SilentlyContinue).Count) {
        $evtx = @(Get-ArchiveFiles $Path | Where-Object { $_.Extension -eq '.evtx' })
        $bytes = [long]($evtx | Measure-Object Length -Sum).Sum
        $name = Split-Path -Leaf $Path
        return @([pscustomobject]@{
            Name = $name; Path = $Path; Files = $evtx.Count; Bytes = $bytes
            Label = "$name   -   $($evtx.Count) .evtx, $(Format-ByteSize $bytes)   ($Path)"
        })
    }
    return @(Get-ArchiveCandidates $Path | ForEach-Object { $_.Label += "   ($(Split-Path -Parent $_.Path))"; $_ })
}

function Get-ArchiveZipPath([string]$ArchiveRoot, [string]$Name) {
    # HOST.zip, or HOST-2.zip when the host was archived before: an archive is
    # evidence and is never overwritten.
    $path = Join-Path $ArchiveRoot "$Name.zip"
    $i = 1
    while ((Test-Path -LiteralPath $path) -or (Test-Path -LiteralPath "$path.partial")) {
        $i++
        $path = Join-Path $ArchiveRoot "$Name-$i.zip"
    }
    return $path
}

function Get-StreamSha256([IO.Stream]$Stream, [byte[]]$Buffer, [hashtable]$Progress, [IO.Stream]$CopyTo) {
    # The stream's SHA-256, read to the end - and, with -CopyTo, written there
    # on the way, so a file is hashed by the same read that archives it.
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        while (($n = $Stream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
            if ($Progress -and $Progress.Cancel) { throw 'Cancelled by the operator.' }
            [void]$sha.TransformBlock($Buffer, 0, $n, $null, 0)
            if ($CopyTo) { $CopyTo.Write($Buffer, 0, $n) }
            if ($Progress) { $Progress.Done += $n }
        }
        [void]$sha.TransformFinalBlock($Buffer, 0, 0)
        return [BitConverter]::ToString($sha.Hash).Replace('-', '')
    } finally { $sha.Dispose() }
}

function Test-EvtxArchive([string]$ZipPath, [hashtable]$Expected, [hashtable]$Progress) {
    # '' when the zip holds exactly the expected entries with the expected
    # SHA-256, otherwise why not. Reads every byte back through the zip reader,
    # so a truncated write or a corrupt deflate stream fails here.
    Add-Type -AssemblyName System.IO.Compression
    $buf = New-Object byte[] (1MB)
    $fs = [IO.File]::Open((ConvertTo-LongPath $ZipPath), 'Open', 'Read', 'Read')
    try {
        $za = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Read)
        try {
            $seen = @{}
            foreach ($e in $za.Entries) {
                if (-not $Expected.ContainsKey($e.FullName)) { return "unexpected entry $($e.FullName)" }
                $s = $e.Open()
                try { $h = Get-StreamSha256 $s $buf $Progress } finally { $s.Dispose() }
                if ($h -ne $Expected[$e.FullName]) { return "$($e.FullName) does not match its source (SHA-256)" }
                $seen[$e.FullName] = $true
            }
            foreach ($k in $Expected.Keys) { if (-not $seen.ContainsKey($k)) { return "$k is missing from the zip" } }
            return ''
        } finally { $za.Dispose() }
    } catch [System.IO.InvalidDataException] {
        return "the zip is corrupt: $($_.Exception.Message)"
    } finally { $fs.Dispose() }
}

function Move-FileWithRetry([string]$Path, [string]$Destination, [int]$Tries = 5, [int]$DelayMs = 200) {
    # An antivirus or sync client can still hold a file it saw being written
    # for a moment after it closes. A rename that fails then would make the
    # caller throw away a zip that took minutes to build and verify.
    for ($i = 1; ; $i++) {
        try { Move-Item -LiteralPath $Path -Destination $Destination -ErrorAction Stop; return }
        catch { if ($i -ge $Tries) { throw }; Start-Sleep -Milliseconds $DelayMs }
    }
}

function Compress-EvtxFolder {
    # One host folder -> one verified zip in $ArchiveRoot, then the source is
    # deleted. Runs in a background runspace (Start-LibJob); $Progress carries
    # Cancel in and Total/Done/Step out.
    param([string]$Folder, [string]$ArchiveRoot, [hashtable]$Progress, [scriptblock]$LogWriter)
    Add-Type -AssemblyName System.IO.Compression
    if (-not $Progress)  { $Progress = @{ Cancel = $false } }
    if (-not $LogWriter) { $LogWriter = { param($m) } }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $src = (Get-Item -LiteralPath $Folder -ErrorAction Stop).FullName.TrimEnd('\')
    $files = @(Get-ArchiveFiles $src)
    $evtx  = @($files | Where-Object { $_.Extension -eq '.evtx' })
    if (-not $evtx.Count) { throw "no .evtx files in $src" }
    $full = [IO.Path]::GetFullPath($ArchiveRoot).TrimEnd('\')
    if (($full + '\').StartsWith($src + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "the archive folder is inside $src - it would be deleted with it"
    }
    New-Item -ItemType Directory -Path $ArchiveRoot -Force -ErrorAction Stop | Out-Null
    $zip  = Get-ArchiveZipPath $ArchiveRoot (Split-Path -Leaf $src)
    $part = "$zip.partial"
    $total = [long]($files | Measure-Object Length -Sum).Sum
    # Read twice: once into the zip, once back out of it.
    $Progress.Total = 2 * $total; $Progress.Done = [long]0
    $longSrc = ConvertTo-LongPath $src
    $hashes = @{}
    $buf = New-Object byte[] (1MB)
    & $LogWriter "  [..] $($evtx.Count) .evtx ($(Format-ByteSize $total)) -> $part"
    try {
        $Progress.Step = 'compressing'
        $fs = [IO.File]::Open((ConvertTo-LongPath $part), 'CreateNew', 'Write', 'None')
        try {
            $za = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Create)
            try {
                foreach ($f in $files) {
                    $name = $f.FullName.Substring($longSrc.Length).TrimStart('\').Replace('\', '/')
                    $entry = $za.CreateEntry($name, [IO.Compression.CompressionLevel]::Optimal)
                    $entry.LastWriteTime = $f.LastWriteTime
                    $in = $null; $out = $null
                    try {
                        $in  = [IO.File]::Open($f.FullName, 'Open', 'Read', 'Read')
                        $out = $entry.Open()
                        $hashes[$name] = Get-StreamSha256 $in $buf $Progress $out
                    } finally {
                        if ($out) { $out.Dispose() }
                        if ($in)  { $in.Dispose() }
                    }
                }
            } finally { $za.Dispose() }
        } finally { $fs.Dispose() }

        $Progress.Step = 'verifying'
        $bad = Test-EvtxArchive $part $hashes $Progress
        if ($bad) { throw "verification failed - $bad" }
        Move-FileWithRetry $part $zip
    } catch {
        Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
        throw
    }
    $zipBytes = (Get-Item -LiteralPath $zip).Length
    & $LogWriter "  [OK] $zip ($(Format-ByteSize $zipBytes)) - $($files.Count) file(s) verified by SHA-256"

    # The zip is verified, so the source can go. Only the files that went into
    # it, and only if each is still the file that was hashed: one rewritten
    # since (a second instance, a hand edit) has only its OLD copy in the zip.
    # The folders go one by one and only when empty, so nothing added since
    # the snapshot is swept away with them.
    $Progress.Step = 'removing the source'
    $left = @()
    foreach ($f in $files) {
        try {
            $now = [IO.FileInfo]$f.FullName
            if ($now.Length -ne $f.Length -or $now.LastWriteTimeUtc -ne $f.LastWriteTimeUtc) { $left += "$($f.Name) (changed since it was archived)"; continue }
            Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
        } catch { $left += $f.Name }
    }
    $dirs = @(Get-ChildItem -LiteralPath $longSrc -Recurse -Directory -Force -ErrorAction SilentlyContinue |
              Sort-Object { $_.FullName.Length } -Descending | ForEach-Object FullName) + @($longSrc)
    foreach ($d in $dirs) { try { [IO.Directory]::Delete($d, $false) } catch { } }
    if ($left) { & $LogWriter "  [!!] Could not delete from $src (in use?): $($left -join ', ')" }
    else       { & $LogWriter "  [OK] Source removed: $src" }
    [pscustomobject]@{
        Folder = $src; Zip = $zip; Files = $evtx.Count; Bytes = $total; ZipBytes = [long]$zipBytes
        Left = $left; Seconds = $clock.Elapsed.TotalSeconds
    }
}

function Start-LibJob {
    # Runs one function in a background runspace, so the window keeps pumping.
    # -LogWriter lines arrive in .Lines, -Progress is shared (Cancel in,
    # anything the function sets out). The collection, the Archive button and
    # the job queue all run through here. -Script is what the runspace loads
    # first: this lib, or the collector (which loads the lib itself).
    # -Progress is passed in when the caller must put something there before
    # the runspace starts reading it (a test's Cancel, the collector's
    # HostDone queue).
    param([string]$Command, [hashtable]$Parameters, [string]$Script = $script:HayabusaLibPath, [hashtable]$Progress)
    $lines    = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
    $progress = if ($Progress) { $Progress } else { [hashtable]::Synchronized(@{ Cancel = $false }) }
    $ps = [powershell]::Create()
    $null = $ps.AddScript({
        param($LibPath, $Command, $Parameters, $Lines, $Progress)
        . $LibPath
        $Parameters.LogWriter = { param($m) $Lines.Enqueue([string]$m) }.GetNewClosure()
        $Parameters.Progress  = $Progress
        & $Command @Parameters
    }).AddArgument($Script).AddArgument($Command).AddArgument($Parameters).AddArgument($lines).AddArgument($progress)
    [pscustomobject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke(); Lines = $lines; Progress = $progress }
}
function Complete-LibJob($Job) {
    # The function's result; an error inside the runspace is thrown here, as a
    # direct call would have thrown it.
    try { return (@($Job.PowerShell.EndInvoke($Job.Handle)) | Select-Object -Last 1) }
    finally { $Job.PowerShell.Dispose() }
}

# ------------------------------------------------------- accountability PCAP ---
# Before the tool touches the network, the
# operator should be capturing their own traffic, so every packet the mission
# sent can be shown afterwards. Wireshark's dumpcap does the capture; EVTXER
# only starts it, notices when one is already running, and reminds.
# Decided 2026-10-16: keep every file (rolling files, never a ring buffer) and
# warn on low space; try dumpcap as the user and elevate only if Npcap
# refuses. The capture is its own process and outlives EVTXER.

function Find-Dumpcap([string]$WiresharkFolder) {
    foreach ($d in @($WiresharkFolder, (Join-Path $env:ProgramFiles 'Wireshark'), (Join-Path ${env:ProgramFiles(x86)} 'Wireshark'))) {
        if (-not $d) { continue }
        $exe = Join-Path $d 'dumpcap.exe'
        if (Test-Path -LiteralPath $exe) { return $exe }
    }
    return ''
}

function ConvertFrom-DumpcapInterfaces([string[]]$Lines) {
    # dumpcap -D: "5. \Device\NPF_{6B65...} (Wi-Fi)". The device is what -i
    # takes; the name in brackets is what a person recognises.
    @(foreach ($l in $Lines) {
        $m = [regex]::Match("$l", '^\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?\s*$')
        if (-not $m.Success) { continue }
        $name = if ($m.Groups[3].Success -and $m.Groups[3].Value) { $m.Groups[3].Value } else { $m.Groups[2].Value }
        [pscustomobject]@{ Device = $m.Groups[2].Value; Name = $name; Label = "$name   ($($m.Groups[2].Value))" }
    })
}

function Get-DumpcapArgs {
    # Rolling files of $FileSizeMB each (3 GB), and no files: limit - every file is
    # kept (a ring buffer would overwrite the start of the mission).
    param([string]$Interface, [string]$OutFolder, [datetime]$Now = (Get-Date), [int]$FileSizeMB = 3072)
    $file = Join-Path $OutFolder ("evtxer_{0}_{1:yyyyMMdd_HHmmss}.pcapng" -f $env:COMPUTERNAME, $Now)
    return @('-i', $Interface, '-b', "filesize:$($FileSizeMB * 1024)", '-w', $file, '-q')
}

function ConvertFrom-DumpcapCommandLine([string]$CommandLine) {
    # What a running dumpcap is capturing, read from its own command line:
    # every -i and the -w file. Quoted or not. Helper: one of Wireshark's
    # dumpcaps that records nothing - -D/-L list interfaces, -S feeds the
    # welcome page's sparklines for as long as that page is open (review,
    # 2026-10-18: counted as captures, they turned the PCAP pill red).
    $tok = [regex]::Matches("$CommandLine", '"([^"]*)"|(\S+)') | ForEach-Object { if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value } }
    $ifaces = @(); $file = ''; $helper = $false
    for ($i = 0; $i -lt $tok.Count; $i++) {
        if ($tok[$i] -eq '-i' -and $i + 1 -lt $tok.Count) { $ifaces += $tok[$i + 1]; $i++ }
        elseif ($tok[$i] -eq '-w' -and $i + 1 -lt $tok.Count) { $file = $tok[$i + 1]; $i++ }
        elseif ($tok[$i] -cmatch '^(-[SDL]|--list-.*)$') { $helper = $true }
    }
    [pscustomobject]@{ Interfaces = $ifaces; File = $file; Helper = $helper }
}

function Get-RunningCaptures {
    # Every dumpcap on this machine - started by EVTXER, by Wireshark or by
    # hand - with what it is capturing. An elevated one shows no command line
    # to a normal user; it is still reported, as capturing "(unknown)".
    # IsViewer: the one under EVTXER's own Wireshark viewer (Test-ViewerCapture)
    # - it records nothing to keep, so it is not THE capture.
    @(Get-CimInstance Win32_Process -Filter "Name='dumpcap.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
        $c = ConvertFrom-DumpcapCommandLine $_.CommandLine
        if ($c.Helper) { return }
        [pscustomobject]@{ ProcessId = $_.ProcessId; Interfaces = $c.Interfaces; File = $c.File
                           CommandLine = "$($_.CommandLine)"; IsViewer = (Test-ViewerCapture $c.File) }
    })
}

# The live viewer ("it would be good if it did [start the
# Wireshark GUI], we'd have a visual confirmation it's working"). dumpcap still
# makes THE recording - it keeps going when a window is closed, and the
# Wireshark window holds every packet in memory, which a long mission would
# fill. The viewer is Wireshark on the same interface writing a small ring
# (2 x 5 MB) in the temp folder, so it shows the traffic live and stays small.
$script:ViewerFolder = Join-Path ([IO.Path]::GetTempPath()) 'EVTXER-viewer'

function Find-Wireshark([string]$WiresharkFolder) {
    $dumpcap = Find-Dumpcap $WiresharkFolder
    if (-not $dumpcap) { return '' }
    $exe = Join-Path (Split-Path -Parent $dumpcap) 'Wireshark.exe'
    if (Test-Path -LiteralPath $exe) { return $exe }
    return ''
}

function Get-WiresharkViewerArgs([string]$Interface) {
    return @('-i', $Interface, '-k', '-b', 'filesize:5120', '-b', 'files:2',
             '-w', (Join-Path $script:ViewerFolder 'evtxer-live-view.pcapng'))
}

function Test-ViewerCapture([string]$File) {
    return ("$File" -like '*evtxer-live-view*')
}

function Get-PcapPill([object[]]$Captures) {
    # The title-row pill beside "Things are cookin'": is
    # the accountability PCAP recording? $Captures is Get-RunningCaptures, so
    # it is what the machine runs, not what EVTXER remembers starting. The
    # viewer records nothing to keep and does not count.
    $rec = @($Captures | Where-Object { $_ -and -not $_.IsViewer })
    if (-not $rec.Count) {
        return [pscustomobject]@{ On = $false; Text = 'No PCAP'
                                  Tip = 'No accountability capture is running. Click to start one on the Settings tab.' }
    }
    $tip = @($rec | ForEach-Object {
        if ($_.File) { "dumpcap pid $($_.ProcessId) -> $($_.File)" }
        elseif ($_.CommandLine) { "dumpcap pid $($_.ProcessId) - a Wireshark capture to a temporary file" }
        else { "dumpcap pid $($_.ProcessId) - started elevated, so its file cannot be read" }
    }) -join "`n"
    return [pscustomobject]@{ On = $true; Text = 'PCAP rolling'; Tip = $tip }
}

function Get-ReadinessPills {
    # The pills before the PCAP one: is each part of the
    # mission set up? Green when it is, grey when not; the tip says what to
    # do. The same facts the queue waits on.
    param([string]$MissionName, [string]$MissionIndex, [bool]$ElkOk, [string]$ElkHost, [bool]$SoReady, [string]$SoHost)
    $pill = { param($Key, $On, $Text, $Tip) [pscustomobject]@{ Key = $Key; On = [bool]$On; Text = $Text; Tip = $Tip } }
    @(
        if ($MissionIndex) { & $pill Mission $true "Mission: $MissionName" "Uploads go into $MissionIndex." }
        else { & $pill Mission $false 'No mission' 'Name the mission on the Settings tab - uploads wait for it.' }
        if ($ElkOk) { & $pill Elk $true 'ELK connected' "Verified: $ElkHost. Uploads can run." }
        else { & $pill Elk $false 'ELK not verified' 'Press VERIFY CONNECTIVITY on the Upload tab - uploads wait for it.' }
        if ($SoReady) { & $pill So $true 'SO ready' "$SoHost, filled in on the Raw Events tab. The login itself is checked when an import runs." }
        else { & $pill So $false 'SO not set' 'Fill in the Raw Events tab - host, user, password, host key. Only needed for raw imports.' }
    )
}

function Get-WhereToLook([ValidateSet('detections', 'raw')][string]$Kind) {
    # Said after an upload or a raw import (which data
    # shows in Security Onion and which only in Kibana was not obvious).
    if ($Kind -eq 'detections') {
        return "Where to look: Kibana - Discover, or the Hayabusa dashboards (Dashboards tab). Detections are in their own index, so not in Security Onion's Hunt or Alerts."
    }
    return "Where to look: Security Onion's Hunt and Dashboards, and Kibana's Raw Events dashboards."
}

# ------------------------------------------------------------------ guide ---
# The Guide tab (owner, 2026-10-26): a cheat sheet for the crew - a short
# answer to each thing that is not obvious - and one search over it and the
# whole README.txt, which stays the full manual. Each entry's Chapter is a
# README heading (Guide.Tests checks every one exists). Plain ASCII only:
# PowerShell 5.1 reads this BOM-less file in the ANSI code page.
function Get-ReadmeChapters([string]$Text) {
    # A chapter is a heading line underlined with dashes, up to the next one.
    $lines = $Text -split "\r?\n"
    $heads = @(for ($i = 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^-{4,}$' -and $lines[$i - 1].Trim()) { $i - 1 }
    })
    @(for ($k = 0; $k -lt $heads.Count; $k++) {
        $to = if ($k + 1 -lt $heads.Count) { $heads[$k + 1] - 1 } else { $lines.Count - 1 }
        [pscustomobject]@{ Title = $lines[$heads[$k]].Trim(); Body = ($lines[$heads[$k]..$to] -join "`r`n").TrimEnd() }
    })
}

function Get-SearchWords([string]$Query) {
    return @("$Query".ToLowerInvariant() -split '\s+' | Where-Object { $_ })
}

function Test-GuideMatch($Entry, [string]$Query) {
    # Every word, any case, somewhere in the entry.
    $hay = "$($Entry.Group) $($Entry.Title) $($Entry.Answer)".ToLowerInvariant()
    foreach ($w in Get-SearchWords $Query) { if (-not $hay.Contains($w)) { return $false } }
    return $true
}

function Find-ReadmeChapters([object[]]$Chapters, [string]$Query) {
    # The chapters holding every word, the most matches first.
    $words = Get-SearchWords $Query
    if (-not $words.Count) { return @() }
    $hits = @(foreach ($c in $Chapters) {
        $low = $c.Body.ToLowerInvariant(); $n = 0
        foreach ($w in $words) {
            $m = [regex]::Matches($low, [regex]::Escape($w)).Count
            if (-not $m) { $n = 0; break }
            $n += $m
        }
        if ($n) { [pscustomobject]@{ Title = $c.Title; Count = $n; Label = "$($c.Title)   -   $n match$(if ($n -ne 1) { 'es' })" } }
    })
    return @($hits | Sort-Object @{ Expression = 'Count'; Descending = $true }, Title)
}

function Get-GuideEntries {
    $e = { param($Group, $Chapter, $Title, $Answer) [pscustomobject]@{ Group = $Group; Chapter = $Chapter; Title = $Title; Answer = $Answer; More = "More: $Chapter" } }
    $find = 'FINDING THINGS: TIME, PIVOTS, WHERE DATA LANDS'
    $raw = 'EVERY RAW EVENT, NOT JUST DETECTIONS (SECURITY ONION)'
    @(
        & $e 'Times' $find 'When did a raw event really happen? (Security Onion)' (
            'Security Onion 2.4 files raw imports under the time of the IMPORT: @timestamp is when you imported. ' +
            "The event's own time is event.created. In Hunt or Dashboards: set the time range to cover the import, " +
            'add the event.created column and sort by it. In Kibana: the Raw Events dashboards, or Discover with the ' +
            'data view "Raw Windows events (Security Onion)" - its time field is event.created.')
        & $e 'Times' $find 'Are the times on Hayabusa detections right?' (
            "Yes. A detection's @timestamp is when the event happened on the machine, in UTC. Kibana shows it in " +
            "your browser's time zone.")
        & $e 'Pivoting' $find 'How do I get from a detection to the full log?' (
            'Take three fields from the detection: host.name, winlog.channel and winlog.record_id. Search the raw ' +
            'events (Security Onion Hunt, or Kibana Discover) for:  winlog.computer_name:"WS01" AND ' +
            'winlog.channel:"Security" AND winlog.record_id:12345   AND in capitals: Security Onion reads a ' +
            'lower-case "and" as a word to find. Values are case-sensitive - type them as the ' +
            'detection shows them. The logs must have been raw-imported first.')
        & $e 'Pivoting' $find 'Why does a detection not show the whole event?' (
            'Hayabusa sends only what a rule matched: the matched events, with the fields Hayabusa extracts ' +
            '(winlog.event_data.*, hayabusa.details). The whole event, and every event no rule matched, is only ' +
            "in the raw import - Raw Events tab, or the queue's Raw import to SO.")
        & $e 'Where data lands' $find "Why are my detections not in Security Onion's Hunt or Alerts?" (
            'Detections go into their own index, hayabusa-mission-<mission name>, so they can be dropped cleanly. ' +
            "Hunt and Alerts search only Security Onion's own indices. Look in Kibana: Discover, or the Hayabusa " +
            'dashboards (the Dashboards tab imports them).')
        & $e 'Where data lands' $find 'Where do raw events land?' (
            "In Security Onion's own logs-import-so data stream: Hunt, Dashboards, and Kibana's Raw Events " +
            'dashboards. Security Onion only - a plain Elastic stack has no importer, so only detections go there.')
        & $e 'Where data lands' 'THINGS WORTH KNOWING' 'Which EVTXER version made a detection?' (
            'agent.version on every detection EVTXER converts (from v72); event.ingested says when it was ' +
            'converted. In Kibana: agent.version : 72')
        & $e 'Duplicates' 'THINGS WORTH KNOWING' 'What if I upload the same logs to ELK twice?' (
            'Nothing doubles. Every detection has a fixed id (event.id); one already in the index is counted as ' +
            "'already there' and skipped, so a re-pull adds only new detections. One exception: a rules update " +
            'that renamed a rule brings its old detections back under the new title.')
        & $e 'Duplicates' $raw 'What if I raw-import the same logs twice?' (
            'An identical file is skipped - Security Onion knows files by content (MD5). But the same machine ' +
            'pulled on two days is two different files, and the events they share are imported twice. Queue only ' +
            'the newest folder of each machine.')
        & $e 'Disk' $raw "What does 'LOW DISK on the manager' mean?" (
            'Checked once per raw import: /tmp cannot hold the files, or /nsm would pass 85% full (Security Onion ' +
            'keeps a copy of the files and indexes every event - about 3x the EVTX). Elasticsearch refuses new ' +
            'data at 95%. A warning only - the import still runs. On the manager: df -h /tmp /nsm')
        & $e 'Queue and archive' 'ARCHIVE (SETTINGS TAB)' 'What does Archive delete?' (
            'For each host folder it zips the EVTX into the archive folder, reads every file back (SHA-256), and ' +
            'only then deletes that host folder from the EVTX drop folder. If the drop folder is your only copy - ' +
            'a share you want to keep - leave Archive unticked.')
        & $e 'Queue and archive' 'THE QUEUE (AUTOMATIC PROCESSING)' 'A queue row is amber - why?' (
            'Amber means waiting for you, and the row says what for: the mission name, VERIFY CONNECTIVITY, the ' +
            'Raw Events tab, a password, or the PCAP question. Fix that and the job carries on by itself.')
        & $e 'Queue and archive' 'THE QUEUE (AUTOMATIC PROCESSING)' 'How do I run 30+ machines?' (
            'Settings: point the EVTX drop folder at the folder whose subfolders are the machines. Tick the steps ' +
            'under QUEUE, then Add folders... and Select all. It runs one machine at a time, start to finish. For a ' +
            'second pass (raw import only, say): change the ticks, Clear done, Add folders... again.')
        & $e 'Passwords and PCAP' 'REMEMBERED PASSWORDS' 'Why did EVTXER forget my password?' (
            'A password is kept only when Remember is ticked, after a check that worked - encrypted for your ' +
            'Windows account on this machine. Otherwise it lasts until EVTXER closes, and after a restart the ' +
            'queue waits in amber for it.')
        & $e 'Passwords and PCAP' 'ACCOUNTABILITY PCAP (SETTINGS TAB)' 'The queue stopped after the PCAP question - why?' (
            'Closing that question means cancel: uploads and raw imports wait. Press Retry on the row to be ' +
            'asked again - then START CAPTURE, or Continue without capture.')
        & $e 'Connecting' 'SECURITY ONION: LETTING EVTXER IN' "VERIFY CONNECTIVITY says 'Nothing answered at ...:9200'?" (
            'If the host and port are right, Security Onion''s firewall is not letting this machine in - rare, ' +
            'it usually already is. The message itself names this machine''s IP and the command for the ' +
            'administrator to run on the manager: sudo so-firewall --apply includehost elasticsearch_rest <IP> ' +
            '(for 9200, uploads) or ... includehost analyst <IP> (for 443, the Kibana tab).')
        & $e 'Connecting' 'SECURITY ONION: LETTING EVTXER IN' 'We sign in with SSO - does EVTXER work?' (
            'EVTXER logs in with a username and password. If an SSO-only account is refused: uploads - an API ' +
            'key made in Kibana, Username left empty; dashboards - import kibana dashboards\' +
            'hayabusa-kibana-objects.ndjson by hand in Kibana (Stack Management > Saved Objects > Import); raw ' +
            'imports use an SSH account and are not affected.')
        & $e 'Mission and pills' 'MISSION (SETTINGS TAB)' 'What is the mission name for?' (
            'Every upload of the mission goes into one index, hayabusa-mission-<name>; uploads wait until it is ' +
            "named. 'Delete mission index...' removes just that index - rarely needed when the stack is rebuilt " +
            'after each mission.')
        & $e 'Mission and pills' 'THE EIGHT TABS' 'What do the pills at the top mean?' (
            'Mission, ELK, SO: green = set up, grey = not yet (SO is only needed for raw imports). PCAP: red with ' +
            'a pulsing dot = recording. Click one to open the tab that fixes it.')
    )
}

function Test-PcapReminderDue($Settings, [int]$RunningCount, [datetime]$Now = (Get-Date),
                              # Answered "continue without capture" already this
                              # session (once per session - the
                              # PCAP pill shows the state the rest of the time).
                              [switch]$AnsweredThisSession) {
    # Ask only when it can matter: the reminder is on, it was not put off
    # until a later day, nothing is capturing already, and it was not
    # already answered since EVTXER started.
    if ("$($Settings.PcapReminder)" -eq 'off') { return $false }
    if ($RunningCount -gt 0) { return $false }
    if ($AnsweredThisSession) { return $false }
    $until = [datetime]::MinValue
    if ([datetime]::TryParseExact("$($Settings.PcapSnoozeUntil)", 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture,
                                  [Globalization.DateTimeStyles]::None, [ref]$until) -and $Now.Date -lt $until) { return $false }
    return $true
}

function Get-PcapSnoozeDate([datetime]$Now = (Get-Date)) {
    # "Don't remind me until tomorrow": silent for the rest of today.
    return $Now.Date.AddDays(1).ToString('yyyy-MM-dd')
}

function Test-NpcapRefused([string]$Text) {
    # dumpcap's words when Npcap is installed admin-only and the user is not.
    return ("$Text" -match '(?i)access is denied|permission|administrator|npcap.*(not running|admin)|couldn''t run|you don''t have')
}

# ------------------------------------------------------ remembered passwords ---
# No password is stored "unless you can create a safe
# storage for it". This is that, and only that - not a password manager:
# opt-in, per connection, encrypted with Windows' DPAPI for the CURRENT USER.
# The file is useless to another Windows account, on another machine, or
# copied anywhere. It lives in the user's own profile (%LOCALAPPDATA%), never
# in the tool folder, so deployment copies and handoff packages cannot carry
# it. One file per kind|host|user, named by a hash so the folder does not even
# list which servers were used.
$script:SecretFolder = Join-Path $env:LOCALAPPDATA 'EVTXER\secrets'

function Get-SecretPath([string]$Kind, [string]$HostName, [string]$User, [string]$Folder = $script:SecretFolder) {
    $id = "$Kind|$("$HostName".Trim().ToLowerInvariant())|$("$User".Trim())"
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($id))) -replace '-', '').Substring(0, 32) }
    finally { $sha.Dispose() }
    return (Join-Path $Folder "$h.dpapi")
}

function Save-RememberedSecret([string]$Kind, [string]$HostName, [string]$User, [string]$Secret, [string]$Folder = $script:SecretFolder) {
    Add-Type -AssemblyName System.Security
    New-Item -ItemType Directory -Path $Folder -Force | Out-Null
    $enc = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($Secret),
               [Text.Encoding]::UTF8.GetBytes("EVTXER|$Kind"), [Security.Cryptography.DataProtectionScope]::CurrentUser)
    [IO.File]::WriteAllText((Get-SecretPath $Kind $HostName $User $Folder), [Convert]::ToBase64String($enc))
}

function Get-RememberedSecret([string]$Kind, [string]$HostName, [string]$User, [string]$Folder = $script:SecretFolder) {
    # The secret, or $null - none stored, or stored by another Windows
    # account or on another machine (DPAPI refuses), or damaged.
    $path = Get-SecretPath $Kind $HostName $User $Folder
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        Add-Type -AssemblyName System.Security
        $plain = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String([IO.File]::ReadAllText($path).Trim()),
                     [Text.Encoding]::UTF8.GetBytes("EVTXER|$Kind"), [Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Text.Encoding]::UTF8.GetString($plain)
    } catch { return $null }
}

function Remove-RememberedSecret([string]$Kind, [string]$HostName, [string]$User, [string]$Folder = $script:SecretFolder) {
    Remove-Item -LiteralPath (Get-SecretPath $Kind $HostName $User $Folder) -Force -ErrorAction SilentlyContinue
}

# ------------------------------------------------------- one at a time ---
# One operator at a time per install. A second
# EVTXER on the same install - even from another RDP session - is refused and
# told who has it open. The mutex is Global\ so other sessions see it, and
# named after the install folder so two installs on one server do not block
# each other. Windows releases it when the process ends, crash included, so a
# dead EVTXER never locks the install. The lock file only says who.
function Get-InstanceMutexName([string]$AppRoot) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$AppRoot".TrimEnd('\').ToLowerInvariant()))) -replace '-', '').Substring(0, 24) }
    finally { $sha.Dispose() }
    return "Global\EVTXER-$h"
}

function Enter-SingleInstance([string]$AppRoot) {
    # Ok = this process now holds the install; otherwise Holder says who does.
    $lock = Join-Path $AppRoot 'evtxer.lock'
    $got = $false; $m = $null
    try {
        $m = New-Object System.Threading.Mutex($false, (Get-InstanceMutexName $AppRoot))
        try { $got = $m.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $got = $true }
    } catch [System.UnauthorizedAccessException] {
        # Created by another Windows account, which holds it now.
        $got = $false
    }
    if ($got) {
        try {
            [pscustomobject]@{ User = "$env:USERDOMAIN\$env:USERNAME"; Machine = $env:COMPUTERNAME; Pid = $PID
                               Since = (Get-Date).ToString('yyyy-MM-dd HH:mm') } | ConvertTo-Json -Compress |
                Set-Content -LiteralPath $lock -Encoding UTF8
        } catch { }
        return [pscustomobject]@{ Ok = $true; Mutex = $m; Holder = '' }
    }
    $holder = 'another operator'
    try {
        $l = Get-Content -LiteralPath $lock -Raw -ErrorAction Stop | ConvertFrom-Json
        $holder = "$($l.User) (since $($l.Since), process $($l.Pid))"
    } catch { }
    if ($m) { $m.Dispose() }
    return [pscustomobject]@{ Ok = $false; Mutex = $null; Holder = $holder }
}

# ------------------------------------------------- off-the-window runners ---
function Invoke-PumpedTool {
    # Invoke-ExternalTool's twin for code that runs OFF the window's thread
    # (the job queue): the same compiled pump, but the lines go to -LogWriter
    # and Cancel comes from the shared -Progress table. -1 when cancelled.
    # The parameters match Invoke-ExternalTool's, so Invoke-SoImport can hand
    # the same hashtable to either one.
    param([string]$Label, [string]$Exe, [string[]]$Arguments, [string]$WorkDir, [string]$Detail,
          [string]$StandardInput, [System.Collections.Generic.List[string]]$Capture, [string[]]$Mask,
          [switch]$NoCancel, [hashtable]$Progress, [scriptblock]$LogWriter,
          # Below-normal priority: a queued scan must not slow the operator's
          # own collection or the window.
          [switch]$Low)
    if (-not $WorkDir) { $WorkDir = Split-Path -Parent $Exe }
    Initialize-ProcessPump
    if ($LogWriter -and $Label) { & $LogWriter "> $Label $Detail" }
    $pump = New-Object EvtxerProcessPump($Exe, (ConvertTo-ProcessArgumentLine $Arguments), $WorkDir, $StandardInput)
    if ($Low) { try { (Get-Process -Id $pump.Id).PriorityClass = 'BelowNormal' } catch { } }
    $killed = $false
    try {
        while ($true) {
            # IsDone BEFORE draining - see Invoke-ExternalTool.
            $done = $pump.IsDone
            foreach ($line in $pump.Drain()) {
                $clean = $line -replace '\x1b?\[[0-9;]*m', ''
                foreach ($m in @($Mask | Where-Object { $_ })) { $clean = $clean.Replace($m, '********') }
                if ($null -ne $Capture) { $Capture.Add($clean) }
                if ($LogWriter -and $clean.Trim()) { & $LogWriter $clean }
            }
            if ($done) { break }
            if ($Progress) { $Progress.Cpu = $pump.CpuTime.TotalSeconds }
            if ($Progress -and $Progress.Cancel -and -not $NoCancel -and -not $killed) { $killed = $true; $pump.Kill() }
            Start-Sleep -Milliseconds 100
        }
        if ($killed) { return -1 }
        return $pump.ExitCode
    } finally { $pump.Dispose() }
}

function Publish-EcsFile {
    # The upload itself - checked, streamed, then counted back - used by the
    # Upload tab and by the job queue, so the two can never differ. Returns
    # Outcome 'Success' | 'MISMATCH' | 'Refused' with the tally; a network or
    # HTTP error throws. The caller keeps its own screen: -Log ($text, $kind),
    # -OnCheck ($lines) while checking, -OnBatch ($tally, $docs) per batch.
    param([string]$Base, [hashtable]$Headers, [string]$Index, [string]$Path,
          # index-template.json's text.
          [string]$Template,
          # Counted under when the file carries no import.id of its own.
          [string]$ImportId,
          [int]$BatchSize = 2000, [switch]$Overwrite,
          [scriptblock]$Log, [scriptblock]$OnCheck, [scriptblock]$OnBatch)
    if (-not $Log) { $Log = { param($t, $k) } }
    $r = [pscustomobject]@{ Outcome = 'FAILED'; Detail = ''; Docs = 0; Created = 0; Updated = 0; Duplicate = 0; Failed = 0; Errors = @() }

    # ---- hayabusa-* guard: never relax this, even for a shared/append upload ----
    # The last point before the write, and the only one every upload passes.
    if (-not (Test-HayabusaIndexName $Index)) {
        throw "refusing to write to '$Index'. An index name must start with 'hayabusa-' and contain only lowercase letters, digits, dot, dash or underscore."
    }

    # ---- the batch: checked, then streamed ----------------------------------
    # Two passes over the file and neither one keeps it in memory. Holding
    # every line (and a parsed copy of it) is what took 10 GB of RAM and ten
    # silent minutes on a 550k-detection batch. Duplicates are not decided per
    # host: each detection carries a fixed id (event.id) and Elasticsearch
    # refuses one it already holds, so nothing is doubled.
    & $Log "`nChecking the batch...`n" 'info'
    $check = Test-EcsFile $Path -OnProgress $OnCheck
    $r.Docs = $check.Docs
    if ($check.BadLines.Count) {
        $shown = (@($check.BadLines) | Select-Object -First 5) -join ', '
        $more  = if ($check.BadLines.Count -gt 5) { ', ...' } else { '' }
        $r.Detail = "$($check.BadLines.Count) line(s) of $([IO.Path]::GetFileName($Path)) are not valid JSON (line $shown$more). The file is damaged or was cut short - convert the EVTX again. Nothing was sent."
        & $Log "`nRefusing to upload: $($r.Detail)`n" 'err'
        $r.Outcome = 'Refused'
        return $r
    }
    if ($check.MissingId) {
        & $Log ("$('{0:N0}' -f $check.MissingId) document(s) carry no detection id - this ecs.jsonl was converted by an older version. " +
                "They are uploaded, but uploading them again would double them. Convert the EVTX again to get duplicate protection.`n") 'warn'
    }

    # A template is cluster-wide, so an API key limited to hayabusa-* may not
    # install one (403). A new index then gets the same settings and mappings
    # when it is created, below.
    $noTemplate = $false
    try {
        Invoke-RestMethod -Uri "$Base/_index_template/hayabusa-evtx" -Method Put -Headers $Headers `
            -ContentType 'application/json' -Body $Template -TimeoutSec 60 | Out-Null
        & $Log "Index template installed (hayabusa-*)`n" 'ok'
    } catch {
        if ($_.Exception.Message -notmatch '403') { throw }
        $noTemplate = $true
        $why = if ("$($Headers.Authorization)" -like 'ApiKey *') { 'normal for an API key limited to hayabusa-*' } else { 'it lacks manage_index_templates' }
        & $Log "This login may not change index templates ($why) - a new index gets the settings itself.`n" 'info'
    }

    # What the FILE's own import.ids already have in the index, so the check
    # at the end can ask Elasticsearch how many documents this upload really
    # added. A missing index holds none.
    $ids = @($check.ImportIds | Where-Object { $_ })
    if (-not $ids) { $ids = @($ImportId) }
    $idBody = (@{ query = @{ terms = @{ 'import.id' = $ids } } } | ConvertTo-Json -Compress -Depth 5)
    $before = 0; $indexExists = $true
    try {
        $before = [long](Invoke-EsJson -Uri "$Base/$Index/_count" -Method Post -Headers $Headers `
                            -ContentType 'application/json' -Body $idBody -TimeoutSec 30).count
    } catch {
        if ($_.Exception.Message -notmatch '404') { throw }
        $indexExists = $false
    }
    if (-not $indexExists -and $noTemplate) {
        try {
            Invoke-EsJson -Uri "$Base/$Index" -Method Put -Headers $Headers -ContentType 'application/json' `
                -Body (Get-IndexCreateBody $Template) -TimeoutSec 60 | Out-Null
            & $Log "Index '$Index' created with the hayabusa-* settings`n" 'ok'
        } catch {
            # Another upload (the queue, the Upload tab) may have created it
            # between the check and here - then it is there, which is the point.
            $createError = $_
            try { Invoke-EsJson -Uri "$Base/$Index/_count" -Method Get -Headers $Headers -TimeoutSec 30 | Out-Null } catch { throw $createError }
        }
    }

    if ($indexExists) {
        # The template applies only when an index is CREATED. An index from
        # before v37 would store the new fields but not index them, silently.
        try {
            Invoke-EsJson -Uri "$Base/$Index/_mapping" -Method Put -Headers $Headers -ContentType 'application/json' `
                -Body (Get-IndexMappingPatch $Template) -TimeoutSec 60 | Out-Null
            Invoke-EsJson -Uri "$Base/$Index/_settings" -Method Put -Headers $Headers -ContentType 'application/json' `
                -Body '{"index.mapping.total_fields.limit":10000}' -TimeoutSec 60 | Out-Null
        } catch {
            & $Log ("Could not add the current field mappings to '$Index' ($($_.Exception.Message)) - this account may lack the " +
                    "'manage' privilege on it. The upload goes on, but the event fields of these detections are only " +
                    "searchable in an index created by v37 or later.`n") 'warn'
        }
        # Detections uploaded before v36 have no fixed id, so nothing can
        # recognise them as the same detection.
        try {
            $legacy = [long](Invoke-EsJson -Uri "$Base/$Index/_count" -Method Post -Headers $Headers -ContentType 'application/json' `
                                -Body '{"query":{"bool":{"must_not":{"exists":{"field":"event.id"}}}}}' -TimeoutSec 30).count
            if ($legacy) {
                & $Log ("'$Index' holds $('{0:N0}' -f $legacy) detection(s) uploaded before v36, without a detection id. " +
                        "If this batch repeats any of their logs, those will be stored a second time - use a new index for re-uploads.`n") 'warn'
            }
        } catch { }
    }

    & $Log "`nUPLOADING $('{0:N0}' -f $check.Docs) document(s) to $Index`n" 'info'
    # Names of their own: the block below runs inside Send-EcsFile, whose own
    # $OnBatch would otherwise be the one found.
    $publishOnBatch = $OnBatch; $publishDocs = $check.Docs
    $tally = Send-EcsFile -Base $Base -Headers $Headers -Index $Index -Path $Path -BatchSize $BatchSize -Overwrite:$Overwrite -OnBatch {
        param($t) if ($publishOnBatch) { & $publishOnBatch $t $publishDocs }
    }
    $r.Created = $tally.Created; $r.Updated = $tally.Updated; $r.Duplicate = $tally.Duplicate
    $r.Failed = $tally.Failed; $r.Errors = @($tally.Errors)
    if ($tally.FieldsRefused) {
        & $Log ("$('{0:N0}' -f $tally.FieldsRefused) detection(s) were refused for their event fields (a field whose shape clashed, or the index's field limit) " +
                "and were stored WITHOUT winlog.event_data instead, tagged '$($script:FieldsRefusedTag)'. Their fields are still in hayabusa.details and the local results file.`n") 'warn'
    }

    Invoke-RestMethod -Uri "$Base/$Index/_refresh" -Method Post -Headers $Headers -TimeoutSec 60 | Out-Null

    & $Log ("`nnew              : $('{0:N0}' -f $r.Created)`nupdated          : $('{0:N0}' -f $r.Updated)`nalready in index : $('{0:N0}' -f $r.Duplicate)" +
            "`nfailed           : $($r.Failed)`n") 'plain'
    foreach ($e in $r.Errors) { & $Log "  $($e.type): $($e.reason)`n" 'err' }
    if ($r.Duplicate) {
        & $Log "$('{0:N0}' -f $r.Duplicate) detection(s) were already in '$Index' from an earlier upload (a re-pull, or the same logs twice). They were not added again.`n" 'info'
    }

    # Two checks, both answered by Elasticsearch: it gave a verdict on every
    # document sent, and the index now holds exactly as many more documents
    # under this import.id as it says it created.
    $after = [long](Invoke-EsJson -Uri "$Base/$Index/_count" -Method Post -Headers $Headers `
                        -ContentType 'application/json' -Body $idBody -TimeoutSec 30).count
    $answered = $r.Created + $r.Updated + $r.Duplicate + $r.Failed
    $grew = $after - $before
    $problems = @()
    if ($r.Failed -gt 0) { $problems += "$($r.Failed) document(s) failed" }
    if ($answered -ne $check.Docs) { $problems += "Elasticsearch answered for $answered of $($check.Docs) document(s)" }
    # An updated detection moves under this file's import.id only if it was
    # stored under another one, so with updates the growth is a range.
    if ($grew -lt $r.Created -or $grew -gt ($r.Created + $r.Updated)) {
        $problems += "it reported $($r.Created) new$(if ($r.Updated) { " and $($r.Updated) updated" }) but the index grew by $grew under this file's import.id"
    }
    if ($problems) {
        $r.Outcome = 'MISMATCH'; $r.Detail = $problems -join '; '
        & $Log "`nMISMATCH - $($r.Detail). Investigate before using this data.`n" 'err'
    } else {
        $r.Outcome = 'Success'; $r.Detail = "$($r.Created) new, $($r.Updated) updated, $($r.Duplicate) already in index"
        & $Log "`nOK - every document is accounted for.`n" 'ok'
    }
    return $r
}

function Invoke-SoImport {
    # Raw EVTX to Security Onion: a private staging folder on the manager,
    # each file copied with pscp, so-import-evtx run there, and the staged
    # copies always removed. Used by the Raw Events tab and the job queue.
    # -Run runs one program from a hashtable of Invoke-ExternalTool's
    # parameters and returns its exit code: the tab hands it to
    # Invoke-ExternalTool, the queue to Invoke-PumpedTool. Never throws - the
    # cleanup must always run, so the outcome is in the result.
    param([object[]]$Files, [string]$HostName, [int]$Port = 22, [string]$User, [string]$HostKey,
          [string]$Password, [scriptblock]$Run, [scriptblock]$IsCancelled, [scriptblock]$Log,
          # ($done, $total, $text) as it goes: the copies count up, then
          # (0, 0, ...) while so-import-evtx works on the manager.
          [scriptblock]$OnProgress)
    if (-not $Log) { $Log = { param($t, $k) } }
    if (-not $OnProgress) { $OnProgress = { param($d, $t, $x) } }
    $r = [pscustomobject]@{ Outcome = 'FAILED'; Detail = ''; Error = ''; Sent = 0; Bytes = [long]0; Left = ''; Result = $null; DiskWarning = '' }
    $soPw = $null; $soRemote = ''; $soStaged = $false
    # One remote command; with -Sudo the password goes to plink's stdin,
    # which plink hands to the remote command, where sudo -S reads it.
    $soPlink = {
        param([string]$Label, [string]$Command, [switch]$Sudo, [switch]$NoCancel)
        $out = New-Object System.Collections.Generic.List[string]
        $p = @{ Label = $Label; Exe = (Find-PuttyTool plink); Detail = $HostName; Capture = $out; Mask = @($Password)
                Arguments = (Get-PlinkArgs -HostName $HostName -Port $Port -User $User -HostKey $HostKey -PasswordFile $soPw -Command $Command) }
        if ($Sudo)     { $p.StandardInput = "$Password`n" }
        if ($NoCancel) { $p.NoCancel = $true }
        $code = & $Run $p
        [pscustomobject]@{ Code = $code; Lines = @($out) }
    }
    try {
        $soPw = New-PasswordFile $Password
        $soRemote = New-SoImportStagingDir
        & $Log "`n$('=' * 70)`nRAW EVENTS -> Security Onion $HostName ($(@($Files).Count) file(s))`nstaging: $soRemote`n$('=' * 70)`n" 'info'
        $s = & $soPlink 'Stage on the manager' (Get-SoRemoteCommand Stage $soRemote)
        if ($s.Code -ne 0 -or -not ($s.Lines -match 'EVTXER-STAGED')) { throw "could not create $soRemote on the manager (exit $($s.Code))" }
        $soStaged = $true
        # The manager's free space, read on that same call - once per import.
        $r.DiskWarning = @(Get-SoDiskWarning @(ConvertFrom-DfOutput $s.Lines) ([long](@($Files) | Measure-Object Length -Sum).Sum)) -join ' '
        if ($r.DiskWarning) { & $Log "LOW DISK ON THE MANAGER: $($r.DiskWarning)`n" 'warn' }

        $i = 0; $n = @($Files).Count
        foreach ($f in $Files) {
            if (& $IsCancelled) { throw 'Cancelled by the operator.' }
            $i++
            & $OnProgress ($i - 1) $n "copying file $i of $n"
            $a = Get-PscpArgs -HostName $HostName -Port $Port -User $User -HostKey $HostKey -PasswordFile $soPw `
                    -LocalFile $f.FullName -RemotePath "$soRemote/$(Get-SoImportRemoteName $i $f.FullName)"
            & $Log "copy $i/${n}: $($f.FullName) ($(Format-ByteSize $f.Length))`n" 'plain'
            $code = & $Run @{ Label = "Copy $i/$n"; Exe = (Find-PuttyTool pscp); Arguments = $a; Detail = $f.Name; Mask = @($Password) }
            if ($code -ne 0) { throw "copying $($f.Name) failed (pscp exit $code)" }
            $r.Sent++; $r.Bytes += $f.Length
        }

        if (& $IsCancelled) { throw 'Cancelled by the operator.' }
        # Not cancellable once started: killing plink would not stop the
        # importer on the manager, the cleanup would then delete files it is
        # still reading, and Security Onion marks each file imported as it
        # goes - a half-imported file would be skipped on every later try.
        & $Log "`nRunning so-import-evtx on the manager (Cancel waits for it to finish)...`n" 'info'
        & $OnProgress 0 0 'Security Onion is importing them'
        $imp = & $soPlink 'so-import-evtx' (Get-SoRemoteCommand Import $soRemote) -Sudo -NoCancel
        $r.Result = Get-SoImportResult $imp.Lines
        $r.Detail = "$($r.Result.Imported) imported, $($r.Result.Skipped) already imported (skipped), $($r.Result.Warnings) warning(s)"
        if (-not ($r.Result.Complete -and $imp.Code -eq 0)) { throw "so-import-evtx did not complete (exit $($imp.Code)): $($r.Detail) - see the log" }
        $r.Outcome = if ($r.Result.Warnings) { 'Partial' } else { 'Success' }
    } catch {
        $r.Error = $_.Exception.Message
        $r.Detail = (@($r.Detail, $r.Error) | Where-Object { $_ }) -join '; '
        if ((& $IsCancelled) -or $r.Error -match 'Cancelled') { $r.Outcome = 'Cancelled' }
        & $Log "RAW EVENT IMPORT FAILED: $($r.Error)`n" 'err'
    } finally {
        # The staged copies are evidence sitting in /tmp on someone else's
        # server: removed whatever happened, and said so if that failed too.
        if ($soStaged) {
            $c = & $soPlink 'Clean up the manager' (Get-SoRemoteCommand Clean $soRemote) -NoCancel
            if ($c.Lines -match 'EVTXER-CLEANED') { & $Log "Staging folder removed from the manager.`n" 'ok' }
            else { $r.Left = $soRemote; & $Log "[!!] Could not remove $soRemote on the manager - delete it by hand.`n" 'err' }
        }
        if ($soPw) { Remove-Item -LiteralPath $soPw -Force -ErrorAction SilentlyContinue }
    }
    # In Detail, so the tab, the queue and the activity log carry it - on
    # success and on the failure it may have predicted.
    if ($r.DiskWarning) { $r.Detail = "$($r.Detail) - LOW DISK on the manager: $($r.DiskWarning.TrimEnd('.'))" }
    return $r
}

# ---------------------------------------------------------------- job queue ---
# Phase 2 step 2: the operator only collects. Each
# collected host folder becomes one job, and jobs run one at a time, off the
# window's thread: a Hayabusa scan of that folder only -> ECS -> upload,
# appended to the mission index -> raw import to Security Onion -> archive.
# Which of those a job does comes from the queue pane's switches when it is
# queued. The queue is logs\queue.json, rewritten whole on every change (a new
# copy, then swapped in, so a crash never leaves half a file); what each step
# did goes to the activity log, as every other action's does.
$script:QueueStepText = @{
    scan    = @{ Short = 'scan';       Run = 'Scanning with Hayabusa';       Wait = 'Waiting to scan';           Colour = '#5B9BD5' }
    ecs     = @{ Short = 'ECS';        Run = 'Converting to ECS';            Wait = 'Waiting to convert to ECS'; Colour = '#A98BD9' }
    upload  = @{ Short = 'upload';     Run = 'Uploading';                    Wait = 'Waiting to upload';         Colour = '#4FB8B0' }
    raw     = @{ Short = 'raw import'; Run = 'Raw import to Security Onion'; Wait = 'Waiting for raw import';    Colour = '#8C93E6' }
    archive = @{ Short = 'archive';    Run = 'Archiving';                    Wait = 'Waiting to archive';        Colour = '#C8A26B' }
}
$script:QueueColour = @{ waiting = '#E8B04A'; done = '#7EC87E'; failed = '#F2A0A0' }

function Get-QueueSteps($Settings) {
    # Upload needs the conversion's file, so it is only offered with it.
    $s = @()
    if ($Settings.AutoConvert -eq 'on') {
        $s += 'scan', 'ecs'
        if ($Settings.AutoUpload -eq 'on') { $s += 'upload' }
    }
    if ($Settings.AutoRaw -eq 'on')     { $s += 'raw' }
    if ($Settings.AutoArchive -eq 'on') { $s += 'archive' }
    return $s
}

function New-QueueJob([string]$Folder, [string[]]$Steps, [string]$OutRoot, [datetime]$Now = (Get-Date)) {
    # Its own results folder, made now: a re-collected host or a second job
    # for the same folder never writes over an earlier job's results.
    $name = Split-Path -Leaf $Folder
    $out = Get-NextFreeFolder (Join-Path $OutRoot $name)
    New-Item -ItemType Directory -Path $out -Force | Out-Null
    [pscustomobject]@{
        Id = [guid]::NewGuid().ToString('N').Substring(0, 8)
        Folder = $Folder; Name = $name; OutDir = $out
        Steps = @($Steps); Step = 0; State = 'queued'; Note = ''
        Detections = -1
        # Minted once, so a retried conversion or upload is counted under
        # the same id.
        ImportId = $Now.ToString('yyyyMMddHHmmss') + [guid]::NewGuid().ToString('N').Substring(0, 8)
        Added = $Now.ToString('s'); Finished = ''; Seconds = 0
    }
}

function Read-JobQueue([string]$Path) {
    # A job that was running when EVTXER closed did not finish that step: it
    # goes back in the queue at that same step, which is safe to run again
    # (Hayabusa and ECS rewrite this job's own files, the upload refuses a
    # detection it already holds, so-import-evtx skips a file it has, and the
    # archive zips whatever is still there).
    $jobs = @()
    try {
        $parsed = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
        # PS 5.1 hands a JSON array over as ONE object; assigned first, @() is
        # the array itself.
        $jobs = @($parsed)
    } catch { return }
    foreach ($j in $jobs) {
        $j.Steps = @($j.Steps)
        if ($j.State -eq 'running') {
            $j.State = 'queued'
            $j.Note = "Interrupted - EVTXER closed during '$($script:QueueStepText[[string]$j.Steps[$j.Step]].Run)'; it starts there again."
        }
    }
    return $jobs
}

function Save-JobQueue($Jobs, [string]$Path) {
    $tmp = "$Path.new"
    [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject @($Jobs) -Depth 4), (New-Object Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($tmp, $Path, [NullString]::Value) }
    else { [IO.File]::Move($tmp, $Path) }
}

function Get-QueueOrder($Jobs) {
    # The list as shown and as run: the jobs still to finish in the
    # operator's order, then the finished ones, newest first. The first
    # 'queued' job is the next to run - so a job keeps its place while it
    # runs, and the one at the top runs step after step until it is done or
    # has to wait.
    $j = @($Jobs)
    return @(@($j | Where-Object { $_.State -ne 'done' }) +
             @($j | Where-Object { $_.State -eq 'done' } | Sort-Object Finished -Descending))
}

function Move-QueueJob($Jobs, [string]$Id, [ValidateSet('up', 'down', 'next')][string]$Where) {
    # 'next' = to the top: it runs as soon as the step running now is
    # finished. Finished jobs never move.
    $list = [Collections.ArrayList]@(Get-QueueOrder $Jobs)
    $i = -1
    for ($k = 0; $k -lt $list.Count; $k++) { if ($list[$k].Id -eq $Id) { $i = $k } }
    if ($i -lt 0 -or $list[$i].State -eq 'done') { return $list.ToArray() }
    $last = $list.Count - @($list | Where-Object { $_.State -eq 'done' }).Count - 1
    $to = switch ($Where) {
        'up'   { [Math]::Max(0, $i - 1) }
        'down' { [Math]::Min($last, $i + 1) }
        'next' { 0 }
    }
    $job = $list[$i]; $list.RemoveAt($i); $list.Insert($to, $job)
    return $list.ToArray()
}

function Update-QueueBlockers($Jobs, [hashtable]$Blockers) {
    # $Blockers: step -> what the operator must do first ('' or missing =
    # nothing). A job whose next step is blocked waits, in amber, saying so;
    # it goes back to the queue by itself once the reason is gone. Returns
    # whether anything changed.
    $changed = $false
    foreach ($j in @($Jobs)) {
        if ($j.State -notin 'queued', 'waiting') { continue }
        $why = [string]$Blockers[[string]$j.Steps[$j.Step]]
        $state = if ($why) { 'waiting' } else { 'queued' }
        if ($j.State -ne $state -or $j.Note -ne $why) { $j.State = $state; $j.Note = $why; $changed = $true }
    }
    return $changed
}

function Get-QueueStage($Job) {
    # What the row says and its colour. The colour is the step it is on or
    # waiting for, so a glance shows how far each host has got; amber is
    # "waiting for you", green done, red failed - and the words say the same,
    # for a dim screen or anyone who does not see colour.
    $step = [string]@($Job.Steps)[$Job.Step]
    $t = $script:QueueStepText[$step]
    switch ($Job.State) {
        'running' { return [pscustomobject]@{ Text = $t.Run; Colour = $t.Colour } }
        'queued'  { return [pscustomobject]@{ Text = $t.Wait; Colour = $t.Colour } }
        'waiting' { return [pscustomobject]@{ Text = "Waiting for you: $($Job.Note)"; Colour = $script:QueueColour.waiting } }
        'done'    { return [pscustomobject]@{ Text = "Done$(if ($Job.Note) { " - $($Job.Note)" })"; Colour = $script:QueueColour.done } }
        default   {
            $at = if ($t) { " at '$($t.Run)'" } else { '' }
            if ($Job.Note -eq 'Cancelled') { return [pscustomobject]@{ Text = "Cancelled${at} - Retry goes on from there"; Colour = $script:QueueColour.failed } }
            return [pscustomobject]@{ Text = "Failed${at}: $($Job.Note)"; Colour = $script:QueueColour.failed }
        }
    }
}

function Get-QueueJobProgress($Job, $Progress) {
    # The bar on a queue row: how far the WHOLE job has got, each step an
    # equal share and the running step filling its own share as it goes
    # (every row shows a bar, and a working one moves).
    # Busy = a step that cannot measure itself - the Hayabusa scan prints
    # nothing until it ends, so-import-evtx runs on the manager - and then
    # the bar moves without a number, with the scan's CPU time climbing, so
    # working never looks like stuck. Detail is added to the row's words.
    $n = [Math]::Max(1, @($Job.Steps).Count)
    if ($Job.State -eq 'done') { return [pscustomobject]@{ Pct = 100.0; Busy = $false; Detail = '' } }
    $base = 100.0 * [int]$Job.Step / $n
    if ($Job.State -ne 'running' -or -not $Progress) {
        return [pscustomobject]@{ Pct = [Math]::Round($base, 1); Busy = $false; Detail = '' }
    }
    $total = [double]$Progress.Total
    if ($total -gt 0) {
        $f = [Math]::Min(1.0, [Math]::Max(0.0, [double]$Progress.Done / $total))
        $detail = if ($Progress.Note) { [string]$Progress.Note } else { "$([Math]::Floor(100 * $f))%" }
        return [pscustomobject]@{ Pct = [Math]::Round($base + 100.0 * $f / $n, 1); Busy = $false; Detail = $detail }
    }
    $cpu = if ([string]@($Job.Steps)[$Job.Step] -eq 'scan' -and [double]$Progress.Cpu -ge 1) { "CPU $(Format-JobDuration ([timespan]::FromSeconds([double]$Progress.Cpu)))" } else { '' }
    [pscustomobject]@{ Pct = [Math]::Round($base, 1); Busy = $true; Detail = ((@([string]$Progress.Note, $cpu) | Where-Object { $_ }) -join ', ') }
}

function Test-QueueHoldsFolder($Jobs, [string]$Folder) {
    # A host folder a job still needs: the manual Archive must not zip and
    # delete it underneath the queue.
    foreach ($j in @($Jobs)) {
        if ($j.State -ne 'done' -and $j.Folder -eq $Folder) { return $true }
    }
    return $false
}

function Invoke-QueueStep {
    # One step of one queued job, in a background runspace (Start-LibJob).
    # Never touches the window: lines go to -LogWriter, progress to -Progress
    # (Done/Total out, Cancel in), and the result says what happened plus the
    # activity-log row for the window to write. $Context carries what the
    # window knows - the Hayabusa path, the connections, the mission index,
    # the archive folder - and the passwords, in memory only.
    param($Job, [hashtable]$Context, [hashtable]$Progress, [scriptblock]$LogWriter)
    # New-LedgerRow stamps the version, which only the launcher defines.
    $script:ToolVersion = $Context.ToolVersion
    # Names of their own: these are read from inside callbacks that run in
    # other functions, which may have a $Progress or $LogWriter of their own.
    $qp = $Progress; $qlog = $LogWriter
    $qlog2 = { param($t, $k) foreach ($l in ("$t" -split "`r?`n")) { if ($l.Trim()) { & $qlog $l } } }
    $step = [string]@($Job.Steps)[$Job.Step]
    $results = Join-Path $Job.OutDir 'results.jsonl'
    $ecs = Get-EcsOutputPath $results
    $r = [pscustomobject]@{ Ok = $false; Cancelled = $false; Summary = ''; Detections = $null; Skip = @(); Ledger = @(); Warning = '' }
    $row = @{ Target = $Job.Name; Output = ''; Files = '' }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    & $qlog "==== $(Get-Date -Format s) $($script:QueueStepText[$step].Run): $($Job.Folder)"
    try {
        switch ($step) {
            'scan' {
                $row.Action = 'Convert'; $row.Protocol = 'Hayabusa scan (job queue)'; $row.Output = $results
                New-Item -ItemType Directory -Path $Job.OutDir -Force | Out-Null
                $cap = New-Object System.Collections.Generic.List[string]
                $a = Get-HayabusaScanArgs -EvtxDir $Job.Folder -OutFile $results -HtmlReport (Join-Path $Job.OutDir 'results-summary.html')
                $code = Invoke-PumpedTool -Label 'Hayabusa scan' -Exe $Context.HayabusaExe -Arguments $a -Capture $cap -Progress $qp -LogWriter $qlog -Low
                if ($code -eq -1) { throw 'Cancelled.' }
                if ($code -ne 0) { throw "Hayabusa exited with code $code" }
                $cov = Get-HayabusaCoverage ($cap -join "`n")
                $has = (Test-Path -LiteralPath $results) -and (Get-Item -LiteralPath $results).Length -gt 0
                if (-not $has) { $r.Detections = 0; $r.Skip = @('ecs', 'upload') }
                $r.Summary = if ($cov) { $cov.Text } elseif ($has) { 'scanned' } else { 'no detections - nothing to convert or upload' }
            }
            'ecs' {
                $row.Action = 'Convert'; $row.Protocol = 'ECS (job queue)'; $row.Output = $ecs
                $c = Convert-HayabusaJsonlToEcs -Source $results -Destination $ecs -ImportId $Job.ImportId -EvtxDir $Job.Folder -OnProgress {
                    param($done, $all) $qp.Done = $done; $qp.Total = $all; [bool]$qp.Cancel
                }
                if ($c.Cancelled) { throw 'Cancelled.' }
                $r.Detections = [long]$c.Converted
                $row.Files = "$($c.Converted) documents"
                $r.Summary = "$('{0:N0}' -f $c.Converted) detection(s) converted$(if ($c.Bad) { ", $($c.Bad) line(s) unreadable" })"
                if (-not $c.Converted) { $r.Skip = @('upload') }
            }
            'upload' {
                $row.Action = 'Upload'; $row.Protocol = 'HTTPS (Elasticsearch, job queue)'; $row.Output = $Context.Index
                $row.Target = $Context.EsHost; $row.Port = $Context.EsPort; $row.Account = $Context.EsUser
                $p = Publish-EcsFile -Base $Context.EsBase -Headers $Context.EsHeaders -Index $Context.Index -Path $ecs `
                        -Template ([IO.File]::ReadAllText($Context.TemplatePath)) -ImportId $Job.ImportId -Log $qlog2 -OnBatch {
                    param($t, $docs)
                    if ($qp.Cancel) { throw 'Cancelled.' }
                    $qp.Total = $docs; $qp.Done = $t.Created + $t.Updated + $t.Duplicate + $t.Failed
                }
                $row.Files = "$($p.Created) documents"
                if ($p.Outcome -ne 'Success') { throw "upload $($p.Outcome): $($p.Detail)" }
                $r.Summary = "$($p.Detail) in '$($Context.Index)'"
            }
            'raw' {
                $row.Action = 'SO import'; $row.Protocol = 'SSH (pscp + so-import-evtx, job queue)'
                $row.Target = $Context.SoHost; $row.Port = $Context.SoPort; $row.Account = $Context.SoUser
                $files = @(Get-SoImportFiles $Job.Folder)
                if (-not $files.Count) { throw "no .evtx files in $($Job.Folder)" }
                $s = Invoke-SoImport -Files $files -HostName $Context.SoHost -Port $Context.SoPort -User $Context.SoUser `
                        -HostKey $Context.SoHostKey -Password $Context.SoPassword -Log $qlog2 `
                        -OnProgress { param($d, $t, $x) $qp.Done = $d; $qp.Total = $t; $qp.Note = $x } `
                        -Run { param($p) Invoke-PumpedTool @p -Progress $qp -LogWriter $qlog } -IsCancelled { [bool]$qp.Cancel }
                $row.Files = "$($s.Sent)/$($files.Count) EVTX"; $row.Bytes = $s.Bytes; $row.LeftOnTarget = $s.Left
                if ($s.Result -and $s.Result.WideUrl) { $row.Output = $s.Result.WideUrl }
                if ($s.Outcome -eq 'Cancelled') { throw 'Cancelled.' }
                if ($s.Outcome -notin 'Success', 'Partial') { throw $s.Detail }
                $r.Summary = $s.Detail
                $r.Warning = $s.DiskWarning
            }
            'archive' {
                $row.Action = 'EVTX archive'; $row.Protocol = $(if ($Context.ArchiveRoot -like '\\*') { 'SMB' } else { 'local' })
                $row.Output = $Context.ArchiveRoot      # the zip replaces it once there is one
                $z = Compress-EvtxFolder -Folder $Job.Folder -ArchiveRoot $Context.ArchiveRoot -Progress $qp -LogWriter $qlog
                $row.Files = "$($z.Files) EVTX"; $row.Bytes = $z.Bytes; $row.Output = $z.Zip; $row.Integrity = 'SHA-256 verified'
                $r.Summary = "$($z.Files) EVTX zipped to $($z.Zip)"
            }
            default { throw "unknown step '$step'" }
        }
        $r.Ok = $true
    } catch {
        $r.Cancelled = [bool]$qp.Cancel -or $_.Exception.Message -eq 'Cancelled.'
        $r.Summary = if ($r.Cancelled) { 'Cancelled' } else { $_.Exception.Message }
        & $qlog "[!!] $($r.Summary)"
    } finally {
        if ($row.Action) {
            $res = if ($r.Ok) { 'Success' } elseif ($r.Cancelled) { 'Cancelled' } else { 'FAILED' }
            $details = (@("job queue $($Job.Id)", $r.Summary, "import.id $($Job.ImportId)") | Where-Object { $_ }) -join '; '
            $r.Ledger = @(New-LedgerRow @row -Result $res -Seconds $clock.Elapsed.TotalSeconds -Details $details)
        }
    }
    & $qlog "==== $(if ($r.Ok) { 'done' } else { 'stopped' }) in $(Format-JobDuration $clock.Elapsed): $($r.Summary)"
    return $r
}

# ------------------------------------------------------------ rules update ---
# The rule updater. Hayabusa's own
# update-rules clones hayabusa-rules with libgit2, and three things about it
# were measured before this was built: it refuses a rules folder that is not
# a git clone (the field copies ship without rules\.git) - so the rules in use
# are moved aside first; it exits 0 even when it fails - so success is judged
# by what arrived; and it cannot write a path over 259 characters - so a
# folder too deep is refused up front, not half updated.
#
# Every move here stops on failure and is checked (code review: a locked
# folder made a silent Move-Item nest the new rules inside the old ones and
# still report success). Hayabusa must never be left without its rules, or
# with two sets of them.
$script:RulesMarker = 'evtxer-rules.txt'

function Get-RuleFiles([string]$RulesDir, [string]$Filter = '*') {
    # Every file below rules\ except git's own (thousands of objects in a
    # clone), which are never walked.
    foreach ($d in Get-ChildItem -LiteralPath $RulesDir -Directory -ErrorAction SilentlyContinue) {
        if ($d.Name -eq '.git') { continue }
        Get-ChildItem -LiteralPath $d.FullName -Recurse -Filter $Filter -File -ErrorAction SilentlyContinue
    }
}

function Get-RulesInfo([string]$RulesDir) {
    # How many rules, and where they last came from (the marker an update
    # leaves; none = the rules EVTXER shipped with).
    $n = @(Get-RuleFiles $RulesDir '*.yml').Count
    $from = ''
    try { $from = ([IO.File]::ReadAllText((Join-Path $RulesDir $script:RulesMarker))).Trim() } catch { }
    [pscustomobject]@{ Count = $n; From = $from; HasPrevious = (Test-Path -LiteralPath "$RulesDir.previous") }
}

function Get-LongestRulePath([string]$RulesDir) {
    # Characters below rules\ of the deepest file - 166 in October 2026.
    $max = 0
    foreach ($f in Get-RuleFiles $RulesDir) {
        $len = $f.FullName.Length - $RulesDir.Length
        if ($len -gt $max) { $max = $len }
    }
    return $max
}

# Get-LongestRulePath of the rules EVTXER ships (Hayabusa 4.2.0 rules, Oct
# 2026). The launcher warns when its folder is too deep for this one; a Layout
# test keeps it in step when the rules are re-copied.
$script:DeepestShippedRule = 166

function Test-RulesPathFits([string]$RulesDir, [int]$Longest, [int]$Margin = 15) {
    # Windows' 260-character limit, with room for the rules to grow deeper.
    return ($RulesDir.Length + $Longest + $Margin) -le 259
}

function Move-RulesFolder([string]$From, [string]$To) {
    # A rename that either happens or throws - and is checked, because a
    # Move-Item onto an existing folder moves INTO it instead.
    if (Test-Path -LiteralPath $To) { throw "$To is in the way" }
    Move-Item -LiteralPath $From -Destination $To -ErrorAction Stop
    if ((Test-Path -LiteralPath $From) -or -not (Test-Path -LiteralPath $To)) { throw "could not move $From to $To" }
}

function Remove-RulesLeftovers([string]$HayabusaDir) {
    # Old backups and failed attempts set aside by earlier updates. Best
    # effort: one still locked is tried again next time.
    foreach ($d in Get-ChildItem -LiteralPath $HayabusaDir -Directory -Filter 'rules.discard*' -ErrorAction SilentlyContinue) {
        Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Repair-HayabusaRules([string]$HayabusaDir) {
    # After a crash or a killed window in the middle of an update or a
    # restore: the rules are put back where Hayabusa reads them. Returns what
    # it did ('' = nothing was wrong).
    $rules = Join-Path $HayabusaDir 'rules'; $prev = "$rules.previous"; $swap = "$rules.swap"
    $did = @()
    if (-not (Test-Path -LiteralPath $rules)) {
        # A restore stopped after its first move holds the rules in .swap;
        # an update stopped before its end holds them in .previous.
        if (Test-Path -LiteralPath $swap) { Move-RulesFolder $swap $rules; $did += 'rules.swap' }
        elseif (Test-Path -LiteralPath $prev) { Move-RulesFolder $prev $rules; $did += 'rules.previous' }
    }
    if ((Test-Path -LiteralPath $swap) -and -not (Test-Path -LiteralPath $prev)) { Move-RulesFolder $swap $prev; $did += 'the backup' }
    if ($did) { return "put back from $($did -join ' and ')" }
    return ''
}

function Update-HayabusaRules {
    # Replaces hayabusa-x64\rules with the latest hayabusa-rules: from GitHub
    # (Hayabusa's own update-rules), or from a zip downloaded on another
    # machine (-ZipFile; GitHub's Code > Download ZIP). The rules in use go
    # to rules.previous first and come straight back if anything fails.
    param([string]$HayabusaExe, [string]$ZipFile, [int]$MinRules = 1000,
          [hashtable]$Progress, [scriptblock]$LogWriter)
    if (-not $LogWriter) { $LogWriter = { param($m) } }
    $dir = Split-Path -Parent $HayabusaExe
    $rules = Join-Path $dir 'rules'; $prev = "$rules.previous"
    $stamp = Get-Date -Format 'yyyyMMddHHmmss'
    $healed = Repair-HayabusaRules $dir
    if ($healed) { & $LogWriter "[..] The rules were missing after an interrupted update - $healed." }
    Remove-RulesLeftovers $dir
    $before = Get-RulesInfo $rules
    $longest = [Math]::Max(166, (Get-LongestRulePath $rules))
    if (-not (Test-RulesPathFits $rules $longest)) {
        throw "EVTXER sits in too deep a folder for the rules: $rules is $($rules.Length) characters and the deepest rule adds $longest, past Windows' 260-character limit. Move the EVTXER folder somewhere shorter, such as C:\EVTXER, and update there."
    }
    & $LogWriter "Rules now: $($before.Count) rule files$(if ($before.From) { ", $($before.From)" } else { ', as shipped' })"
    # The older backup is set aside (not deleted) until the new one exists.
    if (Test-Path -LiteralPath $prev) { Move-RulesFolder $prev "$rules.discard-$stamp" }
    Move-RulesFolder $rules $prev
    $tmp = ''; $cap = $null
    try {
        if ($ZipFile) {
            $source = "file $([IO.Path]::GetFileName($ZipFile))"
            & $LogWriter "Unpacking $ZipFile"
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ('evtxer-rules-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::ExtractToDirectory($ZipFile, $tmp)
            # GitHub's zip wraps everything in hayabusa-rules-main\.
            $root = $tmp
            $sub = @(Get-ChildItem -LiteralPath $tmp -Directory)
            if ($sub.Count -eq 1 -and -not (Test-Path -LiteralPath (Join-Path $tmp 'config'))) { $root = $sub[0].FullName }
            if ([IO.Path]::GetPathRoot($root) -eq [IO.Path]::GetPathRoot($rules)) { Move-RulesFolder $root $rules }
            else { Copy-Item -LiteralPath $root -Destination $rules -Recurse -ErrorAction Stop }
        } else {
            $source = 'GitHub (Yamato-Security/hayabusa-rules)'
            $cap = New-Object System.Collections.Generic.List[string]
            $code = Invoke-PumpedTool -Label 'Hayabusa update-rules' -Exe $HayabusaExe -Arguments @('update-rules', '-q', '-K') `
                        -WorkDir $dir -Capture $cap -Progress $Progress -LogWriter $LogWriter
            if ($code -eq -1) { throw 'Cancelled.' }
        }
        $after = Get-RulesInfo $rules
        $config = Test-Path -LiteralPath (Join-Path $rules 'config\default_details.txt')
        if ($after.Count -lt $MinRules -or -not $config) {
            $why = @($cap | Where-Object { $_ -match '\[ERROR\]' } | Select-Object -Last 1)
            throw ("the new rules are incomplete: $($after.Count) rule files$(if (-not $config) { ', no config\default_details.txt' })" +
                   $(if ($why) { " - Hayabusa said: $(($why[0] -replace '^\s*\[ERROR\]\s*', '').Trim())" }))
        }
        $from = "updated $(Get-Date -Format 'yyyy-MM-dd HH:mm') from $source"
        [IO.File]::WriteAllText((Join-Path $rules $script:RulesMarker), $from)
        & $LogWriter "[OK] $($after.Count) rule files, $from (were $($before.Count))"
        [pscustomobject]@{ Before = $before.Count; After = $after.Count; From = $from }
    } catch {
        $err = $_.Exception.Message
        # Never leave Hayabusa without its rules, or with two sets: whatever
        # arrived is set aside, then the rules in use come back - checked.
        try {
            if (Test-Path -LiteralPath $rules) { Move-RulesFolder $rules "$rules.discard-failed-$stamp" }
            Move-RulesFolder $prev $rules
        } catch {
            & $LogWriter "[!!] The update failed AND the rules in use could not be put back: $($_.Exception.Message). They are in $prev - close EVTXER and rename that folder to rules (EVTXER also does this by itself when it next starts)."
            throw "the update failed ($err), and the rules in use could not be put back - they are in $prev"
        }
        & $LogWriter "[!!] Rules not updated - the rules in use were put back."
        throw $err
    } finally {
        if ($tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        Remove-RulesLeftovers $dir
    }
}

function Restore-HayabusaRules([string]$HayabusaDir) {
    # Undo: the rules from before the last update come back, and the ones
    # replaced become the backup - so an undo can be undone. Each move is
    # checked; an interrupted one is finished by Repair-HayabusaRules.
    [void](Repair-HayabusaRules $HayabusaDir)
    $rules = Join-Path $HayabusaDir 'rules'; $prev = "$rules.previous"; $swap = "$rules.swap"
    if (-not (Test-Path -LiteralPath $prev)) { throw 'there are no earlier rules to go back to' }
    if (Test-Path -LiteralPath $swap) { throw "$swap is left from an interrupted restore - close and reopen EVTXER, which puts it back" }
    Move-RulesFolder $rules $swap
    try { Move-RulesFolder $prev $rules }
    catch { Move-RulesFolder $swap $rules; throw }
    Move-RulesFolder $swap $prev
    Get-RulesInfo $rules
}
