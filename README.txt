EVTXER
======

Collect Windows event logs from remote hosts, analyse them with Hayabusa,
review them with Takajo, and upload the detections to an Elastic (ELK)
stack - Security Onion or a plain Elastic stack (tested on 8.7 and 9).

Everything needed is in this folder. No Python, no installer, no internet.


RUN IT
------

Double-click EVTXER.cmd. That is all - no Set-ExecutionPolicy
first. It starts PowerShell with the policy bypassed for that one window only;
nothing on the machine is changed. From a prompt, the same thing is:

    powershell -ExecutionPolicy Bypass -File .\code\HayabusaMissionTool.ps1

EVTXER runs as ADMINISTRATOR. The .cmd asks Windows for it (one UAC prompt).
Plain WinRM collection needs it, because it adds the targets to this PC's
WinRM TrustedHosts list (and puts the list back afterwards). Refused, EVTXER
still starts and says so: SMB and WinRM over HTTPS work without it. Two
things to know about running elevated:
  - A drive letter mapped as the normal user (Z:\ etc.) is not visible to an
    elevated program. Give share folders (Archive, EVTX drop folder) as
    \\server\share\... paths instead.
  - Plain WinRM also needs this PC's WinRM service running
    (as administrator: Start-Service WinRM). The Collect tab says so when
    WinRM is picked.
  - Started from a mapped drive letter, the .cmd turns it into its
    \\server\share path first; if it cannot, it starts without admin.
  - If UAC asks for a DIFFERENT admin account, EVTXER runs as that account:
    passwords remembered under your own account are not found (tick Remember
    again), and links EVTXER opens start the browser as that account too.
  - Keep the EVTXER folder writable by administrators only. It runs with
    admin rights, so anyone who can change its files (the scripts, or the
    dumpcap path in code\settings.conf) could run their own code as admin.

If it still refuses, the policy is set by Group Policy, which overrides the
command line - that needs the machine's admin, not this tool.

Requires Windows x64 and PowerShell 5.1 (built into Windows 10/11).


THE EIGHT TABS
--------------

1. Collect                  Pull .evtx from remote hosts over SMB or WinRM
                            (plain, or over HTTPS).
                            Lands in evtx\<hostname>_<timestamp>\

2. Convert                  Scan those logs with Hayabusa. Writes two files -
                            see below.

3. Upload                   Ship the detections to an Elasticsearch index.

4. Takajo                   CSV results, or an offline HTML report (OPEN
                            REPORT opens it from disk - nothing listens).

5. Dashboards               Import the 9 dashboards and 9 saved searches into
                            Kibana, using the connection from tab 3.
                            Security Onion only - on plain Elastic, import by hand.

6. Raw Events               Send the .evtx themselves to the Security Onion
                            manager and run its own importer there, so EVERY
                            event is searchable - not only the ones a
                            Hayabusa rule matched. Security Onion only.

7. Settings                 THIS MISSION first: the mission name (see
                            MISSION), accountability PCAP (see ACCOUNTABILITY
                            PCAP) and ARCHIVE (see ARCHIVE). Then SETUP, set
                            once per machine: the EVTX drop folder and the
                            Hayabusa rules.

8. Guide                    A cheat sheet: a short answer to each thing that
                            is not obvious (times in Security Onion, from a
                            detection to the full log, where data lands,
                            duplicates, what Archive deletes, passwords...).
                            Its search box searches the cheat sheet AND this
                            whole README; its More button opens the chapter.
                            Usable while a job runs.

THE TOP BAR shows at a glance whether the mission is ready. Click a pill to
open the tab that fixes it:

    Mission   green once the mission is named (Settings tab)
    ELK       green once VERIFY CONNECTIVITY passed (Upload tab)
    SO        green once the Raw Events tab is filled in - only needed
              for raw imports, so grey is fine on a plain Elastic stack
    PCAP      red, dot pulsing, while an accountability capture records;
              grey "No PCAP" when none does (hover for the file)

"Things are cookin'" joins them while anything runs. A usual mission: name
it, START CAPTURE, VERIFY CONNECTIVITY, then collect - the queue does the
rest. After an upload or a raw import the log says where the data shows:
detections only in Kibana (their own index, so not in Security Onion's Hunt
or Alerts), raw events in Security Onion's Hunt and Dashboards too.

The log is the pane on the RIGHT. Drag the bar between it and the tabs to
make it wider; the width is remembered. While a job runs, the line above the
log shows what it is doing, how long it has run and - for Hayabusa and Takajo
- the CPU time it has used: if CPU time keeps rising, it is working, not hung.
CANCEL stops it. A WinRM collection stops in the middle of an export, the
archive or a download (an SMB copy finishes its current file), and still
cleans up the target. While the target exports or zips, the line shows how
many MB it has written so far and how long the step has run, so a big log
no longer looks frozen. Two boxes under the bar:

  Run Hayabusa and Takajo in their own console window
      Shows their own progress bar and time remaining. The log pane then only
      records start, finish and exit code.
  Open the run log in Notepad when a job finishes
      Every job's full output - including Hayabusa's and Takajo's summary
      tables - is saved as logs\run_<job>_<date>_<time>.txt.

Each tab also has a "Show command" button: the same job as PowerShell to
copy and paste, filled in from what is on the tab. See MANUAL PROCEDURES.


WHERE THE FILES GO
------------------

    input\
      targets\                 YOU PUT FILES HERE: host lists for the Collect
                               tab, one host per line (.txt)

    evtx\<host>_<timestamp>\   collected logs, or drop your own EVTX here.
                               Collect writes here, Convert reads from here.
                               The Settings tab can move this folder.

    pcap\                      your accountability captures (Settings tab)

    archive\<host>_<timestamp>.zip
                               raw EVTX archived by the Settings tab - or
                               wherever the Settings tab points it, such as
                               \\server\share\evidence. Made on first use.

    output\
      hayabusa\                what Hayabusa produced
        results.jsonl          raw timeline    ->  Takajo tab
        results.ecs.jsonl      ECS transform   ->  Upload tab
        results.csv            optional analyst copy, local only
        results-summary.html   Hayabusa's own results summary, as a web page
        jobs\<host folder>\    the same three files, per host, from the
                               queue (see THE QUEUE)
      takajo\                  what Takajo produced
        case-1, case-1-2 ...   automagic CSV results, one folder per run
        html\                  offline HTML report

    logs\                      mission_<date>_<time>.log: everything the log pane
                               showed in that session. run_<job>_<date>.txt:
                               one job's full output, summary tables included.
      activity_log.csv         EVERY port test, access check, collection,
                               conversion, upload and archive, across all
                               sessions -
                               see ACTIVITY LOG below.
      queue.json               the queue, saved on every change
      queue\<host>_<id>.log    everything one queued job's steps printed

The folders are created when the tool starts. Paths follow wherever this
folder is copied - nothing is tied to one machine (a drop folder or archive
chosen on the Settings tab is the exception: Default puts it back).

The two .jsonl files are NOT interchangeable. results.jsonl feeds Takajo;
results.ecs.jsonl feeds the ELK upload. Both tabs check what you
give them and will tell you if it is the wrong one.


TARGETS (COLLECT TAB)
---------------------

Type IP addresses or host names, one per line or comma-separated, or "Load
target file..." (a .txt from input\targets\). The count under the buttons is
how many hosts the collection will visit - each once. "Expand list..." opens
every target in a large window to scroll, paste or delete; "Tidy" sorts them
(IP addresses in number order, then names) and drops duplicates; OK puts the
list back in the tab and the loaded file becomes part of it.


CREDENTIALS (COLLECT TAB)
-------------------------

The account needs local administrator rights ON THE TARGET. Fill in the
Domain box and type the plain username - the tool adds the right prefix for
every target, and the hint under the box shows the exact account it will use:

    Domain = CORP, user      every target logs in as CORP\user
    Domain = corp.local      every target logs in as user@corp.local - a
                             domain name with a dot becomes this form, which
                             always works for a real AD domain
    Domain empty, user       each target logs in as ITSELF\user - a local
                             account, e.g. 192.0.2.48\user
    OTHER\user or user@upn   used exactly as typed; the Domain box is ignored

One Domain applies to the whole run. A target not on that domain simply
fails on its own - the rest still collect. Clear the Domain box and press
RETRY FAILED to try it with a local account.

Both domain and local accounts work, over SMB and over WinRM.

RESULTS: when a run ends, the log shows RESULTS BY TARGET - one line per
target with OK / PARTIAL / FAILED, the account used and the logs collected -
and saves the same as evtx\collection_<date>_<time>.csv.

Two Windows rules that bite local accounts:

- A local admin that is NOT the built-in Administrator is stripped of its
  admin rights over the network unless the TARGET has
  LocalAccountTokenFilterPolicy=1:
      New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -PropertyType DWord -Value 1 -Force
  Symptom: "Access is denied" with a password you know is right.
  This setting weakens the target (it lets every local admin account act
  remotely, which is what pass-the-hash attacks rely on). Prefer a domain
  account, LAPS or the built-in Administrator; if you set it, remove it
  when the collection is done:
      Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy

- WinRM to a workgroup target (or any IP) needs the target in the client's
  TrustedHosts, and the WinRM service running on YOUR machine:
      Start-Service WinRM
      Set-Item WSMan:\localhost\Client\TrustedHosts -Value <target> -Concatenate -Force
  Verify Access does the TrustedHosts part for you if the tool runs as
  administrator. Symptom without it: "the destination machine must be added
  to the TrustedHosts configuration setting".

- WinRM over HTTPS (port 5986) is for targets whose plain WinRM listener is
  turned off by policy. It needs no TrustedHosts change and no admin rights
  on YOUR machine, but the TARGET needs a certificate and an HTTPS listener:
      winrm quickconfig -transport:https
  The certificate must be trusted here and carry the name you type. If it is
  self-signed, or you typed an IP address, tick "Skip certificate check": the
  data is still encrypted, but nothing proves the target is the machine you
  meant. TEST PORTS shows which of 5985 / 5986 each target offers, and a
  collection on the wrong one says which one to pick instead.

Use VERIFY ACCESS before a real collection: it proves the port, the
credentials, the log folder and that Security.evtx is genuinely readable,
in seconds.


WHAT A COLLECTION LEAVES ON THE TARGET
--------------------------------------

Nothing is installed or copied onto a target, and no script file is left
there. But a collection is a remote admin logon, and the target logs it:

- SMB: mounts C$ and copies the log files. Nothing runs on the target.
  Leaves a network logon (Security 4624 type 3, 4672) and, where file-share
  auditing is on, share-access events (5140/5145).

- WinRM / WinRM over HTTPS: opens a remote PowerShell session (wsmprovhost.exe
  runs on the target), runs wevtutil once per log into
  C:\Windows\Temp\EVTX_Export_<8 hex>, hashes and zips the exports, then
  deletes them. Leaves the same logon events, Windows PowerShell 400/403,
  WinRM/Operational events, PowerShell 4104 script blocks where script-block
  logging is on, and a process event per wevtutil where process auditing or
  Sysmon is on.

The collected logs therefore contain some of the collection itself: each log
is a snapshot taken when it is exported, so the logon is in Security, and
Sysmon - exported LAST on purpose - holds the wevtutil runs for the others.
Hayabusa will flag some of it: "Remote PowerShell Session (PS Classic)" (low)
on every WinRM collection, "Remote PowerShell Session Host Process (WinRM)"
(medium) where process auditing or Sysmon is on, and informational logon
rules. Expect to see your own collection account in the results.

The tool marks them for you. Each collection's manifest.json records the
visit (your account, your address, the times, the staging folder), and the
conversion tags every detection that matches it  evtxer-collection  - tagged,
never deleted. In Kibana add   NOT tags:evtxer-collection   to hide them, or
tags:evtxer-collection to see exactly what the collection caused. A dedicated
collection account makes the match even cleaner.

On the network, Security Onion / Zeek records the SMB or WinRM session and
its authentication, and an EDR on the target may report remote PowerShell.
TEST PORTS touches tcp/445, 5985 and 5986 on every target.

"Not on this host": a log the target does not have (Sysmon not installed,
AppLocker on a Home edition, Task Scheduler's log switched off) is listed as
not on the host and does NOT count against it. A log that exists but fails
to arrive still makes the host PARTIAL - and so does a missing Security,
System, Application or PowerShell log, which every Windows host has: if one
of those is "missing", something on that host is wrong.


MANUAL PROCEDURES (IF THE TOOL BREAKS)
--------------------------------------

The Show command button on each tab gives these with YOUR paths and targets
filled in - use that if the tool still opens. The examples below assume this
folder is C:\EVTXER; replace that, <TARGET> and <USER> with your own. Paste
into PowerShell. For the collection, open it with "Run as administrator".

1. Collect over WinRM (the DFIR preset). For WinRM over HTTPS add
   -UseSSL -Port 5986 to New-PSSession (and, for a self-signed certificate
   or an IP target, -SessionOption (New-PSSessionOption -SkipCACheck
   -SkipCNCheck -SkipRevocationCheck)) and skip the TrustedHosts lines.
   For a domain account write the Account as 'CORP\<USER>'.

    # Manual EVTX collection over WinRM - what COLLECT does, step by step.
    # Paste into an ELEVATED PowerShell on this workstation. Nothing is installed
    # on the target. It asks for the password; nothing here stores it.
    $hosts = @(
        @{ Name = '<TARGET>'; Account = '<TARGET>\<USER>' }
    )
    $logs  = @(
        'Security'
        'System'
        'Application'
        'Windows PowerShell'
        'Microsoft-Windows-PowerShell/Operational'
        'Microsoft-Windows-TaskScheduler/Operational'
        'Microsoft-Windows-Windows Defender/Operational'
        'Microsoft-Windows-CodeIntegrity/Operational'
        'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
        'Microsoft-Windows-WMI-Activity/Operational'
        'Microsoft-Windows-Bits-Client/Operational'
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
        'Microsoft-Windows-AppLocker/EXE and DLL'
        'Microsoft-Windows-AppLocker/MSI and Script'
        'Microsoft-Windows-Sysmon/Operational'
    )
    $out   = 'C:\EVTXER\evtx'
    $pw    = Read-Host -AsSecureString 'Password'
    $stage = 'C:\Windows\Temp\EVTX_Export_00000000'

    # Workgroup or IP targets: WinRM needs them in TrustedHosts. Note the value
    # printed here so you can put it back afterwards (last line).
    Start-Service WinRM
    (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value (($hosts | ForEach-Object { $_.Name }) -join ',') -Concatenate -Force

    # WinRM: export each log ON the target with wevtutil (it reads logs Windows
    # holds open), pull the files back, then delete the staging folder.
    foreach ($h in $hosts) {
        $cred = New-Object System.Management.Automation.PSCredential($h.Account, $pw)
        $s = New-PSSession -ComputerName $h.Name -Credential $cred
        $dest = Join-Path $out ('{0}_{1}' -f $h.Name, (Get-Date -Format 'yyyyMMdd_HHmm'))
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Invoke-Command -Session $s -ArgumentList $stage, $logs -ScriptBlock {
            param($stage, $logs)
            New-Item -ItemType Directory -Path $stage -Force | Out-Null
            foreach ($l in $logs) {
                wevtutil epl $l (Join-Path $stage (($l -replace '[/\\]', '_') + '.evtx')) /overwrite:true
            }
        }
        Copy-Item -FromSession $s -Path "$stage\*.evtx" -Destination $dest
        Invoke-Command -Session $s -ArgumentList $stage -ScriptBlock { param($stage) Remove-Item -LiteralPath $stage -Recurse -Force }
        Remove-PSSession $s
        Get-ChildItem $dest -Filter *.evtx | Get-FileHash -Algorithm SHA256 |
            Export-Csv (Join-Path $dest 'hashes.csv') -NoTypeInformation
    }

    # Afterwards, put TrustedHosts back to the value printed above:
    # Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<old value>' -Force

   Over SMB instead (nothing runs on the target; a log Windows holds open
   may refuse to copy):

    New-Item -ItemType Directory -Path 'C:\EVTXER\evtx\<TARGET>' -Force
    New-PSDrive -Name EVTXSRC -PSProvider FileSystem -Root '\\<TARGET>\C$' -Credential (Get-Credential)
    Copy-Item 'EVTXSRC:\Windows\System32\winevt\Logs\Security.evtx' 'C:\EVTXER\evtx\<TARGET>\'
    Remove-PSDrive EVTXSRC

   (a channel's file name is its name with / written as %4, e.g.
   Microsoft-Windows-Sysmon%4Operational.evtx)

2. Scan with Hayabusa:

    # Manual Hayabusa scan - exactly what SCAN + CONVERT runs first.
    # Hayabusa finds its rules folder from the current folder, so run it from its own.
    Set-Location 'C:\EVTXER\code\hayabusa-x64'
    & 'C:\EVTXER\code\hayabusa-x64\hayabusa-4.2.0-win-x64.exe' dfir-timeline -d 'C:\EVTXER\evtx' -o 'C:\EVTXER\output\hayabusa\results.jsonl' -t JSONL -p super-verbose -w -O -b -C -H 'C:\EVTXER\output\hayabusa\results-summary.html'

3. Convert for the upload (results.jsonl -> results.ecs.jsonl):

    # Manual ECS conversion - the same function the Convert tab runs.
    # Start PowerShell with:   powershell -ExecutionPolicy Bypass
    . 'C:\EVTXER\code\HayabusaLib.ps1'
    $script:ToolVersion = 'NN'   # NN = the number in EVTXER's title bar - stamps agent.version
    Convert-HayabusaJsonlToEcs -Source 'C:\EVTXER\output\hayabusa\results.jsonl' -Destination 'C:\EVTXER\output\hayabusa\results.ecs.jsonl'

4. Takajo:

    # Manual Takajo - what RUN AUTOMAGIC and BUILD OFFLINE HTML run.
    # Takajo reads conf\ and templates\ from the CURRENT folder, so run it from its own.
    Set-Location 'C:\EVTXER\code\takajo'

    # automagic: every CSV analysis into a NEW folder (it refuses one that exists).
    & .\takajo-2.16.1-win-x64.exe automagic --timeline 'C:\EVTXER\output\hayabusa\results.jsonl' --output 'C:\EVTXER\output\takajo\case-1' --level informational --quiet

    # html-report: --output must be RELATIVE to the takajo folder (it prepends ./).
    & .\takajo-2.16.1-win-x64.exe html-report --timeline 'C:\EVTXER\output\hayabusa\results.jsonl' --output '..\..\output\takajo\html' --rulepath 'C:\EVTXER\code\hayabusa-x64\rules' --dboutput 'C:\EVTXER\output\takajo\takajo-report.sqlite' --sqlite --clobber --quiet


THINGS WORTH KNOWING
--------------------

- SMB does not encrypt the collected log data in transit (by default). WinRM
  does, on either port. Neither sends your password in cleartext.

- A red "UNEXPECTED ERROR" line in the log means the tool hit a bug, caught it
  and kept running. Finish what you were doing, then send the log file it
  names (logs\mission_<date>_<time>.log) so it can be fixed.

- The upload pins the Elasticsearch certificate by default. Press Fetch, confirm
  the fingerprint once, and every later connection must match it.
  The Dashboards tab needs a SECOND fingerprint (its own Fetch button):
  Security Onion's web interface on port 443 uses a different certificate
  from Elasticsearch on 9200. Without it the import fails with "Could not
  establish trust relationship for the SSL/TLS secure channel".

- Something failed? Every run writes logs\mission_<date>_<time>.log with
  everything the log pane showed. Send that file along with the version
  number from the title bar.

- Fields marked * are required. The rest are optional.

- Every collection writes manifest.json beside the logs: a SHA-256 of each
  file. Over WinRM the copies are hashed ON THE TARGET first and compared, so
  the manifest shows the transfer was faithful, not just that files arrived.
  SMB reads live logs that Windows is still writing to, so those are hashed
  once, locally, and recorded as "not compared" rather than as verified.

- If a host fails or comes back partial, RETRY FAILED collects just those
  hosts again - fix the credentials or the firewall first, the button reads
  them fresh.

- Before collecting, free space is checked against an estimate. It warns, it
  does not refuse: the estimate is a rule of thumb.

- Index names must start with "hayabusa-". This is deliberate: it stops the
  tool writing into the stack's own indices (Security Onion's, or a plain Elastic stack's).
  Capitals are lowercased as you type. After an upload the tool reads the
  index back and says how many documents Elasticsearch holds in it.

- Case / label fills in from the last collection: one target becomes its IP,
  several become their range and a count (10.1.2.3-40-5hosts). A label you
  typed yourself is never replaced.

- While anything runs, "Things are cookin'" spins at the top and every tab is
  locked. The CANCEL button beside the log stays usable.

- If the connection drops during a collection, nothing half-copied is kept:
  files land as <name>.partial and get their real name only when complete.
  Files that fully arrived stay. Press RETRY FAILED to collect the host again
  into a fresh folder. A WinRM hash mismatch makes the host PARTIAL too. If
  the export folder could not be removed from the target, the log names it
  (C:\Windows\Temp\EVTX_Export_<8 hex>): delete it by hand, or the next WinRM
  collection from that host removes it once it is a day old.

- Every detection EVTXER converts says which EVTXER made it and when:
  agent.version (the EVTXER version) and event.ingested (when it was
  converted). A conversion typed by hand (MANUAL PROCEDURES) needs its
  $script:ToolVersion line for that - Show command writes it. In Kibana,
  agent.version : 72 shows only what v72 converted - handy when one index
  holds uploads from several versions. The version is not part of the
  detection's id, so a newer EVTXER does not duplicate old detections.

- Nothing is uploaded twice. Every detection carries a fixed id
  (event.id), and Elasticsearch refuses one it already holds. So: a host
  pulled again two weeks later adds only its NEW detections (the old ones
  stay, even if they have rolled out of the target's log since); the same
  logs pulled twice by mistake, or the same file uploaded twice, add
  nothing; an upload that dropped part way can simply be run again into the
  SAME index (tick "Allow appending"). The result line says how many were
  new and how many were already there. An ecs.jsonl converted before v36
  has no ids: convert it again to get this. An index that already holds
  detections from before v36 is named in the log: the same logs uploaded
  into it again are stored twice - use a new index for those.

- "Update detections already in the index" (beside UPLOAD): a detection
  already stored is replaced by this upload's copy instead of skipped -
  for a re-upload after a newer version of this tool converted the same
  logs with more fields. Still never doubles. Appending into an index made
  by an older version also adds the newer field mappings to it (needs the
  'manage' right on the index; the log says if it was refused).

- The ECS conversion uses every CPU core but one (up to 16), and the upload
  reads the file as it sends it, so a batch of half a million detections
  needs no more memory than a small one. More cores on the VM = faster
  conversion; more RAM does not matter for it.

- Hayabusa outputs only events that MATCH A RULE, not every record. After
  each scan the log says how much: "COVERAGE: 3,140 of 7,053 event records
  matched a rule". To have every raw event searchable as well, use Security
  Onion's own importer (below).

- In Kibana's Discover the rule bookkeeping (rule author, rule file, rule
  dates, import file, ECS version...) is hidden by the data view's field
  filters - re-import the dashboards to get this. The fields are still in
  the index: Stack Management > Data Views > hayabusa-* > Field filters
  shows them again.

- "Hayabusa - PEAK Hunt" is the hunting dashboard: every table puts the
  RAREST answers first (rare rules, quiet hosts, Office spawning shells,
  programs with hashes on one host, new services, run keys, dropped files,
  remote/RDP/NTLM logons, failed logons, Kerberoasting, credential access,
  rare ports and DNS, PowerShell script text). Start at panel 1 and click a
  value to filter the rest. The (i) beside each title says what to look for.
  Its newer panels need data converted with v34 or later (they use the
  logon type, service, file, registry, DNS and script-block fields): older
  uploads still show in the other panels.

- Every field of a detected event is its own field, under its real Windows
  name: winlog.event_data.TargetUserName, .IpAddress, .LogonType,
  .CommandLine, .ServiceName ... - the names Winlogbeat and Security Onion
  use. In Discover, pick them from the field list as columns or click a
  value to filter; in a visualization, chart them. Hayabusa's short names
  (TgtUser, SrcIP) are translated back using Hayabusa's own tables.
  hayabusa.details still holds Hayabusa's one-line summary. This needs data
  converted with v37 or later, uploaded into a NEW index (an index created
  before v37 does not map these fields, though they are still stored).
  Values are as Hayabusa reports them, e.g. LogonType "3 - NETWORK".

- "Hayabusa - Results Summary" is Hayabusa's own end-of-scan summary (and
  its logon-summary), rebuilt from the uploaded detections: totals and
  unique rules per level, the busiest day per level, the computers with
  the most distinct detections, every alert, the timeline, and successful
  and failed logons. Checked against Hayabusa's HTML report on its 600-file
  sample set: the same numbers, except that Total detections counts each
  detection once where Hayabusa counts every copy of a duplicated log.

- "Hayabusa - MITRE ATT&CK" holds the tactic and technique panels, which
  used to sit on the Overview and PEAK dashboards. Only detections whose
  rule carries an ATT&CK tag appear there; its first panel says how many.

- "Raw Events - Anomaly Hunt (Security Onion)" and "Hayabusa - Anomaly
  Hunt" (every raw event / the detections; the second also works on plain Elastic)
  hunt for what "rarest first" misses, in seven numbered sections:
    1. Only on one machine - programs, services, scheduled tasks, accounts,
       parent > child programs, PowerShell start lines: fewest machines first
    2. New lately - first seen, newest first, on the whole network and on
       each machine (a tool arriving on one more machine = lateral movement)
    3. Odd hours - machine x hour of day / day of week heatmaps (UTC: the
       logs store UTC, the target's time zone is not in them)
    4. Wrong place - svchost.exe & co outside System32, anything run or
       installed from Temp, AppData, Users\Public, Downloads, the Recycle Bin
    5. Bursts - events and failed logons per machine per day
    6. Fan-out - one account on many machines, one source trying many
       accounts, one machine reached from many sources
    7. Longest command lines - process, PowerShell start and service lines
  Most targets keep default Windows logging: program starts (sections 1, 2,
  4, 7) need Sysmon or process-creation auditing (4688) and show "No
  results" without them; services (7045), logons and PowerShell starts
  (400) are always there. Scheduled tasks need the TaskScheduler log or
  4698 auditing, both OFF by default on Windows 10/11 - often empty.
  Windows' own accounts (SYSTEM, DWM-n, OpenSSH's sshd_n ...) are left out
  of the account panels, but only when the event carries their real SID -
  a look-alike stays visible. Loopback (::1, 127.0.0.1) is not a fan-out
  source. On real machines
  start with sections 4, 6 and 7, then use 1 and 2 as leads. Tested on
  Hayabusa's attack samples mixed with two real workstations: the attacks
  surface near the top of every section.


THE QUEUE (AUTOMATIC PROCESSING)
--------------------------------

The operator only collects. Every host the Collect tab brings in becomes a job
in the QUEUE at the bottom of the window (always in sight, whatever tab is
open), and the rest runs by itself, one host at a time:

    scan with Hayabusa -> convert to ECS -> upload to the mission index
    -> raw import to Security Onion -> archive

Which of those steps run is ticked on the queue pane itself, "Runs by
itself:" (Convert, Upload, Raw import to SO, Archive when done).
Out of the box: convert and upload ON; raw import and archive OFF (archive
deletes the original EVTX after a verified zip, and raw import sends them to
another server - both are your call). A change applies to hosts queued from
then on.

The colour of a row is the step it is on or waiting for:

    blue    scan            purple  ECS          teal   upload
    indigo  raw import      tan     archive
    AMBER   waiting for you - the row says what for
    green   done            red     failed or cancelled - the row says why

Every row has a bar, filling left to right, for how far that host has got
(each step an equal share). A row that is working MOVES: converting,
uploading, archiving and the raw import count up ("copying file 37 of 149");
the Hayabusa scan and Security Onion's own import cannot measure themselves,
so their bar runs back and forth and the scan shows its CPU time climbing.
A bar that stands still is waiting - the row says what for.

A job waits (amber) instead of failing when it needs you:
- upload: name the mission (Settings tab) and press VERIFY CONNECTIVITY on
  the Upload tab. With "Remember password" ticked, that is one click per
  session.
- raw import: fill in the Raw Events tab - host, user, password, host key.
While one host waits, the next one is scanned; the waiting one goes on by
itself as soon as it has what it needs.

Buttons: Move up / Move down / Run next (to the top: it runs as soon as the
step running now finishes), Retry (a failed job starts again at the step that
failed), Cancel (stops the running job), Remove (takes a job off the list -
its files stay), Clear done, Add folders... (queue host folders already in
the drop folder, e.g. copied in from a USB stick), Open log (everything the
selected job's steps printed), Hide.

Each job writes its own results, never anyone else's:
output\hayabusa\jobs\<host folder>\results.jsonl, results.ecs.jsonl and
results-summary.html. Every step is a row in the activity log.

The queue is saved (logs\queue.json) and survives a restart or a crash.
Closing EVTXER while a job runs asks first; the step stops, and the job starts
again at that same step the next time EVTXER opens. Every step is safe to
run again: Hayabusa and ECS rewrite that job's own files, the upload refuses a
detection it already holds, Security Onion skips a file it already has, and
the archive zips whatever is still there.

The first network step of a session asks the accountability PCAP question
once for the whole queue (see ACCOUNTABILITY PCAP).

The manual Archive list on the Settings tab does not offer a folder the queue
still needs, and "Delete mission index..." refuses while queued uploads remain.


ANTIVIRUS ON THE EVTXER MACHINE (READ BEFORE A MISSION)
-------------------------------------------------------

Logs from a compromised machine contain the attacker's own commands - a
Mimikatz command line, a PowerShell attack script - and so do Hayabusa's
results, which quote them. Windows Defender on the machine running EVTXER
can treat those files as malware: measured on 2026-10-16, it blocked copies
of a sample log and LOCKED Hayabusa's own results file mid-run. On a mission
that means evidence quarantined, or a scan or upload that fails for no
visible reason.

Before a mission, whoever manages the EVTXER machine should add a Defender
exclusion for EVTXER's evidence and results folders (not the whole drive),
for example:
    <EVTXER folder>\evtx      <EVTXER folder>\output     <EVTXER folder>\archive
(or wherever the Settings tab moved the drop folder and the archive).
In Windows Security: Virus & threat protection > Manage settings >
Exclusions > Add an exclusion > Folder. It needs administrator rights.

Symptoms that it is Defender: "Permission denied" or "Access is denied" on
a file EVTXER itself just wrote, files vanishing from evtx\ or output\, or
Windows Security > Protection history listing EVTXER's folders.


HAYABUSA RULES (SETTINGS TAB)
-----------------------------

New detection rules come out every few days. The Settings tab shows how many
rules EVTXER has and when they were last updated.

- UPDATE RULES (internet): fetches the latest hayabusa-rules from GitHub
  (Hayabusa's own update-rules). Asks the accountability PCAP question first.
- Update from file...: for a machine with no internet. On a connected
  machine open github.com/Yamato-Security/hayabusa-rules, Code, Download
  ZIP; bring the zip over and pick it here.
- Restore previous rules: the rules from before the last update come back
  (and the replaced ones become the backup, so it can be undone).

The rules in use are always kept as a backup and come back by themselves if
an update fails or is incomplete. Every update is in the activity log.
While the rules are being replaced, the queue holds any scan or conversion.

If EVTXER sits in a very deep folder, the update is refused: some rule files
have long names, and Windows cannot write a path past 260 characters. Move
the EVTXER folder somewhere shorter, such as C:\EVTXER.


MISSION (SETTINGS TAB)
----------------------

Name the mission once (e.g. op-falcon). Every upload of it goes into one
index, hayabusa-mission-op-falcon - the same index on every day and for every
host, appended to. A detection is never stored twice: each has a fixed ID.
"Use on the Upload tab" puts that index in the Upload tab (and the tab starts
on it when EVTXER opens).

When the mission is over, "Delete mission index..." removes it: it needs a
verified connection on the Upload tab, shows how many detections are in it,
and deletes only after you type the index name exactly. It can only ever
delete that one hayabusa- index. The deletion is in the activity log.


ONE OPERATOR AT A TIME
----------------------

Only one EVTXER can be open per copy of the tool - also across RDP sessions
on a shared server. A second one says who has it open ("EVTXER is already
open by DOMAIN\user since 08:12") and closes. Two separate copies on one
server do not block each other. If EVTXER crashes the copy is free again at
once; nothing needs unlocking.


REMEMBERED PASSWORDS
--------------------

Passwords are not saved unless you tick "Remember" beside one (Upload tab:
Elasticsearch; Raw Events tab: SSH). Then, after a SUCCESSFUL check, it is
kept encrypted with Windows' own DPAPI for your Windows account on this
machine:
- in your profile (%LOCALAPPDATA%\EVTXER\secrets), never in the tool
  folder - a copy of the tool or a handoff package cannot carry it;
- no other Windows account and no other computer can decrypt it;
- one per server and user - it is only ever filled in for that connection.
"Forget" deletes it; so does unticking Remember and checking again.


ACCOUNTABILITY PCAP (SETTINGS TAB)
----------------------------------

Capture your own traffic while EVTXER works, so every packet of the mission
can be shown afterwards. Needs Wireshark (with Npcap) on this machine; EVTXER
uses its dumpcap.

- Settings tab: Wireshark folder (found by itself in the usual place), the
  interface to capture (Refresh lists them), the PCAP folder (default pcap\
  beside evtx\), and START CAPTURE / Stop capture.
- Every file is kept: a new file every 3 GB, never a ring buffer. The status
  line warns when the PCAP folder has less than 10 GB free - the capture
  stops when the disk is full.
- The capture keeps running when EVTXER closes. If one is already running
  (started by EVTXER, by Wireshark or by hand) the tab shows what it captures
  and offers no second one. Stop capture stops every dumpcap on the machine
  and says so first.
- If Npcap was installed for administrators only, Start capture asks Windows
  to run dumpcap elevated (one UAC prompt).
- To SEE it working, Wireshark opens on the same interface when a capture
  starts ("Watch in Wireshark" opens it any time; a tickbox turns that off).
  It is only a viewer: it keeps the last few MB, and closing it does not stop
  the recording.
- Before every network action - collect, verify, test ports, upload, index
  check, dashboards, certificate fetch, raw import, archive to a share - EVTXER
  asks "Is accountability PCAP started?":
    START CAPTURE   start it now, then carry on
    OK              carry on without one (noted in the log)
    Don't remind me until tomorrow
  Closing the question cancels the action. It is not asked while a capture is
  running, and the reminder can be switched off on the Settings tab.
- Starting and stopping a capture are rows in the activity log.


ARCHIVE (SETTINGS TAB)
----------------------

Once a host's logs are converted and uploaded, ARCHIVE SELECTED moves them
out of the drop folder:

- One zip per host folder: its .evtx and its manifest.json (the SHA-256 of
  each file as it was collected). Nothing else - Hayabusa's output stays in
  output\.
- The zip is written as <name>.zip.partial. Every file is hashed as it goes
  in, then the whole zip is read back and every file hashed again; only a
  zip that matches gets its real name, and only then is the host folder
  deleted. A file that changed in the meantime is left where it is.
- Cancel, a full disk or a dropped share deletes the .partial and leaves the
  host folder exactly as it was.
- The archive can be a network share (\\server\share\folder). Nothing is
  stored to log on to it: if Windows Explorer can open the share as you, so
  can the tool. A host archived twice gets <name>-2.zip; nothing is ever
  overwritten.
- Each host folder archived is a row in the activity log, with the zip's
  path.
- Measured: 1.3 GB of EVTX (5,980 files) to an SMB share in 20 seconds,
  verification included; EVTX compress to about a sixteenth.


ACTIVITY LOG
------------

logs\activity_log.csv - one row per thing the tool did, across every
session, never rewritten: date, time (local and UTC), your Windows account,
this machine and its IP, the action (Port test, Verify access, Collect,
Convert, Verify connection, Upload, SO import, EVTX archive), the target,
port and protocol, the account used on the target (never a password), the
result, files, size, duration, the hash verdict, anything left on the
target, the output folder, zip or index, and the tool version.

It is written as each action finishes, so it survives closing the tool, a
crash or a reboot, and every later session adds to the same file. Re-copying
a new version of the tool never touches logs\.

"Open activity log" (beside the log) opens a COPY in Excel. "Export..." saves
the whole log wherever you choose (a USB stick, a share) to hand over:
  .csv - every column, opens in Excel
  .txt - a readable report, one block per action, empty fields left out
If you open the real file in Excel yourself, Excel locks it: new rows then
wait in activity_log-pending.csv and are added the next time the file is
free. An export includes those waiting rows too.

"Network log..." saves the network log (.csv for Excel): only the actions that went
over the network - port tests, access checks, collections, uploads, Security
Onion imports, rule downloads, archives to a share - one row each, in these
columns: Date / time, Target IP, Command run, Success (Yes / No / Partial),
Pulled / sent, Duration, Notes (the integrity check, or why it failed).
Scanning, converting and a local archive never touch a target, so they stay
in the full activity log only.

"Logs folder" opens logs\ in Explorer, for troubleshooting: mission_*.log
(everything a session printed), run_*.txt (each Hayabusa/Takajo run, the
log Notepad opens after a job), queue\ (each queued job's steps) and the
activity log.


EVERY RAW EVENT, NOT JUST DETECTIONS (SECURITY ONION)
-----------------------------------------------------

Security Onion has its own EVTX importer, so-import-evtx, that indexes every
record, raw, into its own logs-import-so data stream (not hayabusa-*). Tab 6
runs it for you:

  - Manager host, SSH user and password (an account that may sudo), then
    Fetch the host key and confirm the fingerprint with the admin (on the
    manager: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub). TEST
    CONNECTION checks SSH, sudo and the importer.
  - Folder: defaults to evtx\ (every collected host); any folder of .evtx.
  - IMPORT TO SECURITY ONION copies the files to a private temporary folder
    on the manager, runs sudo so-import-evtx, deletes the folder again
    (after a failure or Cancel too) and shows the link to the events.
  - WHEN: Security Onion 2.4 files imported events under the time of the
    IMPORT, not when they happened (checked on 2.4.211: its importer keeps
    the event's own time only in event.created). The link the tab shows
    covers both - from the oldest event to tomorrow - so use it, or search
    import.id over the last day. To sort by when things happened, add the
    event.created column.
  - A file already imported is skipped - Security Onion names each import
    after the file's MD5 - so sending the same logs twice adds nothing.
  - DISK: each import reads the manager's free space once, on the call that
    stages the files (df of /tmp and /nsm - nothing is polled), and warns
    "LOW DISK on the manager" when /tmp cannot hold the files or /nsm would
    pass 85% full (Security Onion keeps a copy of the files and indexes
    every event - about 3x the EVTX, a rough rule; Elasticsearch refuses new
    data at 95%). A warning only: the import still runs. Before a big run,
    check on the manager:  df -h /tmp /nsm
  - The password is never on a command line, never in the
    log: PuTTY's plink/pscp (code\putty) read it from a temporary file only
    your Windows account can read, deleted straight after.
  - The manager must be a manager-type node (standalone, eval, import or
    manager) - so-import-evtx refuses to run anywhere else.

By hand, the same thing is:

  1. Copy the collected .evtx files to the manager (WinSCP, or scp):
       scp evtx\<host>_<timestamp>\*.evtx <user>@<manager>:/tmp/evtx-import/
  2. On the manager:
       sudo so-import-evtx /tmp/evtx-import/*.evtx
  3. It prints a link to the imported events.

Or in the web interface: Grid -> the manager -> upload an .evtx; it runs the
same importer. Search the raw events beside the Hayabusa index: detections
for triage, raw events for context. A plain Elastic stack has no
so-import-evtx; there, Winlogbeat can read .evtx files instead.


HOST LINKS - DETECTIONS AND RAW EVENTS, PER MACHINE
---------------------------------------------------

After an upload (Upload tab) or a raw import (Raw Events tab), each machine
gets two links under the result, and the same URLs go into the log:

  Hayabusa detections   Kibana Discover, the detections data view, that
                        machine only
  Raw events            Security Onion's dashboards, its raw events

Both cover ALL time: every collection ever made of that machine, so two
missions against the same host line up on one timeline.

The machine is named as its own events name it (the Computer field), not
by the folder or the IP you typed. One machine often writes both WIN10 and
WIN10.corp.local; the links find both, in any case.

A link that cannot be built yet says why instead: the detections link
needs one upload first (to learn the Kibana data view, then remembered),
the raw link needs the Security Onion manager on the Raw Events tab.
Security Onion only for the raw side - a plain Elastic stack has no raw
events.


FINDING THINGS: TIME, PIVOTS, WHERE DATA LANDS
----------------------------------------------

Where each kind of data goes:

  Detections (Upload tab, queue's Upload)
      Into the mission's own index, hayabusa-mission-<mission name>. Seen
      in KIBANA only: Discover (data view "Hayabusa EVTX detections") and the Hayabusa
      dashboards. NOT in Security Onion's Hunt or Alerts - those search
      Security Onion's own indices, and a separate index can be dropped
      cleanly. Same on a plain Elastic stack.
  Raw events (Raw Events tab, queue's Raw import to SO)
      Into Security Onion's own logs-import-so data stream. Seen in
      Security Onion's Hunt and Dashboards, and in Kibana's Raw Events
      dashboards. Security Onion only.

Detections are not the whole log. Hayabusa sends only what a rule matched:
the matched events, with the fields Hayabusa extracts (winlog.event_data.*,
hayabusa.details). The full event - and every event no rule matched - is
only in the raw import.

TIME. A detection's @timestamp is when the event happened on the machine,
in UTC (Kibana shows it in the browser's time zone). Raw events are
different: Security Onion 2.4 files an import under the time of the
IMPORT, so their @timestamp is when you imported them, and the event's own
time is in event.created (checked on Security Onion 2.4.211).
  - In Security Onion's Hunt / Dashboards: set the time range to cover the
    import (today, if you imported today), add the event.created column
    and sort by it.
  - In Kibana: the Raw Events dashboards, or Discover with the data view
    "Raw Windows events (Security Onion)". Its time field is event.created,
    so the time picker and every chart follow when things really happened.

FROM A DETECTION TO THE FULL LOG (the pivot). Three fields name one event:
the machine, the log and the record number. From the detection take

    host.name   winlog.channel   winlog.record_id

and search the raw events (Hunt, or Kibana Discover with the data view
"Raw Windows events (Security Onion)") for

    winlog.computer_name:"WS01" AND winlog.channel:"Security" AND winlog.record_id:12345

AND in capitals: Security Onion's search reads a lower-case "and" as a word
to find, and finds nothing. The values are case-sensitive: type them
exactly as the detection shows them. The host links (HOST LINKS above) do the machine part for you.

WHICH VERSION, WHEN. Every detection EVTXER converts carries agent.version
(the EVTXER that converted it, from v72) and event.ingested (when). agent.version : 72 in
Kibana shows only what v72 converted.


SECURITY ONION: LETTING EVTXER IN
---------------------------------

Security Onion's firewall only lets listed machines reach it. EVTXER needs:

  Upload tab            port 9200 (Elasticsearch)
  Dashboards tab        port 443  (the web interface - analysts usually have it)
  Raw Events tab        port 22    (SSH - open to anywhere by default)

USUALLY NOTHING TO DO. If uploads from this machine have worked before, or
VERIFY CONNECTIVITY on the Upload tab succeeds, this machine is already let
through - skip the firewall step. It is needed only when VERIFY CONNECTIVITY
says "Nothing answered at <manager>:9200" (or the Kibana tab cannot reach
443) although the host and port are right. That message then names this
machine's IP address and prints the exact command, filled in, to hand to the
Security Onion administrator:

    Nothing answered at so-manager:9200. ... this PC's address is 10.1.2.3.
    Ask its administrator to run on the manager:
        sudo so-firewall --apply includehost elasticsearch_rest 10.1.2.3

THE FIREWALL STEP (only then). On the Security Onion manager, an
administrator runs, with the EVTXER machine's IP address:

    sudo so-firewall --apply includehost elasticsearch_rest <EVTXER IP>
    sudo so-firewall --apply includehost analyst <EVTXER IP>

The first lets it reach Elasticsearch (9200, uploads); the second the web
interface (443, dashboards) - skip that one if a browser on this machine
already opens SOC. Nothing else in Security Onion changes. (The groups are
Security Onion 2.4's own. Checked on 2.4.211, 2026-10-16.)

The account: Security Onion copies its web-interface (SOC) users into
Elasticsearch, so the Upload tab logs in with a SOC user's email and
password. It must be allowed to create the hayabusa-* index - tested with a
SOC administrator; a plain analyst account was not tested. The Kibana
Dashboards tab uses the same account.

SINGLE SIGN-ON (SSO). EVTXER logs in with a username and password. An
account that signs in only through SSO may have no Security Onion password
(not yet tested against an SSO Security Onion). If the login is refused:
  - Uploads: use an API key (below) - make it in Kibana, signed in through
    SSO, and leave Username empty on the Upload tab.
  - Dashboards: import them by hand - in Kibana (signed in through SSO),
    Stack Management > Saved Objects > Import, the file
    kibana dashboards\hayabusa-kibana-objects.ndjson (see IMPORT.txt there).
  - Raw imports are not affected: they use an SSH account on the manager.
  - Or ask the administrator for a local (non-SSO) account for EVTXER.

SAFER: AN API KEY THAT CAN ONLY TOUCH hayabusa-* INDEXES. A SOC
administrator's password can write to every index in Security Onion. A key
cannot: Elasticsearch itself refuses it anything outside hayabusa-*. Make one
once, in Kibana > Dev Tools (logged in as an administrator):

    POST /_security/api_key
    { "name": "evtxer",
      "role_descriptors": { "hayabusa": {
        "cluster": ["monitor"],
        "index": [{ "names": ["hayabusa-*"],
                    "privileges": ["create_index","manage","read","write","view_index_metadata"] }] } } }

Copy the "encoded" value from the answer - it is shown ONCE. On the Upload
tab leave Username EMPTY and paste the key into "Password or API key".
Remember works for it too. Revoke it in Kibana > Stack Management > API keys.
With a key the upload says "This login may not change index templates" -
that is expected: a new index gets the same settings itself. The Kibana
Dashboards tab still needs a username and password (the key cannot import
dashboards). On Elastic 8.7 the same recipe should work - the API
is the same - but it was tested on Elasticsearch 9 only.

When imported raw events are searched, remember Security Onion 2.4 files them
under the time they were IMPORTED; the event's own time is event.created
(the "Raw Events - PEAK Hunt" dashboard already uses it).


PLAIN ELASTIC (NOT SECURITY ONION)
----------------------------------

The same tool works against a plain Elastic stack
(for example Elastic 8.7.0). Tested end to end against Elasticsearch + Kibana 8.7.0.

- ONE-TIME SETUP ON THE STACK: create the upload role and user first.
  Step by step: kibana dashboards\ELASTIC-SETUP.txt

- UPLOAD TAB: host = the Elasticsearch IP, port 9200, the user from
  ELASTIC-SETUP.txt. The Upload tab works the same on Security Onion
  and on plain Elastic.

- NO "Open in Kibana" LINK after an upload with the restricted account. That
  is expected. Open Discover and pick "Hayabusa EVTX detections".

- DASHBOARDS: tab 5 is for Security Onion only. On plain Elastic, import
  kibana dashboards\hayabusa-kibana-objects-8.7.ndjson by hand -
  kibana dashboards\IMPORT.txt has the browser steps.


THIRD-PARTY SOFTWARE
--------------------

EVTXER runs Hayabusa and Takajo (both by Yamato Security, GNU AGPLv3) and
PuTTY (Simon Tatham, MIT licence) as separate programs, unmodified. The
detection rules are under the Detection Rule License 1.1, and each rule's
author stays with its detections (rule.author). code\licenses\NOTICE.txt
lists every component with its copyright and licence, and that folder holds
the licence texts and the source code of Hayabusa and Takajo.

Giving EVTXER to another team is fine. Pass on the whole folder, including
code\licenses\, and the licences are met.



FOLDER CONTENTS
---------------

    EVTXER.cmd                double-click this to start (version in the
                              title bar)
  Yours - the folders you open:

    input\ evtx\ output\ logs\   created for you - see WHERE THE FILES GO
    kibana dashboards\        the dashboards themselves - tab 5 imports them
                              for you; kibana dashboards\IMPORT.txt covers
                              doing it by hand in a browser;
                              ELASTIC-SETUP.txt = role/user setup on plain Elastic;
                              the -8.7 file = dashboards for Kibana 8.7

  The tool's - leave alone; the .cmd will not start without it:

    code\                     every script, one file per tab
    code\hayabusa-x64\        Hayabusa 4.2.0 + rules (rules of 21 Oct 2026)
    code\takajo\              Takajo 2.16.1 + templates
    code\putty\               PuTTY 0.85 plink + pscp (tab 6), signed by
                              its author; LICENCE beside them
    code\assets\              the EVTXER window icon
    code\licenses\            licences of everything EVTXER ships that it
                              did not write, and the source of Hayabusa
                              and Takajo - see THIRD-PARTY SOFTWARE
    code\index-template.json  the Elasticsearch index template
    code\importer.conf        the Upload tab's saved settings (after first use)
    code\settings.conf        the Settings tab's drop and archive folders
    code\soimport.conf        tab 6's saved settings - host, user, host key
                              (never the password)
