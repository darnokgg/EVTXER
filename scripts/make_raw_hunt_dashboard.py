#!/usr/bin/env python3
"""Raw-event hunting dashboard: PEAK baseline hunts on Security Onion's raw
Windows events - the ones so-import-evtx (EVTXER's Raw Events tab) puts there.

The Hayabusa dashboards show DETECTIONS: only the events a Sigma rule matched.
This one reads EVERY event, so it finds what no rule caught - the same PEAK
idea as make_peak_dashboard.py (rare first: noise repeats, intrusions mostly
do not), on the fields Security Onion 2.4 stores (operator request,
2026-10-16: "PowerShell commands, strange PowerShell commands - PEAK").

Field names were read from a real Security Onion 2.4.211 import of the
599-file sample corpus (a lab Security Onion, 2026-10-16), not guessed:
  - the Windows machine is winlog.computer_name. host.name there is the
    Security Onion box itself ("manager");
  - winlog.event_id, winlog.record_id and every winlog.event_data.* field are
    KEYWORDS, so a query on them is exact and case-sensitive - "both cases"
    below is why;
  - 4104 script text is powershell.file.script_block_text; Sysmon 1 fills
    process.command_line (a wildcard field) and process.name/parent.name;
    4688 keeps its command line in winlog.event_data.CommandLine;
  - Windows PowerShell 400/600/800 carry their text in
    winlog.event_data.Data.#text (an array of strings);
  - log-cleared events (1102, 104) keep the account in userdata.LogFileCleared.
  - Security Onion 2.4.211 files an imported event under the time it was
    IMPORTED in @timestamp; the event's own time is event.created. So this
    data view's time field is event.created: the time picker means "when it
    happened on the host", the same clock as the Hayabusa detections.

Every panel's description (the (i) beside its title) says why it matters.

Usage:
  python scripts/make_raw_hunt_dashboard.py -o output/hayabusa-raw-hunt.ndjson
Ids start with "hayabusa-" so export_dashboards.py carries them into
kibana/hayabusa-kibana-objects.ndjson with the others.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_dashboard import stamp, col_count, col_date, datatable, labelled, xy  # noqa: E402
from make_hunt_dashboard import col_terms_ordered, lens as hunt_lens  # noqa: E402
from make_peak_dashboard import col_unique  # noqa: E402

DASHBOARD_ID = "hayabusa-raw-hunt-dashboard"
DATA_VIEW_ID = "hayabusa-raw-dataview"
SEARCH_ID = "hayabusa-raw-search-scriptblocks"
# so-import-evtx writes to logs-import-so; a Security Onion that collects
# Windows events with Elastic Agent keeps the same fields in these.
INDEX_PATTERN = "logs-import-so*,logs-windows.*,logs-system.*"
TIME_FIELD = "event.created"
# All time, as EVTXER's own per-host links: old evidence is still evidence
# (the sample corpus reaches back to 2013), and a log's events can predate
# the mission by years.
TIME_FROM = "1970-01-01T00:00:00.000Z"
TIME_TO = "now"

HOST = "winlog.computer_name"
ED = "winlog.event_data."

# Windows PowerShell 400 keeps the command line PowerShell was started with
# inside one long text (winlog.event_data.Data.#text, an array) next to a
# per-start SequenceNumber and RunspaceId - so that text is unique every
# time and cannot be ranked. This runtime field cuts out the
# "HostApplication=..." line alone. It lives in the data view.
HOST_APPLICATION = "op.HostApplication"
HOST_APPLICATION_SCRIPT = (
    "def w = params._source.winlog; if (w == null) return; def ed = w.event_data; "
    "if (ed == null || ed.Data == null) return; def t = ed.Data['#text']; if (t == null) return; "
    "if (!(t instanceof List)) { t = [t]; } "
    "for (def s : t) { if (s == null) continue; String x = s.toString(); int i = x.indexOf('HostApplication='); "
    # Painless has no '\n' escape in a string literal: the newline is made from its code.
    "if (i < 0) continue; int e = x.indexOf(Character.toString((char) 10), i); "
    "String v = e < 0 ? x.substring(i + 16) : x.substring(i + 16, e); emit(v.trim()); return; }"
)


def _cases(words):
    """KQL on a keyword is case-sensitive: each word as written (write the
    spelling Windows uses - MSBuild.exe, -WindowStyle), lower, UPPER and
    Capitalised."""
    out = []
    for w in words:
        for v in (w, w.lower(), w.upper(), w.capitalize()):
            if v not in out:
                out.append(v)
    return out


def _any(field, patterns):
    """field: (*a* or *b* ...) - patterns hold no spaces (KQL would split them)."""
    return f"{field}: (" + " or ".join(patterns) + ")"


def _names(field, exes):
    return _any(field, [f'"{v}"' for v in _cases(exes)])


def _ends(field, exes):
    return _any(field, [f"*\\\\{v}" for v in _cases(exes)])


SUSPICIOUS_PS = ["FromBase64String", "DownloadString", "DownloadFile", "Net.WebClient", "IEX", "Invoke-Expression",
                 "-enc", "-Enc", "-EncodedCommand", "-nop", "-NoP", "-NoProfile", "-NonI", "-WindowStyle",
                 "-ExecutionPolicy", "hidden", "bypass", "Invoke-WebRequest", "Start-BitsTransfer",
                 "Reflection.Assembly", "VirtualAlloc", "Invoke-Mimikatz", "AmsiUtils"]
LOLBINS = ["rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "CertUtil.exe", "bitsadmin.exe",
           "wmic.exe", "WMIC.exe", "MSBuild.exe", "InstallUtil.exe", "cscript.exe", "wscript.exe", "RegAsm.exe",
           "RegSvcs.exe", "odbcconf.exe", "cmstp.exe", "CMSTP.exe", "forfiles.exe", "pcalua.exe"]
OFFICE_AND_SERVERS = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe",
                      "w3wp.exe", "sqlservr.exe", "httpd.exe", "tomcat.exe", "java.exe", "WmiPrvSE.exe"]
SHELLS = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
          "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe"]

PS4104 = 'winlog.event_id: "4104"'
SYSMON1 = 'winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: "1"'
SEC4688 = 'winlog.channel: "Security" and winlog.event_id: "4688"'


def lens(obj_id, title, description, visualization, columns, column_order, query=""):
    obj = hunt_lens(obj_id, title, description, visualization, columns, column_order, query)
    obj["references"][0]["id"] = DATA_VIEW_ID
    return obj


def table(obj_id, title, description, rows, query, extra_metrics=None, metric_label="Events"):
    """rows = [(field, size, label, 'asc'|'desc'), ...]; the first row sets the ranking.

    Lens nests the rows, so an event WITHOUT one of the row fields drops out
    of the whole table - silently (a 7045 has no ServiceFileName, a 1102 no
    Channel; Lens's missingBucket did not bring them back on 9.0.8). Every
    row field must be one that ALL the panel's events carry."""
    cols, order = {}, []
    for i, (field, size, label, direction) in enumerate(rows):
        cid = f"c_r{i}"
        cols[cid] = col_terms_ordered(field, size, label, direction)
        order.append(cid)
    cols["c_metric"] = col_count(metric_label)
    order.append("c_metric")
    for i, (field, label) in enumerate(extra_metrics or []):
        cid = f"c_u{i}"
        cols[cid] = col_unique(field, label)
        order.append(cid)
    return lens(obj_id, title, description, datatable(columns=order), labelled(cols), order, query=query)


def timeline(obj_id, title, description, split_field, query=""):
    cols = labelled({
        "c_bucket": col_date(TIME_FIELD, "When it happened (event.created)"),
        "c_split": col_terms_ordered(split_field, 8, "Log", "desc"),
        "c_metric": col_count("Events"),
    })
    vis = xy(series="bar_stacked", x="c_bucket", y=("c_metric",), split="c_split")
    return lens(obj_id, title, description, vis, cols, ["c_bucket", "c_split", "c_metric"], query=query)


def build_panels():
    p = []
    y = 0

    def row(*panels_and_widths, h):
        nonlocal y
        x = 0
        for obj, w in panels_and_widths:
            p.append((obj, {"x": x, "y": y, "w": w, "h": h}))
            x += w
        y += h

    # ---- 0. What is here -------------------------------------------------
    row((timeline("hayabusa-raw-timeline", "Raw events over time, by log",
                  "Every imported Windows event by the time it happened. A gap in a busy log, or "
                  "a log that stops early, is where to look for clearing or a stopped service.",
                  "winlog.channel", "winlog.channel: *"), 48),
        h=12)
    row((table("hayabusa-raw-rare-ids", "1. RARE event IDs - hunt here first",
               "Event IDs seen least often across all hosts. Thousands of the same ID is normal "
               "activity; an ID seen once or twice (log cleared, service installed, account "
               "created) is the line to open. Click one to filter the whole dashboard.",
               [("winlog.event_id", 30, "Event ID", "asc"), ("winlog.channel", 1, "Log", "desc")],
               "winlog.event_id: *", extra_metrics=[(HOST, "Hosts")]), 24),
        (table("hayabusa-raw-hosts", "2. Hosts and their logs",
               "What each machine sent, quietest hosts first. A host with no Security log, or "
               "far fewer events than its peers, may have had its logs cleared or was not "
               "collected fully.",
               [(HOST, 25, "Computer", "asc"), ("winlog.channel", 5, "Log", "desc")],
               "winlog.channel: *"), 24),
        h=16)

    # ---- 1. PowerShell ---------------------------------------------------
    row((table("hayabusa-raw-ps-suspicious", "3. Suspicious PowerShell script blocks (4104)",
               "Script text with the usual attacker tells: Base64 decoding, download cradles "
               "(Net.WebClient, DownloadString), IEX, -enc, -nop, hidden windows, AMSI bypass. "
               "Each line is the code that actually ran, decoded by PowerShell itself.",
               [("powershell.file.script_block_text", 25, "Script block", "asc"), (HOST, 3, "Computer", "desc")],
               f"{PS4104} and " + _any("powershell.file.script_block_text",
                                       [f"*{w}*" for w in _cases(SUSPICIOUS_PS)])), 48),
        h=16)
    row((table("hayabusa-raw-ps-rare", "4. RAREST PowerShell script blocks (4104)",
               "Every script block, the ones seen least often first. Admin scripts repeat on "
               "every host; a one-off block on one machine is what a person typed or a "
               "dropper ran.",
               [("powershell.file.script_block_text", 30, "Script block", "asc")],
               f"{PS4104} and powershell.file.script_block_text: *", extra_metrics=[(HOST, "Hosts")]), 30),
        (table("hayabusa-raw-ps-hosts", "5. PowerShell script blocks by host",
               "Which machines ran PowerShell with script logging on, and how much. A "
               "workstation that suddenly logs hundreds of blocks deserves a look.",
               [(HOST, 20, "Computer", "desc")],
               PS4104, extra_metrics=[("powershell.file.script_block_text", "Distinct blocks")]), 18),
        h=16)
    row((table("hayabusa-raw-ps-classic", "6. RAREST PowerShell starts - Windows PowerShell log (400)",
               "Every time PowerShell started, the classic Windows PowerShell log keeps the "
               "full command line it was started with (HostApplication) - even where script "
               "block logging is off. Rarest first: -enc, -w hidden, -nop and download "
               "cradles show up here.",
               [(HOST_APPLICATION, 25, "PowerShell started as (HostApplication)", "asc"),
                (HOST, 2, "Computer", "desc")],
               f'winlog.channel: "Windows PowerShell" and winlog.event_id: "400" and {HOST_APPLICATION}: *'), 48),
        h=15)

    # ---- 2. Execution ----------------------------------------------------
    row((table("hayabusa-raw-4688-rare", "7. RAREST command lines - process creation (4688)",
               "Every process start the Security log recorded (needs command-line auditing), "
               "rarest first. One-off commands on one host are what a person ran.",
               [(ED + "CommandLine", 30, "Command line", "asc")],
               f"{SEC4688} and {ED}CommandLine: *", extra_metrics=[(HOST, "Hosts")]), 24),
        (table("hayabusa-raw-sysmon1-rare", "8. RAREST command lines - Sysmon process creation (1)",
               "The same from Sysmon, which also records the parent and hashes. Rarest first.",
               [("process.command_line", 30, "Command line", "asc")],
               SYSMON1, extra_metrics=[(HOST, "Hosts")]), 24),
        h=16)
    row((table("hayabusa-raw-lolbins", "9. LOLBins - Windows' own tools used to attack",
               "rundll32, regsvr32, mshta, certutil, bitsadmin, wmic, msbuild and friends are "
               "signed Microsoft programs attackers use to download, decode and run code. "
               "Read the command line: a URL, a temp folder or a .dll from a user folder is "
               "the lead. Sysmon process creation.",
               [("process.name", 15, "Program", "desc"), ("process.command_line", 5, "Command line", "asc"),
                (HOST, 1, "Computer", "desc")],
               f"{SYSMON1} and " + _names("process.name", LOLBINS)), 24),
        (table("hayabusa-raw-lolbins-4688", "10. LOLBins - from the Security log (4688)",
               "The same programs from process creation auditing, for hosts without Sysmon "
               "(only events that carry a command line).",
               [(ED + "NewProcessName", 15, "Program", "desc"), (ED + "CommandLine", 5, "Command line", "asc"),
                (HOST, 1, "Computer", "desc")],
               f"{SEC4688} and {ED}CommandLine: * and " + _ends(ED + "NewProcessName", LOLBINS)), 24),
        h=16)
    row((table("hayabusa-raw-bad-parents", "11. Shells started by Office, web servers and databases",
               "A document, a web server or a database starting cmd, PowerShell, mshta or "
               "rundll32. Almost never legitimate: macro malware and web shells look like this.",
               [("process.parent.name", 15, "Parent", "desc"), ("process.name", 5, "Child", "desc"),
                (HOST, 3, "Computer", "desc")],
               f"{SYSMON1} and " + _names("process.parent.name", OFFICE_AND_SERVERS)
               + " and " + _names("process.name", SHELLS)), 48),
        h=13)

    # ---- 3. Accounts and lateral movement -------------------------------
    row((table("hayabusa-raw-logon-types", "12. Logons by type (4624)",
               "2 = at the keyboard, 3 = over the network (shares, PsExec, WMI), 10 = RDP, "
               "9 = runas /netonly. Type 3 and 10 from unexpected accounts are lateral movement.",
               [(ED + "LogonType", 10, "Logon type", "desc"), (ED + "TargetUserName", 5, "Account", "asc")],
               'winlog.channel: "Security" and winlog.event_id: "4624"', extra_metrics=[(HOST, "Hosts")]), 18),
        (table("hayabusa-raw-remote-logons", "13. Remote logons (3, 10) - source > host > account",
               "Who came in over the network, from where. One source address fanning out to "
               "many hosts with the same account is lateral movement. Only logons that "
               "name a source address (Security Onion drops the '-' Windows writes for "
               "many Kerberos logons - those are in panel 12).",
               [(ED + "IpAddress", 20, "From", "desc"), (HOST, 5, "To", "desc"),
                (ED + "TargetUserName", 3, "Account", "desc")],
               'winlog.channel: "Security" and winlog.event_id: "4624" and ' + ED + 'LogonType: ("3" or "10") '
               'and ' + ED + 'IpAddress: * and not ' + ED + 'IpAddress: ("-" or "::1" or "127.0.0.1")'), 30),
        h=16)
    row((table("hayabusa-raw-failed", "14. Failed logons (4625) - by source",
               "Many accounts tried from one source is password spraying; many failures with "
               "few accounts is guessing. Click a source to filter, then read the accounts and "
               "SubStatus (0xc000006a = wrong password, 0xc0000064 = no such user) in Discover.",
               [(ED + "IpAddress", 25, "From", "desc")],
               'winlog.channel: "Security" and winlog.event_id: "4625" and ' + ED + 'IpAddress: *',
               extra_metrics=[(ED + "TargetUserName", "Accounts tried"), (HOST, "Hosts")]), 24),
        (table("hayabusa-raw-explicit", "15. Explicit credentials (4648) - who used whose",
               "A logged-on user supplied another account's password (runas, net use, "
               "PsExec -u). The account on the left using the one on the right to reach "
               "the server is how credentials move between hosts.",
               [(ED + "SubjectUserName", 15, "Logged on as", "desc"), (ED + "TargetUserName", 5, "Used", "desc"),
                (ED + "TargetServerName", 3, "To", "desc")],
               'winlog.channel: "Security" and winlog.event_id: "4648"'), 24),
        h=16)
    row((table("hayabusa-raw-rdp", "16. RDP logons - rarest accounts (4624 type 10)",
               "Remote desktop sessions. Service accounts or brand-new accounts using RDP, or "
               "RDP from an address that has no business there.",
               [(ED + "TargetUserName", 20, "Account", "asc"), (ED + "IpAddress", 3, "From", "desc"),
                (HOST, 3, "To", "desc")],
               'winlog.event_id: "4624" and ' + ED + 'LogonType: "10"'), 24),
        (table("hayabusa-raw-rdp-1149", "17. RDP connections accepted (1149)",
               "TerminalServices-RemoteConnectionManager 1149: a user authenticated to RDP. "
               "It is logged even when the Security log has rolled over. (A 1149 that names "
               "no account is left out.)",
               [("userdata.EventXML.Param1", 20, "Account", "asc"), ("userdata.EventXML.Param3", 3, "From", "desc"),
                (HOST, 3, "To", "desc")],
               'winlog.channel: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" '
               'and winlog.event_id: "1149" and userdata.EventXML.Param1: * and userdata.EventXML.Param3: *'), 24),
        h=15)

    # ---- 4. Persistence --------------------------------------------------
    row((table("hayabusa-raw-services", "18. New services (7045) - rarest first",
               "PsExec, remote admin tools and much ransomware arrive as a new service. Random "
               "names, %COMSPEC%, powershell -nop -w hidden, \\\\ADMIN$ or a binary in Temp are "
               "the ones to open. System log 7045.",
               [(ED + "ServiceName", 30, "Service", "asc"), (HOST, 2, "Computer", "desc"),
                (ED + "ImagePath", 1, "Binary", "desc")],
               'winlog.channel: "System" and winlog.event_id: "7045"', extra_metrics=[(HOST, "Hosts")]), 28),
        (table("hayabusa-raw-services-4697", "19. Services installed - Security log (4697)",
               "The same act seen by the Security log (needs 'Audit Security System Extension'). "
               "It also names the account that installed the service.",
               [(ED + "ServiceName", 15, "Service", "asc"), (ED + "ServiceFileName", 1, "Binary", "desc"),
                (ED + "SubjectUserName", 1, "Installed by", "desc")],
               'winlog.channel: "Security" and winlog.event_id: "4697"', extra_metrics=[(HOST, "Hosts")]), 20),
        h=15)
    row((table("hayabusa-raw-tasks", "20. Scheduled tasks created (4698)",
               "A task is the simplest way to survive a reboot. Tasks created by a user "
               "account (not SYSTEM), or with names that imitate Windows, are the leads; the "
               "task's XML holds the command.",
               [(ED + "TaskName", 25, "Task", "asc"), (HOST, 2, "Computer", "desc"),
                (ED + "SubjectUserName", 1, "Created by", "desc")],
               'winlog.channel: "Security" and winlog.event_id: "4698"'), 24),
        (table("hayabusa-raw-accounts", "21. New accounts and group changes (4720, 4728, 4732, 4756)",
               "4720 = account created (Account is the new user); 4728/4732/4756 = someone added "
               "to a group (Account is the group; the member's SID is in the event). An attacker "
               "adding themselves to Administrators shows up here.",
               [("winlog.event_id", 4, "Event", "desc"), (ED + "TargetUserName", 10, "Account / group", "asc"),
                (ED + "SubjectUserName", 2, "Done by", "desc")],
               'winlog.channel: "Security" and winlog.event_id: ("4720" or "4728" or "4732" or "4756")'), 24),
        h=15)

    # ---- 5. Defense evasion and credential access -----------------------
    row((table("hayabusa-raw-cleared", "22. Logs cleared (1102 / 104)",
               "Clearing a log is how an intruder hides. 1102 = Security log cleared, 104 = "
               "another log (its name is in userdata.LogFileCleared.Channel). Who did it, and on "
               "which host, is the start of the investigation - check what came just before.",
               [(HOST, 20, "Computer", "desc"), ("userdata.LogFileCleared.SubjectUserName", 3, "Cleared by", "desc"),
                ("winlog.event_id", 2, "Event", "desc")],
               # 104 is also the ID of unrelated events from other providers
               # (a smart-card driver's, on a test workstation) - only the Eventlog's
               # own 104 is "log cleared".
               'winlog.provider.name: "Microsoft-Windows-Eventlog" and '
               '((winlog.channel: "Security" and winlog.event_id: "1102") or '
               '(winlog.channel: "System" and winlog.event_id: "104"))'), 24),
        (table("hayabusa-raw-defender", "23. Defender detections (1116 / 1117)",
               "Windows Defender found something (1116) or acted on it (1117). A hacking tool "
               "caught on one host means the attacker had it there - look at what ran on "
               "that host around the same time.",
               [(ED + "Threat Name", 15, "Threat", "desc"), (HOST, 3, "Computer", "desc"),
                (ED + "Path", 1, "Path", "desc")],
               'winlog.channel: "Microsoft-Windows-Windows Defender/Operational" and '
               'winlog.event_id: ("1116" or "1117")'), 24),
        h=15)
    row((table("hayabusa-raw-lsass", "24. LSASS memory access (Sysmon 10)",
               "A process opening lsass.exe is how credentials are dumped. GrantedAccess 0x1010, "
               "0x1410 or 0x1fffff from anything but security software is the classic shape.",
               [("process.executable", 15, "Accessed by", "desc"), (ED + "GrantedAccess", 3, "Access", "desc"),
                (HOST, 3, "Computer", "desc")],
               'winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: "10" and '
               + _any(ED + "TargetImage", ["*lsass.exe", "*LSASS.EXE", "*Lsass.exe"])), 48),
        h=13)
    return p


def build_search():
    """Script blocks are long; besides the tables, a document list to read them whole."""
    return {
        "id": SEARCH_ID, "type": "search", "managed": False,
        "attributes": {
            "title": "Raw events: PowerShell script blocks (4104)",
            "description": "Every 4104 script block, newest first. Search inside it from the "
                           "query bar, e.g. powershell.file.script_block_text: *DownloadString*",
            "columns": [HOST, "winlog.record_id", "powershell.file.script_block_text"],
            "sort": [[TIME_FIELD, "desc"]],
            "grid": {}, "hideChart": True, "isTextBasedQuery": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": PS4104, "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})},
        },
        "references": [{"id": DATA_VIEW_ID, "type": "index-pattern",
                        "name": "kibanaSavedObjectMeta.searchSourceJSON.index"}],
    }


def build_data_view():
    return {
        "id": DATA_VIEW_ID, "type": "index-pattern", "managed": False,
        "attributes": {
            "title": INDEX_PATTERN,
            "name": "Raw Windows events (Security Onion)",
            "timeFieldName": TIME_FIELD,
            "fields": "[]", "fieldFormatMap": "{}",
            "runtimeFieldMap": json.dumps({HOST_APPLICATION: {
                "type": "keyword", "script": {"source": HOST_APPLICATION_SCRIPT}}}),
            "sourceFilters": "[]", "allowHidden": False,
            "fieldAttrs": json.dumps({
                TIME_FIELD: {"customLabel": "When it happened"},
                HOST: {"customLabel": "Computer"},
                "powershell.file.script_block_text": {"customLabel": "PowerShell script block"},
            }),
        },
        "references": [],
    }


def build_dashboard(panels, search, search_y):
    pj, refs = [], []
    for i, (obj, grid) in enumerate(panels, start=1):
        name = f"panel_{i}"
        pj.append({"type": "lens", "gridData": {**grid, "i": str(i)}, "panelIndex": str(i),
                   "embeddableConfig": {"enhancements": {}}, "panelRefName": name})
        refs.append({"name": name, "type": "lens", "id": obj["id"]})
    i = str(len(panels) + 1)
    pj.append({"type": "search", "gridData": {"x": 0, "y": search_y, "w": 48, "h": 18, "i": i},
               "panelIndex": i, "embeddableConfig": {"enhancements": {}}, "panelRefName": f"panel_{i}"})
    refs.append({"name": f"panel_{i}", "type": "search", "id": search["id"]})
    return {
        "id": DASHBOARD_ID, "type": "dashboard", "managed": False,
        "attributes": {
            "title": "Raw Events - PEAK Hunt (Security Onion)",
            "description": "PEAK baseline hunting on EVERY raw Windows event Security Onion "
                           "holds (so-import-evtx / EVTXER's Raw Events tab), not only the ones "
                           "Hayabusa flagged. Tables are sorted so the RARE answers come first. "
                           "Time = when the event happened (event.created). Pivot from a "
                           "Hayabusa detection: winlog.computer_name + winlog.channel + "
                           "winlog.record_id finds its raw event; then widen to the host.",
            "panelsJSON": json.dumps(pj),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "syncCursor": True,
                                       "syncTooltips": True, "hidePanelTitles": False}),
            "version": 3, "timeRestore": True, "timeFrom": TIME_FROM, "timeTo": TIME_TO,
            "refreshInterval": {"pause": True, "value": 60000},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": refs,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", default="output/hayabusa-raw-hunt.ndjson")
    args = ap.parse_args()

    panels = build_panels()
    search_y = max(g["y"] + g["h"] for _, g in panels)
    search = stamp(build_search())
    search["typeMigrationVersion"] = "10.5.0"   # as make_peak_dashboard: what 9.0.8 stamps
    objects = ([stamp(build_data_view())] + [stamp(o) for o, _ in panels]
               + [search, stamp(build_dashboard(panels, search, search_y))])
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        for o in objects:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"wrote {len(objects)} objects -> {args.output}")
    print(f"  1 data view, {len(panels)} panels, 1 saved search, 1 dashboard ({DASHBOARD_ID})")


if __name__ == "__main__":
    main()
