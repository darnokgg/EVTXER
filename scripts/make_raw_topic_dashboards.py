#!/usr/bin/env python3
"""Three topic dashboards on EVTXER's raw events (v82, owner 2026-10-29):

  Raw Events - Lateral Movement      shares, PsExec and friends, RDP sessions,
                                     who logged on to what, outbound connections
  Raw Events - Active Directory      DCSync, directory changes, delegation, SID
                                     history, trusts, resets, certificates,
                                     Kerberos encryption (the domain controllers)
  Raw Events - Persistence & Evasion autostart registry, WMI, BITS, DLLs and
                                     drivers, file drops, injection, PowerShell
                                     modules, Defender, firewall, audit policy

They cover the event types "Raw Events - PEAK Hunt" has no panel for, and do
not repeat its panels (remote logons, RDP 1149, the four Kerberos hunts).
The fields are the raw converter's (HayabusaLib.ps1 $script:RawEventFields),
checked against the sample corpus and a test workstation's raw events; the
conventions (and traps) are make_raw_hunt_dashboard.py's:
  - a Lens table drops every event missing ANY of its row fields, so rows are
    fields all the panel's events carry, the rest are unique-count columns -
    and an empty value is not written at all (an unsigned driver has no
    Signature), so a field that can be empty is never a row;
  - every winlog.event_data.* is a case-sensitive keyword: write the spelling
    Windows writes, and both cases where Windows varies;
  - the export has no provider name: events are told apart by channel and id.

Most targets keep default logging; Sysmon, AD CS auditing and directory
service auditing are rarer. A panel says which log feeds it, and "No results"
is an honest answer for a network that does not log it.

The raw data view (hayabusa-raw-dataview) is made by make_raw_hunt_dashboard.py
and carries the anomaly runtime fields (only the shipped export has them):
these panels reference it by id and never redefine it.

Usage:
  python -I scripts/make_raw_topic_dashboards.py -o output/hayabusa-raw-topics.ndjson
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_dashboard import stamp  # noqa: E402
from make_hunt_dashboard import col_terms_ordered  # noqa: E402
from make_anomaly_dashboards import heatmap as anomaly_heatmap  # noqa: E402
from make_raw_hunt_dashboard import (DATA_VIEW_ID, HOST, ED, TIME_FROM, TIME_TO,  # noqa: E402
                                     _cases, table, timeline)

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
FIREWALL = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
BITS = "Microsoft-Windows-Bits-Client/Operational"
PS_OPERATIONAL = "Microsoft-Windows-PowerShell/Operational"
TRUE = '("True" or "true")'
LOOPBACK = '("127.0.0.1" or "::1")'


def ev(channel, *ids):
    return f'winlog.channel: "{channel}" and winlog.event_id: (' + " or ".join(f'"{i}"' for i in ids) + ")"


def kq(pattern):
    """A KQL wildcard value: * stays a wildcard; backslash, colon and the other
    KQL characters are escaped, so paths can be written as they are. Kibana's
    KQL cannot escape a space in an unquoted value (and a quoted one has no
    wildcards), so a space matches as * - "Image File Execution Options"
    becomes *Image*File*Execution*Options*.

    Elasticsearch 8.7's wildcard query matches nothing when an escaped
    backslash follows a literal character or is followed by * (*Version\\Run*,
    *AppData\\*, even *\\* - 0 hits; *\\Run* works; 9.x has no such bug). So
    a backslash always sits between a * and a letter: one before a * is
    dropped, the others get a * in front - *\\AppData*, *\\CurrentVersion*\\Run*.
    A touch looser - say what to leave out."""
    out = ""
    for i, ch in enumerate(pattern):
        nxt = pattern[i + 1] if i + 1 < len(pattern) else ""
        if ch == "\\":
            if nxt != "*" and not out.endswith("*"):
                out += "*"
            if nxt not in ("*", "\\", ""):
                out += "\\\\"
        elif ch == " ":
            out += "*"
        else:
            out += "\\" + ch if ch in '():<>"' else ch
    return out


def like(field, patterns):
    return f"{field}: (" + " or ".join(kq(p) for p in patterns) + ")"


def one_of(field, values):
    return f"{field}: (" + " or ".join(f'"{v}"' for v in values) + ")"


def fq(name):
    """A field name with a space (Defender's "New Value"): KQL cannot escape it
    either, but it takes a wildcard in a field name - New*Value."""
    return ED + name.replace(" ", "*")


def heatmap(obj_id, title, description, x_col, y_field, y_label, query):
    v = {"prefix": "", "note": "", "data_view": DATA_VIEW_ID}
    obj = anomaly_heatmap(v, obj_id, title, description, x_col, y_field, query)
    obj["attributes"]["state"]["datasourceStates"]["formBased"]["layers"]["layer1"]["columns"]["c_y"]["label"] = y_label
    return obj


class Layout:
    def __init__(self):
        self.panels, self.y = [], 0

    def row(self, *panels_and_widths, h):
        x = 0
        for obj, w in panels_and_widths:
            self.panels.append((obj, {"x": x, "y": self.y, "w": w, "h": h}))
            x += w
        self.y += h


# ==================================================== 1. Lateral movement ==
L = "hayabusa-raw-lateral-"
REMOTE_TOOLS = _cases(["PSEXESVC", "PAExec", "RemCom", "csexec"])
# A service binary run from ADMIN$, through %COMSPEC%, or via \\127.0.0.1 (Impacket).
REMOTE_BINARY = [r"*\ADMIN$\*", "*%COMSPEC%*", "*%comspec%*", r"*\\127.0.0.1\*"]
IPC = like(ED + "ShareName", [r"*\IPC$"])
HIDDEN_SHARE = like(ED + "ShareName", ["*$"])


def lateral_panels():
    p = Layout()
    p.row((timeline(L + "timeline", "Lateral movement over time, by event",
                    "Share access (5140/5145), network and RDP logons (4624 types 3 and 10), explicit "
                    "credentials (4648) and RDP sessions (21-25) by the time they happened. A burst on "
                    "one evening across many hosts is the shape of an intruder moving.",
                    "winlog.event_id",
                    f"({ev(SECURITY, '5140', '5145', '4648')}) or ({ev(SECURITY, '4624')} and "
                    f'{ED}LogonType: ("3" or "10")) or ({ev(LSM, "21", "22", "24", "25")})',
                    split_label="Event"), 48), h=11)
    p.row((table(L + "admin-shares", "1. Hidden shares opened (5140) - from > share > account",
                 "C$, ADMIN$ and IPC$ are how files are copied to a host and how PsExec, sc \\\\host and "
                 "WMI reach it. One source opening C$ or ADMIN$ on many hosts is lateral movement; "
                 "the same from a workstation (not an admin jump box) is the lead. Security 5140 "
                 "(needs 'Audit File Share'; on by default on domain controllers only).",
                 [("source.ip", 15, "From", "desc"), (ED + "ShareName", 5, "Share", "desc"),
                  ("user.name", 3, "Account", "desc")],
                 f"{ev(SECURITY, '5140')} and {HIDDEN_SHARE} and source.ip: * "
                 f"and not source.ip: {LOOPBACK}", extra_metrics=[(HOST, "Hosts")]), 24),
          (table(L + "pipes", "2. Named pipes opened over IPC$ (5145) - rarest first",
                 "What a remote machine asked this one to do. svcctl = create or start a service "
                 "(PsExec, sc \\\\host), atsvc = schedule a task, winreg = remote registry, samr / "
                 "lsarpc / srvsvc = account and share enumeration (BloodHound, net view), spoolss = "
                 "the printer bug. A pipe seen once or twice (PSEXESVC-..., a random name) is a "
                 "remote tool's own. Security 5145 ('Audit Detailed File Share' - often off).",
                 [(ED + "RelativeTargetName", 20, "Pipe", "asc"), ("source.ip", 3, "From", "desc")],
                 f"{ev(SECURITY, '5145')} and {IPC} and source.ip: *",
                 extra_metrics=[(HOST, "Hosts")]), 24),
          h=16)
    p.row((table(L + "share-files", "3. Files reached through C$ / ADMIN$ (5145) - rarest first",
                 "The files a remote account read or wrote through a hidden share: a tool dropped "
                 "into ADMIN$ (the Windows folder), output collected from C$\\Windows\\Temp, a user's "
                 "Desktop browsed from elsewhere. Security 5145.",
                 [(ED + "RelativeTargetName", 25, "File", "asc"), (ED + "ShareName", 2, "Share", "desc")],
                 f"{ev(SECURITY, '5145')} and {HIDDEN_SHARE} and not {IPC}",
                 extra_metrics=[("source.ip", "From"), (HOST, "Hosts")]), 24),
          (table(L + "remote-exec", "4. Remote execution - PsExec, PAExec, RemCom, smbexec",
                 "The service such a tool installs on its target (System 7045, Security 4697) and the "
                 "file or pipe it opens there (5145): PSEXESVC, PAExec, RemCom, csexec, or a service "
                 "binary run from ADMIN$, through %COMSPEC% or via \\\\127.0.0.1 (Impacket's smbexec "
                 "and psexec). Each line is a host that was run remotely; 'From' says from where.",
                 [(HOST, 15, "Run on", "desc"), ("winlog.event_id", 3, "Event", "desc")],
                 f"({ev(SECURITY, '5145')} and {like(ED + 'RelativeTargetName', [f'*{t}*' for t in REMOTE_TOOLS])}) "
                 f"or ({ev('System', '7045')} and ({like(ED + 'ServiceName', [f'{t}*' for t in REMOTE_TOOLS])} or "
                 f"{like(ED + 'ImagePath', REMOTE_BINARY)})) "
                 f"or ({ev(SECURITY, '4697')} and ({like(ED + 'ServiceName', [f'{t}*' for t in REMOTE_TOOLS])} or "
                 f"{like(ED + 'ServiceFileName', REMOTE_BINARY)}))",
                 extra_metrics=[("source.ip", "From"), (ED + "ServiceName", "Services")]), 24),
          h=16)
    p.row((heatmap(L + "logon-matrix", "5. Network logons - which source reached which host (4624, types 3 and 10)",
                   "One square per source and host, darker = more logons. A row lit across many "
                   "columns is one machine reaching many hosts - an admin jump box, or an intruder. "
                   "The accounts are in 'Raw Events - PEAK Hunt' panel 13. Security 4624.",
                   col_terms_ordered(HOST, 12, "To", "desc"), "source.ip", "From",
                   f'{ev(SECURITY, "4624")} and {ED}LogonType: ("3" or "10") and source.ip: * '
                   f"and not source.ip: {LOOPBACK}"), 48),
          h=16)
    p.row((table(L + "rdp-sessions", "6. RDP sessions (21, 22, 24, 25) - from > account > host",
                 "The session itself, from TerminalServices-LocalSessionManager: 21 logon, 22 shell "
                 "started, 24 disconnected, 25 reconnected. Kept even when the Security log has "
                 "rolled over. An address that has no business on RDP, or an admin account "
                 "hopping host to host, is the lead. Console logons (LOCAL) are left out.",
                 [(ED + "Address", 15, "From", "desc"), (ED + "User", 5, "Account", "desc"), (HOST, 3, "To", "desc")],
                 f"{ev(LSM, '21', '22', '24', '25')} and {ED}Address: * and not {ED}Address: (\"LOCAL\" or {LOOPBACK[1:-1]})"), 24),
          (table(L + "net-admin-ports", "7. Connections to remote-admin ports (Sysmon 3)",
                 "SMB 445/139, RPC 135, RDP 3389, WinRM 5985/5986 and SSH 22 opened by a program, not "
                 "the System process (which carries normal file sharing). PowerShell or a tool "
                 "reaching 5985 or 445 on another host is lateral movement from this one. Sysmon 3.",
                 [("destination.port", 7, "Port", "desc"), ("process.executable", 10, "Program", "desc"),
                  ("destination.ip", 3, "To", "desc")],
                 f"{ev(SYSMON, '3')} and {ED}Initiated: {TRUE} and destination.port: "
                 "(445 or 139 or 135 or 3389 or 5985 or 5986 or 22) and not process.executable: \"System\" "
                 "and not destination.ip: (\"127.0.0.0/8\" or \"::1\")",
                 extra_metrics=[(HOST, "Hosts")]), 24),
          h=15)
    p.row((table(L + "net-rare", "8. Outbound connections - rarest programs first (Sysmon 3)",
                 "Every program that opened a connection, the rarest first, with where it went. "
                 "Browsers and updaters repeat; a tool in a user folder, a LOLBin (mshta, rundll32, "
                 "certutil) or a script host calling out is the lead. Sysmon event 3 (only where "
                 "Sysmon is installed and logs network connections).",
                 [("process.executable", 20, "Program", "asc"), ("destination.ip", 3, "To", "desc"),
                  ("destination.port", 2, "Port", "desc")],
                 f"{ev(SYSMON, '3')} and {ED}Initiated: {TRUE}", extra_metrics=[(HOST, "Hosts")]), 48),
          h=16)
    return p.panels


# ===================================================== 2. Active Directory ==
A = "hayabusa-raw-ad-"
DCSYNC_RIGHTS = ["1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",   # DS-Replication-Get-Changes
                 "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",   # ... -All
                 "89e95b76-444d-4c62-991a-0facbeda640c"]   # ... -In-Filtered-Set
RISKY_ATTRIBUTES = ["member", "servicePrincipalName", "msDS-AllowedToActOnBehalfOfOtherIdentity",
                    "msDS-AllowedToDelegateTo", "msDS-KeyCredentialLink", "userAccountControl", "sIDHistory",
                    "adminCount", "scriptPath", "nTSecurityDescriptor", "gPLink", "gPCFileSysPath",
                    "gPCMachineExtensionNames", "msDS-GroupMSAMembership"]
UNSET = '("-" or "%%1793")'   # how 4738/4742 write "not changed" / "<value not set>"
ADCS_REQUESTS = ["4886", "4887", "4888", "4889"]
ADCS_ALL = [str(i) for i in range(4882, 4900)]
COMPUTER = like(ED + "SubjectUserName", ["*$"])   # a machine account: a DC replicating, a computer


def ad_panels():
    p = Layout()
    p.row((timeline(A + "timeline", "Directory and account changes over time, by event",
                    "Directory access and changes (4662, 5136), account and computer changes (4738, "
                    "4742), resets (4724), lockouts (4740), SID history (4765/4766), trusts "
                    "(4706/4707/4716) and certificate services (4882-4899). Logged on the domain controllers.",
                    "winlog.event_id",
                    ev(SECURITY, "4662", "5136", "4738", "4742", "4724", "4740", "4765", "4766", "4706",
                       "4707", "4716", *ADCS_ALL), split_label="Event"), 48), h=11)
    p.row((table(A + "dcsync", "1. DCSync - replication rights used by an account that is not a DC (4662)",
                 "Replicating the directory hands over every password hash (Mimikatz lsadump::dcsync, "
                 "Impacket secretsdump). Domain controllers ($ accounts) do it all day and are left "
                 "out; anything else here is a finding - unless it is Entra Connect's MSOL_ account. "
                 "Security 4662 on the DCs ('Audit Directory Service Access').",
                 [(ED + "SubjectUserName", 10, "Account", "desc"), (HOST, 5, "DC", "desc")],
                 f"{ev(SECURITY, '4662')} and {like(ED + 'Properties', [f'*{g}*' for g in _cases(DCSYNC_RIGHTS)])} "
                 f"and not {COMPUTER}",
                 extra_metrics=[(ED + "ObjectName", "Objects")]), 24),
          (table(A + "object-access", "2. Directory objects accessed by people - rarest first (4662)",
                 "Every directory access by an account that is not a computer, rarest account first. "
                 "AccessMask 0x100 is an extended right (replication, password reset), 0x20 a write, "
                 "0x40000 a permission change (WRITE_DAC). A user account with hundreds of these is "
                 "enumerating or tampering. Security 4662 on the DCs.",
                 [(ED + "SubjectUserName", 15, "Account", "asc"), (ED + "AccessMask", 3, "Access", "desc")],
                 f"{ev(SECURITY, '4662')} and not {COMPUTER}",
                 extra_metrics=[(ED + "ObjectName", "Objects"), (HOST, "DCs")]), 24),
          h=15)
    p.row((table(A + "risky-changes", "3. Directory changes an attacker makes (5136)",
                 "member (into a group), servicePrincipalName (to kerberoast it), "
                 "msDS-AllowedToActOnBehalfOfOtherIdentity (resource-based delegation), "
                 "msDS-KeyCredentialLink (shadow credentials), userAccountControl, sIDHistory, "
                 "adminCount, scriptPath, nTSecurityDescriptor (permissions, e.g. DCSync rights granted), "
                 "gPLink / gPCFileSysPath (a GPO linked or redirected). Read who did it. Security 5136 "
                 "('Audit Directory Service Changes', with SACLs on the objects).",
                 [(ED + "AttributeLDAPDisplayName", 12, "Attribute", "desc"), (ED + "ObjectDN", 5, "Object", "desc"),
                  (ED + "SubjectUserName", 2, "Changed by", "desc")],
                 f"{ev(SECURITY, '5136')} and {one_of(ED + 'AttributeLDAPDisplayName', RISKY_ATTRIBUTES)}",
                 extra_metrics=[(ED + "AttributeValue", "Values")]), 48),
          h=15)
    p.row((table(A + "changes-rare", "4. Every directory change - rarest attribute first (5136)",
                 "All of it, the attributes changed least often first: GPO version numbers and "
                 "descriptions repeat; a one-off attribute on one object is the one to read. "
                 "Security 5136.",
                 [(ED + "AttributeLDAPDisplayName", 25, "Attribute", "asc"), (ED + "SubjectUserName", 2, "Changed by", "desc")],
                 ev(SECURITY, "5136"), extra_metrics=[(ED + "ObjectDN", "Objects")]), 24),
          (table(A + "uac", "5. Account flags changed - userAccountControl (4738, 4742)",
                 "Old and new userAccountControl of a user (4738) or computer (4742). Flags to look for "
                 "in the new value: 0x400000 no Kerberos pre-auth (AS-REP roastable), 0x80000 trusted "
                 "for delegation, 0x1000000 trusted to authenticate for delegation, 0x20 no password "
                 "required, 0x10000 password never expires, 0x2 disabled. Security log on the DCs.",
                 [(ED + "TargetUserName", 15, "Account", "asc"), (ED + "OldUacValue", 2, "Was", "desc"),
                  (ED + "NewUacValue", 2, "Now", "desc")],
                 # Old/NewUacValue are in every 4738/4742; UserAccountControl
                 # names the flags only when they changed ("-" otherwise).
                 f"{ev(SECURITY, '4738', '4742')} and {ED}OldUacValue: * and {ED}NewUacValue: * "
                 f'and {ED}UserAccountControl: * and not {ED}UserAccountControl: "-"',
                 extra_metrics=[(ED + "SubjectUserName", "Changed by")]), 24),
          h=15)
    p.row((table(A + "delegation", "6. Delegation and SPNs set on accounts (4738, 4742)",
                 "An account given AllowedToDelegateTo (constrained delegation) or new "
                 "ServicePrincipalNames. Delegation lets the account act as any user to those "
                 "services; an SPN on a user account makes it kerberoastable. Open the events in "
                 "Discover to read the values; 5136 (panel 3) shows them too.",
                 [(ED + "TargetUserName", 15, "Account", "asc"), ("winlog.event_id", 2, "Event", "desc")],
                 f"{ev(SECURITY, '4738', '4742')} and (({ED}AllowedToDelegateTo: * and not {ED}AllowedToDelegateTo: {UNSET}) "
                 f"or ({ED}ServicePrincipalNames: * and not {ED}ServicePrincipalNames: {UNSET}))",
                 extra_metrics=[(ED + "SubjectUserName", "Changed by")]), 24),
          (table(A + "sid-trusts", "7. SID history and domain trusts (4765, 4766, 4706, 4707, 4716)",
                 "SID history added to an account (4765, or a failed try 4766) gives it another "
                 "account's rights - Domain Admins' SID is the classic. A trust created (4706), "
                 "removed (4707) or changed (4716) opens or reshapes the path between domains. "
                 "Rare and always worth a look. Security log on the DCs.",
                 [("winlog.event_id", 5, "Event", "desc"), (HOST, 5, "DC", "desc"),
                  (ED + "SubjectUserName", 3, "Done by", "desc")],
                 ev(SECURITY, "4765", "4766", "4706", "4707", "4716"),
                 extra_metrics=[(ED + "TargetUserName", "Accounts"), (ED + "DomainName", "Trusted domains")]), 24),
          h=15)
    p.row((table(A + "resets", "8. Password resets and lockouts (4724, 4723, 4740)",
                 "4724 = an account reset someone else's password - an attacker taking over an "
                 "account does exactly this; 4723 = a user changed their own; 4740 = locked out "
                 "(guessing; the machine the attempts came from is the event's TargetDomainName, "
                 "'Caller Computer Name').",
                 [(ED + "TargetUserName", 20, "Account", "desc"), ("winlog.event_id", 3, "Event", "desc"),
                  (ED + "SubjectUserName", 2, "Done by", "desc")],
                 ev(SECURITY, "4724", "4723", "4740")), 24),
          (table(A + "adcs", "9. Certificate requests - AD CS (4886-4889)",
                 "Certificates requested from the CA, the rarest requester first. Attributes holding "
                 "SAN:upn=... (a name chosen by the requester) on a template that allows it is ESC1 / "
                 "ESC6 - a certificate for another user, Administrator included. Needs 'Audit "
                 "Certification Services' on the CA server - off by default.",
                 [(ED + "Requester", 15, "Requester", "asc"), ("winlog.event_id", 4, "Event", "desc")],
                 f"{ev(SECURITY, *ADCS_REQUESTS)} and {ED}Requester: *",
                 extra_metrics=[(ED + "Attributes", "Attribute sets"), (HOST, "CAs")]), 24),
          h=15)
    p.row((timeline(A + "kerberos-etypes", "10. Kerberos ticket encryption over time (4768, 4769)",
                    "0x12 / 0x11 = AES (normal), 0x17 / 0x18 = RC4, 0x1 / 0x3 = DES. RC4 rising in an AES "
                    "domain is kerberoasting, overpass-the-hash or a forged ticket (attack tools ask for "
                    "RC4 by default). Failures (0xffffffff) are left out. Security log on the DCs.",
                    ED + "TicketEncryptionType",
                    f'{ev(SECURITY, "4768", "4769")} and {ED}TicketEncryptionType: * and not '
                    f'{ED}TicketEncryptionType: "0xffffffff"', split_label="Encryption"), 48), h=11)
    return p.panels


# ============================================ 3. Persistence and evasion ==
P = "hayabusa-raw-persist-"
AUTOSTART_KEYS = [r"*\CurrentVersion\Run*", r"*\Policies\Explorer\Run\*", r"*Image File Execution Options*",
                  r"*\SilentProcessExit\*", r"*\Winlogon\*", r"*\Services\*\ImagePath", r"*\Services\*\ServiceDll",
                  r"*\Control\Lsa\*", r"*AppInit_DLLs*", r"*\Environment\UserInitMprLogonScript",
                  r"*\Explorer\Shell Folders\Startup", r"*\Explorer\User Shell Folders\Startup",
                  # COM hijacking is per user (HKCR's are installers registering)
                  r"HKU\*\InprocServer32*", r"*\Office\*\Addins\*"]
USER_WRITABLE = [r"*\AppData\*", r"*\Temp\*", r"*\TEMP\*", r"*\temp\*", r"*\Users\Public\*", r"*\ProgramData\*",
                 r"*\Downloads\*", r"*\Desktop\*"]
RUNNABLE = _cases(["exe", "dll", "sys", "ps1", "bat", "cmd", "vbs", "js", "hta", "scr", "lnk"])


def persistence_panels():
    p = Layout()
    p.row((table(P + "autostart", "1. Autostart registry values set (Sysmon 13) - rarest first",
                 "Run / RunOnce keys, Image File Execution Options (debugger hijack), Winlogon "
                 "(Shell, Userinit), a service's ImagePath or ServiceDll, LSA packages (a new SSP "
                 "reads passwords), AppInit_DLLs, a user's own COM server (hijacking) and Office add-ins: what starts "
                 "by itself. 'Set to' is the value - a path in a user folder or a script host is the "
                 "lead. Sysmon 13 (where Sysmon logs registry changes).",
                 [(ED + "TargetObject", 25, "Registry value", "asc"), (ED + "Details", 1, "Set to", "desc"),
                  ("process.executable", 1, "Set by", "desc")],
                 # *\CurrentVersion*\Run* (see kq) also matches Explorer\RunMRU, the Run box's history
                 f"{ev(SYSMON, '13')} and {like(ED + 'TargetObject', AUTOSTART_KEYS)} and not "
                 f"{like(ED + 'TargetObject', ['*RunMRU*'])}",
                 extra_metrics=[(HOST, "Hosts")]), 48),
          h=16)
    wmi_note = (" A WMI subscription is a filter (19: when), a consumer (20: what runs) and a binding "
                "(21: the two joined) - survives reboots with no file on disk. Sysmon 19-21.")
    p.row((table(P + "wmi-filters", "2. WMI event filters (Sysmon 19)",
                 "When it fires: the WQL query (every 60 s, a process start, a logon)." + wmi_note,
                 [(ED + "Name", 10, "Filter", "asc"), (ED + "Query", 1, "Query", "desc"), (HOST, 1, "Computer", "desc")],
                 ev(SYSMON, "19")), 16),
          (table(P + "wmi-consumers", "3. WMI consumers (Sysmon 20)",
                 "What runs: a command line or a script." + wmi_note,
                 [(ED + "Name", 10, "Consumer", "asc"), (ED + "Destination", 1, "Runs", "desc"), (HOST, 1, "Computer", "desc")],
                 ev(SYSMON, "20")), 16),
          (table(P + "wmi-bindings", "4. WMI bindings (Sysmon 21)",
                 "A filter joined to a consumer - the subscription is live." + wmi_note,
                 [(ED + "Consumer", 10, "Consumer", "asc"), (ED + "Filter", 1, "Filter", "desc"), (HOST, 1, "Computer", "desc")],
                 ev(SYSMON, "21")), 16),
          h=14)
    p.row((table(P + "bits", "5. BITS downloads (59) - rarest address first",
                 "BITS fetches files in the background and survives reboots; attackers use it "
                 "(bitsadmin, Start-BitsTransfer) to download tools and keep a job alive. Windows "
                 "Update, Office and Chrome repeat; an address seen once, or a raw IP, is the lead. "
                 "The job's name is in the event (Discover). Bits-Client/Operational 59 - on by default.",
                 # not the job's "name": the template maps its twin "Name" (Sysmon WMI) - a panel on
                 # it would draw an error wherever BITS was not collected
                 [(ED + "url", 25, "Address", "asc")],
                 ev(BITS, "59"), extra_metrics=[(HOST, "Hosts")]), 24),
          (table(P + "ps-modules", "6. PowerShell module logging (4103) - rarest first",
                 "Each cmdlet PowerShell ran with its parameters (Payload), even where script block "
                 "logging is off. Admin modules repeat; a one-off Invoke-WebRequest, New-Object "
                 "Net.WebClient, Add-MpPreference or Set-MpPreference is the lead. PowerShell/"
                 "Operational 4103 (needs module logging - often off).",
                 [(ED + "Payload", 25, "Command and parameters", "asc")],
                 f"{ev(PS_OPERATIONAL, '4103')} and {ED}Payload: *", extra_metrics=[(HOST, "Hosts")]), 24),
          h=15)
    p.row((table(P + "dll-unsigned", "7. Unsigned DLLs loaded (Sysmon 7) - rarest first",
                 "A DLL with no valid signature loaded into a process: side-loading (a signed program "
                 "beside a planted DLL), injection, or a tool. A user folder or Temp is the lead. "
                 "Sysmon 7 (where Sysmon logs image loads - heavy, often filtered).",
                 [(ED + "ImageLoaded", 20, "DLL", "asc"), ("process.executable", 2, "Loaded by", "desc")],
                 f"{ev(SYSMON, '7')} and (not {ED}Signed: {TRUE} or not {ED}SignatureStatus: \"Valid\")",
                 extra_metrics=[(HOST, "Hosts")]), 24),
          (table(P + "drivers", "8. Drivers loaded (Sysmon 6) - rarest first",
                 "Every driver loaded, the rarest first, with its signature status. A vulnerable "
                 "signed driver (bring-your-own-driver, used to kill security tools) or an unsigned "
                 "one is the lead; the signer is in the 'Signers' column. Sysmon 6.",
                 [(ED + "ImageLoaded", 20, "Driver", "asc"), (ED + "SignatureStatus", 2, "Signature", "desc")],
                 ev(SYSMON, "6"), extra_metrics=[(ED + "Signature", "Signers"), (HOST, "Hosts")]), 24),
          h=15)
    p.row((table(P + "file-drops", "9. Programs and scripts written to user folders (Sysmon 11)",
                 "An .exe, .dll, .ps1, .bat, .vbs, .js, .hta, .scr or shortcut created in AppData, "
                 "Temp, Public, ProgramData, Downloads or a Desktop - where a download or a dropper "
                 "lands. Rarest first. Sysmon 11.",
                 [(ED + "TargetFilename", 20, "File", "asc"), ("process.executable", 1, "Written by", "desc")],
                 f"{ev(SYSMON, '11')} and {like(ED + 'TargetFilename', USER_WRITABLE)} and "
                 f"{like(ED + 'TargetFilename', [f'*.{e}' for e in RUNNABLE])}",
                 extra_metrics=[(HOST, "Hosts")]), 24),
          (table(P + "ads", "10. Alternate data streams - Mark of the Web (Sysmon 15)",
                 "A file given a stream: mostly Zone.Identifier, the mark Windows puts on a "
                 "download - its HostUrl (in the event's Contents, when Sysmon keeps them - open it "
                 "in Discover) says where it came from. A stream on an .exe, or a stream with "
                 "another name, is hiding data. Sysmon 15.",
                 [(ED + "TargetFilename", 20, "File", "asc"), (HOST, 2, "Computer", "desc")],
                 ev(SYSMON, "15")), 24),
          h=15)
    p.row((table(P + "defender-off", "11. Defender switched off (5001, 5010, 5012, 5013)",
                 "5001 real-time protection off, 5010 antispyware off, 5012 antivirus off, 5013 tamper "
                 "protection stopped a change. Switching Defender off is a common step before the "
                 "payload. Windows Defender/Operational - on by default.",
                 [(HOST, 15, "Computer", "desc"), ("winlog.event_id", 4, "Event", "desc")],
                 ev(DEFENDER, "5001", "5010", "5012", "5013")), 16),
          (table(P + "defender-config", "12. Defender settings changed (5007) - rarest first",
                 "The setting's new value. Exclusions\\Paths, \\Processes or \\Extensions added is how an "
                 "attacker keeps a tool from being scanned; DisableRealtimeMonitoring and friends "
                 "turn protection off. Windows Defender/Operational 5007.",
                 [(ED + "New Value", 20, "New value", "asc"), (HOST, 2, "Computer", "desc")],
                 f"{ev(DEFENDER, '5007')} and {fq('New Value')}: *"), 32),
          h=15)
    p.row((table(P + "injection", "13. Code injected into another process (Sysmon 8)",
                 "CreateRemoteThread: one process starting code inside another. Debuggers and some "
                 "security tools do it; PowerShell, Office, a tool in a user folder or anything "
                 "targeting lsass, explorer or a browser is the lead. Sysmon 8.",
                 [(ED + "SourceImage", 15, "Injector", "desc"), (ED + "TargetImage", 3, "Into", "desc")],
                 ev(SYSMON, "8"), extra_metrics=[(HOST, "Hosts")]), 24),
          (table(P + "firewall-rules", "14. Firewall rules added or changed (2004, 2005, 2097, 2099)",
                 "A rule opening a port or letting a program out - a backdoor listener or a C2 "
                 "channel. 'Changed by' is the program that did it: mmc is a person, WmiPrvSE or "
                 "netsh is a script. Firewall log - on by default (2097/2099 on Windows 11).",
                 [(ED + "RuleName", 20, "Rule", "asc"), (ED + "ModifyingApplication", 2, "Changed by", "desc")],
                 f"{ev(FIREWALL, '2004', '2005', '2097', '2099')} and {ED}RuleName: * and {ED}ModifyingApplication: *",
                 extra_metrics=[(HOST, "Hosts")]), 24),
          h=15)
    p.row((table(P + "firewall-off", "15. Firewall switched off or rules removed (2003, 2006, 2033, 2052)",
                 "2003 a profile setting changed (the firewall turned off), 2006 / 2052 a rule deleted, "
                 "2033 every rule deleted. Firewall log.",
                 [(HOST, 15, "Computer", "desc"), ("winlog.event_id", 4, "Event", "desc")],
                 ev(FIREWALL, "2003", "2006", "2033", "2052"),
                 extra_metrics=[(ED + "RuleName", "Rules"), (ED + "ModifyingApplication", "Changed by")]), 24),
          (table(P + "audit-policy", "16. Audit policy turned down (4719)",
                 "Success or failure auditing removed from a subcategory (%%8448 = success removed, "
                 "%%8450 = failure removed): an intruder blinding the Security log before acting. "
                 "Group Policy refreshes write 4719 too - by SYSTEM, the same subcategories everywhere. "
                 "The subcategory GUID names it (0CCE9215... = Logon). Security 4719.",
                 [(HOST, 15, "Computer", "desc"), (ED + "SubjectUserName", 3, "Changed by", "desc")],
                 f"{ev(SECURITY, '4719')} and {like(ED + 'AuditPolicyChanges', ['*8448*', '*8450*'])}",
                 extra_metrics=[(ED + "SubcategoryGuid", "Subcategories")]), 24),
          h=15)
    return p.panels


DASHBOARDS = [
    ("hayabusa-raw-lateral-dashboard", "Raw Events - Lateral Movement",
     "How an intruder moved between machines, from EVERY Windows event EVTXER sent (hayabusa-raw-*): "
     "hidden shares and named pipes, PsExec and its relatives, RDP sessions, which source logged on to "
     "which host, outbound connections. Remote logons by account and RDP 1149 are on 'Raw Events - "
     "PEAK Hunt'. Time = when the event happened.", lateral_panels),
    ("hayabusa-raw-ad-dashboard", "Raw Events - Active Directory",
     "The domain controllers' story from EVERY raw event (hayabusa-raw-*): DCSync, directory changes, "
     "delegation and SPNs, account flags, SID history, trusts, password resets, certificate requests and "
     "Kerberos encryption over time. Most panels need the DCs' Security logs; the four Kerberos hunts "
     "(kerberoasting, AS-REP, spraying, PKINIT) are on 'Raw Events - PEAK Hunt'.", ad_panels),
    ("hayabusa-raw-persist-dashboard", "Raw Events - Persistence & Evasion",
     "How an intruder stays and hides, from EVERY raw event (hayabusa-raw-*): autostart registry, WMI "
     "subscriptions, BITS jobs, unsigned DLLs and drivers, files dropped in user folders, injection, "
     "PowerShell modules, Defender and firewall changes, audit policy. New services, tasks and cleared "
     "logs are on 'Raw Events - PEAK Hunt'. Many panels need Sysmon: 'No results' is an honest answer.",
     persistence_panels),
]


def build_dashboard(dash_id, title, description, panels):
    pj, refs = [], []
    for i, (obj, grid) in enumerate(panels, start=1):
        name = f"panel_{i}"
        pj.append({"type": "lens", "gridData": {**grid, "i": str(i)}, "panelIndex": str(i),
                   "embeddableConfig": {"enhancements": {}}, "panelRefName": name})
        refs.append({"name": name, "type": "lens", "id": obj["id"]})
    return {
        "id": dash_id, "type": "dashboard", "managed": False,
        "attributes": {
            "title": title, "description": description,
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
    ap.add_argument("-o", "--output", default="output/hayabusa-raw-topics.ndjson")
    args = ap.parse_args()

    objects = []
    for dash_id, title, description, make in DASHBOARDS:
        panels = make()
        objects += [stamp(o) for o, _ in panels] + [stamp(build_dashboard(dash_id, title, description, panels))]
        print(f"  {title}: {len(panels)} panels ({dash_id})")
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        for o in objects:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"wrote {len(objects)} objects -> {args.output}")


if __name__ == "__main__":
    main()
