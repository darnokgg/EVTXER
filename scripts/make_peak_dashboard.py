#!/usr/bin/env python3
"""Third dashboard: PEAK-style baseline hunts, built for Hayabusa detections.

PEAK (Prepare, Execute, Act with Knowledge) is Splunk SURGe's hunting method.
Its "baseline" hunt is stack counting: sort what you have by how OFTEN it
occurs and read the bottom of the list, because noise repeats and intrusions
mostly do not. jconeby/elastic-peak-dashboards applies that to Zeek and
Suricata; none of its panels read Windows event data, and it carries no
licence, so nothing is copied from it - these are the same ideas rebuilt for
hayabusa-* fields (operator request, 2026-10-14).

Every table here is a question with the rare answers first. Each panel's
description (the (i) beside its title) says what to look for.

Caveat that applies to every panel: Hayabusa outputs DETECTIONS, not every
event, so "rare" means rare among what the rules flagged.

ATT&CK moved to its own dashboard in v37 (make_mitre_dashboard.py).

Relies on the hunt fields the ECS conversion promotes since v34
(winlog.logon.type, service.name, file.path, registry.path,
dns.question.name, process.parent.command_line,
powershell.file.script_block_text). Older imports simply leave those panels
empty.

Usage:
  python scripts/make_peak_dashboard.py -o output/hayabusa-peak.ndjson
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_dashboard import DATA_VIEW_ID, stamp, col_count, datatable, labelled  # noqa: E402
from make_hunt_dashboard import col_terms_ordered, lens, build_dashboard as build_lens_dashboard  # noqa: E402

DASHBOARD_ID = "hayabusa-peak-dashboard"
SEARCH_ID = "hayabusa-search-scriptblocks"

# KQL on a keyword field is case-sensitive, and Windows reports the same
# program as WINWORD.EXE on one box and winword.exe on another - so both.
def _both(names):
    out = []
    for n in names:
        for v in (n.lower(), n.upper()):
            if f'"{v}"' not in out:
                out.append(f'"{v}"')
    return " or ".join(out)

OFFICE_AND_SERVERS = _both(["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
                            "mspub.exe", "visio.exe", "acrord32.exe", "w3wp.exe", "sqlservr.exe",
                            "httpd.exe", "nginx.exe", "tomcat.exe", "java.exe", "wmiprvse.exe"])
SHELLS = _both(["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe"])


def col_unique(field, label):
    """Distinct values of a field - e.g. on how many hosts something appears."""
    return {"label": label, "dataType": "number", "operationType": "unique_count",
            "scale": "ratio", "sourceField": field, "isBucketed": False,
            "params": {"emptyAsNull": True}}


def table(obj_id, title, description, rows, query, extra_metrics=None, metric_label="Times seen"):
    """A datatable: rows = [(field, size, label, 'asc'|'desc'), ...], ranked by count.

    The first row sets the ranking direction; nested rows show the top few
    values inside each first-level bucket.
    """
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

    # ---- 1. Hunt here first: the rarest detections, and where they sit ----
    row((table("hayabusa-peak-rare-rules", "1. RARE detections - hunt here first",
               "Rules that fired least often, informational ones left out. A rule that fired "
               "once on one host is the most interesting line on this dashboard; one that "
               "fired 4,000 times is configuration. Click a rule to filter everything below.",
               [("rule.name", 30, "Detection rule", "asc")],
               "not hayabusa.level: informational",
               extra_metrics=[("host.name", "Hosts")]), 24),
        (table("hayabusa-peak-rare-hosts", "2. Hosts with the least activity",
               "Hosts that produced the fewest detections. A box that is normally silent "
               "and shows one or two medium/high hits is a better lead than the noisiest "
               "server. Hosts that were never touched by a rule do not appear at all.",
               [("host.name", 25, "Computer", "asc")],
               "not hayabusa.level: informational",
               extra_metrics=[("rule.name", "Distinct rules")]), 24),
        h=16)

    # The account is a count, not a third row: Lens drops every detection
    # that lacks a nested row's field - 2,373 of 13,917 here (17%) on the
    # sample corpus had no user.name and vanished from their host's rows.
    row((table("hayabusa-peak-chains", "3. Who did what, where - host > rule",
               "The detection chain per host: which rules fired there and how many "
               "accounts they involved. Click a host and a rule, then read the accounts in "
               "Discover - one account under many rules on one host is a session worth "
               "reconstructing.",
               [("host.name", 20, "Computer", "desc"), ("rule.name", 5, "Detection rule", "desc")],
               "not hayabusa.level: informational", extra_metrics=[("user.name", "Accounts")]), 48),
        h=16)

    # ---- 2. Execution -----------------------------------------------------
    row((table("hayabusa-peak-bad-parents", "4. Shells spawned by Office, browsers and servers",
               "A document, a web server or a database starting cmd, PowerShell, mshta, "
               "rundll32 and the like. Almost never legitimate; check the command line.",
               [("process.parent.name", 15, "Parent", "desc"), ("process.name", 5, "Child", "desc"),
                ("host.name", 3, "Computer", "desc")],
               f"process.parent.name: ({OFFICE_AND_SERVERS}) and process.name: ({SHELLS})"), 24),
        (table("hayabusa-peak-parent-cmdline", "5. RAREST parent command lines",
               "What launched the suspicious process, in full. A macro document path, a "
               "web shell, or an encoded parent shows up here.",
               [("process.parent.command_line", 20, "Parent command line", "asc")],
               "process.parent.command_line: *",
               extra_metrics=[("host.name", "Hosts")]), 24),
        h=15)

    row((table("hayabusa-peak-hashes", "6. Programs with hashes - on how many hosts",
               "Each executable with its SHA-256 and the number of hosts it ran on. A program "
               "on ONE host, or one name with several hashes, is the lead. Hashes exist only "
               "where Sysmon was installed; copy one into VirusTotal or your TI platform.",
               [("process.executable", 30, "Program", "asc"), ("file.hash.sha256", 3, "SHA-256", "desc")],
               "file.hash.sha256: *",
               extra_metrics=[("host.name", "Hosts")]), 48),
        h=16)

    # ---- 3. Persistence ---------------------------------------------------
    row((table("hayabusa-peak-services", "7. Services installed - host > service > binary",
               "Event 7045/4697: a service was installed. PsExec, remote admin tools and "
               "much ransomware arrive this way. Binaries in Temp, ProgramData, Users or "
               "with random names are the ones to open.",
               [("host.name", 20, "Computer", "desc"), ("service.name", 5, "Service", "asc"),
                ("file.path", 1, "Binary", "desc")],
               'event.code: ("7045" or "4697")'), 28),
        (table("hayabusa-peak-registry", "8. RAREST registry keys written",
               "Autoruns and other persistence keys (Sysmon 12-14) seen least often.",
               [("registry.path", 25, "Registry key", "asc")],
               "registry.path: *",
               extra_metrics=[("host.name", "Hosts")]), 20),
        h=15)

    row((table("hayabusa-peak-files", "9. RAREST files created",
               "Files written (Sysmon 11/23) and file paths named by other rules, rarest "
               "first. Scripts and executables dropped in user-writable folders stand out.",
               [("file.path", 30, "File", "asc"), ("host.name", 1, "Computer", "desc")],
               "file.path: * and not event.code: (\"7045\" or \"4697\")"), 48),
        h=14)

    # ---- 4. Accounts and lateral movement --------------------------------
    row((table("hayabusa-peak-remote-logons", "10. Remote logons - source > target > account",
               "Network (type 3) and RDP (type 10) logons. The same account fanning out from "
               "one source to many hosts is lateral movement.",
               [("source.ip", 20, "From", "desc"), ("host.name", 5, "To", "desc"),
                ("user.name", 3, "Account", "desc")],
               'winlog.logon.type: ("Network" or "RemoteInteractive" or "NetworkCleartext" or '
               '"NewCredentials") and source.ip: *'), 24),
        (table("hayabusa-peak-rdp", "11. RDP logons - rarest accounts",
               "Interactive remote desktop sessions, rarest accounts first. Service "
               "accounts or brand-new accounts using RDP deserve a look.",
               [("user.name", 20, "Account", "asc"), ("source.ip", 3, "From", "desc")],
               'winlog.logon.type: "RemoteInteractive"'), 24),
        h=15)

    row((table("hayabusa-peak-ntlm", "12. NTLM logons - rarest accounts",
               "NTLM in a Kerberos domain is how pass-the-hash and relaying look. Rare "
               "accounts and unexpected sources first.",
               [("user.name", 20, "Account", "asc"), ("source.ip", 3, "From", "desc"),
                ("host.name", 3, "To", "desc")],
               # winlog.event_data since v37; the hayabusa.* paths still
               # match detections uploaded before it.
               'winlog.event_data.AuthenticationPackageName: "NTLM" or '
               'hayabusa.details.AuthenticationPackageName: "NTLM" or hayabusa.extra.AuthenticationPackageName: "NTLM"'), 24),
        (table("hayabusa-peak-failed", "13. Failed logons - source > account",
               "Event 4625. Many accounts from one source is spraying; many failures for "
               "one account is guessing.",
               [("source.ip", 20, "From", "desc"), ("user.name", 5, "Account", "desc")],
               'event.code: "4625"',
               extra_metrics=[("user.name", "Accounts tried")]), 24),
        h=15)

    row((table("hayabusa-peak-kerberoast", "14. Kerberos service tickets - rarest services",
               "Event 4769, rarest services first. A user requesting tickets for many "
               "services, or with RC4 (0x17) encryption, is Kerberoasting.",
               [("service.name", 25, "Service", "asc"), ("user.name", 3, "Requested by", "desc")],
               'event.code: "4769"'), 24),
        (table("hayabusa-peak-rc4", "15. RC4 (0x17) service tickets",
               "Kerberos tickets issued with RC4. Modern domains use AES; RC4 requests are "
               "the classic Kerberoasting signature.",
               [("user.name", 20, "Requested by", "desc"), ("service.name", 5, "Service", "desc")],
               'event.code: "4769" and (winlog.event_data.TicketEncryptionType: "0x17" or '
               'hayabusa.details.TicketEncryptionType: "0x17" or hayabusa.extra.TicketEncryptionType: "0x17")'), 24),
        h=15)

    row((table("hayabusa-peak-dcsync", "16. Credential access - DCSync, LSASS, dumping",
               "Credential Access detections by rule and host, with how many accounts. "
               "DCSync (T1003.006) from anything but a domain controller is an emergency.",
               [("rule.name", 15, "Detection rule", "desc"), ("host.name", 3, "Computer", "desc")],
               'threat.tactic.name: "Credential Access"', extra_metrics=[("user.name", "Accounts")]), 48),
        h=14)

    # ---- 5. Network and DNS ----------------------------------------------
    row((table("hayabusa-peak-rare-ports", "17. RAREST destination ports",
               "Outbound connections (Sysmon 3) by destination port, rarest first, with the "
               "program that made them. Odd high ports from scripting hosts are C2 shapes.",
               [("destination.port", 25, "Port", "asc"), ("process.name", 3, "Program", "desc")],
               "destination.port: *"), 24),
        (table("hayabusa-peak-rare-dns", "18. RAREST DNS queries",
               "Sysmon 22 lookups, rarest first. Random-looking or newly seen domains, and "
               "lookups made by unusual programs.",
               [("dns.question.name", 30, "Domain", "asc"), ("process.name", 1, "Program", "desc")],
               "dns.question.name: *"), 24),
        h=15)

    return p


def build_search():
    """PowerShell script blocks are text (too long to aggregate), so they get a
    document list rather than a table."""
    return {
        "id": SEARCH_ID, "type": "search", "managed": False,
        "attributes": {
            "title": "Hayabusa: PowerShell Script Blocks",
            "description": "Event 4104: the script text PowerShell actually ran, decoded. "
                           "Search inside it from the query bar, e.g. "
                           "powershell.file.script_block_text: *DownloadString*",
            "columns": ["host.name", "user.name", "rule.name", "powershell.file.script_block_text"],
            "sort": [["@timestamp", "desc"]],
            "grid": {}, "hideChart": True, "isTextBasedQuery": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "powershell.file.script_block_text: *", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})},
        },
        "references": [{"id": DATA_VIEW_ID, "type": "index-pattern",
                        "name": "kibanaSavedObjectMeta.searchSourceJSON.index"}],
    }


def build_dashboard(panels, search, search_y):
    """The hunt dashboard's builder, re-titled, with the script-block search
    appended as the last panel."""
    d = build_lens_dashboard(panels)
    a = d["attributes"]
    pj = json.loads(a["panelsJSON"])
    i = str(len(panels) + 1)
    pj.append({"type": "search", "gridData": {"x": 0, "y": search_y, "w": 48, "h": 18, "i": i},
               "panelIndex": i, "embeddableConfig": {"enhancements": {}}, "panelRefName": f"panel_{i}"})
    d["references"].append({"name": f"panel_{i}", "type": "search", "id": search["id"]})
    d["id"] = DASHBOARD_ID
    a.update(
        title="Hayabusa - PEAK Hunt",
        description="PEAK-style baseline hunting on Hayabusa detections: every table is "
                    "sorted so the RARE answers come first, because noise repeats and "
                    "intrusions mostly do not. Start at panel 1, click a value to filter "
                    "the whole dashboard, then open Discover for the raw detections. "
                    "Only events that matched a rule are here, not every log record. "
                    "The query bar hides this tool's own collection activity "
                    "(tags: evtxer-collection); clear it to see that too.",
        panelsJSON=json.dumps(pj),
        kibanaSavedObjectMeta={"searchSourceJSON": json.dumps(
            {"query": {"query": "not tags: evtxer-collection", "language": "kuery"}, "filter": []})},
    )
    return d

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", default="output/hayabusa-peak.ndjson")
    args = ap.parse_args()

    panels = build_panels()
    search_y = max(g["y"] + g["h"] for _, g in panels)
    search = build_search()
    search = stamp(search)
    # make_dashboard.stamp knows no "search" version; this is what the live
    # 9.0.8 stamped on the saved searches already in the export.
    search["typeMigrationVersion"] = "10.5.0"
    objects = [stamp(o) for o, _ in panels] + [search, stamp(build_dashboard(panels, search, search_y))]
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        for o in objects:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"wrote {len(objects)} objects -> {args.output}")
    print(f"  {len(panels)} tables, 1 saved search, 1 dashboard ({DASHBOARD_ID})")


if __name__ == "__main__":
    main()
