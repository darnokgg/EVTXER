#!/usr/bin/env python3
"""Make the Hayabusa data usable by operators who don't know the field names.

Three layers, all of which remove the need to memorise anything:

  1. FIELD LABELS  - renames fields in the Kibana UI. An operator sees
     "PowerShell Script Text", not "hayabusa.details.ScriptBlockText".
     Descriptions show on hover. Applies everywhere: Discover's field list,
     Lens, dashboard panels.

  2. DASHBOARD CONTROLS - dropdown filters at the top of the dashboard,
     populated from the real values in the index. Operators pick "critical"
     from a list instead of typing `hayabusa.level: "critical"`.

  3. SAVED SEARCHES - pre-built Discover views with the right columns and
     query already set. Operators open "Hayabusa: PowerShell Activity" and
     are looking at PowerShell, with no query written.

Only touches objects whose id starts with `hayabusa-`.

Usage:
  python scripts/operator_setup.py --dry-run
  python scripts/operator_setup.py
"""
import argparse
import json
import sys
import uuid

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")
from kibana_setup import Kibana, load_env, DEFAULT_ENV, DATA_VIEW_ID, DASHBOARD_ID

SEARCH_MIGRATION = "10.5.0"
CORE_MIGRATION = "8.8.0"

# --- 1. Friendly names -----------------------------------------------------
# label, description
FIELD_LABELS = {
    "hayabusa.level":        ("Severity", "Hayabusa alert level: critical, high, medium, low, informational."),
    "rule.name":             ("Detection Rule", "Name of the Sigma/Hayabusa rule that matched."),
    "rule.id":               ("Rule ID", "Unique rule identifier (UUID)."),
    "rule.ruleset":          ("Rule File", "YAML file the rule came from."),
    "host.name":             ("Computer", "Windows computer name the event came from."),
    "user.name":             ("User Account", "Primary account involved in the event."),
    "user.domain":           ("User Domain", "Domain or workgroup of the account."),
    "user.id":               ("User SID", "Windows security identifier."),

    "process.command_line":  ("Command Line", "Full command line, including arguments. THIS is what was typed or run."),
    "process.executable":    ("Program Path", "Full path to the executable on disk."),
    "process.name":          ("Program", "Executable filename, e.g. powershell.exe."),
    "process.pid":           ("Process ID", "PID (decoded from hex where Windows logged it that way)."),
    "process.parent.name":   ("Parent Program", "What launched this process. Key for spotting odd chains."),
    "process.parent.executable": ("Parent Program Path", "Full path of the launching process."),

    "hayabusa.details.ScriptBlockText": ("PowerShell Script Text", "The actual PowerShell code that executed."),
    "hayabusa.details.Payload":         ("PowerShell Payload", "Payload content from PowerShell logging."),
    "hayabusa.details.CommandLine":     ("Command Line (raw)", "Command line as Hayabusa reported it."),
    "hayabusa.details.LogonType":       ("Logon Type", "2=Interactive 3=Network 10=RDP."),
    "hayabusa.details.ServiceName":     ("Service Name", "Windows service involved."),
    "hayabusa.details.TargetUserName":  ("Target Account", "Account being acted upon."),
    "hayabusa.details.IpAddress":       ("Source IP (raw)", "IP as recorded in the event."),

    "winlog.channel":        ("Event Log", "Which Windows log, e.g. Security or Sysmon/Operational."),
    "winlog.event_id":       ("Event ID", "Windows event ID, e.g. 4624 logon, 1 process create."),
    "winlog.record_id":      ("Record Number", "Position within the source EVTX file."),
    "winlog.provider_name":  ("Log Provider", "Component that wrote the event."),

    "event.severity":        ("Severity Score", "0-100, HIGHER = WORSE. Note Suricata data uses the opposite scale."),
    "event.code":            ("Event ID", "Windows event ID as a keyword."),

    "threat.tactic.name":    ("MITRE Tactic", "ATT&CK tactic, e.g. Lateral Movement."),
    "threat.tactic.id":      ("MITRE Tactic ID", "ATT&CK tactic ID, e.g. TA0008."),
    "threat.technique.id":   ("MITRE Technique", "ATT&CK technique ID, e.g. T1059.001."),

    "source.ip":             ("Source IP", "Where the activity came from."),
    "source.port":           ("Source Port", "Source port."),
    "destination.ip":        ("Destination IP", "Where the activity went."),
    "related.user":          ("All Accounts", "Every account mentioned in the event - search here to catch all."),
    "related.ip":            ("All IPs", "Every IP mentioned in the event."),
    "related.hosts":         ("All Hostnames", "Every hostname mentioned in the event."),

    "file.hash.sha256":      ("SHA256", "File hash - paste into VirusTotal."),
    "file.hash.md5":         ("MD5", "File hash."),
    "log.file.path":         ("Source EVTX File", "Which .evtx file this came from."),
    "import.id":             ("Import Batch", "Groups one upload together."),
    "hayabusa.rule_status":  ("Rule Maturity", "stable / test / experimental."),
    "message":               ("Summary", "Short description of what matched."),
}

# --- 2. Dashboard dropdowns ------------------------------------------------
CONTROLS = [
    ("Severity",       "hayabusa.level",       "small"),
    ("Computer",       "host.name",            "medium"),
    ("Detection Rule", "rule.name",            "large"),
    ("User Account",   "user.name",            "medium"),
    ("Program",        "process.name",         "medium"),
    ("MITRE Tactic",   "threat.tactic.name",   "medium"),
]

# --- 3. Pre-built Discover views -------------------------------------------
COLS_EXEC = ["hayabusa.level", "rule.name", "host.name", "user.name",
             "process.name", "process.command_line"]
COLS_ALERT = ["hayabusa.level", "rule.name", "host.name", "user.name",
              "winlog.channel", "threat.tactic.name"]

SAVED_SEARCHES = [
    ("hayabusa-search-commands", "Hayabusa: Commands Executed",
     "Everything with a command line. Start here for 'what was run'.",
     "process.command_line: *", COLS_EXEC),

    ("hayabusa-search-powershell", "Hayabusa: PowerShell Activity",
     "PowerShell detections plus the actual script text where captured.",
     'process.name: "powershell.exe" or hayabusa.details.ScriptBlockText: * '
     'or winlog.channel: "Microsoft-Windows-PowerShell/Operational"',
     ["hayabusa.level", "rule.name", "host.name", "user.name",
      "process.command_line", "hayabusa.details.ScriptBlockText"]),

    ("hayabusa-search-critical", "Hayabusa: Critical and High Only",
     "The findings that matter. Drops the 57% informational noise.",
     "event.severity >= 75", COLS_ALERT),

    ("hayabusa-search-lolbin", "Hayabusa: LOLBins and Scripting",
     "Living-off-the-land binaries and script interpreters attackers abuse.",
     'process.name: ("certutil.exe" or "mshta.exe" or "regsvr32.exe" or '
     '"rundll32.exe" or "wscript.exe" or "cscript.exe" or "bitsadmin.exe" or '
     '"python.exe" or "wmic.exe" or "msbuild.exe")', COLS_EXEC),

    ("hayabusa-search-encoded", "Hayabusa: Encoded / Obfuscated Commands",
     "Base64, -enc, bypass flags. Strong signal of deliberate evasion.",
     "process.command_line: (*enc* or *EncodedCommand* or *FromBase64* or "
     "*bypass* or *hidden* or *noprofile*)", COLS_EXEC),

    ("hayabusa-search-logons", "Hayabusa: Logon Activity",
     "Logons and logon failures. Logon Type 3 = network, 10 = RDP.",
     'winlog.event_id: ("4624" or "4625" or "4648" or "4672")',
     ["hayabusa.level", "rule.name", "host.name", "user.name",
      "source.ip", "hayabusa.details.LogonType"]),

    ("hayabusa-search-network", "Hayabusa: Detections with an IP",
     "Detections carrying a source IP - pivot these into Hunt against Zeek.",
     "source.ip: *",
     ["hayabusa.level", "rule.name", "host.name", "user.name",
      "source.ip", "destination.ip"]),
]


def apply_labels(kb, dry):
    r = kb.call("GET", f"/api/data_views/data_view/{DATA_VIEW_ID}")
    if r.status_code != 200:
        sys.exit(f"data view missing: HTTP {r.status_code}. Run kibana_setup.py first.")
    known = set(r.json()["data_view"].get("fields", {}))
    payload, skipped = {}, []
    for field, (label, desc) in FIELD_LABELS.items():
        if known and field not in known:
            skipped.append(field)
            continue
        payload[field] = {"customLabel": label, "customDescription": desc}
    if dry:
        print(f"  WOULD label {len(payload)} fields "
              f"({len(skipped)} not present in this index yet)")
        return
    r = kb.call("POST", f"/api/data_views/data_view/{DATA_VIEW_ID}/fields",
                json={"fields": payload})
    if r.status_code == 200:
        print(f"  labelled {len(payload)} fields")
        if skipped:
            print(f"  skipped {len(skipped)} not present in the index: "
                  f"{', '.join(sorted(skipped)[:6])}"
                  f"{' ...' if len(skipped) > 6 else ''}")
    else:
        print(f"  FAILED: HTTP {r.status_code} {r.text[:300]}")


def build_control_group():
    panels = {}
    for order, (title, field, width) in enumerate(CONTROLS):
        cid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"hayabusa-ctl-{field}"))
        # Keep explicitInput to EXACTLY these keys. Kibana 9.0.8 renders the
        # dropdown empty ("No options found") if extra keys such as
        # searchTechnique or selectedOptions are present. Verified against a
        # working Security Onion dashboard's control config.
        panels[cid] = {
            "type": "optionsListControl",
            "order": order,
            "grow": True,
            "width": width,
            "explicitInput": {
                "id": cid,
                "fieldName": field,
                "title": title,
                "singleSelect": False,
                "enhancements": {},
            },
        }
    return {
        "controlStyle": "oneLine",
        "chainingSystem": "HIERARCHICAL",
        "showApplySelections": False,
        "ignoreParentSettingsJSON": json.dumps({
            "ignoreFilters": False, "ignoreQuery": False,
            "ignoreTimerange": False, "ignoreValidations": False}),
        "panelsJSON": json.dumps(panels),
    }, list(panels.keys())


def add_controls(kb, dashboard_id, dry):
    r = kb.call("GET", f"/api/saved_objects/dashboard/{dashboard_id}")
    if r.status_code != 200:
        print(f"  dashboard {dashboard_id} not found (HTTP {r.status_code}) - skipping")
        return
    obj = r.json()
    attrs = obj["attributes"]
    refs = [x for x in obj["references"]
            if not x["name"].startswith("controlGroup_")]

    cg, ids = build_control_group()
    for cid in ids:
        refs.append({"name": f"controlGroup_{cid}:optionsListDataView",
                     "type": "index-pattern", "id": DATA_VIEW_ID})
    attrs["controlGroupInput"] = cg

    if dry:
        print(f"  WOULD add {len(ids)} dropdown controls to {dashboard_id}: "
              f"{', '.join(t for t, _, _ in CONTROLS)}")
        return
    r = kb.call("PUT", f"/api/saved_objects/dashboard/{dashboard_id}",
                json={"attributes": attrs, "references": refs})
    if r.status_code == 200:
        print(f"  added {len(ids)} dropdowns to {dashboard_id}: "
              f"{', '.join(t for t, _, _ in CONTROLS)}")
    else:
        print(f"  FAILED: HTTP {r.status_code} {r.text[:300]}")


def create_saved_searches(kb, dry):
    for sid, title, desc, query, columns in SAVED_SEARCHES:
        if dry:
            print(f"  WOULD create saved search '{title}'")
            continue
        body = {
            "attributes": {
                "title": title,
                "description": desc,
                "columns": columns,
                "sort": [["@timestamp", "desc"]],
                "grid": {},
                "hideChart": False,
                "isTextBasedQuery": False,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "query": {"query": query, "language": "kuery"},
                        "filter": [],
                        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    })
                },
            },
            "references": [{
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern", "id": DATA_VIEW_ID,
            }],
        }
        kb.call("DELETE", f"/api/saved_objects/search/{sid}")
        r = kb.call("POST", f"/api/saved_objects/search/{sid}", json=body)
        status = "created" if r.status_code in (200, 201) else f"FAILED {r.status_code}"
        print(f"  {status:<8} {title}")
        if r.status_code not in (200, 201):
            print(f"           {r.text[:200]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env-file", default=DEFAULT_ENV)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--dashboards", nargs="*", default=[DASHBOARD_ID],
                    help="Dashboard ids to attach controls to")
    args = ap.parse_args()

    kb = Kibana(load_env(args.env_file))
    print(f"connected to https://{kb.host}/kibana\n")

    print("1. FIELD LABELS (operators see friendly names, not field paths)")
    apply_labels(kb, args.dry_run)

    print("\n2. DASHBOARD CONTROLS (dropdowns instead of typing queries)")
    for d in args.dashboards:
        add_controls(kb, d, args.dry_run)

    print("\n3. SAVED SEARCHES (pre-built Discover views)")
    create_saved_searches(kb, args.dry_run)

    if not args.dry_run:
        print(f"\nDashboard : https://{kb.host}/kibana/app/dashboards#/view/{DASHBOARD_ID}")
        print(f"Discover  : https://{kb.host}/kibana/app/discover  (Open -> pick a 'Hayabusa:' search)")


if __name__ == "__main__":
    main()
