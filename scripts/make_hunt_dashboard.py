#!/usr/bin/env python3
"""Second dashboard: threat-hunting views the overview dashboard lacks.

The overview answers "what fired most". This one answers "what looks wrong",
which is a different question and mostly needs the OPPOSITE sort order --
rare things, not common ones.

Panels:
  * Least-frequency analysis: rarest programs, command lines, parent->child
    pairs and users. Malware is rare by definition; noise is common.
  * Suspicious execution: HackTool/Suspicious rules, LOLBins, interpreters.
  * Scripts: PowerShell script text, encoded/obfuscated commands.
  * Network: external (non-RFC1918) destinations.
  * Persistence: service installations and registry autoruns.

Usage:
  python scripts/make_hunt_dashboard.py -o output/hayabusa-hunt.ndjson
  python scripts/kibana_setup.py --ndjson output/hayabusa-hunt.ndjson
"""
import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_dashboard import (  # noqa: E402
    DATA_VIEW_ID, TIME_FROM, TIME_TO, stamp,
    col_count, col_date, datatable, xy, metric, pie,
)

DASHBOARD_ID = "hayabusa-hunt-dashboard"

LOLBINS = ('"certutil.exe" or "mshta.exe" or "regsvr32.exe" or "rundll32.exe" or '
           '"wscript.exe" or "cscript.exe" or "bitsadmin.exe" or "wmic.exe" or '
           '"msbuild.exe" or "installutil.exe" or "regasm.exe" or "odbcconf.exe" or '
           '"forfiles.exe" or "pcalua.exe" or "desktopimgdownldr.exe"')

INTERPRETERS = ('"powershell.exe" or "pwsh.exe" or "cmd.exe" or "python.exe" or '
                '"wscript.exe" or "cscript.exe" or "mshta.exe" or "bash.exe"')

# RFC1918 + loopback + link-local + multicast. Anything else is "outside".
INTERNAL = ('source.ip: (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16 or '
            '127.0.0.0/8 or 169.254.0.0/16 or 224.0.0.0/4)')


def col_terms_ordered(field, size, label, direction="desc", order_col="c_metric"):
    """Terms bucket. direction='asc' gives least-frequency analysis."""
    return {
        "label": label,
        "dataType": "string",
        "operationType": "terms",
        "scale": "ordinal",
        "sourceField": field,
        "isBucketed": True,
        "params": {
            "size": size,
            "orderBy": {"type": "column", "columnId": order_col},
            "orderDirection": direction,
            "otherBucket": False,
            "missingBucket": False,
        },
    }


def lens(obj_id, title, description, visualization, columns, column_order, query=""):
    """Like make_dashboard.lens but supports a per-panel KQL query."""
    layer_id = "layer1"
    return {
        "id": obj_id,
        "type": "lens",
        "managed": False,
        "attributes": {
            "title": title,
            "description": description,
            "visualizationType": visualization["_type"],
            "state": {
                "visualization": {k: v for k, v in visualization.items() if k != "_type"},
                "query": {"query": query, "language": "kuery"},
                "filters": [],
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            layer_id: {
                                "columns": columns,
                                "columnOrder": column_order,
                                "incompleteColumns": {},
                                "sampling": 1,
                            }
                        }
                    }
                },
                "internalReferences": [],
                "adHocDataViews": {},
            },
        },
        "references": [{
            "type": "index-pattern", "id": DATA_VIEW_ID,
            "name": f"indexpattern-datasource-layer-{layer_id}",
        }],
    }


def build_panels():
    p = []
    y = 0

    # ---- ROW 1: least-frequency analysis, the headline technique ----------
    p.append((lens(
        "hayabusa-hunt-rare-programs", "RAREST programs (least-frequency analysis)",
        "Programs seen fewest times. Malware is rare; legitimate software is common. "
        "Random-looking names here are worth immediate attention.",
        datatable(columns=["c_bucket", "c_metric"]),
        {"c_metric": col_count("Times seen"),
         "c_bucket": col_terms_ordered("process.name", 30, "Program", "asc")},
        ["c_bucket", "c_metric"], query="process.name: *"),
        {"x": 0, "y": y, "w": 16, "h": 17}))

    p.append((lens(
        "hayabusa-hunt-rare-cmdline", "RAREST command lines",
        "One-off command lines. Attacker commands are usually unique; "
        "scheduled tasks and scripts repeat.",
        datatable(columns=["c_bucket", "c_metric"]),
        {"c_metric": col_count("Times seen"),
         "c_bucket": col_terms_ordered("process.command_line", 30, "Command Line", "asc")},
        ["c_bucket", "c_metric"], query="process.command_line: *"),
        {"x": 16, "y": y, "w": 32, "h": 17}))
    y += 17

    # ---- ROW 2: parent/child + rare users --------------------------------
    p.append((lens(
        "hayabusa-hunt-parent-child", "Unusual parent -> child process pairs",
        "Rarest launch relationships. services.exe spawning calc.exe, or "
        "winword.exe spawning powershell.exe, are the shapes to look for.",
        datatable(columns=["c_parent", "c_child", "c_metric"]),
        {"c_metric": col_count("Times seen"),
         "c_parent": col_terms_ordered("process.parent.name", 20, "Parent Program", "asc"),
         "c_child": col_terms_ordered("process.name", 1, "Child Program")},
        ["c_parent", "c_child", "c_metric"], query="process.parent.name: *"),
        {"x": 0, "y": y, "w": 24, "h": 16}))

    p.append((lens(
        "hayabusa-hunt-rare-users", "RAREST user accounts",
        "Accounts appearing least often. Newly created or attacker-used accounts "
        "surface here before anything alerts on them.",
        datatable(columns=["c_bucket", "c_metric"]),
        {"c_metric": col_count("Times seen"),
         "c_bucket": col_terms_ordered("user.name", 25, "User Account", "asc")},
        ["c_bucket", "c_metric"], query="user.name: *"),
        {"x": 24, "y": y, "w": 24, "h": 16}))
    y += 16

    # ---- ROW 3: suspicious execution -------------------------------------
    p.append((lens(
        "hayabusa-hunt-hacktools", "HackTools and suspicious executables",
        "Rules explicitly naming hacking tools or suspicious binaries.",
        xy(series="bar_horizontal"),
        {"c_metric": col_count(),
         "c_bucket": col_terms_ordered("rule.name", 15, "Detection Rule")},
        ["c_bucket", "c_metric"],
        query='rule.name: (*HackTool* or *Suspicious* or *Malicious* or *Mimikatz*)'),
        {"x": 0, "y": y, "w": 24, "h": 15}))

    p.append((lens(
        "hayabusa-hunt-lolbins", "LOLBin usage",
        "Living-off-the-land binaries: signed Microsoft tools abused to download, "
        "execute or bypass controls.",
        xy(series="bar_horizontal", split="c_split"),
        {"c_metric": col_count(),
         "c_bucket": col_terms_ordered("process.name", 15, "Program"),
         "c_split": col_terms_ordered("hayabusa.level", 5, "Severity")},
        ["c_bucket", "c_split", "c_metric"], query=f"process.name: ({LOLBINS})"),
        {"x": 24, "y": y, "w": 24, "h": 15}))
    y += 15

    # ---- ROW 4: scripting -------------------------------------------------
    p.append((lens(
        "hayabusa-hunt-interpreters", "Script interpreters",
        "Which interpreters ran, split by severity.",
        pie(shape="donut"),
        {"c_metric": col_count(),
         "c_bucket": col_terms_ordered("process.name", 10, "Interpreter")},
        ["c_bucket", "c_metric"], query=f"process.name: ({INTERPRETERS})"),
        {"x": 0, "y": y, "w": 16, "h": 15}))

    p.append((lens(
        "hayabusa-hunt-encoded", "Encoded / obfuscated commands",
        "base64, -enc, -bypass, hidden windows. Deliberate evasion, not normal admin work.",
        datatable(columns=["c_host", "c_bucket", "c_metric"]),
        {"c_metric": col_count(),
         "c_host": col_terms_ordered("host.name", 20, "Computer"),
         "c_bucket": col_terms_ordered("process.command_line", 1, "Command Line")},
        ["c_host", "c_bucket", "c_metric"],
        query="process.command_line: (*enc* or *EncodedCommand* or *FromBase64* or "
              "*bypass* or *hidden* or *noprofile* or *DownloadString* or *IEX*)"),
        {"x": 16, "y": y, "w": 32, "h": 15}))
    y += 15

    # ---- ROW 5: network + persistence ------------------------------------
    p.append((lens(
        "hayabusa-hunt-external", "Connections OUTSIDE the network",
        "Source IPs that are not RFC1918/loopback/multicast. Pivot these into "
        "Hunt against Zeek and Suricata.",
        datatable(columns=["c_bucket", "c_host", "c_metric"]),
        {"c_metric": col_count(),
         "c_bucket": col_terms_ordered("source.ip", 20, "External IP"),
         "c_host": col_terms_ordered("host.name", 1, "Computer")},
        ["c_bucket", "c_host", "c_metric"], query=f"source.ip: * and not {INTERNAL}"),
        {"x": 0, "y": y, "w": 24, "h": 15}))

    p.append((lens(
        "hayabusa-hunt-persistence", "Persistence: services, autoruns, scheduled tasks",
        "How an attacker survives a reboot. Service installs are the classic "
        "lateral-movement footprint.",
        xy(series="bar_horizontal", split="c_split"),
        {"c_metric": col_count(),
         "c_bucket": col_terms_ordered("rule.name", 15, "Detection Rule"),
         "c_split": col_terms_ordered("hayabusa.level", 5, "Severity")},
        ["c_bucket", "c_split", "c_metric"],
        query="rule.name: (*Service* or *Registry* or *Autorun* or *Scheduled* or "
              "*Startup* or *Persist* or *WMI*)"),
        {"x": 24, "y": y, "w": 24, "h": 15}))
    y += 15

    # ---- ROW 6: timing ----------------------------------------------------
    p.append((lens(
        "hayabusa-hunt-offhours", "Activity by hour of day",
        "Attacker activity often clusters outside business hours. Bars far from "
        "the normal working-day shape deserve a look.",
        xy(series="bar_stacked", split="c_split"),
        {"c_metric": col_count(),
         "c_bucket": col_date(),
         "c_split": col_terms_ordered("host.name", 10, "Computer")},
        ["c_bucket", "c_split", "c_metric"], query="event.severity >= 50"),
        {"x": 0, "y": y, "w": 48, "h": 14}))

    return p


def build_dashboard(panels):
    pj, refs = [], []
    for i, (obj, grid) in enumerate(panels, start=1):
        name = f"panel_{i}"
        pj.append({"type": "lens", "gridData": {**grid, "i": str(i)},
                   "panelIndex": str(i), "embeddableConfig": {"enhancements": {}},
                   "panelRefName": name})
        refs.append({"name": name, "type": "lens", "id": obj["id"]})
    return {
        "id": DASHBOARD_ID, "type": "dashboard", "managed": False,
        "attributes": {
            "title": "Hayabusa - Threat Hunting",
            "description": "Rare-event and behaviour-focused views. Use alongside the "
                           "Overview dashboard: Overview shows what fired most, this "
                           "shows what looks wrong.",
            "panelsJSON": json.dumps(pj),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": True,
                                       "syncCursor": True, "syncTooltips": True,
                                       "hidePanelTitles": False}),
            "version": 3, "timeRestore": True,
            "timeFrom": TIME_FROM, "timeTo": TIME_TO,
            "refreshInterval": {"pause": True, "value": 60000},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": refs,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", default="output/hayabusa-hunt.ndjson")
    args = ap.parse_args()

    panels = build_panels()
    objects = [stamp(o) for o, _ in panels] + [stamp(build_dashboard(panels))]
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        for o in objects:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"wrote {len(objects)} objects -> {args.output}")
    print(f"  {len(panels)} panels, 1 dashboard ({DASHBOARD_ID})")


if __name__ == "__main__":
    main()
