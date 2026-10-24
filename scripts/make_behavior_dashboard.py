#!/usr/bin/env python3
"""Third dashboard: behavioural analytics.

Overview  = what fired most.
Hunting   = what is rare.
Behaviour = what is ANOMALOUS relative to the rest of the estate -- software
            that exists on only one machine, programs appearing for the first
            time, and logon patterns that indicate lateral movement.

Panels:
  * Host baseline    - programs present on only one host (320 of 428 here)
  * Software spread  - how many distinct programs each host ran
  * First seen       - earliest appearance per program; newest = most suspicious
  * Logon heatmap    - logon type against host; Type 3/10 concentration is
                       the classic lateral-movement fingerprint
  * Logon over time  - bursts of network logons
  * Accounts by logon type

Uses the `op.LogonType` runtime field created by operator_setup.py, because
LogonType lives inside the flattened `hayabusa.details` object.

Usage:
  python scripts/make_behavior_dashboard.py -o output/hayabusa-behavior.ndjson
  python scripts/kibana_setup.py --ndjson output/hayabusa-behavior.ndjson
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_dashboard import (  # noqa: E402
    DATA_VIEW_ID, TIME_FROM, TIME_TO, stamp, col_count, col_date, datatable, xy,
)
from make_hunt_dashboard import col_terms_ordered, lens  # noqa: E402

DASHBOARD_ID = "hayabusa-behavior-dashboard"
LOGON_FIELD = "op.LogonType"


def col_unique(field, label):
    return {
        "label": label, "dataType": "number", "operationType": "unique_count",
        "isBucketed": False, "scale": "ratio", "sourceField": field,
    }


def col_min_date(label="First seen", field="@timestamp"):
    return {
        "label": label, "dataType": "date", "operationType": "min",
        "isBucketed": False, "scale": "interval", "sourceField": field,
        "params": {"emptyAsNull": True},
    }


def col_max_date(label="Last seen", field="@timestamp"):
    return {
        "label": label, "dataType": "date", "operationType": "max",
        "isBucketed": False, "scale": "interval", "sourceField": field,
        "params": {"emptyAsNull": True},
    }


def heatmap(layer_id="layer1", value="c_metric", x="c_x", y="c_y"):
    return {
        "_type": "lnsHeatmap",
        "shape": "heatmap",
        "layerId": layer_id,
        "layerType": "data",
        "valueAccessor": value,
        "xAccessor": x,
        "yAccessor": y,
        "legend": {"isVisible": True, "position": "right", "type": "heatmap_legend"},
        "gridConfig": {
            "type": "heatmap_grid", "isCellLabelVisible": True,
            "isXAxisLabelVisible": True, "isYAxisLabelVisible": True,
            "isXAxisTitleVisible": False, "isYAxisTitleVisible": False,
        },
    }


def build_panels():
    p, y = [], 0

    # ---- ROW 1: host baseline -------------------------------------------
    p.append((lens(
        "hayabusa-bhv-single-host", "Software found on only ONE host",
        "Programs whose 'Hosts' count is 1. In a managed estate, legitimate "
        "software appears on many machines. A binary unique to one box is either "
        "bespoke, unmanaged, or hostile. 320 of 428 programs qualify here.",
        datatable(columns=["c_bucket", "c_hosts", "c_metric"]),
        {"c_hosts": col_unique("host.name", "Hosts"),
         "c_metric": col_count("Executions"),
         "c_bucket": col_terms_ordered("process.name", 30, "Program", "asc", "c_hosts")},
        ["c_bucket", "c_hosts", "c_metric"], query="process.name: *"),
        {"x": 0, "y": y, "w": 24, "h": 17}))

    p.append((lens(
        "hayabusa-bhv-host-spread", "Software diversity per host",
        "Distinct programs seen on each machine. An outlier running far more "
        "distinct binaries than its peers is worth explaining.",
        xy(series="bar_horizontal"),
        {"c_metric": col_unique("process.name", "Distinct programs"),
         "c_bucket": col_terms_ordered("host.name", 20, "Computer")},
        ["c_bucket", "c_metric"], query="process.name: *"),
        {"x": 24, "y": y, "w": 24, "h": 17}))
    y += 17

    # ---- ROW 2: first seen ----------------------------------------------
    p.append((lens(
        "hayabusa-bhv-first-seen", "First seen - newest programs in the estate",
        "Earliest appearance of each program, newest first. Genuinely NEW software "
        "is a stronger signal than merely rare software. Check the top rows against "
        "your change record.",
        datatable(columns=["c_bucket", "c_first", "c_last", "c_metric"]),
        {"c_first": col_min_date(), "c_last": col_max_date(),
         "c_metric": col_count("Executions"),
         "c_bucket": col_terms_ordered("process.name", 30, "Program", "desc", "c_first")},
        ["c_bucket", "c_first", "c_last", "c_metric"], query="process.name: *"),
        {"x": 0, "y": y, "w": 28, "h": 17}))

    p.append((lens(
        "hayabusa-bhv-first-seen-users", "First seen - newest accounts",
        "Accounts by first appearance. Newly created accounts near the end of an "
        "incident timeline are a common persistence move.",
        datatable(columns=["c_bucket", "c_first", "c_metric"]),
        {"c_first": col_min_date(), "c_metric": col_count("Events"),
         "c_bucket": col_terms_ordered("user.name", 25, "User Account", "desc", "c_first")},
        ["c_bucket", "c_first", "c_metric"], query="user.name: *"),
        {"x": 28, "y": y, "w": 20, "h": 17}))
    y += 17

    # ---- ROW 3: logon behaviour -----------------------------------------
    p.append((lens(
        "hayabusa-bhv-logon-heatmap", "Logon type by host",
        "Type 3 = Network, Type 10 = RDP. A host suddenly showing many Type 3 or "
        "Type 10 logons is the classic lateral-movement fingerprint.",
        heatmap(),
        {"c_metric": col_count("Logons"),
         "c_x": col_terms_ordered(LOGON_FIELD, 12, "Logon Type"),
         "c_y": col_terms_ordered("host.name", 20, "Computer")},
        ["c_y", "c_x", "c_metric"], query=f"{LOGON_FIELD}: *"),
        {"x": 0, "y": y, "w": 28, "h": 18}))

    p.append((lens(
        "hayabusa-bhv-logon-users", "Accounts by logon type",
        "Which accounts authenticate which way. A service account doing "
        "interactive or RDP logons is an anomaly.",
        datatable(columns=["c_user", "c_type", "c_metric"]),
        {"c_metric": col_count("Logons"),
         "c_user": col_terms_ordered("user.name", 25, "User Account"),
         "c_type": col_terms_ordered(LOGON_FIELD, 1, "Logon Type")},
        ["c_user", "c_type", "c_metric"], query=f"{LOGON_FIELD}: *"),
        {"x": 28, "y": y, "w": 20, "h": 18}))
    y += 18

    # ---- ROW 4: logon volume over time ----------------------------------
    p.append((lens(
        "hayabusa-bhv-logon-time", "Logon activity over time by type",
        "Spikes in network logons often mark the moment lateral movement began.",
        xy(series="bar_stacked", split="c_split"),
        {"c_metric": col_count("Logons"), "c_bucket": col_date(),
         "c_split": col_terms_ordered(LOGON_FIELD, 10, "Logon Type")},
        ["c_bucket", "c_split", "c_metric"], query=f"{LOGON_FIELD}: *"),
        {"x": 0, "y": y, "w": 48, "h": 14}))
    y += 14

    # ---- ROW 5: host x rule concentration -------------------------------
    p.append((lens(
        "hayabusa-bhv-host-rule", "Rule activity concentrated on few hosts",
        "Detection rules that fire on only one or two machines. Estate-wide noise "
        "sorts to the bottom; targeted activity rises to the top.",
        datatable(columns=["c_bucket", "c_hosts", "c_metric"]),
        {"c_hosts": col_unique("host.name", "Hosts"),
         "c_metric": col_count("Detections"),
         "c_bucket": col_terms_ordered("rule.name", 30, "Detection Rule", "asc", "c_hosts")},
        ["c_bucket", "c_hosts", "c_metric"], query="event.severity >= 50"),
        {"x": 0, "y": y, "w": 48, "h": 17}))

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
            "title": "Hayabusa - Behavioural Analytics",
            "description": "Anomaly-focused views: host baselining, first-seen "
                           "tracking, and logon-pattern analysis. Finds things no "
                           "signature flagged.",
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
    ap.add_argument("-o", "--output", default="output/hayabusa-behavior.ndjson")
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
