#!/usr/bin/env python3
"""Fifth dashboard: MITRE ATT&CK, on its own.

Until v37 the tactic and technique panels sat on the Overview and PEAK
dashboards, where the operator found them more noise than help (operator
request, 2026-10-15) - only some Sigma rules carry an ATT&CK tag, so they
describe part of the picture at best. They live here now, for whoever wants
the ATT&CK view, and the other dashboards stay about the detections.

The three moved panels keep their saved-object ids (hayabusa-mitre-tactics,
hayabusa-mitre-techniques, hayabusa-peak-tactics), so importing this over an
older set replaces them rather than leaving copies behind.

Usage:
  python scripts/make_mitre_dashboard.py -o output/hayabusa-mitre.ndjson
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_dashboard import stamp, col_count, col_terms, col_date, xy, datatable, metric, labelled  # noqa: E402
from make_dashboard import lens as plain_lens  # noqa: E402
from make_hunt_dashboard import build_dashboard as build_lens_dashboard  # noqa: E402
from make_peak_dashboard import table  # noqa: E402

DASHBOARD_ID = "hayabusa-mitre-dashboard"
MAPPED = "threat.tactic.name: *"


def build_panels():
    p = []
    p.append((plain_lens(
        "hayabusa-mitre-mapped", "Detections with an ATT&CK mapping",
        "How many detections carry a tactic at all. Only rules tagged with ATT&CK "
        "do, so everything on this dashboard describes that share, not every detection.",
        metric(), labelled({"c_metric": col_count("Detections with a tactic", kuery=MAPPED)}), ["c_metric"]),
        {"x": 0, "y": 0, "w": 12, "h": 8}))
    p.append((plain_lens(
        "hayabusa-mitre-timeline", "Tactics over time",
        "When each tactic was seen. Discovery, then Credential Access, then Lateral "
        "Movement in that order is how an intrusion usually reads.",
        xy(series="bar_stacked", split="c_split"),
        {"c_metric": col_count(), "c_bucket": col_date(),
         "c_split": col_terms("threat.tactic.name", 10, "Tactic")},
        ["c_bucket", "c_split", "c_metric"]),
        {"x": 12, "y": 0, "w": 36, "h": 14}))
    p.append((plain_lens(
        "hayabusa-mitre-tactics", "MITRE ATT&CK tactics",
        "Detections per ATT&CK tactic.",
        xy(series="bar_horizontal"),
        {"c_metric": col_count(), "c_bucket": col_terms("threat.tactic.name", 15, "Tactic")},
        ["c_bucket", "c_metric"]),
        {"x": 0, "y": 8, "w": 12, "h": 20}))
    p.append((table(
        "hayabusa-peak-tactics", "ATT&CK tactic > host",
        "Which hosts each tactic was seen on. Execution plus Persistence plus "
        "Lateral Movement on the same host is the story of an intrusion.",
        [("threat.tactic.name", 15, "Tactic", "desc"), ("host.name", 5, "Computer", "desc")],
        MAPPED), {"x": 12, "y": 14, "w": 18, "h": 16}))
    p.append((plain_lens(
        "hayabusa-mitre-techniques", "Top ATT&CK techniques",
        "Technique IDs from the matched Sigma rules.",
        datatable(columns=["c_bucket", "c_metric"]),
        labelled({"c_metric": col_count("Times seen"), "c_bucket": col_terms("threat.technique.id", 20, "Technique")}),
        ["c_bucket", "c_metric"]),
        {"x": 30, "y": 14, "w": 18, "h": 16}))
    p.append((table(
        "hayabusa-mitre-technique-rules", "Technique > rule > host",
        "Which rules produced each technique, and where. Open a technique's rules in "
        "Discover to see the events behind it.",
        [("threat.technique.id", 20, "Technique", "desc"), ("rule.name", 5, "Detection rule", "desc"),
         ("host.name", 3, "Computer", "desc")],
        "threat.technique.id: *"), {"x": 0, "y": 30, "w": 48, "h": 16}))
    return p


def build_dashboard(panels):
    d = build_lens_dashboard(panels)
    d["id"] = DASHBOARD_ID
    d["attributes"].update(
        title="Hayabusa - MITRE ATT&CK",
        description="The ATT&CK view of the Hayabusa detections: tactics, techniques, "
                    "where and when. Only detections whose Sigma rule carries an ATT&CK "
                    "tag appear here (see the first panel for how many). The query bar "
                    "hides this tool's own collection activity (tags: evtxer-collection); "
                    "clear it to see that too.",
        kibanaSavedObjectMeta={"searchSourceJSON": json.dumps(
            {"query": {"query": "not tags: evtxer-collection", "language": "kuery"}, "filter": []})},
    )
    return d


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", default="output/hayabusa-mitre.ndjson")
    args = ap.parse_args()
    panels = build_panels()
    objects = [stamp(o) for o, _ in panels] + [stamp(build_dashboard(panels))]
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        for o in objects:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"wrote {len(objects)} objects -> {args.output}")
    print(f"  {len(panels)} panels, 1 dashboard ({DASHBOARD_ID})")


if __name__ == "__main__":
    main()
