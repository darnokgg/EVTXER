#!/usr/bin/env python3
"""Sixth dashboard: Hayabusa's own Results Summary, in Kibana.

Hayabusa ends every scan with a Results Summary (the console screen, and the
HTML report the Convert tab writes beside the results). Its authors chose what
is worth seeing first, so this dashboard rebuilds it from the uploaded
detections (operator request, 2026-10-15):

  First / last detection            -> panel row 1
  Total and unique detections       -> "Detections by level"
  Dates with most total detections  -> "Busiest day per level"
  Computers with most unique dets.  -> "Computers with most unique detections"
  All alerts per level              -> "All alerts by level"
  (hayabusa logon-summary)          -> "Successful logons" / "Failed logons"

Not here, because Elasticsearch never receives them: "Total events analyzed"
and "Data reduction" (only events that matched a rule are uploaded - the
Convert tab's COVERAGE line has them), and the per-computer ATT&CK tactics,
which are on the MITRE ATT&CK dashboard.

"Busiest day" groups by the op.DetectionDay runtime field (the UTC date of
@timestamp), which lives in the data view - see DETECTION_DAY below. Lens
cannot rank date-histogram buckets, so a day has to be a term.

Usage:
  python scripts/make_summary_dashboard.py -o output/hayabusa-summary.ndjson
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_dashboard import stamp, col_count, col_date, xy, datatable, metric, labelled  # noqa: E402
from make_hunt_dashboard import col_terms_ordered, lens, build_dashboard as build_lens_dashboard  # noqa: E402
from make_behavior_dashboard import col_unique, col_min_date, col_max_date  # noqa: E402

DASHBOARD_ID = "hayabusa-summary-dashboard"
# Unique detections are counted by rule.id, not rule.name: several rules share
# a title, and only the id count reproduces Hayabusa's numbers (checked on the
# 600-file sample corpus: 19/271/247/83/68 by id, 17/239/222/69/63 by name).
# Hayabusa's levels, in its own order (worst first).
LEVELS = ["emergency", "critical", "high", "medium", "low", "informational"]
# The data view runtime field the busiest-day table groups by. Added to the
# data view with Kibana's runtime_field API and shipped inside the export, the
# same way as the op.* fields the Behavioural dashboard reads.
DETECTION_DAY = {
    "name": "op.DetectionDay",
    "runtimeField": {"type": "keyword", "script": {"source":
        "if (doc['@timestamp'].size() != 0) { emit(doc['@timestamp'].value.toString().substring(0, 10)); }"}},
}


def col_levels(label="Level"):
    """One row per Hayabusa level, always in severity order (a terms bucket
    would sort by count, putting informational first)."""
    return {"label": label, "dataType": "string", "operationType": "filters", "scale": "ordinal",
            "isBucketed": True,
            "params": {"filters": [{"input": {"query": f'hayabusa.level: "{lv}"', "language": "kuery"},
                                    "label": lv} for lv in LEVELS]}}


def table(obj_id, title, description, cols, order, query=""):
    return lens(obj_id, title, description, datatable(columns=order), labelled(cols), order, query=query)


def tile(obj_id, title, description, col, color):
    return lens(obj_id, title, description, metric(color=color), labelled({"c_metric": col}), ["c_metric"])


def build_panels():
    p = []
    # ---- the header: when, how many, how varied ---------------------------
    for (oid, title, desc, col, color), (x, w) in zip([
        ("hayabusa-summary-first", "First detection", "The earliest detection in range (Hayabusa: First detection).",
         col_min_date("First detection"), "#6092C0"),
        ("hayabusa-summary-last", "Last detection", "The latest detection in range (Hayabusa: Last detection).",
         col_max_date("Last detection"), "#6092C0"),
        ("hayabusa-summary-total", "Total detections", "Every detection (Hayabusa: Total detections).",
         col_count("Total detections"), "#0077cc"),
        ("hayabusa-summary-unique", "Unique detections", "Distinct rules that fired (Hayabusa: Unique detections).",
         col_unique("rule.id", "Unique detections"), "#0077cc"),
        ("hayabusa-summary-hosts", "Computers", "Computers with at least one detection.",
         col_unique("host.name", "Computers"), "#54B399"),
    ], [(0, 10), (10, 10), (20, 10), (30, 9), (39, 9)]):
        p.append((tile(oid, title, desc, col, color), {"x": x, "y": 0, "w": w, "h": 6}))

    # ---- per level --------------------------------------------------------
    p.append((table(
        "hayabusa-summary-levels", "Detections by level",
        "Hayabusa's Total and Unique detections per level, with how many computers and when. "
        "Unique = distinct rules, counted by rule ID as Hayabusa does (several rules share a "
        "title). Click a level to filter the dashboard.",
        {"c_level": col_levels(), "c_metric": col_count("Total detections"),
         "c_unique": col_unique("rule.id", "Unique detections"), "c_hosts": col_unique("host.name", "Computers"),
         "c_first": col_min_date("First"), "c_last": col_max_date("Last")},
        ["c_level", "c_metric", "c_unique", "c_hosts", "c_first", "c_last"]),
        {"x": 0, "y": 6, "w": 28, "h": 12}))
    p.append((table(
        "hayabusa-summary-busiest-day", "Busiest day per level",
        "Hayabusa's 'Dates with most total detections': the single day (UTC) with the most "
        "detections at each level. A burst of high detections on one day is where to start.",
        {"c_level": col_levels(), "c_day": col_terms_ordered(DETECTION_DAY["name"], 1, "Day (UTC)"),
         "c_metric": col_count("Detections that day")},
        ["c_level", "c_day", "c_metric"]),
        {"x": 28, "y": 6, "w": 20, "h": 12}))
    p.append((table(
        "hayabusa-summary-computers", "Computers with most unique detections, by level",
        "Hayabusa's 'Computers with most unique detections': per level, the computers on which "
        "the most DIFFERENT rules fired. Many distinct rules on one box is a story; one rule "
        "firing thousands of times is usually noise.",
        {"c_level": col_levels(), "c_host": col_terms_ordered("host.name", 10, "Computer", order_col="c_unique"),
         "c_unique": col_unique("rule.id", "Unique detections"), "c_metric": col_count("Total detections")},
        ["c_level", "c_host", "c_unique", "c_metric"]),
        {"x": 0, "y": 18, "w": 22, "h": 20}))
    p.append((table(
        "hayabusa-summary-alerts", "All alerts by level",
        "Hayabusa's 'All alerts': every rule that fired, per level, with its count and how many "
        "computers it fired on. Read the critical and high ones in full.",
        {"c_level": col_levels(), "c_rule": col_terms_ordered("rule.name", 100, "Detection rule"),
         "c_metric": col_count("Detections"), "c_hosts": col_unique("host.name", "Computers")},
        ["c_level", "c_rule", "c_metric", "c_hosts"]),
        {"x": 22, "y": 18, "w": 26, "h": 20}))
    p.append((lens(
        "hayabusa-summary-timeline", "Detection timeline by level",
        "Hayabusa's detection frequency timeline: when detections happened, stacked by level.",
        xy(series="bar_stacked", split="c_split"),
        labelled({"c_bucket": col_date(label="Time"), "c_split": col_levels(), "c_metric": col_count("Detections")}),
        ["c_bucket", "c_split", "c_metric"]),
        {"x": 0, "y": 38, "w": 48, "h": 12}))

    # ---- hayabusa logon-summary --------------------------------------------
    logon_rows = [("user.name", 25, "Target account"), ("host.name", 5, "Target computer"),
                  ("winlog.logon.type", 3, "Logon type"), ("winlog.event_data.WorkstationName", 3, "Source computer"),
                  # The raw IpAddress, not source.ip: a local logon's "-" is no IP, so it has no
                  # source.ip, and a Lens table silently drops an event missing a row field -
                  # 39 of 347 sample logons vanished (2026-10-17). "-" is what Hayabusa shows.
                  ("winlog.event_data.IpAddress", 3, "Source IP")]
    for oid, title, desc, code, y in [
        ("hayabusa-summary-logons", "Successful logons (4624)",
         "Like hayabusa logon-summary: who logged on to which computer, how, and from where. "
         "Counts detections, so only logons a Hayabusa rule reported (its logon rules cover "
         "the common types). Source computer and IP need data converted with v37 or later.", "4624", 50),
        ("hayabusa-summary-failed", "Failed logons (4625)",
         "Like hayabusa logon-summary's failed logons: which accounts failed on which computer, "
         "from where. Many accounts from one source is spraying.", "4625", 66),
    ]:
        cols = {f"c_r{i}": col_terms_ordered(f, n, lbl) for i, (f, n, lbl) in enumerate(logon_rows)}
        cols["c_metric"] = col_count("Count")
        order = [f"c_r{i}" for i in range(len(logon_rows))] + ["c_metric"]
        p.append((table(oid, title, desc, cols, order, query=f'event.code: "{code}"'),
                  {"x": 0, "y": y, "w": 48, "h": 16}))
    return p


def build_dashboard(panels):
    d = build_lens_dashboard(panels)
    d["id"] = DASHBOARD_ID
    d["attributes"].update(
        title="Hayabusa - Results Summary",
        description="Hayabusa's own Results Summary (the end-of-scan screen and HTML report), "
                    "rebuilt from the uploaded detections: totals and unique rules per level, the "
                    "busiest day per level, the computers with the most distinct detections, every "
                    "alert, the timeline, and a logon summary. Events that matched no rule are not "
                    "uploaded, so Hayabusa's 'Total events analyzed' and 'Data reduction' are in the "
                    "Convert tab's COVERAGE line instead. The query bar hides this tool's own "
                    "collection activity (tags: evtxer-collection); clear it to see that too.",
        kibanaSavedObjectMeta={"searchSourceJSON": json.dumps(
            {"query": {"query": "not tags: evtxer-collection", "language": "kuery"}, "filter": []})},
    )
    return d


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", default="output/hayabusa-summary.ndjson")
    ap.add_argument("--runtime-field", action="store_true",
                    help="Print the op.DetectionDay runtime field as the JSON body for "
                         "POST /api/data_views/data_view/<id>/runtime_field, and exit")
    args = ap.parse_args()
    if args.runtime_field:
        print(json.dumps(DETECTION_DAY))
        return
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
