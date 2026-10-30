#!/usr/bin/env python3
"""Mission timeline: detections and raw events on one screen (v81).

EVTXER keeps two indices per mission - hayabusa-mission-<name> (Hayabusa
detections, event.kind alert) and hayabusa-raw-<name> (every event, event.kind
event) - with the same field layout. This dashboard reads both through one
data view, "Mission - everything" (hayabusa-*), so a host's whole story is on
one timeline: where its activity spikes, which detections fired then, and the
raw events around them. Owner, 2026-10-29: "a joined ELK dashboard, display
both at the same time".

Kept as two indices on purpose (raw is ~50-100x the volume and has its own
lifespan; the detection dashboards stay fast and need no event.kind filter);
joined here, at the view.

Usage:
  python scripts/make_mission_timeline_dashboard.py -o output/hayabusa-mission-timeline.ndjson
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_dashboard import stamp, col_count, col_date, datatable, labelled, xy  # noqa: E402
from make_hunt_dashboard import col_terms_ordered, lens as hunt_lens  # noqa: E402

DASHBOARD_ID = "hayabusa-mission-timeline-dashboard"
DATA_VIEW_ID = "hayabusa-everything-dataview"
SEARCH_ID = "hayabusa-mission-timeline-search"
INDEX_PATTERN = "hayabusa-*"
TIME_FIELD = "@timestamp"
TIME_FROM = "1970-01-01T00:00:00.000Z"
TIME_TO = "now"
HOST = "host.name"
DETECTION = 'event.kind: "alert"'
RAW = 'event.kind: "event"'


def lens(obj_id, title, description, visualization, columns, column_order, query=""):
    obj = hunt_lens(obj_id, title, description, visualization, columns, column_order, query)
    obj["references"][0]["id"] = DATA_VIEW_ID
    return obj


def over_time(obj_id, title, description, split_field, split_label, query):
    cols = labelled({
        "c_bucket": col_date(TIME_FIELD, "When it happened"),
        "c_split": col_terms_ordered(split_field, 10, split_label, "desc"),
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

    # Detections are a few hundred against hundreds of thousands of events:
    # stacked in one chart they would vanish, so two charts on the same time
    # axis (the dashboard syncs the cursor between them).
    row((over_time("hayabusa-timeline-detections", "Detections over time, by level",
                   "What Hayabusa flagged, when it happened. Hover a spike: the chart below shows "
                   "the raw activity of the same moment.",
                   "hayabusa.level", "Level", DETECTION), 48), h=11)
    row((over_time("hayabusa-timeline-raw", "Every event over time, by host",
                   "All the activity the logs hold (raw events). A detection inside a burst of "
                   "activity on one host - or in a quiet hour - is the one to open.",
                   HOST, "Computer", RAW), 48), h=11)

    hosts_cols = labelled({
        "c_host": col_terms_ordered(HOST, 50, "Computer", "desc", order_col="c_det"),
        "c_det": col_count("Detections", kuery=DETECTION),
        "c_high": col_count("High / critical", kuery=DETECTION + ' and hayabusa.level: ("high" or "critical")'),
        "c_raw": col_count("Raw events", kuery=RAW),
    })
    order = ["c_host", "c_det", "c_high", "c_raw"]
    row((lens("hayabusa-timeline-hosts", "Hosts - detections beside their raw events",
              "Each machine with what it was flagged for and how much it logged. Many "
              "detections on a host with few events is a quiet host doing loud things; a "
              "host with raw events but no detections had nothing a rule knows. Click a "
              "host to filter the whole dashboard.",
              datatable(columns=order), hosts_cols, order), 24),
        (lens("hayabusa-timeline-rules", "Detections by rule - rarest first",
              "Every rule that fired, the rarest first, with the machines it fired on.",
              datatable(columns=["c_rule", "c_metric", "c_hosts"]),
              labelled({"c_rule": col_terms_ordered("rule.name", 30, "Rule", "asc"),
                        "c_metric": col_count("Detections"),
                        "c_hosts": {"label": "Hosts", "dataType": "number", "operationType": "unique_count",
                                    "isBucketed": False, "scale": "ratio", "sourceField": HOST}}),
              ["c_rule", "c_metric", "c_hosts"], query=DETECTION), 24),
        h=16)
    return p


def build_search():
    """Detections and raw events interleaved by time - the joined timeline to read."""
    return {
        "id": SEARCH_ID, "type": "search", "managed": False,
        "attributes": {
            "title": "Mission timeline - detections and raw events",
            "description": "Both indices by time. Filter a host and a time range; event.kind tells "
                           "a detection (alert) from a raw event (event). From a detection, "
                           "'View surrounding documents' shows the raw events of the same moment.",
            "columns": ["event.kind", HOST, "rule.name", "hayabusa.level", "winlog.channel", "winlog.event_id",
                        "user.name", "process.command_line"],
            "sort": [[TIME_FIELD, "desc"]],
            "grid": {}, "hideChart": False, "isTextBasedQuery": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "", "language": "kuery"},
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
            "name": "Mission - everything",
            "timeFieldName": TIME_FIELD,
            "fields": "[]", "fieldFormatMap": "{}", "runtimeFieldMap": "{}",
            "sourceFilters": "[]", "allowHidden": False,
            "fieldAttrs": json.dumps({
                TIME_FIELD: {"customLabel": "When it happened"},
                HOST: {"customLabel": "Computer"},
                "event.kind": {"customLabel": "alert = detection, event = raw"},
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
    pj.append({"type": "search", "gridData": {"x": 0, "y": search_y, "w": 48, "h": 20, "i": i},
               "panelIndex": i, "embeddableConfig": {"enhancements": {}}, "panelRefName": f"panel_{i}"})
    refs.append({"name": f"panel_{i}", "type": "search", "id": search["id"]})
    return {
        "id": DASHBOARD_ID, "type": "dashboard", "managed": False,
        "attributes": {
            "title": "Mission timeline - detections and raw events",
            "description": "Hayabusa detections (hayabusa-mission-*) and every raw event "
                           "(hayabusa-raw-*) of the mission on one timeline, through the data view "
                           "'Mission - everything'. Filter a host: its detections, its activity "
                           "and the events around each detection, together.",
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
    ap.add_argument("-o", "--output", default="output/hayabusa-mission-timeline.ndjson")
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
