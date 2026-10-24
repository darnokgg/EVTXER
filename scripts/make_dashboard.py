#!/usr/bin/env python3
"""Generate a Kibana saved-objects NDJSON: data view + Lens panels + dashboard.

Produces a file you import through Kibana's UI (Stack Management -> Saved
Objects -> Import). Nothing is written to Security Onion by this script -- it
only writes a local file, so it is safe to run and re-run.

Import is reversible: everything lands under the tag/ids below and can be
deleted from the same Saved Objects screen.

Usage:
  python scripts/make_dashboard.py -o output/hayabusa-dashboard.ndjson
"""
import argparse
import json

DATA_VIEW_ID = "hayabusa-evtx-dataview"
INDEX_PATTERN = "hayabusa-evtx-*"
TIME_FIELD = "@timestamp"

# Saved objects MUST carry migration metadata or Kibana's import throws a 500
# ("Internal Server Error") rather than a useful validation message. These
# values were read from the live .kibana index on this specific cluster --
# do not guess them, re-read them if the Kibana version changes.
CORE_MIGRATION_VERSION = "8.8.0"
TYPE_MIGRATION_VERSION = {
    "index-pattern": "8.0.0",
    "dashboard": "10.2.0",
    # No lens objects existed on this Kibana to copy from. This value was
    # obtained by POSTing one lens object to /api/saved_objects/lens and reading
    # back the migrationVersion Kibana assigned it. Omitting it makes the import
    # API fail with an opaque HTTP 500.
    "lens": "8.9.0",
}


def stamp(obj):
    """Add the migration metadata Kibana's import pipeline requires."""
    obj["coreMigrationVersion"] = CORE_MIGRATION_VERSION
    tmv = TYPE_MIGRATION_VERSION.get(obj["type"])
    if tmv:
        obj["typeMigrationVersion"] = tmv
    return obj

# Dashboards store a time range so they open on data instead of the default
# "last 15 minutes", which is the usual reason a new Kibana dashboard looks
# empty. Relative, not fixed: a fixed 2013-2025 window (the sample corpus's
# span) showed nothing at all for real data.
TIME_FROM = "now-5y"
TIME_TO = "now"

# Hayabusa level colours, roughly matching its own terminal output.
LEVEL_COLORS = {
    "critical": "#a80000",
    "high": "#bd271e",
    "medium": "#d6bf57",
    "low": "#6092c0",
    "informational": "#98a2b3",
}


def col_count(label="Count of detections", kuery=None):
    col = {
        "label": label,
        "dataType": "number",
        "operationType": "count",
        "isBucketed": False,
        "scale": "ratio",
        "sourceField": "___records___",
    }
    if kuery:
        # Lens per-column filter, so a metric can count a subset without
        # constraining the rest of the dashboard.
        col["filter"] = {"query": kuery, "language": "kuery"}
    return col


def labelled(cols):
    """Lens shows a column's own label only when it is flagged custom;
    otherwise the header reads "Count of records" / "Top 20 values of ...". """
    for c in cols.values():
        c["customLabel"] = True
    return cols


def col_terms(field, size, label, order_col="c_metric"):
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
            "orderDirection": "desc",
            "otherBucket": False,
            "missingBucket": False,
        },
    }


def col_date(field=TIME_FIELD, label=TIME_FIELD):
    return {
        "label": label,
        "dataType": "date",
        "operationType": "date_histogram",
        "sourceField": field,
        "isBucketed": True,
        "scale": "interval",
        "params": {"interval": "auto", "includeEmptyRows": True, "dropPartials": False},
    }


def lens(obj_id, title, description, visualization, columns, column_order):
    """Assemble one Lens saved object over a single layer."""
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
                "query": {"query": "", "language": "kuery"},
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
        "references": [
            {
                "type": "index-pattern",
                "id": DATA_VIEW_ID,
                "name": f"indexpattern-datasource-layer-{layer_id}",
            }
        ],
    }


def xy(layer_id="layer1", series="bar_stacked", x="c_bucket", y=("c_metric",), split=None):
    layer = {
        "layerId": layer_id,
        "accessors": list(y),
        "position": "top",
        "seriesType": series,
        "showGridlines": False,
        "layerType": "data",
        "xAccessor": x,
    }
    if split:
        layer["splitAccessor"] = split
    return {
        "_type": "lnsXY",
        "legend": {"isVisible": True, "position": "right"},
        "valueLabels": "hide",
        "preferredSeriesType": series,
        "layers": [layer],
    }


def datatable(layer_id="layer1", columns=()):
    return {
        "_type": "lnsDatatable",
        "layerId": layer_id,
        "layerType": "data",
        "columns": [{"columnId": c, "isTransposed": False} for c in columns],
    }


def metric(layer_id="layer1", accessor="c_metric", color="#0077cc"):
    return {
        "_type": "lnsMetric",
        "layerId": layer_id,
        "layerType": "data",
        "metricAccessor": accessor,
        "color": color,
    }


def pie(layer_id="layer1", groups=("c_bucket",), metric_id="c_metric", shape="donut"):
    return {
        "_type": "lnsPie",
        "shape": shape,
        "layers": [
            {
                "layerId": layer_id,
                "primaryGroups": list(groups),
                "metrics": [metric_id],
                "numberDisplay": "percent",
                "categoryDisplay": "default",
                "legendDisplay": "show",
                "legendPosition": "right",
                "nestedLegend": False,
                "layerType": "data",
            }
        ],
    }


def build_panels():
    """Each entry: (saved object, grid position)."""
    p = []

    # --- row 1: headline numbers -----------------------------------------
    p.append((
        lens("hayabusa-metric-total", "Total detections",
             "Every Hayabusa detection in the current time range and filters.",
             metric(color="#0077cc"),
             {"c_metric": col_count("Total detections")}, ["c_metric"]),
        {"x": 0, "y": 0, "w": 8, "h": 7},
    ))

    p.append((
        lens("hayabusa-metric-critical", "Critical + high",
             "Detections at level critical or high (event.severity >= 75).",
             metric(color="#bd271e"),
             {"c_metric": col_count("Critical + high", kuery="event.severity >= 75")},
             ["c_metric"]),
        {"x": 8, "y": 0, "w": 8, "h": 7},
    ))

    p.append((
        lens("hayabusa-metric-hosts", "Hosts affected",
             "Distinct host.name values with at least one detection.",
             metric(color="#6092c0"),
             {"c_metric": {
                 "label": "Hosts affected", "dataType": "number",
                 "operationType": "unique_count", "isBucketed": False,
                 "scale": "ratio", "sourceField": "host.name",
             }}, ["c_metric"]),
        {"x": 16, "y": 0, "w": 8, "h": 7},
    ))

    p.append((
        lens("hayabusa-metric-rules", "Unique rules fired",
             "Distinct Sigma/Hayabusa rules that matched.",
             metric(color="#54b399"),
             {"c_metric": {
                 "label": "Unique rules fired", "dataType": "number",
                 "operationType": "unique_count", "isBucketed": False,
                 "scale": "ratio", "sourceField": "rule.id",
             }}, ["c_metric"]),
        {"x": 24, "y": 0, "w": 8, "h": 7},
    ))

    p.append((
        lens("hayabusa-level-donut", "Detections by level",
             "Share of detections at each Hayabusa severity level.",
             pie(),
             {"c_metric": col_count(),
              "c_bucket": col_terms("hayabusa.level", 6, "Level")},
             ["c_bucket", "c_metric"]),
        {"x": 32, "y": 0, "w": 16, "h": 14},
    ))

    # --- row 2: timeline --------------------------------------------------
    p.append((
        lens("hayabusa-timeline", "Detections over time by level",
             "Detection volume over time, stacked by severity. Look for bursts.",
             xy(series="bar_stacked", split="c_split"),
             {"c_metric": col_count(),
              "c_bucket": col_date(),
              "c_split": col_terms("hayabusa.level", 6, "Level")},
             ["c_bucket", "c_split", "c_metric"]),
        {"x": 0, "y": 7, "w": 32, "h": 14},
    ))

    # --- row 3: top rules + top hosts ------------------------------------
    p.append((
        lens("hayabusa-top-rules", "Top 20 rules",
             "Which detection rules fire most. High counts often mean noise worth tuning.",
             datatable(columns=["c_bucket", "c_split", "c_metric"]),
             {"c_metric": col_count(),
              "c_bucket": col_terms("rule.name", 20, "Rule"),
              "c_split": col_terms("hayabusa.level", 1, "Level")},
             ["c_bucket", "c_split", "c_metric"]),
        {"x": 0, "y": 21, "w": 24, "h": 15},
    ))

    p.append((
        lens("hayabusa-top-hosts", "Top hosts",
             "Hosts with the most detections, split by severity.",
             xy(series="bar_horizontal_stacked", split="c_split"),
             {"c_metric": col_count(),
              "c_bucket": col_terms("host.name", 15, "Host"),
              "c_split": col_terms("hayabusa.level", 6, "Level")},
             ["c_bucket", "c_split", "c_metric"]),
        {"x": 24, "y": 21, "w": 24, "h": 15},
    ))

    # --- row 4: users + channels (ATT&CK has its own dashboard since v37:
    # make_mitre_dashboard.py) -----------------------------------------
    p.append((
        lens("hayabusa-top-users", "Top users",
             "Accounts appearing in detections (user.name).",
             xy(series="bar_horizontal"),
             {"c_metric": col_count(),
              "c_bucket": col_terms("user.name", 15, "User")},
             ["c_bucket", "c_metric"]),
        {"x": 0, "y": 36, "w": 16, "h": 14},
    ))

    p.append((
        lens("hayabusa-channels", "Event log channels",
             "Which Windows log the detections came from.",
             xy(series="bar_horizontal"),
             {"c_metric": col_count(),
              "c_bucket": col_terms("winlog.channel", 12, "Channel")},
             ["c_bucket", "c_metric"]),
        {"x": 16, "y": 36, "w": 16, "h": 14},
    ))

    p.append((
        lens("hayabusa-source-ips", "Top source IPs",
             "Source addresses promoted from the event data. Pivot these against "
             "Zeek/Suricata data in Hunt.",
             datatable(columns=["c_bucket", "c_metric"]),
             {"c_metric": col_count(),
              "c_bucket": col_terms("source.ip", 15, "Source IP")},
             ["c_bucket", "c_metric"]),
        {"x": 32, "y": 36, "w": 16, "h": 14},
    ))

    return p


def build_dashboard(panels):
    panels_json, references = [], []
    for i, (obj, grid) in enumerate(panels, start=1):
        name = f"panel_{i}"
        panels_json.append({
            "type": "lens",
            "gridData": {**grid, "i": str(i)},
            "panelIndex": str(i),
            "embeddableConfig": {"enhancements": {}},
            "panelRefName": name,
        })
        references.append({"name": name, "type": "lens", "id": obj["id"]})

    return {
        "id": "hayabusa-overview-dashboard",
        "type": "dashboard",
        "managed": False,
        "attributes": {
            "title": "Hayabusa - EVTX Detection Overview",
            "description": (
                "Windows event log detections from Hayabusa (Sigma rules). "
                "Severity is higher = worse (critical 99 ... informational 1) -- note "
                "Suricata data elsewhere in Security Onion uses the opposite scale."
            ),
            "panelsJSON": json.dumps(panels_json),
            "optionsJSON": json.dumps({
                "useMargins": True, "syncColors": True,
                "syncCursor": True, "syncTooltips": True, "hidePanelTitles": False,
            }),
            "version": 3,
            "timeRestore": True,
            "timeFrom": TIME_FROM,
            "timeTo": TIME_TO,
            "refreshInterval": {"pause": True, "value": 60000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []}
                )
            },
        },
        "references": references,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", default="output/hayabusa-dashboard.ndjson")
    ap.add_argument("--no-data-view", action="store_true",
                    help="Omit the data view (use when kibana_setup.py creates it via the API)")
    args = ap.parse_args()

    data_view = {
        "id": DATA_VIEW_ID,
        "type": "index-pattern",
        "managed": False,
        "attributes": {
            "title": INDEX_PATTERN,
            "name": "Hayabusa EVTX detections",
            "timeFieldName": TIME_FIELD,
            "fields": "[]",
            "sourceFilters": "[]",
            "fieldFormatMap": "{}",
            "runtimeFieldMap": "{}",
            "allowNoIndex": False,
        },
        "references": [],
    }

    panels = build_panels()
    dashboard = build_dashboard(panels)

    objects = [obj for obj, _ in panels] + [dashboard]
    if not args.no_data_view:
        objects.insert(0, data_view)
    objects = [stamp(o) for o in objects]

    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        for obj in objects:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        f.write(json.dumps({"excludedObjects": [], "excludedObjectsCount": 0,
                            "exportedCount": len(objects),
                            "missingRefCount": 0, "missingReferences": []}) + "\n")

    print(f"wrote {len(objects)} saved objects -> {args.output}")
    print(f"  {'no data view (created via API)' if args.no_data_view else '1 data view (' + INDEX_PATTERN + ')'},"
          f" {len(panels)} Lens panels, 1 dashboard")
    print(f"  dashboard time range: {TIME_FROM} .. {TIME_TO}")


if __name__ == "__main__":
    main()
