#!/usr/bin/env python3
"""Rewrite the Hayabusa Kibana export so a Kibana 8.7 accepts it.

The shipped export (kibana/hayabusa-kibana-objects.ndjson) came from Kibana
9.0.8. Kibana 8.7 refuses it outright:

    Document "hayabusa-evtx-dataview" has a "coreMigrationVersion" which
    belongs to a more recent version of Kibana [8.8.0].

Kibana 8.8 changed the migration metadata from a per-type
`migrationVersion: {"lens": "8.6.0"}` object to a flat `typeMigrationVersion`,
and 8.10 added `managed`. This script stamps each object with the metadata a
native Kibana 8.7.0 export carries (read from a live 8.7.0, not guessed) and
drops the fields 8.7 does not know. The attributes themselves - Lens state,
panels, saved-search columns - are already in shapes 8.7 understands.

Verified by importing the output into Elasticsearch + Kibana 8.7.0 and
opening every dashboard. Local file only: nothing is sent anywhere.

Usage:
  python scripts/convert_dashboards_87.py
  python scripts/convert_dashboards_87.py -i in.ndjson -o out.ndjson
"""
import argparse
import json

CORE_MIGRATION_VERSION = "8.7.0"
# What Kibana 8.7.0 stamps on an object it creates itself, per type.
MIGRATION_VERSION = {
    "index-pattern": "8.0.0",
    "lens": "8.6.0",
    "dashboard": "8.7.0",
    "search": "8.0.0",
}
# Root fields newer than 8.7. `version` is the source cluster's write token,
# meaningless on another cluster.
DROP_ROOT = ("typeMigrationVersion", "managed", "version")


def convert(obj):
    t = obj["type"]
    if t not in MIGRATION_VERSION:
        raise SystemExit(f"no 8.7 migration version known for type '{t}' ({obj['id']})")
    for k in DROP_ROOT:
        obj.pop(k, None)
    obj["coreMigrationVersion"] = CORE_MIGRATION_VERSION
    obj["migrationVersion"] = {t: MIGRATION_VERSION[t]}
    # 8.7's .kibana mapping is strict and has no showApplySelections (added
    # later), so the whole dashboard fails to import with a 500. It was the
    # only strict-mapping violation across the 43 objects.
    obj["attributes"].get("controlGroupInput", {}).pop("showApplySelections", None)
    if t == "lens":
        legacy_date_metric(obj["attributes"])
    return obj


def legacy_date_metric(attrs):
    # 8.7's metric tile cannot show a date ("Metric visualization expression -
    # Unsupported column format: date", found drawing the Results Summary's
    # First / Last detection on a live 8.7.0, 2026-10-20); 9.x can. 8.7's
    # legacy metric shows the same column, formatted as a date.
    if attrs.get("visualizationType") != "lnsMetric":
        return
    vis = attrs["state"]["visualization"]
    layer = attrs["state"]["datasourceStates"]["formBased"]["layers"][vis["layerId"]]
    if layer["columns"][vis["metricAccessor"]].get("dataType") != "date":
        return
    attrs["visualizationType"] = "lnsLegacyMetric"
    attrs["state"]["visualization"] = {"layerId": vis["layerId"], "accessor": vis["metricAccessor"],
                                       "layerType": "data", "colorMode": "None", "size": "xl",
                                       "textAlign": "center"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--input", default="kibana/hayabusa-kibana-objects.ndjson")
    ap.add_argument("-o", "--output", default="kibana/hayabusa-kibana-objects-8.7.ndjson")
    args = ap.parse_args()

    out, n = [], 0
    with open(args.input, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            obj = json.loads(line)
            if "type" not in obj:  # the export's trailing summary line
                continue
            out.append(json.dumps(convert(obj), ensure_ascii=False))
            n += 1
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {n} objects to {args.output}")


if __name__ == "__main__":
    main()
