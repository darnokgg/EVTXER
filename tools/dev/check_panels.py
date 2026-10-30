#!/usr/bin/env python3
"""Does every Lens panel of a dashboard ndjson have data? Read-only.

Runs each panel's query (KQL turned into the equivalent query_string - the
dashboards only use field: value, and/or/not, ( ) and * wildcards) with its
first row's terms aggregation, and prints hits and the first values. It also
counts the hits that carry EVERY row field (and the time field, --time-field):
Lens nests a table's rows and silently drops an event missing any of them, so
"dropped N" is how many events the rendered table will not show.
  python -I tools/dev/check_panels.py output/hayabusa-raw-hunt.ndjson --es https://127.0.0.1:9200 --index logs-import-so-lab --user elastic --pwfile <file> --insecure
A panel with 0 hits is either a wrong field name or no such events in the data.
Panels on runtime fields (op.*) need --runtime-from <the ndjson with the data view>.
"""
import argparse
import base64
import json
import re
import ssl
import sys
import urllib.error
import urllib.request

CTX = ssl.create_default_context()   # verified unless --cafile / --insecure (main)


def kql_to_lucene(q):
    # A wildcard in a field name (New*Value - KQL cannot escape a space) is
    # \* in query_string. This is no KQL syntax check: Lucene accepts things
    # Kibana's KQL refuses (an escaped space), so render the dashboard too.
    q = re.sub(r"([\w.]+)\*([\w.]+)(?=:)", r"\1\\*\2", q)
    q = re.sub(r"\band\b", "AND", q)
    q = re.sub(r"\bor\b", "OR", q)
    q = re.sub(r"(^|[\s(])not\s", r"\1NOT ", q)
    q = re.sub(r"(?<=\S):\s+", ":", q)
    return q or "*"


def bucket_agg(col, size, columns=None):
    """The aggregation a Lens bucket column runs, in the panel's own order: by
    count, by its own key (alphabetical), or by a metric column - distinct
    count, earliest (min) or largest (max)."""
    if col["operationType"] == "date_histogram":
        iv = col.get("params", {}).get("interval", "auto")
        return {"date_histogram": {"field": col["sourceField"],
                                   "calendar_interval": "day" if iv == "1d" else "month", "min_doc_count": 1}}
    params = col.get("params", {})
    direction = params.get("orderDirection", "desc")
    by = params.get("orderBy", {})
    agg = {"terms": {"field": col["sourceField"], "size": size}}
    if by.get("type") == "alphabetical":
        agg["terms"]["order"] = {"_key": direction}
        return agg
    metric = (columns or {}).get(by.get("columnId"), {}) if by.get("type") == "column" else {}
    op = {"unique_count": "cardinality", "min": "min", "max": "max"}.get(metric.get("operationType"))
    if op:
        agg["terms"]["order"] = {"o": direction}
        agg["aggs"] = {"o": {op: {"field": metric["sourceField"]}}}
    else:
        agg["terms"]["order"] = {"_count": direction}
    return agg


def set_tls(args):
    global CTX
    if args.cafile:
        CTX = ssl.create_default_context(cafile=args.cafile)
    elif args.insecure:
        CTX = ssl._create_unverified_context()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ndjson")
    ap.add_argument("--es", required=True)
    ap.add_argument("--index", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--pwfile", required=True)
    ap.add_argument("--cafile", help="trust this CA (e.g. the lab Security Onion's) instead of skipping checks")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification - self-signed LAB boxes only")
    ap.add_argument("--runtime-from", action="append", default=[],
                    help="runtime fields (op.*) the panels use: an ndjson with data views, or the JSON "
                         "scripts/anomaly_runtime_fields.py prints; repeatable")
    ap.add_argument("--time-field", default="event.created", help="the data view's time field ('' = none)")
    a = ap.parse_args()
    set_tls(a)
    runtime = {}
    for path in a.runtime_from:
        text = open(path, encoding="utf-8").read()
        try:
            whole = json.loads(text)
        except ValueError:
            whole = None
        if isinstance(whole, dict) and "type" not in whole:
            runtime.update(whole)          # anomaly_runtime_fields.py --view X
            continue
        for line in text.splitlines():
            o = json.loads(line) if line.strip() else {}
            if o.get("type") == "index-pattern":
                runtime.update(json.loads(o["attributes"].get("runtimeFieldMap") or "{}"))
    auth = "Basic " + base64.b64encode(f"{a.user}:{open(a.pwfile, encoding='utf-8').read().strip()}".encode()).decode()
    empty = 0
    for line in open(a.ndjson, encoding="utf-8"):
        o = json.loads(line)
        if o.get("type") != "lens":
            continue
        st = o["attributes"]["state"]
        layer = next(iter(st["datasourceStates"]["formBased"]["layers"].values()))
        rows = [layer["columns"][c] for c in layer["columnOrder"] if layer["columns"][c].get("isBucketed")]
        terms = [c for c in rows if c["operationType"] == "terms"]
        query = kql_to_lucene(st["query"]["query"])
        body = {"size": 0, "track_total_hits": True,
                "query": {"query_string": {"query": query, "allow_leading_wildcard": True}}}
        if runtime:
            body["runtime_mappings"] = runtime
        heat = o["attributes"]["visualizationType"] == "lnsHeatmap"
        if heat:
            # Heatmap: how many columns (hours, days, dates) and the busiest rows.
            vis = st["visualization"]
            x, y = layer["columns"][vis["xAccessor"]], layer["columns"][vis["yAccessor"]]
            body["aggs"] = {"x": bucket_agg(x, 50), "t": bucket_agg(y, 3)}
        elif terms:
            t = terms[0]
            body["aggs"] = {"t": bucket_agg(t, 3, layer["columns"])}
        r = urllib.request.Request(f"{a.es}/{a.index}/_search", json.dumps(body).encode(),
                                   {"Content-Type": "application/json", "Authorization": auth})
        try:
            d = json.load(urllib.request.urlopen(r, context=CTX, timeout=120))
        except urllib.error.HTTPError as e:
            print(f"ERROR {o['id']}: {e.read().decode()[:300]}")
            empty += 1
            continue
        hits = d["hits"]["total"]["value"]
        # Each first value with what ranked it: the count, or the panel's own
        # order (distinct machines, first seen, longest).
        top = [(str(b.get("key_as_string", b["key"]))[:50], b["o"]["value_as_string"] if "value_as_string" in b.get("o", {})
                else (int(b["o"]["value"]) if b.get("o", {}).get("value") is not None else b["doc_count"]))
               for b in d.get("aggregations", {}).get("t", {}).get("buckets", [])]
        if heat:
            top = [f"{len(d['aggregations']['x']['buckets'])} columns"] + top
        # An event without the FIRST row's field is simply not ranked (no user ->
        # not in "Top users"). One that has it but lacks a NESTED row field (or
        # the time field) vanishes from its first-row bucket, which then
        # under-counts - that silent loss is what "dropped" reports.
        fields = [c["sourceField"] for c in rows if c.get("sourceField")]

        def count(must_exist):
            q = dict(body, aggs={})
            q["query"] = {"bool": {"must": [body["query"]], "filter": [{"exists": {"field": f}} for f in must_exist]}}
            r2 = urllib.request.Request(f"{a.es}/{a.index}/_search", json.dumps(q).encode(),
                                        {"Content-Type": "application/json", "Authorization": auth})
            return json.load(urllib.request.urlopen(r2, context=CTX, timeout=120))["hits"]["total"]["value"]

        ranked = count(fields[:1]) if fields else hits
        kept = count(list(dict.fromkeys(fields + ([a.time_field] if a.time_field else []))))
        mark = "  " if hits and (top or not terms) else "!!"
        if mark == "!!":
            empty += 1
        drop = f"  dropped {ranked - kept}" if kept != ranked else ""
        print(f"{mark} {hits:>7}  {o['attributes']['title'][:60]:60}  {top}{drop}")
    print(f"{empty} panel(s) without data")
    sys.exit(1 if empty else 0)


if __name__ == "__main__":
    main()
