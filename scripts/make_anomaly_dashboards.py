#!/usr/bin/env python3
"""Anomaly Hunt dashboards: the hunts PEAK's "rarest first" misses.

On real workstations (two test machines, 2026-10-17) "rare" turned out
to be mostly harmless one-off driver and update messages. Hunters spot an
intrusion in more ways than "seen rarely"; these are the other seven
(chosen as the most useful):

  1. Only on one machine   - fewest machines first
  2. New lately            - first seen, newest first (whole network, and per machine)
  3. Odd hours             - machine x hour of day / day of week, UTC
  4. Wrong place           - system programs outside their folder, anything run from user-writable folders
  5. Bursts                - events per machine per day
  6. Fan-out               - one account to many machines, one source to many accounts
  7. Longest command lines - encoded and obfuscated payloads are long

One panel list, two data views:
  raw         "Raw Events - Anomaly Hunt" on hayabusa-raw-dataview (hayabusa-raw-*)
              (every event EVTXER sent; the full normal baseline anomaly hunting needs)
  detections  "Hayabusa - Anomaly Hunt" on hayabusa-evtx-dataview
              (Hayabusa's informational rules make it work, thinner)

Most targets keep DEFAULT Windows logging; Sysmon is rare. Every hunt uses the
best record a machine has (program starts: Sysmon 1, else 4688) and leans on
what Windows always writes: logons, 7045 services, scheduled tasks, Windows
PowerShell 400. A panel whose only source a network does not record shows
"No results" - an honest answer, and its description says which logs feed it.

The op.* runtime fields come from scripts/anomaly_runtime_fields.py and live
only in the shipped data views (add them to a lab Kibana by hand).

Usage:
  python -I scripts/make_anomaly_dashboards.py -o output/hayabusa-anomaly.ndjson
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_dashboard import stamp, col_count, col_date, datatable, labelled  # noqa: E402
from make_hunt_dashboard import col_terms_ordered, lens as hunt_lens  # noqa: E402
from make_peak_dashboard import col_unique  # noqa: E402

ONE_MACHINE_ROWS = 500
TIME_FROM = "1970-01-01T00:00:00.000Z"
TIME_TO = "now"
TWICE = (" A machine that records program starts in BOTH Sysmon (event 1) and Windows' own "
         "auditing (4688) counts each start twice.")
PROC_SRC = " Program starts come from Sysmon event 1, else Security 4688 (process-creation auditing)."


def _raw_q(channel, eid):
    return f'(winlog.channel: "{channel}" and winlog.event_id: "{eid}")'


def _det_q(channel, eid):
    return f'(winlog.channel: "{channel}" and event.code: "{eid}")'


def _queries(q):
    return {
        "proc": f'{q("Microsoft-Windows-Sysmon/Operational", 1)} or {q("Security", 4688)}',
        "svc": f'{q("System", 7045)} or {q("Security", 4697)}',
        "task": f'{q("Security", 4698)} or {q("Microsoft-Windows-TaskScheduler/Operational", 106)}',
        "logon": q("Security", 4624),
        "failed": q("Security", 4625),
        "ps": q("Windows PowerShell", 400),
    }


VIEWS = {
    "raw": {
        "dashboard": "hayabusa-raw-anomaly-dashboard", "prefix": "hayabusa-raw-anomaly-",
        "data_view": "hayabusa-raw-dataview",
        "title": "Raw Events - Anomaly Hunt",
        "query": "",
        "host": "host.name", "time": "@timestamp",
        "proc": "op.ProcPath", "parent": "op.ParentPath", "cmd": "op.CmdLine", "cmdlen": "op.CmdLen",
        "svc": "winlog.event_data.ServiceName", "svcbin": "op.ServiceBinary", "svcbinlen": "op.ServiceBinaryLen",
        "task": "winlog.event_data.TaskName", "user": "winlog.event_data.TargetUserName",
        "src": "winlog.event_data.IpAddress", "pshost": "winlog.event_data.HostApplication", "pshostlen": "op.HostApplicationLen",
        "q": _queries(_raw_q),
        "note": (" Every Windows event EVTXER sent, so its own collection visit "
                 "(wevtutil, its staging folder) shows here too."),
    },
    "detections": {
        "dashboard": "hayabusa-anomaly-dashboard", "prefix": "hayabusa-anomaly-",
        "data_view": "hayabusa-evtx-dataview",
        "title": "Hayabusa - Anomaly Hunt",
        "query": "not tags: evtxer-collection",
        "host": "host.name", "time": "@timestamp",
        # op.CmdLine, not process.command_line: the template's ignore_above (8191)
        # leaves the longest lines without a doc value - a row on it drops them.
        "proc": "op.ProcPath", "parent": "op.ParentPath", "cmd": "op.CmdLine", "cmdlen": "op.CmdLen",
        "svc": "service.name", "svcbin": "op.ServiceBinary", "svcbinlen": "op.ServiceBinaryLen",
        "task": "winlog.event_data.TaskName", "user": "user.name",
        "src": "winlog.event_data.IpAddress", "pshost": None, "pshostlen": None,
        "q": _queries(_det_q),
        "note": (" Hayabusa detections only - its informational rules record many ordinary "
                 "events, so this works on plain Elastic too, thinner than the raw view."),
    },
}


# ---- columns -----------------------------------------------------------------
def col_min_date(field, label):
    """Earliest time - "first seen"."""
    return {"label": label, "dataType": "date", "operationType": "min", "scale": "interval",
            "sourceField": field, "isBucketed": False, "params": {"emptyAsNull": True}}


def col_max(field, label):
    return {"label": label, "dataType": "number", "operationType": "max", "scale": "ratio",
            "sourceField": field, "isBucketed": False, "params": {"emptyAsNull": True}}


def col_alpha(field, size, label):
    """Terms in their own order (00..23, 1 Mon..7 Sun), not by count."""
    c = col_terms_ordered(field, size, label, "asc")
    c["params"]["orderBy"] = {"type": "alphabetical", "fallback": False}
    return c


def col_day(field, label):
    c = col_date(field, label)
    c["params"]["interval"] = "1d"
    c["params"]["includeEmptyRows"] = False
    return c


# ---- panels ------------------------------------------------------------------
def _lens(v, suffix, title, description, vis, cols, order, query):
    obj = hunt_lens(v["prefix"] + suffix, title, description + v["note"], vis, labelled(cols), order, query)
    obj["references"][0]["id"] = v["data_view"]
    return obj


def ranked_table(v, suffix, title, description, rows, rank, query, metrics=(), sort=None, date_row=None):
    """rows = [(field, size, label)]; every row ranked by `rank` = (column id, 'asc'|'desc');
    date_row = a date-histogram column nested under them; metrics = [(column id, column)];
    sort = (column id, direction) sorts the flattened table."""
    cols, order = {}, []
    metric_cols = dict(metrics)
    for i, (field, size, label) in enumerate(rows):
        cid = f"c_r{i}"
        cols[cid] = col_terms_ordered(field, size, label, rank[1], order_col=rank[0])
        order.append(cid)
    if date_row:
        cols["c_day"] = date_row
        order.append("c_day")
    for cid, col in metric_cols.items():
        cols[cid] = col
        order.append(cid)
    vis = datatable(columns=order)
    if sort:
        vis["sorting"] = {"columnId": sort[0], "direction": sort[1]}
    return _lens(v, suffix, title, description, vis, cols, order, query)


def heatmap(v, suffix, title, description, x_col, y_field, query):
    cols = {"c_x": x_col, "c_y": col_terms_ordered(y_field, 15, "Machine", "desc"), "c_metric": col_count("Events")}
    vis = {"_type": "lnsHeatmap", "shape": "heatmap", "layerId": "layer1", "layerType": "data",
           "xAccessor": "c_x", "yAccessor": "c_y", "valueAccessor": "c_metric",
           "legend": {"isVisible": True, "position": "right", "type": "heatmap_legend"},
           "gridConfig": {"type": "heatmap_grid", "isCellLabelVisible": False, "isYAxisLabelVisible": True,
                          "isXAxisLabelVisible": True, "isYAxisTitleVisible": False, "isXAxisTitleVisible": False}}
    return _lens(v, suffix, title, description, vis, cols, ["c_x", "c_y", "c_metric"], query)


def _real_source(src):
    """A source that is another machine: not "-" (a local logon) and not the
    machine itself (::1, 127.0.0.1 - which topped fan-out on real machines)."""
    return f'not {src}: ("-" or "::1" or "127.0.0.1")'


def _people(user):
    """Windows' own accounts log on everywhere, every boot: noise in every
    account hunt (lab run, 2026-10-17). Matched by their exact shape in
    op.BuiltinAccount (anomaly_runtime_fields.py), never by a name prefix an
    attacker could borrow."""
    return "not op.BuiltinAccount: true"


def _items(v):
    """What sections 1 and 2 track: (id, label, field, query, extra description)."""
    q = v["q"]
    out = [
        ("programs", "programs", v["proc"], f'({q["proc"]}) and {v["proc"]}: *', PROC_SRC + TWICE),
        ("services", "services", v["svc"], f'({q["svc"]}) and {v["svc"]}: *',
         " Services come from System 7045 (always logged) and Security 4697."),
        ("tasks", "scheduled tasks", v["task"], f'({q["task"]}) and {v["task"]}: *',
         " Tasks come from Security 4698 and TaskScheduler/Operational 106 - both off by default on "
         "Windows 10/11 (empty on both real test machines), so this is often empty."),
        ("accounts", "accounts that logged on", v["user"], f'({q["logon"]}) and {v["user"]}: * and {_people(v["user"])}',
         " Logons come from Security 4624; Windows' built-in accounts (SYSTEM, DWM-n, ...) are left out."),
    ]
    if v["pshost"]:
        out.append(("pslines", "PowerShell start lines", v["pshost"], f'({q["ps"]}) and {v["pshost"]}: *',
                    " Windows PowerShell 400 - written on every PowerShell start, default logging included."))
    return out


def build_panels(view):
    v, q = VIEWS[view], VIEWS[view]["q"]
    H, T = v["host"], v["time"]
    machines = lambda: col_unique(H, "Machines")  # noqa: E731
    p = []  # (lens, width, height)

    # 1. Only on one machine - many rows: items on one machine tie at 1 and
    # Elasticsearch orders ties by name, so a short list could cut the
    # outlier off alphabetically (final review, 2026-10-17).
    for sid, label, field, query, src in _items(v):
        p.append((ranked_table(v, f"one-{sid}", f"1. Only on one machine - {label}",
                               f"{label.capitalize()} seen on the FEWEST machines first. Across a fleet, the one "
                               f"machine that differs is the outlier: a tool, service or account nobody else has. "
                               f"Ties are in name order - page through, or click a machine to narrow." + src,
                               [(field, ONE_MACHINE_ROWS, label.capitalize())], ("c_m0", "asc"), query,
                               [("c_m0", machines()), ("c_m1", col_count("Events"))]), 24, 14))
    p.append((ranked_table(v, "one-parent-child", "1. Only on one machine - parent > child programs",
                           "Which program started which, the pairs on the fewest machines first: Word starting "
                           "PowerShell, a service starting cmd.exe." + PROC_SRC + TWICE,
                           [(v["parent"], ONE_MACHINE_ROWS, "Parent program"), (v["proc"], 5, "Program it started")], ("c_m0", "asc"),
                           f'({q["proc"]}) and {v["parent"]}: * and {v["proc"]}: *',
                           [("c_m0", machines()), ("c_m1", col_count("Starts"))]), 24, 14))

    # 2. New lately
    for sid, label, field, query, src in _items(v):
        p.append((ranked_table(v, f"new-{sid}", f"2. New lately - {label}, new to the network",
                               f"When each of these was FIRST seen anywhere, newest first: something that "
                               f"appeared last week after months of the same routine." + src,
                               [(field, 50, label.capitalize())], ("c_m0", "desc"), query,
                               [("c_m0", col_min_date(T, "First seen")), ("c_m1", machines())]), 24, 14))
        p.append((ranked_table(v, f"new-{sid}-per-machine", f"2. New lately - {label}, new to each machine",
                               f"First seen on EACH machine, newest first: a tool already on some machines that "
                               f"just arrived on another is lateral movement (PsExec spreading)." + src,
                               [(field, 50, label.capitalize()), (H, 10, "Machine")], ("c_m0", "desc"), query,
                               [("c_m0", col_min_date(T, "First seen on this machine"))],
                               sort=("c_m0", "desc")), 24, 14))

    # 3. Odd hours (UTC)
    utc = " Hours and days are UTC - event logs store UTC; the target's own time zone is not in the data."
    p.append((heatmap(v, "hours-logons", "3. Odd hours - logons by hour (UTC)",
                      "Logons per machine per hour of the day. Work happens in office hours; 03:00 stands out." +
                      " Security 4624." + utc, col_alpha("op.HourUTC", 24, "Hour (UTC)"), H, q["logon"]), 48, 12))
    p.append((heatmap(v, "days-logons", "3. Odd hours - logons by day of week (UTC)",
                      "Logons per machine per weekday. A weekend logon on a weekday-only machine stands out." +
                      " Security 4624." + utc, col_alpha("op.DayUTC", 7, "Day (UTC)"), H, q["logon"]), 48, 12))
    p.append((heatmap(v, "hours-programs", "3. Odd hours - program and PowerShell starts by hour (UTC)",
                      "Programs and PowerShell started per machine per hour." + PROC_SRC +
                      " PowerShell starts: Windows PowerShell 400." + TWICE + utc,
                      col_alpha("op.HourUTC", 24, "Hour (UTC)"), H, f'{q["proc"]} or {q["ps"]}'), 48, 12))
    p.append((heatmap(v, "hours-services", "3. Odd hours - services and scheduled tasks by hour (UTC)",
                      "Services installed and tasks created per machine per hour: persistence set up at night." +
                      " System 7045, Security 4697/4698, TaskScheduler 106 (the task logs are off by default)." + utc,
                      col_alpha("op.HourUTC", 24, "Hour (UTC)"), H, f'{q["svc"]} or {q["task"]}'), 48, 12))

    # 4. Wrong place
    p.append((ranked_table(v, "wrong-system", "4. Wrong place - system programs outside their folder",
                           "svchost.exe, lsass.exe, explorer.exe and other Windows programs running from anywhere "
                           "but their own folder (System32/SysWOW64, Windows) - the classic disguise." + PROC_SRC + TWICE,
                           [(v["proc"], 50, "Program")], ("c_m1", "desc"), f'({q["proc"]}) and op.ProcWrongPlace: true',
                           [("c_m0", machines()), ("c_m1", col_count("Starts"))]), 24, 14))
    p.append((ranked_table(v, "wrong-user-folders", "4. Wrong place - programs run from user-writable folders",
                           "Programs started from Temp, AppData, Users\\Public, Downloads, the Recycle Bin or "
                           "PerfLogs - where dropped tools run from. Fewest machines first." + PROC_SRC + TWICE,
                           [(v["proc"], ONE_MACHINE_ROWS, "Program")], ("c_m0", "asc"), f'({q["proc"]}) and op.ProcUserWritable: true',
                           [("c_m0", machines()), ("c_m1", col_count("Starts"))]), 24, 14))
    p.append((ranked_table(v, "wrong-services", "4. Wrong place - services installed from user-writable folders",
                           "Services whose program lives in Temp, AppData, Users\\Public, Downloads, the Recycle Bin, "
                           "PerfLogs or Windows\\Temp - real services live in Program Files or System32."
                           " System 7045, Security 4697.",
                           [(v["svcbin"], 50, "Service program")], ("c_m0", "asc"), f'({q["svc"]}) and op.ServiceUserWritable: true',
                           [("c_m0", machines()), ("c_m1", col_count("Installs"))]), 48, 12))

    # 5. Bursts
    p.append((heatmap(v, "bursts-heatmap", "5. Bursts - events per machine over time",
                      "Every event per machine over time. A bright cell in a dull row is a burst: password "
                      "spraying, mass file access, a stuck process.", col_date(T, "When"), H, ""), 48, 12))
    p.append((ranked_table(v, "bursts-all", "5. Bursts - busiest machine-days, all events",
                           "The machine-days with the most events, busiest first (days are UTC). Compare a machine "
                           "with its own other days.", [(H, 20, "Machine")], ("c_m0", "desc"), "",
                           [("c_m0", col_count("Events"))], sort=("c_m0", "desc"), date_row=col_day(T, "Day (UTC)")), 24, 14))
    p.append((ranked_table(v, "bursts-failed", "5. Bursts - busiest machine-days, failed logons",
                           "Failed logons per machine per day (UTC), busiest first: password guessing and spraying."
                           " Security 4625.", [(H, 20, "Machine")], ("c_m0", "desc"), q["failed"],
                           [("c_m0", col_count("Failed logons"))], sort=("c_m0", "desc"), date_row=col_day(T, "Day (UTC)")), 24, 14))

    # 6. Fan-out
    p.append((ranked_table(v, "fan-accounts", "6. Fan-out - accounts logging on to the most machines",
                           "One account logging on to many machines is lateral movement - or an admin account; "
                           "know which. Security 4624; Windows' built-in accounts are left out.",
                           [(v["user"], 30, "Account")], ("c_m0", "desc"),
                           f'({q["logon"]}) and {v["user"]}: * and {_people(v["user"])}',
                           [("c_m0", machines()), ("c_m1", col_count("Logons")), ("c_m2", col_unique(v["src"], "Sources"))]), 24, 14))
    p.append((ranked_table(v, "fan-sources", "6. Fan-out - sources trying the most accounts",
                           "One source trying many accounts is password spraying. Security 4625; sources without "
                           "an IP (local logons) are not ranked.", [(v["src"], 30, "Source IP")], ("c_m0", "desc"),
                           f'({q["failed"]}) and {v["src"]}: * and {_real_source(v["src"])} and {_people(v["user"])}',
                           [("c_m0", col_unique(v["user"], "Accounts tried")), ("c_m1", col_count("Failed logons")),
                            ("c_m2", machines())]), 24, 14))
    p.append((ranked_table(v, "fan-machines", "6. Fan-out - machines reached from the most sources",
                           "A machine logged on to from many places: a file server is normal, a workstation is not."
                           " Security 4624.", [(H, 30, "Machine")], ("c_m0", "desc"), f'({q["logon"]}) and {v["src"]}: * and {_real_source(v["src"])}',
                           [("c_m0", col_unique(v["src"], "Sources")), ("c_m1", col_unique(v["user"], "Accounts")),
                            ("c_m2", col_count("Logons"))]), 48, 12))

    # 7. Longest command lines
    p.append((ranked_table(v, "long-commands", "7. Longest command lines",
                           "Command lines, longest first: encoded and obfuscated payloads are long." + PROC_SRC + TWICE,
                           [(v["cmd"], 30, "Command line")], ("c_m0", "desc"), f'({q["proc"]}) and {v["cmd"]}: *',
                           [("c_m0", col_max(v["cmdlen"], "Length")), ("c_m1", machines())]), 48, 14))
    if v["pshost"]:
        p.append((ranked_table(v, "long-powershell", "7. Longest PowerShell start lines",
                               "How PowerShell was started, longest first: -enc and long one-liners. Windows "
                               "PowerShell 400 - default logging.", [(v["pshost"], 30, "PowerShell started as")],
                               ("c_m0", "desc"), f'({q["ps"]}) and {v["pshost"]}: *',
                               [("c_m0", col_max(v["pshostlen"], "Length")), ("c_m1", machines())]), 48, 14))
    p.append((ranked_table(v, "long-services", "7. Longest service command lines",
                           "Service command lines, longest first: a service that runs a PowerShell one-liner is a "
                           "common persistence trick. System 7045, Security 4697.",
                           [(v["svcbin"], 30, "Service program")], ("c_m0", "desc"), f'({q["svc"]}) and {v["svcbin"]}: *',
                           [("c_m0", col_max(v["svcbinlen"], "Length")), ("c_m1", machines())]), 48, 12))
    return p


def layout(panels):
    """Left to right, 48 wide; a row wraps when the next panel does not fit."""
    out, x, y, row_h = [], 0, 0, 0
    for obj, w, h in panels:
        if x + w > 48:
            x, y, row_h = 0, y + row_h, 0
        out.append((obj, {"x": x, "y": y, "w": w, "h": h}))
        x, row_h = x + w, max(row_h, h)
    return out


def build_dashboard(view, placed):
    v = VIEWS[view]
    pj, refs = [], []
    for i, (obj, grid) in enumerate(placed, start=1):
        pj.append({"type": "lens", "gridData": {**grid, "i": str(i)}, "panelIndex": str(i),
                   "embeddableConfig": {"enhancements": {}}, "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": "lens", "id": obj["id"]})
    return {
        "id": v["dashboard"], "type": "dashboard", "managed": False,
        "attributes": {
            "title": v["title"],
            "description": ("Seven anomaly hunts beyond 'rarest first': only on one machine, new lately, odd "
                            "hours (UTC), wrong place, bursts, fan-out, longest command lines. On real machines "
                            "start with sections 4, 6 and 7, then use 1 and 2 as leads." + v["note"]),
            "panelsJSON": json.dumps(pj),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "syncCursor": True,
                                       "syncTooltips": True, "hidePanelTitles": False}),
            "version": 3, "timeRestore": True, "timeFrom": TIME_FROM, "timeTo": TIME_TO,
            "refreshInterval": {"pause": True, "value": 60000},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": v["query"], "language": "kuery"}, "filter": []})},
        },
        "references": refs,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", default="output/hayabusa-anomaly.ndjson")
    args = ap.parse_args()
    objects = []
    for view in ("raw", "detections"):
        placed = layout(build_panels(view))
        objects += [stamp(o) for o, _ in placed] + [stamp(build_dashboard(view, placed))]
        print(f"{VIEWS[view]['dashboard']}: {len(placed)} panels")
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        for o in objects:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"wrote {len(objects)} objects -> {args.output}")


if __name__ == "__main__":
    main()
