#!/usr/bin/env python3
"""Runtime fields for the Anomaly Hunt dashboards - the ONE place they are defined.

Lens cannot pick "Sysmon's Image, else 4688's NewProcessName", lowercase a
path, tell a system program in the wrong folder, or take a length - so these
op.* fields do, in Painless, for both data views:
  raw         hayabusa-raw-dataview  (EVTXER's raw events, hayabusa-raw-*; @timestamp)
  detections  hayabusa-evtx-dataview (Hayabusa detections;            @timestamp)

They read the stored event (params._source), not doc values: the templates
map winlog.event_data.* as keywords with an ignore_above, so a long command
line has no doc value at all, and a field one index never saw cannot throw.

Like every runtime field here they live ONLY in the data views of the shipped
export: add them to a lab Kibana's data views (the dict below is the body),
and the export carries them into kibana/*.ndjson.

    python -I scripts/anomaly_runtime_fields.py --view raw   # the runtimeFieldMap as JSON
"""
import argparse
import json
import os
import sys

TIME = {"raw": "@timestamp", "detections": "@timestamp"}

# Where each value comes from, best first.
SOURCES = {
    "raw": {
        "proc": ["winlog.event_data.Image", "winlog.event_data.NewProcessName", "process.executable"],
        "parent": ["winlog.event_data.ParentImage", "winlog.event_data.ParentProcessName", "process.parent.executable"],
        "cmd": ["process.command_line", "winlog.event_data.CommandLine"],
        "service_bin": ["winlog.event_data.ImagePath", "winlog.event_data.ServiceFileName"],
    },
    "detections": {
        "proc": ["process.executable"],
        "parent": ["process.parent.executable"],
        "cmd": ["process.command_line"],
        # file.path is the service line cut at the first .exe (hayabusa_to_ecs
        # binary_path); the whole line is the raw ImagePath (final review).
        "service_bin": ["winlog.event_data.ImagePath", "winlog.event_data.ServiceFileName", "file.path"],
    },
}

# A system program's own folders (lowercase); anywhere else is the wrong place.
SYS32 = ["c:\\windows\\system32\\", "c:\\windows\\syswow64\\"]
HOMES = {name: SYS32 for name in (
    "svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "winlogon.exe", "smss.exe", "wininit.exe",
    "spoolsv.exe", "taskhostw.exe", "conhost.exe", "dllhost.exe", "rundll32.exe", "regsvr32.exe", "cmd.exe",
    "searchindexer.exe", "lsaiso.exe")}
HOMES["explorer.exe"] = ["c:\\windows\\", "c:\\windows\\syswow64\\"]  # 64-bit Windows ships a 32-bit copy
HOMES["powershell.exe"] = ["c:\\windows\\system32\\windowspowershell\\v1.0\\",
                           "c:\\windows\\syswow64\\windowspowershell\\v1.0\\"]
# Folders any user can write to - where dropped tools run from.
USER_WRITABLE = ["\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\", "\\$recycle.bin\\", "\\perflogs\\"]
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
# Windows' own accounts, which log on everywhere every boot - left out of the
# account hunts by their EXACT shape only, and only with the SID of the SAME
# account (security reviews, 2026-10-17): a well-known name with its
# well-known SID, or a session-account prefix + ASCII digits with its SID
# range. No SID, a SID from another account, "DWM-backdoor" or a local
# account named SYSTEM: not built-in - fail closed, the row stays visible.
# (ANONYMOUS LOGON stays because a null session is what an attacker makes -
# ZeroLogon, relaying, enumeration - final review, 2026-10-17. OpenSSH's
# per-connection sshd_<pid> accounts are "VIRTUAL USERS" with an S-1-5-111
# SID - read from a test workstation, 4,951 logons - which only a SYSTEM-level
# process can mint; an ordinary account named sshd_1 gets S-1-5-21.)
BUILTIN_SID = {"SYSTEM": "S-1-5-18", "LOCAL SERVICE": "S-1-5-19", "NETWORK SERVICE": "S-1-5-20"}
BUILTIN_NUMBERED = {"DWM-": "S-1-5-90-", "UMFD-": "S-1-5-96-", "sshd_": "S-1-5-111-"}
# The account the panels show, and the (name, SID) pairs that may describe it:
# a detection's user.name is TargetUserName, else SubjectUserName
# (hayabusa_to_ecs.py) - its SID is the one beside the name it came from.
ACCOUNT = {
    "raw": ("winlog.event_data.TargetUserName",
            [("winlog.event_data.TargetUserName", "winlog.event_data.TargetUserSid")]),
    "detections": ("user.name",
                   [("winlog.event_data.TargetUserName", "winlog.event_data.TargetUserSid"),
                    ("winlog.event_data.SubjectUserName", "winlog.event_data.SubjectUserSid")]),
}


def lit(s):
    """A Painless string literal."""
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def lst(items):
    return "[" + ", ".join(lit(i) for i in items) + "]"


# First non-empty value at any of the dotted paths, in the stored event. A
# literal dotted key ("winlog.event_data.Image") is tried too; a list gives
# its first item.
PRELUDE = (
    "String val(def m, String p) { if (m == null) return null; def cur = null; "
    "if (m.containsKey(p)) { cur = m.get(p); } else { cur = m; "
    "for (String k : p.splitOnToken('.')) { if (!(cur instanceof Map) || !cur.containsKey(k)) return null; cur = cur.get(k); } } "
    "if (cur instanceof List) { if (cur.size() == 0) return null; cur = cur.get(0); } "
    "if (cur == null) return null; String s = cur.toString(); return s.isEmpty() ? null : s; } "
    "String pick(def m, def paths) { for (def p : paths) { String v = val(m, p); if (v != null) return v; } return null; } "
)


def _path_script(paths, body):
    """`body` sees `p`, the first value found (lowercased); nothing is emitted when none is."""
    return PRELUDE + f"String p = pick(params._source, {lst(paths)}); if (p == null) return; p = p.toLowerCase(); " + body


def _keyword(script):
    return {"type": "keyword", "script": {"source": script}}


def _long(script):
    return {"type": "long", "script": {"source": script}}


def _bool(script):
    return {"type": "boolean", "script": {"source": script}}


def _time(view, body):
    f = TIME[view]
    return (f"if (!doc.containsKey({lit(f)}) || doc[{lit(f)}].size() == 0) return; "
            f"ZonedDateTime z = doc[{lit(f)}].value; " + body)


def _wrong_place(paths):
    homes = "[" + ", ".join(f"{lit(k)}: {lst(v)}" for k, v in sorted(HOMES.items())) + "]"
    return _path_script(paths, (
        "int i = p.lastIndexOf('\\\\'); String name = i < 0 ? p : p.substring(i + 1); "
        "String dir = i < 0 ? '' : p.substring(0, i + 1); "
        f"Map homes = {homes}; if (!homes.containsKey(name)) {{ emit(false); return; }} "
        "for (def h : homes.get(name)) { if (dir == h) { emit(false); return; } } emit(true);"))


def _user_writable(paths):
    return _path_script(paths, (
        f"for (def d : {lst(USER_WRITABLE)}) {{ if (p.contains(d)) {{ emit(true); return; }} }} "
        "emit(p.startsWith('c:\\\\windows\\\\temp\\\\'));"))


def _builtin_account(view):
    shown, pairs = ACCOUNT[view]
    named = "[" + ", ".join(f"{lit(k)}: {lit(v)}" for k, v in sorted(BUILTIN_SID.items())) + "]"
    numbered = "[" + ", ".join(f"{lit(k)}: {lit(v)}" for k, v in sorted(BUILTIN_NUMBERED.items())) + "]"
    pair_list = "[" + ", ".join(f"[{lit(n)}, {lit(s)}]" for n, s in pairs) + "]"
    return _bool(PRELUDE + (
        f"String u = val(params._source, {lit(shown)}); if (u == null) return; "
        # The SID beside the same name - never another account's.
        "String sid = null; "
        f"for (def pr : {pair_list}) {{ if (u == val(params._source, pr[0])) {{ sid = val(params._source, pr[1]); break; }} }} "
        "if (sid == null) { emit(false); return; } "
        f"Map named = {named}; String n = u.toUpperCase(); "
        "if (named.containsKey(n)) { emit(sid == named.get(n)); return; } "
        f"Map numbered = {numbered}; "
        "for (def pre : numbered.keySet()) { if (!u.startsWith(pre) || u.length() <= pre.length()) continue; "
        "for (int i = pre.length(); i < u.length(); i++) { char c = u.charAt(i); "
        "if (c < (char) 48 || c > (char) 57) { emit(false); return; } } "
        "emit(sid.startsWith(numbered.get(pre))); return; } "
        "emit(false);"))


def runtime_fields(view):
    """The op.* runtime fields of one data view: {name: {type, script: {source}}}."""
    if view not in SOURCES:
        raise ValueError(f"view must be one of {sorted(SOURCES)}, not {view!r}")
    src = SOURCES[view]
    service_bin = src["service_bin"]
    # On detections file.path is a service's binary only on service events.
    guard = "if (pick(params._source, ['service.name']) == null) return; " if view == "detections" else ""
    f = {
        "op.HourUTC": _keyword(_time(view, "int hh = z.getHour(); emit(hh < 10 ? '0' + hh : '' + hh);")),
        "op.DayUTC": _keyword(_time(view, f"int d = z.getDayOfWeek().getValue(); def n = {lst(DAYS)}; emit(d + ' ' + n[d - 1]);")),
        "op.ProcPath": _keyword(_path_script(src["proc"], "emit(p);")),
        "op.ParentPath": _keyword(_path_script(src["parent"], "emit(p);")),
        "op.CmdLen": _long(PRELUDE + f"String c = pick(params._source, {lst(src['cmd'])}); if (c == null) return; emit((long) c.length());"),
        "op.ProcWrongPlace": _bool(_wrong_place(src["proc"])),
        "op.ProcUserWritable": _bool(_user_writable(src["proc"])),
        "op.ServiceBinary": _keyword(_path_script(service_bin, guard + "emit(p);")),
        "op.ServiceBinaryLen": _long(PRELUDE + guard + f"String c = pick(params._source, {lst(service_bin)}); if (c == null) return; emit((long) c.length());"),
        "op.ServiceUserWritable": _bool(_path_script(service_bin, guard + (
            f"for (def d : {lst(USER_WRITABLE)}) {{ if (p.contains(d)) {{ emit(true); return; }} }} "
            "emit(p.startsWith('c:\\\\windows\\\\temp\\\\'));"))),
        "op.BuiltinAccount": _builtin_account(view),
        # From the stored event: a keyword's ignore_above leaves the longest
        # lines without a doc value, which a row on the field itself drops.
        "op.CmdLine": _keyword(PRELUDE + f"String c = pick(params._source, {lst(src['cmd'])}); if (c == null) return; emit(c);"),
    }
    if view == "raw":
        # A real field since v81 (pulled out of the classic log's text when converted).
        f["op.HostApplicationLen"] = _long(PRELUDE + "String c = pick(params._source, ['winlog.event_data.HostApplication']); "
                                           "if (c == null) return; emit((long) c.trim().length());")
    return f


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--view", required=True, choices=sorted(SOURCES))
    print(json.dumps(runtime_fields(ap.parse_args().view), indent=1))


if __name__ == "__main__":
    main()
