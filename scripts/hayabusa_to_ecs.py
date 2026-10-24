#!/usr/bin/env python3
"""Transform Hayabusa dfir-timeline JSONL into ECS-hybrid documents.

"Hybrid" means: every original Hayabusa field is preserved under `hayabusa.*`,
and the commonly-pivoted ones are ALSO promoted to standard ECS fields so the
data lines up with the Zeek/Suricata telemetry already in Security Onion.

Expects Hayabusa output produced with:  -p super-verbose -t JSONL -O -b
  -O  ISO-8601 timestamps  (the default format does not parse in Elasticsearch)
  -b  full field names     (canonical Windows names map cleanly to ECS)

Usage:
  python hayabusa_to_ecs.py IN.jsonl -o OUT.jsonl [--import-id ID] [--bulk INDEX]
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

ECS_VERSION = "8.11.0"

# Hayabusa level -> numeric severity. Higher = worse, matching Elastic Security's
# convention. NOTE: Suricata documents already in Security Onion use the OPPOSITE
# scale (1 = most severe), so do not compare event.severity across the two.
SEVERITY = {
    "emergency": 100,
    "critical": 99,
    "high": 75,
    "medium": 50,
    "low": 25,
    "informational": 1,
}

# Hayabusa abbreviates ATT&CK tactics (see config/mitre_tactics.txt). Expand to
# canonical names + IDs so threat.tactic.* matches ATT&CK and the Elastic
# Security UI. Note Hayabusa folds attack.defense-evasion into "Stealth", and
# "DefImpair" is a Hayabusa-only tactic with no ATT&CK equivalent.
TACTIC_MAP = {
    "Recon": ("Reconnaissance", "TA0043"),
    "ResDev": ("Resource Development", "TA0042"),
    "InitAccess": ("Initial Access", "TA0001"),
    "Exec": ("Execution", "TA0002"),
    "Persis": ("Persistence", "TA0003"),
    "PrivEsc": ("Privilege Escalation", "TA0004"),
    "Stealth": ("Defense Evasion", "TA0005"),
    "DefImpair": ("Defense Impairment", None),
    "CredAccess": ("Credential Access", "TA0006"),
    "Disc": ("Discovery", "TA0007"),
    "LatMov": ("Lateral Movement", "TA0008"),
    "Collect": ("Collection", "TA0009"),
    "C2": ("Command and Control", "TA0011"),
    "Exfil": ("Exfiltration", "TA0010"),
    "Impact": ("Impact", "TA0040"),
}

TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
HASH_RE = re.compile(r"(\w+)=([0-9a-fA-F]+)")

# Winlogbeat's names for the logon types. Hayabusa's field mapping writes
# "10 - REMOTE_INTERACTIVE"; only the leading number is used.
LOGON_TYPES = {
    0: "System", 2: "Interactive", 3: "Network", 4: "Batch", 5: "Service", 7: "Unlock",
    8: "NetworkCleartext", 9: "NewCredentials", 10: "RemoteInteractive",
    11: "CachedInteractive", 12: "CachedRemoteInteractive", 13: "CachedUnlock",
}
LOGON_RE = re.compile(r"^\s*(\d+)")


BIN_QUOTED_RE = re.compile(r'^"([^"]+)"')
BIN_EXE_RE = re.compile(r"^(.+?\.(exe|dll|sys|com|scr|bat|cmd|ps1))(\s|$)", re.IGNORECASE)


def binary_path(value):
    """A service ImagePath is a command line; cut the arguments (see the
    PowerShell twin, ConvertTo-BinaryPath)."""
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    m = BIN_QUOTED_RE.match(v) or BIN_EXE_RE.match(v)
    return m.group(1) if m else v


def logon_type_name(value):
    m = LOGON_RE.match(str(value))
    if m and int(m.group(1)) in LOGON_TYPES:
        return LOGON_TYPES[int(m.group(1))]
    return str(value).strip()

# Values that carry no information. "n/a" is Hayabusa's own placeholder for a
# field it could not resolve; it is dropped from promoted ECS fields but left
# untouched inside hayabusa.details so the original record stays faithful.
EMPTY = (None, "", "-")
PLACEHOLDERS = {"", "-", "n/a", "N/A"}


def as_int(value):
    """Windows Security logs write PIDs as hex ('0x1a4'); Sysmon uses decimal."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        try:
            return int(v, 16) if v.lower().startswith("0x") else int(v)
        except ValueError:
            return None
    return None


def as_ip(value):
    if not isinstance(value, str):
        return None
    v = value.strip()
    if v in EMPTY or v == "::":
        return None
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        return None


def scalarize(value):
    """Collapse a Hayabusa value to a single meaningful scalar, or None.

    Hayabusa emits a LIST when a field occurs more than once in the source
    event (commonly ['n/a', 'n/a']). ECS fields like process.command_line are
    single-valued, so de-duplicate, drop placeholders, and join what remains.
    """
    if isinstance(value, list):
        seen = []
        for item in value:
            if isinstance(item, str) and item.strip() in PLACEHOLDERS:
                continue
            if item is None or item in seen:
                continue
            seen.append(item)
        if not seen:
            return None
        return seen[0] if len(seen) == 1 else " | ".join(str(x) for x in seen)
    if isinstance(value, str) and value.strip() in PLACEHOLDERS:
        return None
    return value


def dig(details, *names):
    """First present, meaningful value among `names`, collapsed to a scalar.

    Matching is case-insensitive, exact spelling first. Windows is not
    consistent about casing across channels -- Sysmon writes `ProcessId`
    while the firewall channel writes `ProcessID` -- and an exact-match
    lookup silently drops the latter. PowerShell property access is
    case-insensitive by default, so this also keeps HayabusaImport.ps1 and
    this script producing the same documents.
    """
    lowered = {}
    for k, val in details.items():
        lowered.setdefault(k.lower(), val)  # first spelling wins, as above
    for n in names:
        v = scalarize(details.get(n))
        if v in EMPTY:
            v = scalarize(lowered.get(n.lower()))
        if v not in EMPTY:
            return v
    return None


def add(container, key, value):
    if value not in EMPTY and value != []:
        container[key] = value


def basename(path):
    return str(path).replace("/", "\\").split("\\")[-1]


def dedupe_ci(values):
    """De-duplicate case-insensitively, keep first-seen casing, sort case-insensitively.

    Windows hostnames and account names are case-insensitive, so IE8WIN7 and
    IE8Win7 are the same host and should collapse to one entry in related.*.
    The algorithm is spelled out rather than left to sorted(set(...)) because
    the PowerShell port must produce byte-identical output, and the two
    languages disagree on default case handling.
    """
    seen = {}
    for v in values:
        key = str(v).lower()
        if key not in seen:
            seen[key] = v
    return [seen[k] for k in sorted(seen)]


def rename_unnamed(d):
    """Give any blank key a usable name, preserving its value and key order.

    Elasticsearch accepts a "" key inside a `flattened` field, but nothing can
    address it afterwards -- there is no way to write the field path in KQL or
    pick it in Discover -- so the value is effectively invisible. PowerShell
    5.1 is stricter still: ConvertFrom-Json refuses the whole line, which is
    how this was found.
    """
    if not any(k.strip() == "" for k in d):
        return d
    out = {}
    for k, v in d.items():
        out["(unnamed)" if k.strip() == "" else k] = v
    return out


_PAIR = re.compile(r"([^:¦]+?):\s*%([^%]+)%")
DEFAULT_HAYABUSA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "code", "hayabusa-x64")


def long_path(path):
    """The \\\\?\\ form of a path on Windows (no 260-character limit, for
    reading and for walking - a folder past the limit is otherwise never
    entered); the path itself elsewhere. Same as ConvertTo-LongPath."""
    if os.name != "nt":
        return path
    full = os.path.abspath(path)
    if full.startswith("\\\\?\\"):
        return full
    return "\\\\?\\UNC\\" + full[2:] if full.startswith("\\\\") else "\\\\?\\" + full


def load_alias_map(hayabusa_dir):
    """Details' short names back to real field names, from Hayabusa's own
    tables: rules/config/default_details.txt per provider and event ID, and a
    rule's own "details:" line, which wins. Keys "rule:<id>" and
    "<Provider>|<EventID>". Must read the same as Get-DetailsAliasMap in
    code/HayabusaLib.ps1; empty when the folder is not there."""
    out = {}
    if not hayabusa_dir:
        return out

    def table(text):
        return {a.strip(): f.strip() for a, f in _PAIR.findall(text)}

    defaults = os.path.join(hayabusa_dir, "rules", "config", "default_details.txt")
    if os.path.exists(defaults):
        for line in open(defaults, encoding="utf-8"):
            parts = line.rstrip("\r\n").split(",", 2)
            if len(parts) < 3 or parts[1].strip() == "EID":
                continue
            out[f"{parts[0].strip()}|{parts[1].strip()}"] = table(parts[2])
    rid = re.compile(r"(?m)^id:\s*(\S+)")
    rdet = re.compile(r"""(?m)^details:\s*['"]?(.*?)['"]?\s*$""")
    for root, _, files in os.walk(long_path(os.path.join(hayabusa_dir, "rules"))):
        for fn in files:
            if not fn.endswith(".yml"):
                continue
            # root is already the \\?\ form (long_path), so a path past 260
            # characters opens; one that still cannot costs only its names.
            try:
                with open(os.path.join(root, fn), encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            d, i = rdet.search(text), rid.search(text)
            if d and i:
                out[f"rule:{i.group(1)}"] = table(d.group(1))
    return out


def event_data(doc, aliases):
    """Every field of the event under its real name - see Get-EventData."""
    data = {}
    extra = doc.get("ExtraFieldInfo")
    if isinstance(extra, dict):
        data.update(rename_unnamed(extra))
    details = doc.get("Details")
    if isinstance(details, dict):
        m = (aliases or {}).get(f"rule:{doc.get('RuleID')}") or \
            (aliases or {}).get(f"{doc.get('Provider')}|{doc.get('EventID')}") or {}
        for k, v in rename_unnamed(details).items():
            data[m.get(k, k)] = v
    return data


def detection_id(doc):
    """The same detection gets the same id however often it is scanned (a
    re-pull, or the same logs twice), so the upload stores it once. EvtxFile is
    left out on purpose: it is where a copy landed, not what happened. Must
    build the same string as Get-DetectionId in code/HayabusaLib.ps1."""
    def part(name):
        v = doc.get(name)
        return "" if v is None else str(v)
    key = "|".join(part(n) for n in ("Computer", "Channel", "RecordID", "EventID",
                                     "Timestamp", "RuleID", "RuleTitle"))
    return hashlib.sha1(key.encode("utf-8")).hexdigest()


def transform(doc, import_id, import_file=None, aliases=None):
    details = doc.get("Details") or {}
    extra = doc.get("ExtraFieldInfo") or {}
    if not isinstance(details, dict):
        details = {"value": details}
    if not isinstance(extra, dict):
        extra = {"value": extra}
    # Hayabusa's "Reg Key Value Set (Sysmon Alert)" rule emits an unnamed ("")
    # key whose value is the registry value data -- i.e. the persistence payload
    # path. An empty field name cannot be queried in Kibana, so give it a real
    # one. The PowerShell GUI does the same rename, which keeps the two
    # importers producing identical documents.
    details = rename_unnamed(details)
    extra = rename_unnamed(extra)

    level = (doc.get("Level") or "").lower()
    severity = SEVERITY.get(level, 0)

    out = {
        "@timestamp": doc.get("Timestamp"),
        "ecs": {"version": ECS_VERSION},
        "message": doc.get("RuleTitle"),
        "event": {
            "id": detection_id(doc),
            "kind": "alert",
            "module": "hayabusa",
            "dataset": "hayabusa.alert",
            "severity": severity,
            "risk_score": severity,
            "ingested": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
        },
        # Mirrors Security Onion's own convention so one batch can be isolated
        # with `import.id: <id>`, exactly like so-import-pcap data.
        "import": {"id": import_id},
        # ExtraFieldInfo is not written separately any more: all of it is in
        # winlog.event_data, under the same names.
        "hayabusa": {"details": details},
    }

    event_id = doc.get("EventID")
    add(out["event"], "code", str(event_id) if event_id is not None else None)
    add(out["event"], "provider", doc.get("Provider"))
    add(out["import"], "file", import_file or doc.get("EvtxFile"))

    # --- rule ---------------------------------------------------------------
    rule = {}
    add(rule, "name", doc.get("RuleTitle"))
    add(rule, "id", doc.get("RuleID"))
    add(rule, "ruleset", doc.get("RuleFile"))
    if doc.get("RuleAuthor"):
        authors = [a.strip() for a in str(doc["RuleAuthor"]).split(",") if a.strip()]
        add(rule, "author", authors)
    if rule:
        out["rule"] = rule

    # --- host / winlog ------------------------------------------------------
    computer = doc.get("Computer")
    if computer:
        out["host"] = {"name": computer, "hostname": computer}

    winlog = {}
    add(winlog, "channel", doc.get("Channel"))
    add(winlog, "provider_name", doc.get("Provider"))
    add(winlog, "event_id", str(event_id) if event_id is not None else None)
    add(winlog, "record_id", doc.get("RecordID"))
    data = event_data(doc, aliases)
    if data:
        winlog["event_data"] = data
    if winlog:
        out["winlog"] = winlog

    if doc.get("EvtxFile"):
        out["log"] = {"file": {"path": doc["EvtxFile"]}}

    # --- hayabusa-native passthrough ----------------------------------------
    hb = out["hayabusa"]
    for src, dst in (
        ("Level", "level"),
        ("Status", "rule_status"),
        ("RuleCreationDate", "rule_creation_date"),
        ("RuleModifiedDate", "rule_modified_date"),
        ("RuleFile", "rule_file"),
        ("EvtxFile", "evtx_file"),
    ):
        add(hb, dst, doc.get(src))

    # --- threat (MITRE ATT&CK) ----------------------------------------------
    tactics = doc.get("MitreTactics") or []
    mitre_tags = doc.get("MitreTags") or []
    techniques = [t for t in mitre_tags if TECHNIQUE_RE.match(str(t))]
    other_mitre = [t for t in mitre_tags if not TECHNIQUE_RE.match(str(t))]
    if tactics or techniques:
        threat = {"framework": "MITRE ATT&CK"}
        if tactics:
            names, ids = [], []
            for t in tactics:
                name, tid = TACTIC_MAP.get(str(t), (str(t), None))
                if name not in names:
                    names.append(name)
                if tid and tid not in ids:
                    ids.append(tid)
            threat["tactic"] = {"name": names}
            if ids:
                threat["tactic"]["id"] = ids
        if techniques:
            threat["technique"] = {"id": techniques}
        out["threat"] = threat
    # Keep Hayabusa's own abbreviations for anyone used to reading its output.
    add(hb, "mitre_tactics", list(tactics))
    add(hb, "mitre_tags", other_mitre)
    if doc.get("OtherTags"):
        out["tags"] = list(doc["OtherTags"])

    # --- promoted ECS fields from Details -----------------------------------
    users, ips, hosts = [], [], []

    user = {}
    # Hayabusa's short names last; on Sysmon 10 SrcUser (the actor) first.
    sysmon10 = str(doc.get("EventID")) == "10" and "Sysmon" in str(doc.get("Channel") or "")
    user_keys = ("TargetUserName", "SubjectUserName", "User", "AccountName") + (
        ("SrcUser", "TgtUser") if sysmon10 else ("TgtUser", "SrcUser"))
    add(user, "name", dig(details, *user_keys))
    add(user, "domain", dig(details, "TargetDomainName", "SubjectDomainName"))
    add(user, "id", dig(details, "TargetUserSid", "SubjectUserSid"))
    if user:
        out["user"] = user
    for name in user_keys:
        v = scalarize(details.get(name))
        if isinstance(v, str) and v not in users:
            users.append(v)

    src_ip = as_ip(dig(details, "IpAddress", "SourceIp", "SrcIP", "ClientAddress"))
    if src_ip:
        source = {"ip": src_ip}
        port = as_int(dig(details, "IpPort", "SourcePort", "SrcPort"))
        if port is not None:
            source["port"] = port
        out["source"] = source
        ips.append(src_ip)

    dst_ip = as_ip(dig(details, "DestinationIp", "TgtIP", "DestAddress"))
    if dst_ip:
        destination = {"ip": dst_ip}
        port = as_int(dig(details, "DestinationPort", "TgtPort"))
        if port is not None:
            destination["port"] = port
        out["destination"] = destination
        ips.append(dst_ip)

    process = {}
    exe = dig(details, "NewProcessName", "Image", "ProcessName", "Proc")
    add(process, "executable", exe)
    if exe:
        add(process, "name", basename(exe))
    add(process, "command_line", dig(details, "CommandLine", "Cmdline"))
    pid = as_int(dig(details, "NewProcessId", "ProcessId", "PID"))
    if pid is not None:
        process["pid"] = pid
    parent_exe = dig(details, "ParentProcessName", "ParentImage", "ParentProc")
    if parent_exe:
        parent = {"executable": parent_exe, "name": basename(parent_exe)}
        ppid = as_int(dig(details, "ParentProcessId", "ParentPID"))
        if ppid is not None:
            parent["pid"] = ppid
        process["parent"] = parent
    if process:
        out["process"] = process

    hashes = dig(details, "Hashes", "Hash")
    if isinstance(hashes, str) and "=" in hashes:
        found = {k.lower(): v for k, v in HASH_RE.findall(hashes)}
        if found:
            out["file"] = {"hash": found}

    # --- hunt fields: Details first, then ExtraFieldInfo (see the PowerShell
    # twin, ConvertTo-EcsDocument, for why) ---------------------------------
    def dig_any(*names):
        v = dig(details, *names)
        return v if v not in EMPTY else dig(extra, *names)

    # Hayabusa's short aliases only on the events that define them: "Type"
    # is the logon type on 4624/4625/4634 only, "Query" a DNS name on Sysmon
    # 22 only (Sysmon 19 / WMI 5859 use it for WMI queries).
    eid = str(event_id) if event_id is not None else ""

    logon = dig_any("LogonType", *(("Type",) if eid in ("4624", "4625", "4634") else ()))
    if logon not in EMPTY:
        out.setdefault("winlog", {})["logon"] = {"type": logon_type_name(logon)}
    parent_cl = dig_any("ParentCommandLine", "ParentCmdline")
    if parent_cl not in EMPTY:
        out.setdefault("process", {}).setdefault("parent", {})["command_line"] = parent_cl
    svc = dig_any("ServiceName", "Svc")
    if svc not in EMPTY:
        out["service"] = {"name": svc}
    fpath = binary_path(dig_any("TargetFilename", "ImagePath", "ServiceFileName", "Path"))
    if fpath:
        f = out.setdefault("file", {})
        f["path"] = fpath
        f["name"] = basename(fpath)
    sb = dig_any("ScriptBlockText", "ScriptBlock")
    if sb not in EMPTY:
        out["powershell"] = {"file": {"script_block_text": str(sb)}}
    reg = dig_any("TargetObject", "TgtObj", "RegKey", *(("OldName",) if eid == "14" else ()))
    if reg not in EMPTY:
        out["registry"] = {"path": reg}
    query = dig_any("QueryName", *(("Query",) if eid == "22" else ()))
    if query not in EMPTY:
        out["dns"] = {"question": {"name": query}}

    workstation = dig(details, "WorkstationName", "SrcComp")
    if isinstance(workstation, str) and workstation.strip() not in EMPTY:
        hosts.append(workstation)
    if computer:
        hosts.append(computer)

    related = {}
    if users:
        related["user"] = dedupe_ci(users)
    if ips:
        related["ip"] = dedupe_ci(ips)
    if hosts:
        related["hosts"] = dedupe_ci(hosts)
    if related:
        out["related"] = related

    return out


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("input", help="Hayabusa JSONL file")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument(
        "--import-id",
        default=None,
        help="Batch id (default: random 32-hex, mirroring Security Onion's import.id)",
    )
    ap.add_argument(
        "--bulk",
        metavar="INDEX",
        help="Emit Elasticsearch _bulk NDJSON targeting INDEX instead of plain JSONL",
    )
    ap.add_argument("--limit", type=int, help="Only process the first N documents")
    ap.add_argument("--hayabusa-dir", default=DEFAULT_HAYABUSA_DIR,
                    help="Hayabusa folder whose rules name the Details fields (default: the tool's own)")
    args = ap.parse_args()

    import_id = args.import_id or uuid.uuid4().hex
    aliases = load_alias_map(args.hayabusa_dir)
    count = 0

    with open(args.input, encoding="utf-8") as fin, open(
        args.output, "w", encoding="utf-8", newline="\n"
    ) as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            if args.limit and count >= args.limit:
                break
            doc = transform(json.loads(line), import_id, aliases=aliases)
            if args.bulk:
                # create + _id: a detection already in the index is refused,
                # not doubled - the same rule as the GUI's upload.
                action = {"create": {"_index": args.bulk, "_id": doc["event"]["id"]}}
                fout.write(json.dumps(action, ensure_ascii=False) + "\n")
            fout.write(json.dumps(doc, ensure_ascii=False) + "\n")
            count += 1

    print(f"transformed {count} documents -> {args.output}", file=sys.stderr)
    print(f"import.id = {import_id}", file=sys.stderr)


if __name__ == "__main__":
    main()
