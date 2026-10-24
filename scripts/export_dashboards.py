#!/usr/bin/env python3
"""Export the Hayabusa dashboards from a live Kibana into one importable file.

Read-only against the source: it lists and exports, never writes. Takes every
saved object whose id starts with `hayabusa-` (dashboards, Lens panels, saved
searches, the data view with its field labels) plus anything they reference,
so the file imports cleanly into a different Kibana through the UI.

Exports what is LIVE, not what make_*.py would build, so edits made in the
Kibana UI travel with it.

Usage:
  python scripts/export_dashboards.py --env-file .env -o kibana/hayabusa-kibana-objects.ndjson
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kibana_setup import Kibana, load_env, DEFAULT_ENV, ID_PREFIX

TYPES = ["dashboard", "lens", "visualization", "search", "index-pattern"]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--env-file", default=DEFAULT_ENV)
    args = ap.parse_args()

    kb = Kibana(load_env(args.env_file))
    status = kb.call("GET", "/api/status")
    version = status.json().get("version", {}).get("number", "?") if status.status_code == 200 else "?"
    print(f"connected to https://{kb.host}/kibana (Kibana {version})")

    # Paged: Security Onion ships over a thousand dashboards of its own, so a
    # single page silently missed ours.
    wanted, page = [], 1
    while True:
        r = kb.call("GET", "/api/saved_objects/_find",
                    params={"type": TYPES, "per_page": 1000, "page": page})
        if r.status_code != 200:
            sys.exit(f"could not list saved objects: HTTP {r.status_code} {r.text[:300]}")
        body = r.json()
        wanted += [{"type": o["type"], "id": o["id"]} for o in body.get("saved_objects", [])
                   if str(o.get("id", "")).startswith(ID_PREFIX)]
        if page * body.get("per_page", 1000) >= body.get("total", 0):
            break
        page += 1
    if not wanted:
        sys.exit(f"no saved objects with id '{ID_PREFIX}*' found - nothing to export")

    r = kb.call("POST", "/api/saved_objects/_export",
                json={"objects": wanted, "includeReferencesDeep": True})
    if r.status_code != 200:
        sys.exit(f"export failed: HTTP {r.status_code} {r.text[:300]}")

    lines = [l for l in r.text.splitlines() if l.strip()]
    objects = [json.loads(l) for l in lines]
    details = objects[-1] if "exportedCount" in objects[-1] else {}
    if details.get("missingRefCount"):
        print(f"  WARNING: {details['missingRefCount']} referenced object(s) missing: "
              f"{details.get('missingReferences')}")

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")

    print(f"  wrote {details.get('exportedCount', len(lines))} objects to {args.output}")
    for o in objects:
        if o.get("type") in ("dashboard", "search", "index-pattern"):
            a = o.get("attributes", {})
            extra = f"  (pattern {a['title']})" if o["type"] == "index-pattern" else ""
            print(f"    {o['type']:<14} {a.get('name') or a.get('title')}{extra}")
    print(f"  source Kibana version: {version} - the target must be this version or newer")


if __name__ == "__main__":
    main()
