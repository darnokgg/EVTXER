#!/usr/bin/env python3
r"""Compare two Hayabusa builds (or two rule sets) on the same EVTX folder.

  python -I tools/dev/hayabusa_compare.py <old hayabusa.exe> <new hayabusa.exe> <evtx dir> <work dir>

Runs hayabusa_scan_count.py once per build (it counts while Hayabusa writes, so
Defender cannot lock the results first), then prints: total detections, the
output field names each build writes (a new or missing field breaks the ECS
conversion - Convert-HayabusaJsonlToEcs reads them by name), and the rules whose
count changed most. Put <work dir> under the Defender-excluded output\ folder.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def scan(exe, evtx, work, tag):
    out, summ = os.path.join(work, f"{tag}.jsonl"), os.path.join(work, f"{tag}.summary.json")
    subprocess.run([sys.executable, "-I", os.path.join(HERE, "hayabusa_scan_count.py"), exe, evtx, out, summ], check=True)
    return json.load(open(summ))


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    old_exe, new_exe, evtx, work = sys.argv[1:]
    os.makedirs(work, exist_ok=True)
    a, b = scan(old_exe, evtx, work, "old"), scan(new_exe, evtx, work, "new")
    print(f"\ndetections: {a['total']:,} -> {b['total']:,} ({b['total'] - a['total']:+,});"
          f" unparsable lines {a['bad']} -> {b['bad']}; exit {a['exit']} -> {b['exit']}")
    gone, new = sorted(set(a["keys"]) - set(b["keys"])), sorted(set(b["keys"]) - set(a["keys"]))
    print(f"output fields: {len(a['keys'])} -> {len(b['keys'])}; gone {gone or '-'}; new {new or '-'}")
    rules = set(a["rules"]) | set(b["rules"])
    delta = sorted(((b["rules"].get(r, 0) - a["rules"].get(r, 0), r) for r in rules), key=lambda d: -abs(d[0]))
    print(f"rules that fired: {len(a['rules'])} -> {len(b['rules'])}; biggest changes:")
    for d, r in [x for x in delta if x[0]][:25]:
        print(f"  {d:+7,}  {a['rules'].get(r, 0):>6,} -> {b['rules'].get(r, 0):>6,}  {r}")
    if gone:
        print("\nSTOP: the new build no longer writes", gone, "- check Convert-HayabusaJsonlToEcs before shipping it.")


if __name__ == "__main__":
    main()
